const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // built into Node, nothing to install

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Locally this just saves to the project folder. On Render, DB_PATH points at the persistent disk instead.
const db = new Database(process.env.DB_PATH || 'timeclock.db');

const MAX_DEVICES_PER_USER = 2;
const SESSION_DAYS = 30; // how long someone stays logged in before they have to log in again
const DAY_MS = 24 * 60 * 60 * 1000;

// =====================================================================
// Who can do what
//   owner    = runs Punchly. Sees every company, adds/renames companies, creates managers.
//   manager  = runs ONE company. Only ever sees that company's people, shifts and sites.
//   employee = belongs to ONE company. Clocks in/out, requests time off.
// =====================================================================

// =====================================================================
// Database tables
// =====================================================================

// NEW: companies now live in the database, so they can be added and renamed from the dashboard.
// joinCode is what employees type when they sign up, so they never see a list of other companies.
db.exec(`
  CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    joinCode TEXT UNIQUE NOT NULL,
    createdAt INTEGER NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'employee',
    hourlyRate REAL DEFAULT 0
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeId INTEGER,
    clockIn INTEGER,
    clockOut INTEGER
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS user_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    deviceId TEXT NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s','now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL,
    name TEXT NOT NULL,
    lat REAL,
    lng REAL,
    radiusMeters REAL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS pto_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeId INTEGER,
    startDate TEXT,
    endDate TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending'
  )
`);

// One row per logged-in browser. The token is a long random string the browser
// keeps and sends back with every request, so the server knows who is asking.
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    userId INTEGER NOT NULL,
    expiresAt INTEGER NOT NULL
  )
`);

// Forgot-password requests and the one-time codes managers hand out.
// A row with no codeHash = "this person asked for help". A row with a codeHash = a code was issued.
db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    codeHash TEXT,
    expiresAt INTEGER,
    attempts INTEGER DEFAULT 0,
    requestedAt INTEGER NOT NULL
  )
`);

// Adds a column to an existing table only if it isn't there yet,
// so your live database on Render gets upgraded without losing anything.
function addColumnIfMissing(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}
addColumnIfMissing('entries', 'approved', 'INTEGER DEFAULT 0');
addColumnIfMissing('entries', 'site', 'TEXT');
addColumnIfMissing('users', 'companyId', 'INTEGER');  // NEW: which company this person belongs to
addColumnIfMissing('sites', 'companyId', 'INTEGER');  // NEW: which company this site belongs to

// =====================================================================
// Codes (join codes for companies, reset codes for passwords)
// =====================================================================

// Skips look-alike characters (no O/0, I/1/L) so codes are easy to read out loud
const CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function randomCode(length) {
  let code = '';
  for (let i = 0; i < length; i++) code += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  return code;
}
function normalizeCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); // "abcd-efgh" -> "ABCDEFGH"
}
function newJoinCode() {
  let code;
  do { code = randomCode(6); } while (db.prepare('SELECT 1 FROM companies WHERE joinCode = ?').get(code));
  return code;
}

// =====================================================================
// One-time upgrade of an existing database to the new company system
// PRAGMA user_version is a number SQLite stores inside the database file,
// so this block only ever runs once per database.
// =====================================================================
if (db.pragma('user_version', { simple: true }) < 1) {
  db.transaction(() => {
    // Every company name already in use (plus the old placeholder list) becomes a real company row
    const seed = String(process.env.COMPANIES || 'Company A, Company B, Company C, Company D')
      .split(',').map(s => s.trim()).filter(Boolean);
    const inUse = [
      ...db.prepare("SELECT DISTINCT company FROM users WHERE company <> ''").all(),
      ...db.prepare("SELECT DISTINCT company FROM sites WHERE company <> ''").all()
    ].map(r => r.company);

    for (const name of new Set([...seed, ...inUse])) {
      db.prepare('INSERT OR IGNORE INTO companies (name, joinCode, createdAt) VALUES (?, ?, ?)')
        .run(name, newJoinCode(), Date.now());
    }

    db.exec('UPDATE users SET companyId = (SELECT id FROM companies WHERE companies.name = users.company) WHERE companyId IS NULL');
    db.exec('UPDATE sites SET companyId = (SELECT id FROM companies WHERE companies.name = sites.company) WHERE companyId IS NULL');

    // Until now the one manager could see every company, so that account becomes the owner
    db.exec("UPDATE users SET role = 'owner' WHERE role = 'manager'");
  })();
  db.pragma('user_version = 1');
  console.log('Database upgraded to the company system.');
}

// ---- Make the owner account without needing a terminal ----
// On Render: Environment tab -> add MANAGER_EMAIL, MANAGER_PASSWORD (8+ characters) and MANAGER_NAME.
// When the server starts it creates that OWNER account if the email isn't registered yet
// (or upgrades the account to owner if it is). It never overwrites an existing password,
// so once you've logged in you can delete MANAGER_PASSWORD from Render.
function createOwnerFromEnv() {
  const email = String(process.env.MANAGER_EMAIL || '').trim().toLowerCase();
  const password = process.env.MANAGER_PASSWORD || '';
  const name = String(process.env.MANAGER_NAME || 'Owner').trim();
  if (!email) return;

  const existing = db.prepare('SELECT id, role FROM users WHERE lower(email) = ?').get(email);
  if (existing) {
    if (existing.role !== 'owner') {
      db.prepare("UPDATE users SET role = 'owner' WHERE id = ?").run(existing.id);
      console.log('Made ' + email + ' the owner (from MANAGER_EMAIL).');
    }
    return;
  }
  if (password.length < 8) {
    console.log('MANAGER_PASSWORD is missing or shorter than 8 characters, so no owner was created.');
    return;
  }
  db.prepare("INSERT INTO users (company, companyId, name, email, password, role, hourlyRate) VALUES ('', NULL, ?, ?, ?, 'owner', 0)")
    .run(name, email, bcrypt.hashSync(password, 10));
  console.log('Owner account created from environment variables: ' + email);
}
createOwnerFromEnv();

// =====================================================================
// Login checks ("middleware" = a function that runs before a route)
// =====================================================================

// Reads the token the browser sent, finds who it belongs to, and puts that person on req.user.
// Routes then use req.user instead of trusting IDs the browser typed in.
function requireLogin(req, res, next) {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Please log in.' });
  }

  const user = db.prepare(`
    SELECT users.id, users.companyId, companies.name AS companyName,
           users.name, users.email, users.role, users.hourlyRate
    FROM sessions
    JOIN users ON users.id = sessions.userId
    LEFT JOIN companies ON companies.id = users.companyId
    WHERE sessions.token = ? AND sessions.expiresAt > ?
  `).get(token, Date.now());

  if (!user) {
    return res.status(401).json({ success: false, message: 'Your session expired. Please log in again.' });
  }

  req.user = user;
  req.token = token;
  next();
}

// Managers AND the owner get through
function requireManager(req, res, next) {
  requireLogin(req, res, () => {
    if (req.user.role !== 'manager' && req.user.role !== 'owner') {
      return res.status(403).json({ success: false, message: 'Managers only.' });
    }
    next();
  });
}

// Only the owner gets through
function requireOwner(req, res, next) {
  requireLogin(req, res, () => {
    if (req.user.role !== 'owner') {
      return res.status(403).json({ success: false, message: 'Only the Punchly owner can do that.' });
    }
    next();
  });
}

// ---- THE wall between companies ----
// Works out which company a manager-page request is about.
//   - a manager ALWAYS gets their own company, whatever the browser asks for
//   - the owner picks one with ?companyId= (or companyId in the body)
// Every manager route below goes through this or canManage(), so one company can't see another's data.
function companyScope(req, res) {
  const id = req.user.role === 'owner'
    ? Number(req.query.companyId || (req.body && req.body.companyId))
    : req.user.companyId;
  const company = id ? db.prepare('SELECT id, name FROM companies WHERE id = ?').get(id) : null;
  if (!company) {
    res.status(400).json({ success: false, message: 'Pick a company first.' });
    return null;
  }
  return company;
}

// Is this person allowed to touch something that belongs to companyId?
function canManage(req, companyId) {
  return req.user.role === 'owner' || (companyId != null && companyId === req.user.companyId);
}

// Looks up an employee and checks they're in a company this manager runs.
// Answers "not found" either way, so nobody can poke at other companies' IDs.
function findManagedEmployee(req, res, employeeId) {
  const emp = db.prepare("SELECT id, name, companyId FROM users WHERE id = ? AND role = 'employee'").get(employeeId);
  if (!emp || !canManage(req, emp.companyId)) {
    res.status(404).json({ success: false, message: 'Employee not found.' });
    return null;
  }
  return emp;
}

// =====================================================================
// Small helpers
// =====================================================================

function distanceMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000; // Earth's radius in meters
  const toRad = deg => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function msToHours(ms) {
  return Math.round(((ms || 0) / 3600000) * 100) / 100;
}

function isNumber(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function isDateString(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function formatDistance(m) {
  return m >= 1000 ? (m / 1000).toFixed(1) + ' km' : Math.round(m) + ' m';
}

function cleanEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function toCSV(rows, columns) {
  const header = columns.join(',');
  const lines = rows.map(row =>
    columns.map(col => {
      let val = row[col] === null || row[col] === undefined ? '' : row[col];
      // A cell starting with = + - @ can run as a formula in Excel. Prefixing ' makes it plain text.
      if (typeof val === 'string' && /^[=+\-@]/.test(val)) val = "'" + val;
      return '"' + String(val).replace(/"/g, '""') + '"';
    }).join(',')
  );
  return [header, ...lines].join('\n');
}

// The server on Render runs in UTC, so the manager's page sends its own timezone
// (like "America/Chicago") and the CSV times are printed in that timezone instead.
function makeTimeFormatter(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }); // throws if tz isn't a real timezone
    return ts => new Date(ts).toLocaleString('en-US', { timeZone: tz });
  } catch {
    return ts => new Date(ts).toLocaleString('en-US');
  }
}

// The manager's page works out the start/end of the chosen days in local time
// and sends them as plain millisecond numbers, so there's no timezone guessing here.
function exportRange(query) {
  const startMs = Number(query.startMs) || 0;
  const endMs = Number(query.endMs) || Date.now();
  return { startMs, endMs };
}

function safeFilePart(s) {
  return String(s).replace(/[^A-Za-z0-9 _-]/g, '').trim().replace(/\s+/g, '-').toLowerCase() || 'company';
}

// =====================================================================
// Public routes (no login needed)
// =====================================================================

// Lets the sign-up page show "You're joining Acme Builders" once a code is typed.
// Only answers for one exact code, so there's no way to list the companies.
app.get('/join-code/:code', (req, res) => {
  const company = db.prepare('SELECT name FROM companies WHERE joinCode = ?').get(normalizeCode(req.params.code));
  if (!company) return res.status(404).json({ success: false, message: "That company code doesn't exist." });
  res.json({ success: true, name: company.name });
});

app.post('/register', (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || '');
  const deviceId = req.body.deviceId;

  const company = db.prepare('SELECT id, name FROM companies WHERE joinCode = ?').get(normalizeCode(req.body.companyCode));
  if (!company) {
    return res.status(400).json({ success: false, message: "That company code doesn't exist. Ask your manager for it." });
  }
  if (!name) {
    return res.status(400).json({ success: false, message: 'Enter your name.' });
  }
  if (!email.includes('@')) {
    return res.status(400).json({ success: false, message: 'Enter a valid email.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
  }

  // lower() so "Bob@Mail.com" and "bob@mail.com" count as the same email
  if (db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email)) {
    return res.status(400).json({ success: false, message: 'That email is already registered.' });
  }

  // bcrypt scrambles the password one-way. "10" = rounds of scrambling, a solid default.
  const info = db.prepare("INSERT INTO users (company, companyId, name, email, password, role) VALUES (?, ?, ?, ?, ?, 'employee')")
    .run(company.name, company.id, name, email, bcrypt.hashSync(password, 10));

  if (deviceId) {
    db.prepare('INSERT INTO user_devices (userId, deviceId) VALUES (?, ?)').run(info.lastInsertRowid, String(deviceId));
  }

  res.json({ success: true, companyName: company.name });
});

app.post('/login', (req, res) => {
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || '');
  const deviceId = req.body.deviceId ? String(req.body.deviceId) : null;

  const user = db.prepare(`
    SELECT users.*, companies.name AS companyName
    FROM users LEFT JOIN companies ON companies.id = users.companyId
    WHERE lower(users.email) = ?
  `).get(email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ success: false, message: 'Wrong email or password.' });
  }

  if (deviceId) {
    const knownDevices = db.prepare('SELECT DISTINCT deviceId FROM user_devices WHERE userId = ?').all(user.id);
    const alreadyKnown = knownDevices.some(d => d.deviceId === deviceId);
    if (!alreadyKnown && knownDevices.length >= MAX_DEVICES_PER_USER) {
      return res.status(403).json({
        success: false,
        message: 'Device limit reached. Ask your manager to reset your devices.'
      });
    }
    if (!alreadyKnown) {
      db.prepare('INSERT INTO user_devices (userId, deviceId) VALUES (?, ?)').run(user.id, deviceId);
    }
  }

  // Tidy up old sessions, then make a new one for this login
  db.prepare('DELETE FROM sessions WHERE expiresAt <= ?').run(Date.now());
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, userId, expiresAt) VALUES (?, ?, ?)')
    .run(token, user.id, Date.now() + SESSION_DAYS * DAY_MS);

  const { password: _unused, company: _old, ...safeUser } = user; // never send the password hash back

  res.json({ success: true, token, user: safeUser });
});

// ---- Forgot password ----
// There's no email set up, so the manager is the one who hands out reset codes:
// 1) employee taps "Forgot password" -> the request shows up on their company's dashboard
// 2) manager creates a one-time code and tells the employee
// 3) employee enters the code + a new password
app.post('/forgot-password', (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(cleanEmail(req.body.email));
  if (user) {
    const pending = db.prepare('SELECT id FROM password_resets WHERE userId = ? AND codeHash IS NULL').get(user.id);
    if (!pending) {
      db.prepare('INSERT INTO password_resets (userId, requestedAt) VALUES (?, ?)').run(user.id, Date.now());
    }
  }
  // Same answer whether or not the email exists, so nobody can use this to find out who has an account
  res.json({ success: true });
});

app.post('/reset-password', (req, res) => {
  const code = normalizeCode(req.body.code);
  const newPassword = String(req.body.newPassword || '');

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: 'Your new password needs at least 8 characters.' });
  }

  const wrongCode = () => res.status(400).json({
    success: false,
    message: 'That code is wrong or has expired. Ask your manager for a new one.'
  });

  const user = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(cleanEmail(req.body.email));
  if (!user) return wrongCode();

  const reset = db.prepare(`
    SELECT * FROM password_resets
    WHERE userId = ? AND codeHash IS NOT NULL AND expiresAt > ?
    ORDER BY id DESC LIMIT 1
  `).get(user.id, Date.now());

  // 5 wrong tries and the code stops working, so it can't be guessed
  if (!reset || reset.attempts >= 5) return wrongCode();

  if (!bcrypt.compareSync(code, reset.codeHash)) {
    db.prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?').run(reset.id);
    return wrongCode();
  }

  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), user.id);
  db.prepare('DELETE FROM password_resets WHERE userId = ?').run(user.id);
  db.prepare('DELETE FROM sessions WHERE userId = ?').run(user.id); // log out anywhere the old password was used
  res.json({ success: true });
});

// =====================================================================
// Employee routes (must be logged in; everything uses req.user)
// =====================================================================

app.post('/logout', requireLogin, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token);
  res.json({ success: true });
});

app.post('/clock-in', requireLogin, (req, res) => {
  const { latitude, longitude } = req.body;
  const employeeId = req.user.id;

  if (!isNumber(latitude) || !isNumber(longitude)) {
    return res.status(400).json({ success: false, message: 'Location is required to clock in.' });
  }

  const alreadyIn = db.prepare('SELECT id FROM entries WHERE employeeId = ? AND clockOut IS NULL').get(employeeId);
  if (alreadyIn) {
    return res.status(400).json({ success: false, message: 'You are already clocked in.' });
  }

  const sites = db.prepare('SELECT * FROM sites WHERE companyId = ?').all(req.user.companyId);
  const matchedSite = sites.find(site =>
    distanceMeters(latitude, longitude, site.lat, site.lng) <= site.radiusMeters
  );

  if (!matchedSite) {
    if (sites.length === 0) {
      return res.status(403).json({ success: false, message: 'No work sites are set up for your company yet. Ask your manager to add one.' });
    }
    // Tell them how far they are from the closest site's edge
    const nearest = sites
      .map(site => ({ site, gap: distanceMeters(latitude, longitude, site.lat, site.lng) - site.radiusMeters }))
      .sort((a, b) => a.gap - b.gap)[0];
    return res.status(403).json({
      success: false,
      message: `You're about ${formatDistance(nearest.gap)} from ${nearest.site.name}. Move closer and try again.`
    });
  }

  const clockIn = Date.now();
  db.prepare('INSERT INTO entries (employeeId, clockIn, clockOut, site) VALUES (?, ?, NULL, ?)')
    .run(employeeId, clockIn, matchedSite.name);

  res.json({ success: true, clockIn, site: matchedSite.name });
});

app.post('/clock-out', requireLogin, (req, res) => {
  const openEntry = db.prepare(
    'SELECT * FROM entries WHERE employeeId = ? AND clockOut IS NULL ORDER BY id DESC LIMIT 1'
  ).get(req.user.id);

  if (!openEntry) {
    return res.status(400).json({ success: false, message: "You're not clocked in." });
  }

  const clockOut = Date.now();
  db.prepare('UPDATE entries SET clockOut = ? WHERE id = ?').run(clockOut, openEntry.id);

  res.json({ success: true, clockOut });
});

// The work sites for this person's company, so the app can show them on a map before clocking in
app.get('/my-sites', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT name, lat, lng, radiusMeters FROM sites WHERE companyId = ? ORDER BY name').all(req.user.companyId);
  res.json(rows);
});

app.get('/my-entries', requireLogin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, clockIn, clockOut, approved, site
    FROM entries
    WHERE employeeId = ?
    ORDER BY clockIn DESC
    LIMIT 200
  `).all(req.user.id);
  res.json(rows);
});

app.get('/my-summary', requireLogin, (req, res) => {
  const row = db.prepare(`
    SELECT
      SUM(clockOut - clockIn) AS totalMs,
      SUM(CASE WHEN approved = 1 THEN clockOut - clockIn ELSE 0 END) AS approvedMs
    FROM entries
    WHERE employeeId = ? AND clockOut IS NOT NULL
  `).get(req.user.id);
  res.json({ hours: msToHours(row.totalMs), approvedHours: msToHours(row.approvedMs) });
});

app.post('/pto-request', requireLogin, (req, res) => {
  const { startDate, endDate } = req.body;
  const reason = String(req.body.reason || '').trim().slice(0, 500);

  if (!isDateString(startDate) || !isDateString(endDate)) {
    return res.status(400).json({ success: false, message: 'Pick both dates.' });
  }
  if (endDate < startDate) {
    return res.status(400).json({ success: false, message: 'The end date is before the start date.' });
  }

  db.prepare('INSERT INTO pto_requests (employeeId, startDate, endDate, reason, status) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, startDate, endDate, reason, 'pending');
  res.json({ success: true });
});

app.get('/my-pto', requireLogin, (req, res) => {
  const rows = db.prepare(`
    SELECT id, startDate, endDate, reason, status
    FROM pto_requests
    WHERE employeeId = ?
    ORDER BY id DESC
    LIMIT 20
  `).all(req.user.id);
  res.json(rows);
});

// =====================================================================
// Companies (owner sees all; a manager sees only their own)
// =====================================================================

app.get('/me', requireLogin, (req, res) => res.json(req.user));

app.get('/companies', requireManager, (req, res) => {
  const where = req.user.role === 'owner' ? '' : 'WHERE companies.id = ?';
  const params = req.user.role === 'owner' ? [] : [req.user.companyId];
  const companies = db.prepare(`
    SELECT companies.id, companies.name, companies.joinCode,
      (SELECT COUNT(*) FROM users WHERE users.companyId = companies.id AND role = 'employee') AS employeeCount
    FROM companies ${where}
    ORDER BY companies.name COLLATE NOCASE
  `).all(...params);

  // The owner also sees each company's managers
  if (req.user.role === 'owner') {
    const managers = db.prepare("SELECT id, name, email, companyId FROM users WHERE role = 'manager' ORDER BY name").all();
    companies.forEach(c => { c.managers = managers.filter(m => m.companyId === c.id); });
  }
  res.json(companies);
});

app.post('/companies', requireOwner, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ success: false, message: 'Give the company a name.' });
  if (db.prepare('SELECT 1 FROM companies WHERE lower(name) = lower(?)').get(name)) {
    return res.status(400).json({ success: false, message: 'A company with that name already exists.' });
  }
  const info = db.prepare('INSERT INTO companies (name, joinCode, createdAt) VALUES (?, ?, ?)')
    .run(name, newJoinCode(), Date.now());
  res.json({ success: true, id: info.lastInsertRowid });
});

app.post('/companies/:id/rename', requireOwner, (req, res) => {
  const id = Number(req.params.id);
  const name = String(req.body.name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ success: false, message: 'The name can\'t be empty.' });
  if (db.prepare('SELECT 1 FROM companies WHERE lower(name) = lower(?) AND id <> ?').get(name, id)) {
    return res.status(400).json({ success: false, message: 'Another company already has that name.' });
  }
  const info = db.transaction(() => {
    const result = db.prepare('UPDATE companies SET name = ? WHERE id = ?').run(name, id);
    // keep the old text columns in step, so nothing older reads a stale name
    db.prepare('UPDATE users SET company = ? WHERE companyId = ?').run(name, id);
    db.prepare('UPDATE sites SET company = ? WHERE companyId = ?').run(name, id);
    return result;
  })();
  if (!info.changes) return res.status(404).json({ success: false, message: 'Company not found.' });
  res.json({ success: true });
});

// Makes a fresh join code (use it if the old one got shared with the wrong people).
// People who already joined aren't affected.
app.post('/companies/:id/new-code', requireManager, (req, res) => {
  const id = Number(req.params.id);
  if (!canManage(req, id)) return res.status(404).json({ success: false, message: 'Company not found.' });
  const code = newJoinCode();
  const info = db.prepare('UPDATE companies SET joinCode = ? WHERE id = ?').run(code, id);
  if (!info.changes) return res.status(404).json({ success: false, message: 'Company not found.' });
  res.json({ success: true, joinCode: code });
});

// Only empty companies can be deleted, so nobody's hours vanish by accident
app.delete('/companies/:id', requireOwner, (req, res) => {
  const id = Number(req.params.id);
  const people = db.prepare('SELECT COUNT(*) AS n FROM users WHERE companyId = ?').get(id).n;
  if (people > 0) {
    return res.status(400).json({ success: false, message: 'This company still has people in it. Delete or move them first.' });
  }
  db.transaction(() => {
    db.prepare('DELETE FROM sites WHERE companyId = ?').run(id);
    db.prepare('DELETE FROM companies WHERE id = ?').run(id);
  })();
  res.json({ success: true });
});

// The owner creates a manager account for a company (for example, a new client)
app.post('/companies/:id/managers', requireOwner, (req, res) => {
  const company = db.prepare('SELECT id, name FROM companies WHERE id = ?').get(Number(req.params.id));
  if (!company) return res.status(404).json({ success: false, message: 'Company not found.' });

  const name = String(req.body.name || '').trim();
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!name) return res.status(400).json({ success: false, message: 'Enter the manager\'s name.' });
  if (!email.includes('@')) return res.status(400).json({ success: false, message: 'Enter a valid email.' });
  if (password.length < 8) return res.status(400).json({ success: false, message: 'The password needs at least 8 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE lower(email) = ?').get(email)) {
    return res.status(400).json({ success: false, message: 'That email is already registered.' });
  }

  db.prepare("INSERT INTO users (company, companyId, name, email, password, role) VALUES (?, ?, ?, ?, ?, 'manager')")
    .run(company.name, company.id, name, email, bcrypt.hashSync(password, 10));
  res.json({ success: true });
});

app.delete('/managers/:id', requireOwner, (req, res) => {
  const mgr = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'manager'").get(req.params.id);
  if (!mgr) return res.status(404).json({ success: false, message: 'Manager not found.' });
  db.transaction(() => {
    db.prepare('DELETE FROM sessions WHERE userId = ?').run(mgr.id);
    db.prepare('DELETE FROM user_devices WHERE userId = ?').run(mgr.id);
    db.prepare('DELETE FROM password_resets WHERE userId = ?').run(mgr.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(mgr.id);
  })();
  res.json({ success: true });
});

// =====================================================================
// Manager routes (manager = their own company only; owner = the company they picked)
// =====================================================================

app.get('/employees', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  res.json(db.prepare(`
    SELECT users.id, users.name, users.email, users.hourlyRate,
      (SELECT COUNT(DISTINCT deviceId) FROM user_devices WHERE userId = users.id) AS deviceCount
    FROM users
    WHERE role = 'employee' AND companyId = ?
    ORDER BY users.name COLLATE NOCASE
  `).all(company.id));
});

app.post('/set-rate', requireManager, (req, res) => {
  const { hourlyRate } = req.body;
  if (!isNumber(hourlyRate) || hourlyRate < 0) {
    return res.status(400).json({ success: false, message: 'Enter a valid pay rate.' });
  }
  const emp = findManagedEmployee(req, res, req.body.employeeId); if (!emp) return;
  db.prepare('UPDATE users SET hourlyRate = ? WHERE id = ?').run(hourlyRate, emp.id);
  res.json({ success: true });
});

// Deletes an employee and everything tied to them (shifts, time off, devices, logins, reset codes).
app.delete('/employees/:id', requireManager, (req, res) => {
  const emp = findManagedEmployee(req, res, req.params.id); if (!emp) return;

  // A transaction = all of these happen together, or none of them do
  db.transaction(() => {
    db.prepare('DELETE FROM entries WHERE employeeId = ?').run(emp.id);
    db.prepare('DELETE FROM pto_requests WHERE employeeId = ?').run(emp.id);
    db.prepare('DELETE FROM user_devices WHERE userId = ?').run(emp.id);
    db.prepare('DELETE FROM sessions WHERE userId = ?').run(emp.id);
    db.prepare('DELETE FROM password_resets WHERE userId = ?').run(emp.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(emp.id);
  })();

  res.json({ success: true });
});

// Clears an employee's saved devices and logs them out everywhere
app.post('/reset-devices', requireManager, (req, res) => {
  const emp = findManagedEmployee(req, res, req.body.employeeId); if (!emp) return;
  db.prepare('DELETE FROM user_devices WHERE userId = ?').run(emp.id);
  db.prepare('DELETE FROM sessions WHERE userId = ?').run(emp.id);
  res.json({ success: true });
});

app.get('/sites', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  res.json(db.prepare('SELECT id, name, lat, lng, radiusMeters FROM sites WHERE companyId = ? ORDER BY name').all(company.id));
});

app.post('/sites', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  const { lat, lng, radiusMeters } = req.body;
  const name = String(req.body.name || '').trim();

  if (!name) return res.status(400).json({ success: false, message: 'Give the site a name.' });
  if (!isNumber(lat) || lat < -90 || lat > 90 || !isNumber(lng) || lng < -180 || lng > 180) {
    return res.status(400).json({ success: false, message: 'Latitude or longitude is not valid.' });
  }
  if (!isNumber(radiusMeters) || radiusMeters <= 0) {
    return res.status(400).json({ success: false, message: 'Radius must be more than 0.' });
  }

  db.prepare('INSERT INTO sites (company, companyId, name, lat, lng, radiusMeters) VALUES (?, ?, ?, ?, ?, ?)')
    .run(company.name, company.id, name, lat, lng, radiusMeters);
  res.json({ success: true });
});

app.delete('/sites/:id', requireManager, (req, res) => {
  const site = db.prepare('SELECT id, companyId FROM sites WHERE id = ?').get(req.params.id);
  if (!site || !canManage(req, site.companyId)) return res.status(404).json({ success: false, message: 'Site not found.' });
  db.prepare('DELETE FROM sites WHERE id = ?').run(site.id);
  res.json({ success: true });
});

// Who is on the clock right now (to catch forgotten clock-outs)
app.get('/open-entries', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  res.json(db.prepare(`
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NULL AND users.companyId = ?
    ORDER BY entries.clockIn
  `).all(company.id));
});

app.get('/pending-entries', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  res.json(db.prepare(`
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.approved = 0 AND users.companyId = ?
    ORDER BY entries.clockIn
  `).all(company.id));
});

// Finds a shift and checks it belongs to someone in a company this manager runs
function findManagedEntry(req, res, entryId) {
  const entry = db.prepare(`
    SELECT entries.id, users.companyId FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.id = ?
  `).get(entryId);
  if (!entry || !canManage(req, entry.companyId)) {
    res.status(404).json({ success: false, message: 'Shift not found.' });
    return null;
  }
  return entry;
}

// Lets the manager fix a shift's times (e.g. someone forgot to clock out)
app.post('/update-entry', requireManager, (req, res) => {
  const { clockIn, clockOut } = req.body;

  if (!isNumber(clockIn) || !isNumber(clockOut)) {
    return res.status(400).json({ success: false, message: 'Both times are required.' });
  }
  if (clockOut <= clockIn) {
    return res.status(400).json({ success: false, message: 'Clock-out must be after clock-in.' });
  }

  const entry = findManagedEntry(req, res, req.body.entryId); if (!entry) return;
  db.prepare('UPDATE entries SET clockIn = ?, clockOut = ?, approved = 0 WHERE id = ?').run(clockIn, clockOut, entry.id);
  res.json({ success: true });
});

app.post('/approve-entry', requireManager, (req, res) => {
  const entry = findManagedEntry(req, res, req.body.entryId); if (!entry) return;
  db.prepare('UPDATE entries SET approved = 1 WHERE id = ? AND clockOut IS NOT NULL').run(entry.id);
  res.json({ success: true });
});

app.get('/pto-requests', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  const { status } = req.query;
  let sql = `
    SELECT pto_requests.*, users.name AS employeeName FROM pto_requests
    JOIN users ON users.id = pto_requests.employeeId
    WHERE users.companyId = ?
  `;
  const params = [company.id];
  if (status) { sql += ' AND pto_requests.status = ?'; params.push(status); }
  sql += ' ORDER BY pto_requests.startDate';
  res.json(db.prepare(sql).all(...params));
});

app.post('/pto-decision', requireManager, (req, res) => {
  const { requestId, decision } = req.body;
  if (!['approved', 'denied'].includes(decision)) {
    return res.status(400).json({ success: false, message: 'Invalid decision.' });
  }
  const request = db.prepare(`
    SELECT pto_requests.id, users.companyId FROM pto_requests
    JOIN users ON users.id = pto_requests.employeeId
    WHERE pto_requests.id = ?
  `).get(requestId);
  if (!request || !canManage(req, request.companyId)) {
    return res.status(404).json({ success: false, message: 'Request not found.' });
  }
  db.prepare('UPDATE pto_requests SET status = ? WHERE id = ?').run(decision, request.id);
  res.json({ success: true });
});

// ---- Password help (manager side) ----
// The owner sees EVERY request (all companies, plus managers who forgot theirs),
// so nothing gets missed just because the company picker is on a different company.
// A manager sees only their own company's employees.
app.get('/reset-requests', requireManager, (req, res) => {
  const owner = req.user.role === 'owner';
  res.json(db.prepare(`
    SELECT password_resets.id, password_resets.userId, password_resets.requestedAt,
           users.name, users.email, users.role, companies.name AS companyName
    FROM password_resets
    JOIN users ON users.id = password_resets.userId
    LEFT JOIN companies ON companies.id = users.companyId
    WHERE password_resets.codeHash IS NULL
      AND ${owner ? "users.role IN ('employee', 'manager')" : "users.role = 'employee' AND users.companyId = ?"}
    ORDER BY password_resets.requestedAt
  `).all(...(owner ? [] : [req.user.companyId])));
});

// Makes a one-time code (good for 24 hours). Only the scrambled version is stored,
// so the manager sees the code once and should pass it straight to the employee.
app.post('/reset-code', requireManager, (req, res) => {
  // The owner can also make codes for managers; a manager only for their own employees
  let emp;
  if (req.user.role === 'owner') {
    emp = db.prepare("SELECT id FROM users WHERE id = ? AND role IN ('employee', 'manager')").get(req.body.userId);
    if (!emp) return res.status(404).json({ success: false, message: 'Person not found.' });
  } else {
    emp = findManagedEmployee(req, res, req.body.userId); if (!emp) return;
  }

  const code = randomCode(8);
  db.prepare('DELETE FROM password_resets WHERE userId = ?').run(emp.id);
  db.prepare('INSERT INTO password_resets (userId, codeHash, expiresAt, requestedAt) VALUES (?, ?, ?, ?)')
    .run(emp.id, bcrypt.hashSync(code, 10), Date.now() + DAY_MS, Date.now());

  res.json({ success: true, code: code.slice(0, 4) + '-' + code.slice(4) });
});

// ---- CSV exports ----

app.get('/export/attendance', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  const { startMs, endMs } = exportRange(req.query);
  const fmt = makeTimeFormatter(req.query.tz);

  const rows = db.prepare(`
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockIn >= ? AND entries.clockIn <= ? AND users.companyId = ?
    ORDER BY entries.clockIn
  `).all(startMs, endMs, company.id);

  const formatted = rows.map(r => ({
    employee: r.employeeName,
    site: r.site || '',
    clockIn: fmt(r.clockIn),
    clockOut: r.clockOut ? fmt(r.clockOut) : '',
    hours: r.clockOut ? msToHours(r.clockOut - r.clockIn) : '',
    approved: r.approved ? 'Yes' : 'No'
  }));

  const csv = toCSV(formatted, ['employee', 'site', 'clockIn', 'clockOut', 'hours', 'approved']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="punchly-attendance-${safeFilePart(company.name)}.csv"`);
  res.send(csv);
});

app.get('/export/payroll', requireManager, (req, res) => {
  const company = companyScope(req, res); if (!company) return;
  const { startMs, endMs } = exportRange(req.query);

  // Pay only counts APPROVED shifts. Unapproved hours get their own column
  // so the boss can see if something still needs approving before paying people.
  const rows = db.prepare(`
    SELECT users.name AS employeeName, users.hourlyRate,
      SUM(CASE WHEN entries.approved = 1 THEN entries.clockOut - entries.clockIn ELSE 0 END) AS approvedMs,
      SUM(CASE WHEN entries.approved = 0 THEN entries.clockOut - entries.clockIn ELSE 0 END) AS unapprovedMs
    FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.clockIn >= ? AND entries.clockIn <= ? AND users.companyId = ?
    GROUP BY entries.employeeId
    ORDER BY users.name
  `).all(startMs, endMs, company.id);

  const formatted = rows.map(r => {
    const hours = msToHours(r.approvedMs);
    const rate = r.hourlyRate || 0;
    return {
      employee: r.employeeName,
      approvedHours: hours,
      hourlyRate: rate,
      grossPay: Math.round(hours * rate * 100) / 100,
      unapprovedHours: msToHours(r.unapprovedMs)
    };
  });

  const csv = toCSV(formatted, ['employee', 'approvedHours', 'hourlyRate', 'grossPay', 'unapprovedHours']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="punchly-payroll-${safeFilePart(company.name)}.csv"`);
  res.send(csv);
});

// If anything above crashes, send back a clean error instead of a scary HTML page
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ success: false, message: 'Something went wrong on the server.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Punchly is running on port ' + PORT);
});