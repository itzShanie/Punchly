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

const COMPANIES = [
  'Company A',
  'Company B',
  'Company C',
  'Company D'
];

// =====================================================================
// Database tables
// =====================================================================

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

// NEW: one row per logged-in browser. The token is a long random string the browser
// keeps and sends back with every request, so the server knows who is asking.
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    userId INTEGER NOT NULL,
    expiresAt INTEGER NOT NULL
  )
`);

// NEW: forgot-password requests and the one-time codes managers hand out.
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
addColumnIfMissing('entries', 'site', 'TEXT'); // NEW: remembers which site someone clocked in at

// ---- Make the first manager without needing a terminal ----
// On Render: Environment tab -> add MANAGER_EMAIL, MANAGER_PASSWORD (8+ characters) and MANAGER_NAME.
// When the server starts it creates that manager if the email isn't registered yet
// (or upgrades the account to manager if it is). It never overwrites an existing password,
// so once you've logged in you can delete MANAGER_PASSWORD from Render.
function createManagerFromEnv() {
  const email = String(process.env.MANAGER_EMAIL || '').trim().toLowerCase();
  const password = process.env.MANAGER_PASSWORD || '';
  const name = String(process.env.MANAGER_NAME || 'Manager').trim();
  if (!email) return;

  const existing = db.prepare('SELECT id, role FROM users WHERE lower(email) = ?').get(email);
  if (existing) {
    if (existing.role !== 'manager') {
      db.prepare("UPDATE users SET role = 'manager' WHERE id = ?").run(existing.id);
      console.log('Made ' + email + ' a manager (from MANAGER_EMAIL).');
    }
    return;
  }
  if (password.length < 8) {
    console.log('MANAGER_PASSWORD is missing or shorter than 8 characters, so no manager was created.');
    return;
  }
  db.prepare("INSERT INTO users (company, name, email, password, role, hourlyRate) VALUES (?, ?, ?, ?, 'manager', 0)")
    .run(COMPANIES[0], name, email, bcrypt.hashSync(password, 10));
  console.log('Manager account created from environment variables: ' + email);
}
createManagerFromEnv();

// =====================================================================
// Login checks ("middleware" = a function that runs before a route)
// =====================================================================

// Reads the token the browser sent, finds who it belongs to, and puts that person on req.user.
// Routes then use req.user.id instead of trusting an ID the browser typed in.
function requireLogin(req, res, next) {
  const header = req.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Please log in.' });
  }

  const user = db.prepare(`
    SELECT users.id, users.company, users.name, users.email, users.role, users.hourlyRate
    FROM sessions
    JOIN users ON users.id = sessions.userId
    WHERE sessions.token = ? AND sessions.expiresAt > ?
  `).get(token, Date.now());

  if (!user) {
    return res.status(401).json({ success: false, message: 'Your session expired. Please log in again.' });
  }

  req.user = user;
  req.token = token;
  next();
}

// Same as requireLogin, plus the person must be a manager.
function requireManager(req, res, next) {
  requireLogin(req, res, () => {
    if (req.user.role !== 'manager') {
      return res.status(403).json({ success: false, message: 'Managers only.' });
    }
    next();
  });
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

// Reset codes skip look-alike characters (no O/0, I/1/L) so they're easy to read out loud
const CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function makeResetCode() {
  let code = '';
  for (let i = 0; i < 8; i++) code += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  return code;
}
function normalizeCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); // "abcd-efgh" -> "ABCDEFGH"
}

function formatDistance(m) {
  return m >= 1000 ? (m / 1000).toFixed(1) + ' km' : Math.round(m) + ' m';
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

// =====================================================================
// Public routes (no login needed)
// =====================================================================

app.get('/companies', (req, res) => res.json(COMPANIES));

app.post('/register', (req, res) => {
  const company = req.body.company;
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const deviceId = req.body.deviceId;

  if (!COMPANIES.includes(company)) {
    return res.status(400).json({ success: false, message: 'Pick a company.' });
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
  const existing = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);
  if (existing) {
    return res.status(400).json({ success: false, message: 'That email is already registered.' });
  }

  // bcrypt scrambles the password one-way. "10" = rounds of scrambling, a solid default.
  const hashedPassword = bcrypt.hashSync(password, 10);

  const info = db.prepare('INSERT INTO users (company, name, email, password) VALUES (?, ?, ?, ?)')
    .run(company, name, email, hashedPassword);

  if (deviceId) {
    db.prepare('INSERT INTO user_devices (userId, deviceId) VALUES (?, ?)').run(info.lastInsertRowid, String(deviceId));
  }

  res.json({ success: true });
});

app.post('/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const deviceId = req.body.deviceId ? String(req.body.deviceId) : null;

  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email);

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

  const { password: _unused, ...safeUser } = user; // never send the password hash back

  res.json({ success: true, token, user: safeUser });
});

// ---- Forgot password ----
// There's no email set up, so the manager is the one who hands out reset codes:
// 1) employee taps "Forgot password" -> the request shows up on the manager dashboard
// 2) manager creates a one-time code and tells the employee
// 3) employee enters the code + a new password
app.post('/forgot-password', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);
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
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = normalizeCode(req.body.code);
  const newPassword = String(req.body.newPassword || '');

  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: 'Your new password needs at least 8 characters.' });
  }

  const wrongCode = () => res.status(400).json({
    success: false,
    message: 'That code is wrong or has expired. Ask your manager for a new one.'
  });

  const user = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);
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
// Employee routes (must be logged in; everything uses req.user.id)
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

  const sites = db.prepare('SELECT * FROM sites WHERE company = ?').all(req.user.company);
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

// NEW: the work sites for this person's company, so the app can show them on a map before clocking in
app.get('/my-sites', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT name, lat, lng, radiusMeters FROM sites WHERE company = ? ORDER BY name').all(req.user.company);
  res.json(rows);
});

// Only this person's own punches (replaces the old /entries that returned everyone's)
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

// NEW: lets employees see whether their time off was approved
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
// Manager routes (must be logged in AND be a manager)
// The manager can switch between all companies, same as before.
// =====================================================================

app.get('/employees', requireManager, (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT users.id, users.company, users.name, users.email, users.hourlyRate,
      (SELECT COUNT(DISTINCT deviceId) FROM user_devices WHERE userId = users.id) AS deviceCount
    FROM users
    WHERE role = 'employee' ${company ? 'AND company = ?' : ''}
    ORDER BY users.name
  `;
  res.json(db.prepare(sql).all(...(company ? [company] : [])));
});

app.post('/set-rate', requireManager, (req, res) => {
  const { employeeId, hourlyRate } = req.body;
  if (!isNumber(hourlyRate) || hourlyRate < 0) {
    return res.status(400).json({ success: false, message: 'Enter a valid pay rate.' });
  }
  db.prepare('UPDATE users SET hourlyRate = ? WHERE id = ?').run(hourlyRate, employeeId);
  res.json({ success: true });
});

// Deletes an employee and everything tied to them (shifts, time off, devices, logins, reset codes).
// Only works on employees, so a manager can't delete themselves or another manager by accident.
app.delete('/employees/:id', requireManager, (req, res) => {
  const user = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'employee'").get(req.params.id);
  if (!user) return res.status(404).json({ success: false, message: 'Employee not found.' });

  // A transaction = all of these happen together, or none of them do
  db.transaction(() => {
    db.prepare('DELETE FROM entries WHERE employeeId = ?').run(user.id);
    db.prepare('DELETE FROM pto_requests WHERE employeeId = ?').run(user.id);
    db.prepare('DELETE FROM user_devices WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM sessions WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM password_resets WHERE userId = ?').run(user.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  })();

  res.json({ success: true });
});

// NEW: clears an employee's saved devices and logs them out everywhere
app.post('/reset-devices', requireManager, (req, res) => {
  const { employeeId } = req.body;
  db.prepare('DELETE FROM user_devices WHERE userId = ?').run(employeeId);
  db.prepare('DELETE FROM sessions WHERE userId = ?').run(employeeId);
  res.json({ success: true });
});

app.get('/sites', requireManager, (req, res) => {
  const { company } = req.query;
  const rows = company
    ? db.prepare('SELECT * FROM sites WHERE company = ? ORDER BY name').all(company)
    : db.prepare('SELECT * FROM sites ORDER BY name').all();
  res.json(rows);
});

app.post('/sites', requireManager, (req, res) => {
  const { company, lat, lng, radiusMeters } = req.body;
  const name = String(req.body.name || '').trim();

  if (!COMPANIES.includes(company)) return res.status(400).json({ success: false, message: 'Unknown company.' });
  if (!name) return res.status(400).json({ success: false, message: 'Give the site a name.' });
  if (!isNumber(lat) || lat < -90 || lat > 90 || !isNumber(lng) || lng < -180 || lng > 180) {
    return res.status(400).json({ success: false, message: 'Latitude or longitude is not valid.' });
  }
  if (!isNumber(radiusMeters) || radiusMeters <= 0) {
    return res.status(400).json({ success: false, message: 'Radius must be more than 0.' });
  }

  db.prepare('INSERT INTO sites (company, name, lat, lng, radiusMeters) VALUES (?, ?, ?, ?, ?)')
    .run(company, name, lat, lng, radiusMeters);
  res.json({ success: true });
});

app.delete('/sites/:id', requireManager, (req, res) => {
  db.prepare('DELETE FROM sites WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// NEW: who is on the clock right now (to catch forgotten clock-outs)
app.get('/open-entries', requireManager, (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NULL
    ${company ? 'AND users.company = ?' : ''}
    ORDER BY entries.clockIn
  `;
  res.json(db.prepare(sql).all(...(company ? [company] : [])));
});

app.get('/pending-entries', requireManager, (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.approved = 0
    ${company ? 'AND users.company = ?' : ''}
    ORDER BY entries.clockIn
  `;
  res.json(db.prepare(sql).all(...(company ? [company] : [])));
});

// NEW: lets the manager fix a shift's times (e.g. someone forgot to clock out)
app.post('/update-entry', requireManager, (req, res) => {
  const { entryId, clockIn, clockOut } = req.body;

  if (!isNumber(clockIn) || !isNumber(clockOut)) {
    return res.status(400).json({ success: false, message: 'Both times are required.' });
  }
  if (clockOut <= clockIn) {
    return res.status(400).json({ success: false, message: 'Clock-out must be after clock-in.' });
  }

  const info = db.prepare('UPDATE entries SET clockIn = ?, clockOut = ?, approved = 0 WHERE id = ?')
    .run(clockIn, clockOut, entryId);
  if (info.changes === 0) {
    return res.status(404).json({ success: false, message: 'Shift not found.' });
  }
  res.json({ success: true });
});

app.post('/approve-entry', requireManager, (req, res) => {
  db.prepare('UPDATE entries SET approved = 1 WHERE id = ? AND clockOut IS NOT NULL').run(req.body.entryId);
  res.json({ success: true });
});

app.get('/pto-requests', requireManager, (req, res) => {
  const { status, company } = req.query;
  let sql = `
    SELECT pto_requests.*, users.name AS employeeName FROM pto_requests
    JOIN users ON users.id = pto_requests.employeeId
    WHERE 1=1
  `;
  const params = [];
  if (status) { sql += ' AND pto_requests.status = ?'; params.push(status); }
  if (company) { sql += ' AND users.company = ?'; params.push(company); }
  sql += ' ORDER BY pto_requests.startDate';
  res.json(db.prepare(sql).all(...params));
});

app.post('/pto-decision', requireManager, (req, res) => {
  const { requestId, decision } = req.body;
  if (!['approved', 'denied'].includes(decision)) {
    return res.status(400).json({ success: false, message: 'Invalid decision.' });
  }
  db.prepare('UPDATE pto_requests SET status = ? WHERE id = ?').run(decision, requestId);
  res.json({ success: true });
});

// ---- Password help (manager side) ----
app.get('/reset-requests', requireManager, (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT password_resets.id, password_resets.userId, password_resets.requestedAt, users.name, users.email
    FROM password_resets
    JOIN users ON users.id = password_resets.userId
    WHERE password_resets.codeHash IS NULL AND users.role = 'employee'
    ${company ? 'AND users.company = ?' : ''}
    ORDER BY password_resets.requestedAt
  `;
  res.json(db.prepare(sql).all(...(company ? [company] : [])));
});

// Makes a one-time code (good for 24 hours). Only the scrambled version is stored,
// so the manager sees the code once and should pass it straight to the employee.
app.post('/reset-code', requireManager, (req, res) => {
  const user = db.prepare("SELECT id, name FROM users WHERE id = ? AND role = 'employee'").get(req.body.userId);
  if (!user) return res.status(404).json({ success: false, message: 'Employee not found.' });

  const code = makeResetCode();
  db.prepare('DELETE FROM password_resets WHERE userId = ?').run(user.id);
  db.prepare('INSERT INTO password_resets (userId, codeHash, expiresAt, requestedAt) VALUES (?, ?, ?, ?)')
    .run(user.id, bcrypt.hashSync(code, 10), Date.now() + DAY_MS, Date.now());

  res.json({ success: true, code: code.slice(0, 4) + '-' + code.slice(4) });
});

// ---- CSV exports ----

app.get('/export/attendance', requireManager, (req, res) => {
  const { company, tz } = req.query;
  const { startMs, endMs } = exportRange(req.query);
  const fmt = makeTimeFormatter(tz);

  // JOIN pulls the employee's name in the same query (the old code looked each one up separately)
  const sql = `
    SELECT entries.*, users.name AS employeeName FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockIn >= ? AND entries.clockIn <= ?
    ${company ? 'AND users.company = ?' : ''}
    ORDER BY entries.clockIn
  `;
  const rows = db.prepare(sql).all(...(company ? [startMs, endMs, company] : [startMs, endMs]));

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
  res.setHeader('Content-Disposition', 'attachment; filename="punchly-attendance.csv"');
  res.send(csv);
});

app.get('/export/payroll', requireManager, (req, res) => {
  const { company } = req.query;
  const { startMs, endMs } = exportRange(req.query);

  // Pay only counts APPROVED shifts. Unapproved hours get their own column
  // so the boss can see if something still needs approving before paying people.
  const sql = `
    SELECT users.name AS employeeName, users.hourlyRate,
      SUM(CASE WHEN entries.approved = 1 THEN entries.clockOut - entries.clockIn ELSE 0 END) AS approvedMs,
      SUM(CASE WHEN entries.approved = 0 THEN entries.clockOut - entries.clockIn ELSE 0 END) AS unapprovedMs
    FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.clockIn >= ? AND entries.clockIn <= ?
    ${company ? 'AND users.company = ?' : ''}
    GROUP BY entries.employeeId
    ORDER BY users.name
  `;
  const rows = db.prepare(sql).all(...(company ? [startMs, endMs, company] : [startMs, endMs]));

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
  res.setHeader('Content-Disposition', 'attachment; filename="punchly-payroll.csv"');
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