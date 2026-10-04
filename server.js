const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Locally this just saves to the project folder. On Render, DB_PATH will point at the persistent disk instead.
const db = new Database(process.env.DB_PATH || 'timeclock.db');

const MAX_DEVICES_PER_USER = 2;

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

const columns = db.prepare("PRAGMA table_info(entries)").all();
const hasApproved = columns.some(col => col.name === 'approved');
if (!hasApproved) {
  db.exec('ALTER TABLE entries ADD COLUMN approved INTEGER DEFAULT 0');
}

// ---- Sites now live in the database, one list per company, so a manager can edit them ----
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

const COMPANIES = [
  'Company A',
  'Company B',
  'Company C',
  'Company D'
];

function isManager(userId) {
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(userId);
  return !!user && user.role === 'manager';
}

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

app.get('/employees', (req, res) => {
  // SELECT * used to return the password column too — never send that to the browser.
  const { company } = req.query;
  const employees = company
    ? db.prepare(`SELECT id, company, name, email, role, hourlyRate FROM users WHERE role = 'employee' AND company = ?`).all(company)
    : db.prepare(`SELECT id, company, name, email, role, hourlyRate FROM users WHERE role = 'employee'`).all();

  res.json(employees);

});

app.get('/companies', (req, res) => res.json(COMPANIES));

// ---- Sites, filterable by ?company= ----
app.get('/sites', (req, res) => {
  const { company } = req.query;
  const rows = company
    ? db.prepare('SELECT * FROM sites WHERE company = ?').all(company)
    : db.prepare('SELECT * FROM sites').all();
  res.json(rows);
});

app.post('/sites', (req, res) => {
  const { company, name, lat, lng, radiusMeters, managerId } = req.body;
  if (!isManager(managerId)) return res.status(403).json({ success: false, message: 'Managers only' });
  db.prepare('INSERT INTO sites (company, name, lat, lng, radiusMeters) VALUES (?, ?, ?, ?, ?)')
    .run(company, name, lat, lng, radiusMeters);
  res.json({ success: true });
});

app.delete('/sites/:id', (req, res) => {
  if (!isManager(req.query.managerId)) return res.status(403).json({ success: false, message: 'Managers only' });
  db.prepare('DELETE FROM sites WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.post('/set-rate', (req, res) => {
  const { employeeId, hourlyRate, managerId } = req.body;
  if (!isManager(managerId)) return res.status(403).json({ success: false, message: 'Managers only' });
  db.prepare('UPDATE users SET hourlyRate = ? WHERE id = ?').run(hourlyRate, employeeId);
  res.json({ success: true });
});

app.post('/register', (req, res) => {
  const {
    company,
    name,
    email,
    password,
    deviceId
  } = req.body;

  if (!COMPANIES.includes(company)) {
    return res.status(400).json({ success: false, message: 'Invalid company' });
  }

  // bcrypt.hashSync scrambles the password one-way — not even we can reverse it back.
  // The "10" is how many rounds of scrambling; 10 is a solid default.
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {

    const info = db.prepare(`
      INSERT INTO users (
        company,
        name,
        email,
        password
      )
      VALUES (?, ?, ?, ?)
    `).run(
      company,
      name,
      email,
      hashedPassword
    );

    if (deviceId) {
      db.prepare('INSERT INTO user_devices (userId, deviceId) VALUES (?, ?)').run(info.lastInsertRowid, deviceId);
    }

    res.json({
      success: true
    });

  } catch (err) {

    res.status(400).json({
      success: false,
      message: err.message.includes('UNIQUE') ? 'Email already registered' : err.message
    });

  }
});

app.post('/login', (req, res) => {

  const {
    email,
    password,
    deviceId
  } = req.body;

  const user = db.prepare(`
    SELECT *
    FROM users
    WHERE email = ?
  `).get(email);

  // bcrypt.compareSync hashes the attempt the same way and checks if it matches the stored hash
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({
      success: false,
      message: 'Invalid login'
    });
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

  const { password: _unused, ...safeUser } = user; // strip the hashed password before sending the user back

  res.json({
    success: true,
    user: safeUser
  });

});


app.post('/clock-in', (req, res) => {
  const { employeeId, latitude, longitude } = req.body;

  if (typeof latitude !== 'number' || typeof longitude !== 'number') {
    return res.status(400).json({ success: false, message: 'Location required' });
  }

  const employee = db.prepare('SELECT company FROM users WHERE id = ?').get(employeeId);
  if (!employee) {
    return res.status(400).json({ success: false, message: 'Unknown employee' });
  }

  const sites = db.prepare('SELECT * FROM sites WHERE company = ?').all(employee.company);
  const matchedSite = sites.find(site =>
    distanceMeters(latitude, longitude, site.lat, site.lng) <= site.radiusMeters
  );

  if (!matchedSite) {
    return res.status(403).json({
      success: false,
      message: 'Not inside any allowed site'
    });
  }

  const alreadyIn = db.prepare(
    'SELECT id FROM entries WHERE employeeId = ? AND clockOut IS NULL'
  ).get(employeeId);

  if (alreadyIn) {
    return res.status(400).json({ success: false, message: 'Already clocked in' });
  }

  const clockIn = Date.now();
  db.prepare('INSERT INTO entries (employeeId, clockIn, clockOut) VALUES (?, ?, ?)')
    .run(employeeId, clockIn, null);

  res.json({ success: true, employeeId, clockIn, site: matchedSite.name });
});

app.post('/clock-out', (req, res) => {
  const employeeId = req.body.employeeId;

  const openEntry = db.prepare(
    'SELECT * FROM entries WHERE employeeId = ? AND clockOut IS NULL ORDER BY id DESC LIMIT 1'
  ).get(employeeId);

  if (!openEntry) {
    return res.status(400).json({ success: false, message: 'No open clock-in found' });
  }

  db.prepare('UPDATE entries SET clockOut = ? WHERE id = ?').run(Date.now(), openEntry.id);

  res.json({ success: true, employeeId, clockOut: Date.now() });
});

app.get('/entries', (req, res) => {
  const rows = db.prepare('SELECT * FROM entries').all();
  res.json(rows);
});

app.get('/summary', (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT entries.employeeId, SUM(entries.clockOut - entries.clockIn) AS totalMs
    FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL
    ${company ? 'AND users.company = ?' : ''}
    GROUP BY entries.employeeId
  `;
  const rows = db.prepare(sql).all(...(company ? [company] : []));

  const summary = rows.map(row => ({
    employeeId: row.employeeId,
    hours: Math.round((row.totalMs / 3600000) * 100) / 100,
    seconds: Math.round(row.totalMs / 1000)
  }));

  res.json(summary);
});

// ---- Manager: approve completed timesheets ----
app.get('/pending-entries', (req, res) => {
  const { company } = req.query;
  const sql = `
    SELECT entries.* FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.approved = 0
    ${company ? 'AND users.company = ?' : ''}
  `;
  const rows = db.prepare(sql).all(...(company ? [company] : []));
  res.json(rows);
});

app.post('/approve-entry', (req, res) => {
  const { entryId, managerId } = req.body;
  if (!isManager(managerId)) return res.status(403).json({ success: false, message: 'Managers only' });
  db.prepare('UPDATE entries SET approved = 1 WHERE id = ?').run(entryId);
  res.json({ success: true });
});

// ---- PTO requests ----
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

app.post('/pto-request', (req, res) => {
  const { employeeId, startDate, endDate, reason } = req.body;
  db.prepare('INSERT INTO pto_requests (employeeId, startDate, endDate, reason, status) VALUES (?, ?, ?, ?, ?)')
    .run(employeeId, startDate, endDate, reason || '', 'pending');
  res.json({ success: true });
});

app.get('/pto-requests', (req, res) => {
  const { status, company } = req.query;
  let sql = `
    SELECT pto_requests.* FROM pto_requests
    JOIN users ON users.id = pto_requests.employeeId
    WHERE 1=1
  `;
  const params = [];
  if (status) { sql += ' AND pto_requests.status = ?'; params.push(status); }
  if (company) { sql += ' AND users.company = ?'; params.push(company); }
  res.json(db.prepare(sql).all(...params));
});

app.post('/pto-decision', (req, res) => {
  const { requestId, decision, managerId } = req.body;
  if (!isManager(managerId)) return res.status(403).json({ success: false, message: 'Managers only' });
  if (!['approved', 'denied'].includes(decision)) {
    return res.status(400).json({ success: false, message: 'Invalid decision' });
  }
  db.prepare('UPDATE pto_requests SET status = ? WHERE id = ?').run(decision, requestId);
  res.json({ success: true });
});

function toCSV(rows, columns) {
  const header = columns.join(',');
  const lines = rows.map(row =>
    columns.map(col => {
      const val = row[col] === null || row[col] === undefined ? '' : String(row[col]);
      return '"' + val.replace(/"/g, '""') + '"';
    }).join(',')
  );
  return [header, ...lines].join('\n');
}

app.get('/export/attendance', (req, res) => {
  const { start, end, company } = req.query;
  const startMs = start ? new Date(start).getTime() : 0;
  const endMs = end ? new Date(end + 'T23:59:59').getTime() : Date.now();

  const sql = `
    SELECT entries.* FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockIn >= ? AND entries.clockIn <= ?
    ${company ? 'AND users.company = ?' : ''}
    ORDER BY entries.clockIn
  `;
  const rows = db.prepare(sql).all(...(company ? [startMs, endMs, company] : [startMs, endMs]));
 const formatted = rows.map(r => {

  const emp = db.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
  `).get(r.employeeId);

  return {
    employee: emp ? emp.name : r.employeeId,
    clockIn: new Date(r.clockIn).toLocaleString(),
    clockOut: r.clockOut ? new Date(r.clockOut).toLocaleString() : '',
    approved: r.approved ? 'Yes' : 'No'
  };

});

  const csv = toCSV(formatted, ['employee', 'clockIn', 'clockOut', 'approved']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="attendance.csv"');
  res.send(csv);
});

app.get('/export/payroll', (req, res) => {
  const { start, end, company } = req.query;
  const startMs = start ? new Date(start).getTime() : 0;
  const endMs = end ? new Date(end + 'T23:59:59').getTime() : Date.now();

  const sql = `
    SELECT entries.employeeId, SUM(entries.clockOut - entries.clockIn) AS totalMs
    FROM entries
    JOIN users ON users.id = entries.employeeId
    WHERE entries.clockOut IS NOT NULL AND entries.approved = 1 AND entries.clockIn >= ? AND entries.clockIn <= ?
    ${company ? 'AND users.company = ?' : ''}
    GROUP BY entries.employeeId
  `;
  const rows = db.prepare(sql).all(...(company ? [startMs, endMs, company] : [startMs, endMs]));

const formatted = rows.map(r => {

  const emp = db.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
  `).get(r.employeeId);

  const hours =
    Math.round((r.totalMs / 3600000) * 100) / 100;

  const rate =
    emp ? emp.hourlyRate : 0;

  return {
    employee: emp ? emp.name : r.employeeId,
    hours,
    hourlyRate: rate,
    grossPay:
      Math.round(hours * rate * 100) / 100
  };

});
  const csv = toCSV(formatted, ['employee', 'hours', 'hourlyRate', 'grossPay']);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="payroll.csv"');
  res.send(csv);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});