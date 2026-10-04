// Run once: node create-manager.js
// Edit the values below, then delete this file (or just leave it, it's harmless to keep around for later).
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('timeclock.db');

const email = 'lperez@rubixpremierrealty.com';     // CHANGE THIS
const password = '*LarryRE41';        // CHANGE THIS
const name = 'Larry Perez';              // CHANGE THIS

const hashed = bcrypt.hashSync(password, 10);
db.prepare(
  "INSERT INTO users (company, name, email, password, role, hourlyRate) VALUES (?, ?, ?, ?, 'manager', 0)"
).run('Company A', name, email, hashed);

console.log('Manager account created:', email);