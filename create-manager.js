// Creates the Punchly OWNER account (or turns an existing account into the owner).
// The owner sees every company, and creates each company's managers from the dashboard.
//
// Easiest way: just run   node create-manager.js   and answer the questions.
// Or all in one go:       node create-manager.js boss@example.com "a-strong-password" "Boss Name"
//
// IMPORTANT: this writes to the database on the computer you run it on.
// Running it on your laptop does NOT add the owner to the live site on Render.
// For Render, either run it in the "Shell" tab there, or (no Shell needed) use the
// MANAGER_EMAIL / MANAGER_PASSWORD / MANAGER_NAME environment variables described in server.js.

const path = require('path');
const readline = require('readline');

const dbPath = process.env.DB_PATH || 'timeclock.db';

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

async function main() {
  // Loaded in here (not at the top) so that if they fail, we can show a helpful message below
  const Database = require('better-sqlite3');
  const bcrypt = require('bcryptjs');

  console.log('Using database file: ' + path.resolve(dbPath));

  let [email, password, name] = process.argv.slice(2);
  if (!email) email = await ask('Owner email: ');
  if (!name) name = await ask('Owner full name: ');
  if (!password) password = await ask('Password (8+ characters, it will show as you type): ');

  email = String(email || '').trim().toLowerCase();
  if (!email.includes('@')) throw new Error('That email does not look right.');
  if (!name) throw new Error('A name is required.');
  if (!password || password.length < 8) throw new Error('The password needs at least 8 characters.');

  const db = new Database(dbPath);

  // Same users table as server.js, so this works even if the server has never run here
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

  const hashed = bcrypt.hashSync(password, 10);
  const existing = db.prepare('SELECT id FROM users WHERE lower(email) = ?').get(email);

  if (existing) {
    db.prepare("UPDATE users SET role = 'owner', password = ?, name = ? WHERE id = ?").run(hashed, name, existing.id);
    console.log('Done. That existing account is now the owner, with the new password: ' + email);
  } else {
    db.prepare(
      "INSERT INTO users (company, name, email, password, role, hourlyRate) VALUES ('', ?, ?, ?, 'owner', 0)"
    ).run(name, email, hashed);
    console.log('Done. Owner account created: ' + email);
  }
  console.log('Log in at /manager.html');
}

main().catch(err => {
  console.error('\nCould not create the owner: ' + err.message);
  if (/NODE_MODULE_VERSION|was compiled against|invalid ELF|not a valid Win32/i.test(err.message)) {
    console.error('Fix: run   npm rebuild better-sqlite3   in this folder, then try again.');
  } else if (/Cannot find module/i.test(err.message)) {
    console.error('Fix: run   npm install   in this folder first (and make sure you are in the project folder).');
  } else if (/SQLITE_BUSY|database is locked/i.test(err.message)) {
    console.error('Fix: stop the server (Ctrl+C), run this again, then start the server back up.');
  }
  process.exit(1);
});