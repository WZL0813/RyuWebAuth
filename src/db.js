'use strict';

const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(process.env.DB_FILE || path.join(__dirname, '..', '2fa.db'));

db.exec(`CREATE TABLE IF NOT EXISTS users (
  userId TEXT PRIMARY KEY,
  secretEncrypted TEXT,
  recoveryHashes TEXT,
  createdAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId TEXT,
  action TEXT,
  success INTEGER,
  ip TEXT,
  createdAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS accounts (
  userId TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  passwordHash TEXT,
  age INTEGER,
  securityQuestion TEXT,
  securityAnswerHash TEXT,
  twoFactorEnabled INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  role TEXT DEFAULT 'user',
  createdAt INTEGER
)`);

try { db.exec("ALTER TABLE accounts ADD COLUMN role TEXT DEFAULT 'user'"); } catch (e) { /* already exists */ }

db.exec(`CREATE TABLE IF NOT EXISTS pending_regs (
  regId TEXT PRIMARY KEY,
  email TEXT,
  emailCodeHash TEXT,
  emailCodeExpiry INTEGER,
  emailVerified INTEGER DEFAULT 0,
  username TEXT,
  passwordHash TEXT,
  age INTEGER,
  securityQuestion TEXT,
  securityAnswerHash TEXT,
  twoFactorEnabled INTEGER DEFAULT 0,
  userId TEXT,
  createdAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS reset_codes (
  key TEXT PRIMARY KEY,
  codeHash TEXT,
  expiry INTEGER,
  used INTEGER DEFAULT 0,
  createdAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  keyHash TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  userId TEXT,
  permissions TEXT DEFAULT 'read',
  rateLimit INTEGER DEFAULT 60,
  enabled INTEGER DEFAULT 1,
  lastUsedAt INTEGER,
  createdAt INTEGER,
  FOREIGN KEY (userId) REFERENCES accounts(userId)
)`);

db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  sessionId TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  createdAt INTEGER,
  expiresAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS admin_config (
  key TEXT PRIMARY KEY,
  valueEncrypted TEXT,
  createdAt INTEGER
)`);

db.exec(`CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updatedAt INTEGER
)`);

const defaultSettings = [
  ['registration_enabled', '1'],
  ['login_enabled', '1']
];
const insertSetting = db.prepare('INSERT OR IGNORE INTO system_settings (key, value, updatedAt) VALUES (?, ?, ?)');
for (const [k, v] of defaultSettings) {
  insertSetting.run(k, v, Date.now());
}

db.exec("DELETE FROM sessions WHERE expiresAt < " + Date.now());

module.exports = db;
