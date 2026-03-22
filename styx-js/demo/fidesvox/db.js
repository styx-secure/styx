import Database from 'better-sqlite3';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, unlinkSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, 'fidesvox.db');

// Delete old DB if schema is incompatible (check for users table)
if (existsSync(DB_PATH)) {
  try {
    const tmp = new Database(DB_PATH, { readonly: true });
    const tables = tmp.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name);
    tmp.close();
    // Check for required tables and columns
    const userCols = tmp.prepare("PRAGMA table_info(users)").all().map(r => r.name);
    if (!tables.includes('users') || !tables.includes('private_reports') || !userCols.includes('encrypted_privkey_blob')) {
      unlinkSync(DB_PATH);
      console.log('[DB] Removed old database (incompatible schema)');
    }
  } catch {
    unlinkSync(DB_PATH);
  }
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nostr_pubkey TEXT,
    encrypted_privkey_blob TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS survey_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id TEXT NOT NULL,
    org_id TEXT,
    answers TEXT NOT NULL,
    nostr_event_id TEXT UNIQUE NOT NULL,
    received_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS private_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id TEXT NOT NULL,
    org_id TEXT,
    encrypted_blob TEXT NOT NULL,
    nostr_event_id TEXT UNIQUE NOT NULL,
    received_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS report_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id TEXT NOT NULL,
    org_id TEXT,
    channel TEXT,
    source TEXT,
    has_private_bucket INTEGER DEFAULT 0,
    nostr_event_id TEXT UNIQUE NOT NULL,
    received_at TEXT NOT NULL
  );
`);

// --- Prepared statements ---

export const insertUser = db.prepare(`
  INSERT INTO users (email, password_hash) VALUES (?, ?)
`);

export const getUserByEmail = db.prepare(`
  SELECT * FROM users WHERE email = ?
`);

export const getUserById = db.prepare(`
  SELECT id, email, nostr_pubkey, encrypted_privkey_blob, created_at FROM users WHERE id = ?
`);

export const updateUserPubkey = db.prepare(`
  UPDATE users SET nostr_pubkey = ? WHERE id = ?
`);

export const updateUserKeypair = db.prepare(`
  UPDATE users SET nostr_pubkey = ?, encrypted_privkey_blob = ? WHERE id = ?
`);

export const insertResponse = db.prepare(`
  INSERT OR IGNORE INTO survey_responses (survey_id, org_id, answers, nostr_event_id, received_at)
  VALUES (?, ?, ?, ?, ?)
`);

export const insertPrivateReport = db.prepare(`
  INSERT OR IGNORE INTO private_reports (survey_id, org_id, encrypted_blob, nostr_event_id, received_at)
  VALUES (?, ?, ?, ?, ?)
`);

export const insertMetadata = db.prepare(`
  INSERT OR IGNORE INTO report_metadata (survey_id, org_id, channel, source, has_private_bucket, nostr_event_id, received_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

export const getResponsesBySurvey = (surveyId) =>
  db.prepare('SELECT * FROM survey_responses WHERE survey_id = ? ORDER BY id DESC').all(surveyId);

export const getPrivateReportsBySurvey = (surveyId) =>
  db.prepare('SELECT * FROM private_reports WHERE survey_id = ? ORDER BY id DESC').all(surveyId);

export const getMetadataBySurvey = (surveyId) =>
  db.prepare('SELECT * FROM report_metadata WHERE survey_id = ? ORDER BY id DESC').all(surveyId);

export const getAllResponses = () =>
  db.prepare('SELECT * FROM survey_responses ORDER BY id DESC').all();

export const getAllPrivateReports = () =>
  db.prepare('SELECT * FROM private_reports ORDER BY id DESC').all();

export const getAllMetadata = () =>
  db.prepare('SELECT * FROM report_metadata ORDER BY id DESC').all();

export default db;
