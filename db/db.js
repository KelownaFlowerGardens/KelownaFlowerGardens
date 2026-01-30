// db.js


db.prepare(`
  CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    location TEXT,
    preferred_date TEXT,
    venue_size TEXT,
    description TEXT,
    image_path TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

db.prepare(`ALTER TABLE users ADD COLUMN full_name TEXT`).run();
db.prepare(`ALTER TABLE users ADD COLUMN location TEXT`).run();
db.prepare(`ALTER TABLE users ADD COLUMN bio TEXT`).run();
db.prepare(`ALTER TABLE users ADD COLUMN avatar TEXT`).run();
db.prepare(`ALTER TABLE users ADD COLUMN profile_complete INTEGER DEFAULT 0`).run();


CREATE TABLE IF NOT EXISTS rsvps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(member_id, event_id)
);


const Database = require("better-sqlite3");
const db = new Database("database.sqlite");

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  username TEXT UNIQUE,
  password_hash TEXT,
  membership_status TEXT DEFAULT 'pending',
  is_admin INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

module.exports = db;
