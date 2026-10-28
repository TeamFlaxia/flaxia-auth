-- Preserve existing Flaxia user IDs and SRP parameters during migration.
CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  email TEXT COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL DEFAULT '',
  srp_salt TEXT,
  srp_verifier TEXT,
  srp_group TEXT DEFAULT '2048',
  srp_kdf TEXT,
  frozen_at TEXT,
  frozen_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Existing Flaxia sessions use the session token as their id.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  ip_address TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  srp_upgrade_allowed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE srp_handshakes (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  b_scalar TEXT NOT NULL,
  b_pub TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_srp_handshakes_expires ON srp_handshakes(expires_at);
