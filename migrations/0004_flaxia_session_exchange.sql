CREATE TABLE flaxia_authorization_codes (
  code_hash TEXT PRIMARY KEY NOT NULL,
  challenge TEXT NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);

CREATE INDEX idx_flaxia_authorization_codes_expiry ON flaxia_authorization_codes(expires_at);

CREATE TABLE flaxia_session_grants (
  token_hash TEXT PRIMARY KEY NOT NULL,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_flaxia_session_grants_session ON flaxia_session_grants(session_id);

CREATE TABLE flaxia_legacy_fingerprints (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL
);
