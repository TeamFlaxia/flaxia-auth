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

-- The previous Worker clears password_hash while migrating a legacy account.
-- Block that write immediately when this migration lands, including while an
-- old Worker request is in flight. The new Worker saves the fingerprint first.
CREATE TRIGGER require_legacy_fingerprint BEFORE UPDATE OF password_hash ON users
WHEN OLD.password_hash <> '' AND NEW.password_hash = ''
  AND OLD.srp_salt IS NULL AND OLD.srp_verifier IS NULL
  AND NOT EXISTS (SELECT 1 FROM flaxia_legacy_fingerprints WHERE user_id = OLD.id)
BEGIN
  SELECT RAISE(ABORT, 'legacy fingerprint required before conversion');
END;
