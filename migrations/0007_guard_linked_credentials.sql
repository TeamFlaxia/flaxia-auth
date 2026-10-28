-- Preserve the fact that credentials may have been copied even after grants expire.
CREATE TABLE flaxia_credential_guards (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
INSERT OR IGNORE INTO flaxia_credential_guards (user_id) SELECT user_id FROM flaxia_session_grants;
INSERT OR IGNORE INTO flaxia_credential_guards (user_id) SELECT user_id FROM flaxia_legacy_fingerprints;
