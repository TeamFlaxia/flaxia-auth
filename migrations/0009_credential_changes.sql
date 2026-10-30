CREATE TABLE flaxia_credential_changes (
  operation_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grant_hash TEXT NOT NULL,
  expected_salt TEXT,
  expected_verifier TEXT,
  new_salt TEXT,
  new_verifier TEXT,
  new_group TEXT,
  new_kdf TEXT,
  target_stamp TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('prepared', 'committed', 'cancelled'))
);
CREATE UNIQUE INDEX idx_flaxia_one_prepared_change ON flaxia_credential_changes(user_id) WHERE state = 'prepared';
