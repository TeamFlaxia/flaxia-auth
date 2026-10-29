CREATE TABLE flaxia_email_changes (
  operation_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('committed', 'cancelled')),
  expires_at TEXT
);
