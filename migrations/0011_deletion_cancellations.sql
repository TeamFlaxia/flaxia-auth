CREATE TABLE flaxia_deletion_cancellations (
  operation_hash TEXT PRIMARY KEY NOT NULL,
  user_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX flaxia_deletion_cancellations_expiry ON flaxia_deletion_cancellations(expires_at);
