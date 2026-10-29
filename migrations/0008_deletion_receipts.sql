-- Receipts contain hashes only and survive account deletion so ambiguous
-- retries do not recreate credentials or delete a different account.
CREATE TABLE flaxia_deletion_receipts (
  operation_hash TEXT PRIMARY KEY NOT NULL,
  user_hash TEXT NOT NULL,
  grant_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
