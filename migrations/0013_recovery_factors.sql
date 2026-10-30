-- Recovery codes are generated in the browser. Auth stores only an SRP
-- verifier with an independent salt, never the recovery code or Vault phrase.
CREATE TABLE auth_recovery_factors (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  srp_salt TEXT NOT NULL,
  srp_verifier TEXT NOT NULL,
  srp_kdf TEXT NOT NULL
);
