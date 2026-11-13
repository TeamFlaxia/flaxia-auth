-- OAuth connections to third-party services. Auth owns the connection
-- metadata; the credentials themselves never reach this table.
--
-- The access and refresh tokens live in `vault_items` as an
-- `oauth_connection` item, encrypted client-side with the Vault key exactly
-- like every other item. Auth can see which provider a user connected and
-- which scopes were granted, but it can never read or use a token. That is
-- the "no server-side escrow" rule from the application design documents:
-- a server-held key was deleted once already and must not come back.
--
--   provider ─┐
--   scopes   ─┼─► oauth_connections (metadata only)
--   status   ─┤
--             └─► vault_items(kind='oauth_connection') ──AES-GCM──► token

CREATE TABLE oauth_connections (
  id                  TEXT PRIMARY KEY NOT NULL,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,
  provider_sub        TEXT,
  scopes              TEXT NOT NULL DEFAULT '[]',
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  -- The Vault item holding the encrypted token. The server never interprets
  -- it, exactly like every other Vault item.
  vault_item_id       TEXT,
  expires_at          TEXT,
  refresh_expires_at  TEXT,
  last_used_at        TEXT,
  revoked_at          TEXT,
  created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- One connection per provider per user. Reconnecting replaces the row.
CREATE UNIQUE INDEX idx_oauth_connections_user_provider ON oauth_connections(user_id, provider);
CREATE INDEX idx_oauth_connections_user_status ON oauth_connections(user_id, status);

-- A pending authorization. The state and the PKCE verifier are stored only as
-- hashes: the browser keeps the originals, so a database dump cannot be
-- replayed against a provider. A row is consumed exactly once and expires
-- after ten minutes.
CREATE TABLE oauth_transactions (
  id                  TEXT PRIMARY KEY NOT NULL,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,
  state_hash          TEXT NOT NULL,
  code_verifier_hash  TEXT,
  redirect_uri        TEXT NOT NULL,
  return_uri          TEXT,
  expires_at          TEXT NOT NULL,
  consumed_at         TEXT,
  created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX idx_oauth_transactions_user ON oauth_transactions(user_id);
CREATE INDEX idx_oauth_transactions_expiry ON oauth_transactions(expires_at);
