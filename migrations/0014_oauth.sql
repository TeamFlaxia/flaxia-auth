-- OAuth 2.0 / OpenID Connect provider.
-- Codes, tokens and client secrets are stored as hashes only. The signing key
-- is generated on first use; the private JWK lives in D1 (encrypted at rest
-- by Cloudflare) and is never exposed through the JWKS endpoint.

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY NOT NULL,
  client_secret_hash TEXT,
  client_name TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL,
  allowed_scopes TEXT NOT NULL DEFAULT '["openid","profile","email","offline_access"]',
  is_confidential INTEGER NOT NULL DEFAULT 0,
  pkce_required INTEGER NOT NULL DEFAULT 1,
  grant_types TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  revoked_at TEXT
);

CREATE TABLE oauth_authorization_codes (
  code_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  scope TEXT NOT NULL DEFAULT 'openid',
  state TEXT,
  nonce TEXT,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE INDEX idx_oauth_authorization_codes_expiry ON oauth_authorization_codes(expires_at);

CREATE TABLE oauth_access_tokens (
  token_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  refresh_token_hash TEXT,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_oauth_access_tokens_expiry ON oauth_access_tokens(expires_at);
CREATE INDEX idx_oauth_access_tokens_user ON oauth_access_tokens(user_id);

CREATE TABLE oauth_refresh_tokens (
  token_hash TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_oauth_refresh_tokens_expiry ON oauth_refresh_tokens(expires_at);
CREATE INDEX idx_oauth_refresh_tokens_user ON oauth_refresh_tokens(user_id);

CREATE TABLE oauth_signing_keys (
  kid TEXT PRIMARY KEY NOT NULL,
  public_jwk TEXT NOT NULL,
  private_jwk TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  revoked_at TEXT
);
