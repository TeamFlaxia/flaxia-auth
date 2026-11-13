-- A pending authorization request waiting for the user's consent.
--
-- The authorization endpoint validates the request, stores the validated
-- parameters here, and renders a consent page. The POST that approves or
-- denies the request is bound to this row, the user and the session, so the
-- request can be consumed exactly once. The row id is a 256-bit random value
-- and doubles as the unforgeable token of the consent form.

CREATE TABLE IF NOT EXISTS oauth_authorization_requests (
  id                    TEXT PRIMARY KEY NOT NULL,
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id            TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  client_id             TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  state                 TEXT,
  nonce                 TEXT,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  created_at            TEXT NOT NULL,
  expires_at            TEXT NOT NULL,
  consumed_at           TEXT
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_requests_user
  ON oauth_authorization_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_requests_expiry
  ON oauth_authorization_requests(expires_at);
