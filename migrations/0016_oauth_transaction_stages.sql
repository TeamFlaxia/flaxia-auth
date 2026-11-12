-- Track the stages of a server-side OAuth exchange so one authorization
-- transaction can produce at most one token and one connection.
--
-- `consumed_at` is set by the provider callback. `exchanged_at` is set when
-- Auth (or the browser) has turned the code into a token, and `completed_at`
-- when the browser reports that the encrypted token is in the Vault. Both
-- stages are one-shot: a replay must not be able to bind a second token or a
-- second Vault item to the same authorization.

ALTER TABLE oauth_transactions ADD COLUMN exchanged_at TEXT;
ALTER TABLE oauth_transactions ADD COLUMN completed_at TEXT;
