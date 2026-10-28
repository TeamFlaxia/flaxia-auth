-- Old challenges have no trustworthy purpose or session binding.
DELETE FROM srp_handshakes;
ALTER TABLE srp_handshakes ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login';
ALTER TABLE srp_handshakes ADD COLUMN binding_hash TEXT;
