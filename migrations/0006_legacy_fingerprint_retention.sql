-- Existing fingerprints receive the full transition window on deployment.
ALTER TABLE flaxia_legacy_fingerprints ADD COLUMN expires_at TEXT;
UPDATE flaxia_legacy_fingerprints SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+90 days') WHERE expires_at IS NULL;
CREATE TRIGGER set_legacy_fingerprint_expiry AFTER INSERT ON flaxia_legacy_fingerprints
WHEN NEW.expires_at IS NULL
BEGIN
  UPDATE flaxia_legacy_fingerprints SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+90 days') WHERE user_id = NEW.user_id;
END;
CREATE INDEX idx_legacy_fingerprints_expiry ON flaxia_legacy_fingerprints(expires_at);
