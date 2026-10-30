-- Only Auth stores the retry capability. It is erased on acknowledgment or cancel.
ALTER TABLE flaxia_credential_changes ADD COLUMN recovery_token TEXT;
CREATE UNIQUE INDEX flaxia_credential_recovery_one_active ON flaxia_credential_changes(user_id) WHERE recovery_token IS NOT NULL;
