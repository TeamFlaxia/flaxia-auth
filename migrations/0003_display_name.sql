ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
UPDATE users SET display_name = username WHERE display_name = '';
