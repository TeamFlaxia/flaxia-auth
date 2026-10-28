import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

test('migration blocks old conversion and new conversion remains atomic', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const name of ['0001_auth.sql', '0002_auth_rate_limits.sql', '0003_display_name.sql', '0004_flaxia_session_exchange.sql', '0005_bind_srp_handshakes.sql', '0006_legacy_fingerprint_retention.sql']) {
    db.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8'));
  }
  db.exec("INSERT INTO users (id, username, password_hash) VALUES ('u', 'user', 'old-hash')");
  assert.throws(() => db.exec("UPDATE users SET password_hash = '', srp_salt = 'salt', srp_verifier = 'verifier' WHERE id = 'u'"), /legacy fingerprint required/);
  assert.equal(db.prepare("SELECT password_hash FROM users WHERE id = 'u'").get().password_hash, 'old-hash');
  db.exec("BEGIN; INSERT INTO flaxia_legacy_fingerprints (user_id, fingerprint) VALUES ('u', 'fingerprint'); UPDATE users SET password_hash = '', srp_salt = 'salt', srp_verifier = 'verifier' WHERE id = 'u'; COMMIT;");
  assert.equal(db.prepare("SELECT fingerprint FROM flaxia_legacy_fingerprints WHERE user_id = 'u'").get().fingerprint, 'fingerprint');
  db.exec("INSERT INTO sessions (id, user_id, expires_at) VALUES ('expired', 'u', '2000'), ('active', 'u', '9999'); INSERT INTO flaxia_session_grants VALUES ('old-grant', 'expired', 'u'), ('active-grant', 'active', 'u'); DELETE FROM sessions WHERE expires_at <= '2026';");
  assert.deepEqual(db.prepare('SELECT token_hash FROM flaxia_session_grants').all().map(row => row.token_hash), ['active-grant']);
  assert.ok(db.prepare("SELECT expires_at FROM flaxia_legacy_fingerprints WHERE user_id = 'u'").get().expires_at);
  db.exec("UPDATE flaxia_legacy_fingerprints SET expires_at = '2000-01-01T00:00:00.000Z' WHERE user_id = 'u'; DELETE FROM flaxia_legacy_fingerprints WHERE expires_at <= '2026-01-01T00:00:00.000Z'");
  assert.equal(db.prepare("SELECT count(*) AS n FROM flaxia_legacy_fingerprints").get().n, 0);
  db.close();
});
