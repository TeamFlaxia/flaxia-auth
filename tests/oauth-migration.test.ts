import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

const MIGRATIONS = [
  '0001_auth.sql',
  '0002_auth_rate_limits.sql',
  '0003_display_name.sql',
  '0004_flaxia_session_exchange.sql',
  '0005_bind_srp_handshakes.sql',
  '0006_legacy_fingerprint_retention.sql',
  '0007_guard_linked_credentials.sql',
  '0008_deletion_receipts.sql',
  '0009_credential_changes.sql',
  '0010_credential_recovery_capability.sql',
  '0011_deletion_cancellations.sql',
  '0012_email_change_receipts.sql',
  '0013_recovery_factors.sql',
  '0014_vault.sql',
  '0015_oauth_connections.sql',
  '0016_oauth_transaction_stages.sql',
];

function migrated() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const name of MIGRATIONS) {
    db.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8'));
  }
  return db;
}

test('the OAuth migration creates the connection and transaction tables', () => {
  const db = migrated();
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((row: { name: string }) => row.name);
  assert.ok(tables.includes('oauth_connections'));
  assert.ok(tables.includes('oauth_transactions'));
  db.close();
});

test('the connection table stores metadata only, never a token column', () => {
  const db = migrated();
  const columns = db
    .prepare('PRAGMA table_info(oauth_connections)')
    .all()
    .map((row: { name: string }) => row.name);
  // A token column here would make Auth the custodian of the secret and break
  // the "no server-side escrow" rule in docs/e2ee.md.
  for (const forbidden of [
    'access_token',
    'refresh_token',
    'token',
    'payload',
    'ciphertext',
    'item_key',
    'secret',
    'client_secret',
  ]) {
    assert.equal(columns.includes(forbidden), false, `oauth_connections must not have ${forbidden}`);
  }
  assert.ok(columns.includes('vault_item_id'));
  assert.ok(columns.includes('provider'));
  assert.ok(columns.includes('scopes'));
  db.close();
});

test('the transaction table keeps only hashes of the state and verifier', () => {
  const db = migrated();
  const columns = db
    .prepare('PRAGMA table_info(oauth_transactions)')
    .all()
    .map((row: { name: string }) => row.name);
  assert.ok(columns.includes('state_hash'));
  assert.ok(columns.includes('code_verifier_hash'));
  assert.ok(columns.includes('exchanged_at'));
  assert.ok(columns.includes('completed_at'));
  for (const forbidden of ['state', 'code_verifier', 'verifier']) {
    assert.equal(columns.includes(forbidden), false, `oauth_transactions must not have ${forbidden}`);
  }
  db.close();
});

test('a user may hold one connection per provider', () => {
  const db = migrated();
  db.exec("INSERT INTO users (id, username, password_hash) VALUES ('u', 'user', '')");
  const insert = db.prepare(
    `INSERT INTO oauth_connections (id, user_id, provider, scopes, status)
     VALUES (?, 'u', ?, '[]', 'active')`,
  );
  insert.run(`conn_${'a'.repeat(20)}`, 'google');
  assert.throws(() => insert.run(`conn_${'b'.repeat(20)}`, 'google'));
  // A different provider for the same user is fine.
  insert.run(`conn_${'c'.repeat(20)}`, 'slack');
  assert.equal(
    db.prepare('SELECT count(*) AS n FROM oauth_connections WHERE user_id = ?').get('u').n,
    2,
  );
  db.close();
});

test('deleting a user deletes its connections and transactions', () => {
  const db = migrated();
  db.exec("INSERT INTO users (id, username, password_hash) VALUES ('u', 'user', '')");
  db.exec(
    `INSERT INTO oauth_connections (id, user_id, provider, scopes, status)
     VALUES ('conn_${'a'.repeat(20)}', 'u', 'google', '[]', 'active')`,
  );
  db.exec(
    `INSERT INTO oauth_transactions (id, user_id, provider, state_hash, code_verifier_hash, redirect_uri, expires_at)
     VALUES ('tx_1', 'u', 'google', 'h', 'v', 'https://auth.flaxia.app/cb', '2026-11-12T00:10:00.000Z')`,
  );
  db.prepare('DELETE FROM users WHERE id = ?').run('u');
  assert.equal(db.prepare('SELECT count(*) AS n FROM oauth_connections').get().n, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM oauth_transactions').get().n, 0);
  db.close();
});

test('a transaction row cannot be consumed twice', () => {
  const db = migrated();
  db.exec("INSERT INTO users (id, username, password_hash) VALUES ('u', 'user', '')");
  db.exec(
    `INSERT INTO oauth_transactions (id, user_id, provider, state_hash, code_verifier_hash, redirect_uri, expires_at)
     VALUES ('tx_1', 'u', 'google', 'h', 'v', 'https://auth.flaxia.app/cb', '2026-11-12T00:10:00.000Z')`,
  );
  const consume = db.prepare(
    `UPDATE oauth_transactions SET consumed_at = 'now'
     WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
  );
  assert.equal(consume.run('tx_1', '2026-11-12T00:00:00.000Z').changes, 1);
  assert.equal(consume.run('tx_1', '2026-11-12T00:00:00.000Z').changes, 0);
  db.close();
});

test('an expired transaction cannot be consumed', () => {
  const db = migrated();
  db.exec("INSERT INTO users (id, username, password_hash) VALUES ('u', 'user', '')");
  db.exec(
    `INSERT INTO oauth_transactions (id, user_id, provider, state_hash, code_verifier_hash, redirect_uri, expires_at)
     VALUES ('tx_1', 'u', 'google', 'h', 'v', 'https://auth.flaxia.app/cb', '2026-11-12T00:10:00.000Z')`,
  );
  const consume = db.prepare(
    `UPDATE oauth_transactions SET consumed_at = 'now'
     WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
  );
  assert.equal(consume.run('tx_1', '2026-11-12T00:10:00.000Z').changes, 0);
  db.close();
});
