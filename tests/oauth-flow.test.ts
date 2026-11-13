import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  hashState,
  isValidCodeVerifier,
  isValidState,
  newTransaction,
  transactionFromRow,
  transactionExpired,
} from '../src/oauth/flow.ts';

test('state must be an unguessable bounded token', () => {
  assert.equal(isValidState('a'.repeat(43)), true);
  assert.equal(isValidState('a'.repeat(128)), true);
  for (const bad of ['', 'short', 'a'.repeat(42), 'a'.repeat(129), 'a'.repeat(43) + '/', 'a'.repeat(43) + ' ']) {
    assert.equal(isValidState(bad), false, bad);
  }
});

test('the PKCE verifier follows RFC 7636 length and alphabet', () => {
  assert.equal(isValidCodeVerifier('a'.repeat(43)), true);
  assert.equal(isValidCodeVerifier('a'.repeat(128)), true);
  assert.equal(isValidCodeVerifier('-._~'.repeat(20) + 'abc'), true);
  for (const bad of ['', 'a'.repeat(42), 'a'.repeat(129), 'a'.repeat(43) + '+', 'a'.repeat(43) + '/', 'a'.repeat(43) + '=']) {
    assert.equal(isValidCodeVerifier(bad), false, bad);
  }
});

test('the state is stored hashed, never in the clear', async () => {
  const state = 'a'.repeat(43);
  const hash = await hashState(state);
  assert.notEqual(hash, state);
  assert.equal(hash.includes(state), false);
  assert.equal(hash.length, 43);
  // The same state always hashes to the same value so the callback can look
  // it up without a scan.
  assert.equal(await hashState(state), hash);
  assert.notEqual(await hashState('b'.repeat(43)), hash);
});

test('a transaction carries only what the callback needs', async () => {
  const transaction = await newTransaction({
    userId: 'user-1',
    provider: 'google',
    state: 'a'.repeat(43),
    codeVerifier: 'v'.repeat(43),
    redirectUri: 'https://auth.flaxia.app/api/connections/google/callback',
    returnUri: 'https://flaxia.app/settings/connections',
    now: Date.now(),
  });
  assert.equal(transaction.user_id, 'user-1');
  assert.equal(transaction.provider, 'google');
  assert.equal(transaction.state_hash.length, 43);
  assert.equal(transaction.state_hash.includes('a'.repeat(43)), false);
  assert.equal(transaction.redirect_uri, 'https://auth.flaxia.app/api/connections/google/callback');
  assert.equal(transaction.return_uri, 'https://flaxia.app/settings/connections');
  assert.ok(transaction.expires_at > new Date().toISOString());
  // The verifier itself must not be stored; only its hash.
  assert.equal('code_verifier' in transaction, false);
  assert.equal(JSON.stringify(transaction).includes('v'.repeat(43)), false);
});

test('a transaction expires ten minutes after it is created', async () => {
  const now = Date.parse('2026-11-12T00:00:00.000Z');
  const transaction = await newTransaction({
    userId: 'user-1',
    provider: 'slack',
    state: 'a'.repeat(43),
    codeVerifier: 'v'.repeat(43),
    redirectUri: 'https://auth.flaxia.app/api/connections/slack/callback',
    returnUri: 'https://flaxia.app/settings/connections',
    now,
  });
  assert.equal(transaction.expires_at, '2026-11-12T00:10:00.000Z');
  assert.equal(transaction.exchanged_at, null);
  assert.equal(transaction.completed_at, null);
  assert.equal(transactionExpired(transaction, '2026-11-12T00:09:59.000Z'), false);
  assert.equal(transactionExpired(transaction, '2026-11-12T00:10:00.000Z'), true);
  assert.equal(transactionExpired(transaction, '2026-11-12T01:00:00.000Z'), true);
});

test('a stored row becomes a usable transaction again', () => {
  const row = {
    id: 'tx_1',
    user_id: 'user-1',
    provider: 'discord',
    state_hash: 'h'.repeat(43),
    code_verifier_hash: 'v'.repeat(43),
    redirect_uri: 'https://auth.flaxia.app/api/connections/discord/callback',
    return_uri: 'https://flaxia.app/settings/connections',
    expires_at: '2026-11-12T00:10:00.000Z',
    consumed_at: null,
  };
  const transaction = transactionFromRow(row);
  assert.ok(transaction);
  assert.equal(transaction.user_id, 'user-1');
  assert.equal(transaction.provider, 'discord');
  assert.equal(transaction.consumed_at, null);

  const consumed = transactionFromRow({
    ...row,
    consumed_at: '2026-11-12T00:01:00.000Z',
    exchanged_at: '2026-11-12T00:02:00.000Z',
    completed_at: '2026-11-12T00:03:00.000Z',
  });
  assert.ok(consumed);
  assert.equal(consumed.consumed_at, '2026-11-12T00:01:00.000Z');
  assert.equal(consumed.exchanged_at, '2026-11-12T00:02:00.000Z');
  assert.equal(consumed.completed_at, '2026-11-12T00:03:00.000Z');

  assert.equal(transactionFromRow({ ...row, provider: 'unknown-provider' }), null);
  assert.equal(transactionFromRow({ ...row, expires_at: 'not-a-date' }), null);
  assert.equal(transactionFromRow(null), null);
});
