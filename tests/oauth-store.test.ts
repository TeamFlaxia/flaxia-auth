import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  connectionRow,
  isValidConnectionId,
  isValidProviderSub,
  isValidScopeList,
  normalizeScopes,
  parseConnectionMetadata,
  parseProviderList,
  parseScopeList,
} from '../src/oauth/store.ts';

test('connection ids use the shared opaque shape', () => {
  assert.equal(isValidConnectionId(`conn_${'a'.repeat(20)}`), true);
  assert.equal(isValidConnectionId('conn_' + 'a'.repeat(20)), true);
  for (const bad of ['', 'short', 'conn_' + 'a'.repeat(19), 'conn_' + 'a'.repeat(41), 'conn_' + 'A'.repeat(20) + '/', '../etc']) {
    assert.equal(isValidConnectionId(bad), false, bad);
  }
});

test('provider subject identifiers are bounded plain strings', () => {
  assert.equal(isValidProviderSub('1234567890'), true);
  assert.equal(isValidProviderSub('https://example.com/user/1'), true);
  assert.equal(isValidProviderSub(''), false);
  assert.equal(isValidProviderSub('x'.repeat(513)), false);
  assert.equal(isValidProviderSub('line\u0000break'), false);
});

test('scope lists are normalised, de-duplicated and sorted', () => {
  const scopes = normalizeScopes(['gmail.readonly', 'calendar.readonly', 'gmail.readonly', ' openid ']);
  assert.deepEqual(scopes, ['calendar.readonly', 'gmail.readonly', 'openid']);
  assert.equal(isValidScopeList(scopes), true);
  assert.equal(isValidScopeList(['bad scope']), false);
  assert.equal(isValidScopeList(['x'.repeat(65)]), false);
  assert.equal(isValidScopeList([]), false);
});

test('a scope list parses from its stored JSON form', () => {
  assert.deepEqual(parseScopeList('["calendar.readonly","gmail.readonly"]'), ['calendar.readonly', 'gmail.readonly']);
  assert.deepEqual(parseScopeList(['calendar.readonly', 'calendar.readonly']), ['calendar.readonly']);
  assert.deepEqual(parseScopeList('not json'), []);
  assert.deepEqual(parseScopeList(null), []);
  // A scope with whitespace or a quote is not a scope.
  assert.deepEqual(parseScopeList(['bad scope', 'also"bad']), []);
});

test('a provider list parses into known ids only', () => {
  assert.deepEqual(parseProviderList('["google","slack"]'), ['google', 'slack']);
  assert.deepEqual(parseProviderList(['google', 'slack']), ['google', 'slack']);
  assert.deepEqual(parseProviderList(['google', 'unknown-provider']), ['google']);
  assert.deepEqual(parseProviderList('not json'), []);
  assert.deepEqual(parseProviderList(null), []);
});

test('connection metadata is parsed defensively', () => {
  const row = connectionRow({
    id: `conn_${'b'.repeat(20)}`,
    provider: 'google',
    provider_sub: '12345',
    scopes: '["calendar.readonly"]',
    status: 'active',
    vault_item_id: `item_${'c'.repeat(20)}`,
    expires_at: '2026-12-01T00:00:00.000Z',
    refresh_expires_at: null,
    last_used_at: null,
    revoked_at: null,
    created_at: '2026-11-12T00:00:00.000Z',
    updated_at: '2026-11-12T00:00:00.000Z',
  });
  assert.ok(row);
  assert.equal(row.provider, 'google');
  assert.deepEqual(row.scopes, ['calendar.readonly']);
  assert.equal(row.status, 'active');
  assert.equal(row.vault_item_id, `item_${'c'.repeat(20)}`);
});

test('a malformed row is dropped rather than guessed', () => {
  const base = {
    id: `conn_${'b'.repeat(20)}`,
    provider: 'google',
    provider_sub: '12345',
    scopes: '["calendar.readonly"]',
    status: 'active',
    vault_item_id: `item_${'c'.repeat(20)}`,
  };
  assert.equal(connectionRow({ ...base, provider: 'unknown' }), null);
  assert.equal(connectionRow({ ...base, status: 'weird' }), null);
  assert.equal(connectionRow({ ...base, id: 'bad' }), null);
  assert.equal(connectionRow({ ...base, scopes: 'not json' }), null);
  assert.equal(connectionRow(null), null);
  assert.equal(connectionRow('string'), null);
});

test('metadata never carries a token field', () => {
  const parsed = parseConnectionMetadata({
    id: `conn_${'b'.repeat(20)}`,
    provider: 'google',
    scopes: '["calendar.readonly"]',
    status: 'active',
    vault_item_id: `item_${'c'.repeat(20)}`,
    created_at: '2026-11-12T00:00:00.000Z',
    updated_at: '2026-11-12T00:00:00.000Z',
    access_token: 'should-not-appear',
    refresh_token: 'should-not-appear',
    payload: 'should-not-appear',
  });
  assert.ok(parsed);
  assert.equal('access_token' in parsed, false);
  assert.equal('refresh_token' in parsed, false);
  assert.equal('payload' in parsed, false);
  assert.equal(JSON.stringify(parsed).includes('should-not-appear'), false);
});
