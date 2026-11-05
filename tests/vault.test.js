import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { generateSalt, computeVerifier, clientStep1, clientStep2 } from '../src/srp.ts';

const wrangler = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
const encode = bytes => Buffer.from(bytes).toString('base64');
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const wrapped = (length = 32) => `${encode(randomBytes(12))}.${encode(randomBytes(length))}`;
const envelope = () => ({
  salt: encode(randomBytes(16)),
  recovery_salt: encode(randomBytes(16)),
  kdf_params: { alg: 'PBKDF2-SHA256', iterations: 600_000 },
  wrapped_vk: wrapped(),
  recovery_blob: wrapped(),
});

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startWorker(args, label) {
  const worker = spawn(process.execPath, [wrangler, 'dev', '--local', '--ip', '127.0.0.1', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, CI: 'true' },
  });
  let output = '';
  worker.stdout.on('data', data => { output += data; });
  worker.stderr.on('data', data => { output += data; });
  return { worker, getOutput: () => output };
}

async function waitFor(url, worker, getOutput, label) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {}
    if (worker.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`${label} failed to start: ${getOutput()}`);
}

test('Personal Vault is owned by Auth and uses the Auth session', { timeout: 90000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'flaxia-vault-test-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const migration = spawnSync(
    process.execPath,
    [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory],
    { encoding: 'utf8', env: { ...process.env, CI: 'true' } },
  );
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);

  const port = await freePort();
  const auth = await startWorker(['--port', String(port), '--persist-to', directory], 'auth');
  t.after(async () => {
    if (auth.worker.exitCode === null) {
      auth.worker.kill('SIGTERM');
      await new Promise(resolve => auth.worker.once('exit', resolve));
    }
  });
  const base = `http://127.0.0.1:${port}`;
  await waitFor(`${base}/health`, auth.worker, auth.getOutput, 'Auth');

  const request = (path, { method = 'POST', body, cookie, origin = 'https://flaxia.app', ip = '192.0.2.201' } = {}) =>
    fetch(`${base}${path}`, {
      method,
      headers: {
        origin,
        'CF-Connecting-IP': ip,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { cookie } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

  const password = 'vault test password';
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt);
  const registration = await request('/api/auth/register', {
    body: {
      username: 'VaultUser',
      display_name: 'Vault User',
      srp_salt: encode(salt),
      srp_verifier: encode(verifier),
      srp_group: '2048',
      srp_kdf: 'pbkdf2-600k-v2',
    },
  });
  assert.equal(registration.status, 201);
  const user = (await registration.json()).user;
  let cookie = registration.headers.get('set-cookie').split(';')[0];

  const reauthProof = async () => {
    const start = await request('/api/auth/reauth/start', { cookie });
    assert.equal(start.status, 200);
    const challenge = await start.json();
    const first = await clientStep1(password, Uint8Array.from(Buffer.from(challenge.salt, 'base64')));
    const proof = await clientStep2(
      password,
      Uint8Array.from(Buffer.from(challenge.salt, 'base64')),
      first.a,
      Uint8Array.from(Buffer.from(challenge.B, 'base64')),
      challenge.srp_kdf,
    );
    return { challenge_id: challenge.challenge_id, A: encode(proof.A), M1: encode(proof.M1) };
  };

  assert.equal((await request('/api/vault/keys', { method: 'GET' })).status, 401);
  const empty = await request('/api/vault/keys', { method: 'GET', cookie });
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), { enabled: false });

  const firstEnvelope = envelope();
  const dummyProof = { challenge_id: 'x'.repeat(43), A: encode(randomBytes(256)), M1: encode(randomBytes(32)) };
  assert.equal((await request('/api/vault/keys', { cookie, body: firstEnvelope })).status, 400);
  assert.equal((await request('/api/vault/keys', { cookie, origin: 'https://evil.example', body: { ...firstEnvelope, current_srp: dummyProof } })).status, 403);
  assert.equal((await request('/api/vault/keys', { cookie, body: { ...firstEnvelope, salt: 'not base64', current_srp: dummyProof } })).status, 400);
  const enableDevice = `device_${'a'.repeat(20)}`;
  const enabled = await request('/api/vault/keys', {
    cookie,
    body: { ...firstEnvelope, current_srp: await reauthProof(), device_id: enableDevice, device_label: 'Primary' },
  });
  assert.equal(enabled.status, 201, await enabled.clone().text());
  assert.deepEqual(await enabled.json(), { enabled: true, vk_version: 1, device_id: enableDevice });

  const stored = await (await request('/api/vault/keys', { method: 'GET', cookie })).json();
  assert.equal(stored.enabled, true);
  assert.equal(stored.salt, firstEnvelope.salt);
  assert.equal(stored.vk_version, 1);
  assert.equal(stored.devices.length, 1);
  assert.equal(stored.devices[0].id, enableDevice);

  assert.equal((await request('/api/vault/keys', { cookie, body: { ...envelope(), current_srp: await reauthProof() } })).status, 409);
  assert.equal((await request('/api/vault/keys', { method: 'PUT', cookie, body: { ...envelope(), vk_version: 9, current_srp: await reauthProof() } })).status, 409);
  const rotatedEnvelope = envelope();
  const rotated = await request('/api/vault/keys', {
    method: 'PUT',
    cookie,
    body: { ...rotatedEnvelope, vk_version: 1, current_srp: await reauthProof() },
  });
  assert.equal(rotated.status, 200);
  assert.deepEqual(await rotated.json(), { enabled: true, vk_version: 2 });

  const itemId = `item_${'b'.repeat(20)}`;
  const item = { item_key_wrapped: wrapped(), payload: wrapped(80), kind: 'private_note', vk_version: 2 };
  assert.equal((await request(`/api/vault/items/${itemId}`, { method: 'PUT', cookie, body: { ...item, vk_version: 1 } })).status, 409);
  assert.equal((await request(`/api/vault/items/${itemId}`, { method: 'PUT', cookie, body: { ...item, kind: 'public_post' } })).status, 400);
  assert.equal((await request('/api/vault/items/short', { method: 'PUT', cookie, body: item })).status, 400);
  const saved = await request(`/api/vault/items/${itemId}`, { method: 'PUT', cookie, body: item });
  assert.equal(saved.status, 200, await saved.clone().text());
  assert.deepEqual(await saved.json(), { id: itemId, kind: 'private_note', vk_version: 2 });

  const inventory = await (await request('/api/vault/items', { method: 'GET', cookie })).json();
  assert.equal(inventory.items.length, 1);
  assert.equal('payload' in inventory.items[0], false);
  const payloads = await (await request('/api/vault/items?kind=private_note', { method: 'GET', cookie })).json();
  assert.equal(payloads.items[0].payload, item.payload);
  assert.equal((await request('/api/vault/items?kind=public_post', { method: 'GET', cookie })).status, 400);

  // Device pairing: a pending QR becomes active only when the approver proves
  // possession of the scanned peer key.
  const peer = encode(randomBytes(32));
  const pairing = await request('/api/vault/devices', {
    cookie,
    body: { label: 'Phone', peer_pub: peer, ttl_seconds: 60 },
  });
  assert.equal(pairing.status, 201);
  const pairingRow = await pairing.json();
  assert.match(pairingRow.id, /^[A-Za-z0-9_-]{16,40}$/);
  assert.equal((await (await request(`/api/vault/devices/${pairingRow.id}`, { method: 'GET', cookie })).json()).state, 'pending');
  assert.equal((await request(`/api/vault/devices/${pairingRow.id}/approve`, {
    cookie,
    body: { approved_pub: encode(randomBytes(32)), peer_pub: encode(randomBytes(32)), wrapped_vk: wrapped() },
  })).status, 403);
  const approved = await request(`/api/vault/devices/${pairingRow.id}/approve`, {
    cookie,
    body: { approved_pub: encode(randomBytes(32)), peer_pub: peer, wrapped_vk: wrapped() },
  });
  assert.equal(approved.status, 200);
  const pairingActive = await (await request(`/api/vault/devices/${pairingRow.id}`, { method: 'GET', cookie })).json();
  assert.equal(pairingActive.state, 'active');
  assert.equal(typeof pairingActive.wrapped_vk, 'string');
  assert.equal((await request(`/api/vault/devices/${pairingRow.id}/approve`, {
    cookie,
    body: { approved_pub: encode(randomBytes(32)), peer_pub: peer, wrapped_vk: wrapped() },
  })).status, 409);
  assert.equal((await request(`/api/vault/devices/${pairingRow.id}`, { method: 'DELETE', cookie })).status, 403);

  const pending = await request('/api/vault/devices', {
    cookie,
    body: { label: 'Tablet', peer_pub: encode(randomBytes(32)) },
  });
  const pendingRow = await pending.json();
  assert.equal((await request(`/api/vault/devices/${pendingRow.id}`, { method: 'DELETE', cookie })).status, 200);

  // Full device revocation rotates VK and requires the complete item-key
  // inventory, so a stale rewrap cannot silently orphan another item.
  const beforeRevoke = await (await request('/api/vault/items', { method: 'GET', cookie })).json();
  const newVks = envelope();
  const revoked = await request('/api/vault/keys/revoke-device', {
    cookie,
    body: {
      ...newVks,
      vk_version: 2,
      device_id: pairingRow.id,
      current_device_id: enableDevice,
      current_srp: await reauthProof(),
      item_keys: beforeRevoke.items.map(entry => ({
        item_id: entry.id,
        item_key_wrapped: wrapped(),
        item_key_wrapped_before: entry.item_key_wrapped,
      })),
    },
  });
  assert.equal(revoked.status, 200, await revoked.clone().text());
  assert.deepEqual(await revoked.json(), { enabled: true, vk_version: 3 });
  const afterRevoke = await (await request('/api/vault/keys', { method: 'GET', cookie })).json();
  assert.deepEqual(afterRevoke.devices.map(device => device.id), [enableDevice]);

  // Password change must carry the Vault rewrap. Auth commits the verifier and
  // envelope together, and rejects a stale vk_version.
  const newSalt = generateSalt();
  const newPassword = 'new vault test password';
  const newVerifier = await computeVerifier(newPassword, newSalt);
  const srpUpdate = {
    srp_salt: encode(newSalt),
    srp_verifier: encode(newVerifier),
    srp_group: '2048',
    srp_kdf: 'pbkdf2-600k-v2',
  };
  assert.equal((await request('/api/auth/upgrade-srp', { cookie, body: { ...srpUpdate, current_srp: dummyProof } })).status, 409);
  const staleRewrap = { salt: encode(randomBytes(16)), kdf_params: envelope().kdf_params, wrapped_vk: wrapped(), vk_version: 2 };
  const stale = await request('/api/auth/upgrade-srp', {
    cookie,
    body: { ...srpUpdate, vault_kek: staleRewrap, current_srp: dummyProof },
  });
  assert.equal(stale.status, 409);
  assert.equal((await stale.json()).error, 'vault_key_version_conflict');
  const rewrap = { salt: encode(randomBytes(16)), kdf_params: envelope().kdf_params, wrapped_vk: wrapped(), vk_version: 3 };
  const changed = await request('/api/auth/upgrade-srp', {
    cookie,
    body: { ...srpUpdate, vault_kek: rewrap, current_srp: await reauthProof() },
  });
  assert.equal(changed.status, 200, await changed.clone().text());
  const afterChange = await (await request('/api/vault/keys', { method: 'GET', cookie })).json();
  assert.equal(afterChange.vk_version, 4);
  assert.equal(afterChange.wrapped_vk, rewrap.wrapped_vk);
  assert.equal(afterChange.salt, rewrap.salt);
  const changedLogin = await request('/api/auth/login/start', { body: { username: 'VaultUser' } });
  const changedChallenge = await changedLogin.json();
  const changedFirst = await clientStep1(newPassword, Uint8Array.from(Buffer.from(changedChallenge.salt, 'base64')));
  const changedProof = await clientStep2(
    newPassword,
    Uint8Array.from(Buffer.from(changedChallenge.salt, 'base64')),
    changedFirst.a,
    Uint8Array.from(Buffer.from(changedChallenge.B, 'base64')),
    changedChallenge.srp_kdf,
  );
  const changedVerify = await request('/api/auth/login/verify', {
    body: { challenge_id: changedChallenge.challenge_id, A: encode(changedProof.A), M1: encode(changedProof.M1) },
  });
  assert.equal(changedVerify.status, 200);
  cookie = changedVerify.headers.get('set-cookie').split(';')[0];

  // Item deletion is versioned, and deleting a kind is bounded to the caller.
  assert.equal((await request(`/api/vault/items/${itemId}?vk_version=3`, { method: 'DELETE', cookie })).status, 409);
  assert.equal((await request(`/api/vault/items/${itemId}?vk_version=4`, { method: 'DELETE', cookie })).status, 200);
  assert.equal((await request(`/api/vault/items/${itemId}?vk_version=4`, { method: 'DELETE', cookie })).status, 404);

  // Service-bound access uses the same store and a grant-bound proof, so
  // Flaxia can proxy the routes without holding wrapped keys in its D1.
  const bridgePort = await freePort();
  const bridge = await startWorker(
    ['--config', 'tests/fixtures/bridge-proxy.jsonc', '--port', String(bridgePort), '--inspector-port', '0'],
    'bridge',
  );
  t.after(async () => {
    if (bridge.worker.exitCode === null) {
      bridge.worker.kill('SIGTERM');
      await new Promise(resolve => bridge.worker.once('exit', resolve));
    }
  });
  const bridgeBase = `http://127.0.0.1:${bridgePort}`;
  await waitFor(`${bridgeBase}/health`, bridge.worker, bridge.getOutput, 'bridge');
  const pkce = Buffer.from(randomBytes(32)).toString('base64url');
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pkce))).toString('base64url');
  const authorize = await request('/api/auth/flaxia/authorize', { cookie, body: { challenge } });
  assert.equal(authorize.status, 200);
  const { code } = await authorize.json();
  const exchange = await fetch(`${bridgeBase}/api/flaxia/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, verifier: pkce }),
  });
  assert.equal(exchange.status, 200);
  const { grant } = await exchange.json();
  const bridgeVault = (path, body = {}) =>
    fetch(`${bridgeBase}/api/flaxia/vault`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant, user_id: user.id, path, ...body }),
    });
  const bridgeKeys = await bridgeVault('/keys', { method: 'GET' });
  assert.equal(bridgeKeys.status, 200);
  const bridgeStored = await bridgeKeys.json();
  assert.equal(bridgeStored.enabled, true);
  assert.equal(bridgeStored.vk_version, 4);
  const bridgeDenied = await bridgeVault('/keys', {
    method: 'POST',
    body: { ...envelope(), current_srp: dummyProof },
  });
  assert.equal(bridgeDenied.status, 401);

  // One-time import copies the rows Flaxia still holds in its own D1. It is
  // idempotent and refuses to replace a different envelope.
  const importPassword = 'import test password';
  const importSalt = generateSalt();
  const importRegistration = await request('/api/auth/register', {
    ip: '192.0.2.202',
    body: {
      username: 'ImportUser',
      display_name: 'Import User',
      srp_salt: encode(importSalt),
      srp_verifier: encode(await computeVerifier(importPassword, importSalt)),
      srp_group: '2048',
      srp_kdf: 'pbkdf2-600k-v2',
    },
  });
  assert.equal(importRegistration.status, 201);
  const importUser = (await importRegistration.json()).user;
  const importCookie = importRegistration.headers.get('set-cookie').split(';')[0];
  const importAuthorize = await request('/api/auth/flaxia/authorize', {
    cookie: importCookie,
    body: { challenge },
  });
  assert.equal(importAuthorize.status, 200);
  const importCode = (await importAuthorize.json()).code;
  const importExchange = await fetch(`${bridgeBase}/api/flaxia/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: importCode, verifier: pkce }),
  });
  assert.equal(importExchange.status, 200);
  const importGrant = (await importExchange.json()).grant;
  const importEnvelope = { ...envelope(), vk_version: 1 };
  const importDeviceId = `import_${'c'.repeat(20)}`;
  const importItemId = `import_${'d'.repeat(20)}`;
  const importPayload = {
    grant: importGrant,
    user_id: importUser.id,
    keys: importEnvelope,
    devices: [{
      id: importDeviceId,
      label: 'Legacy phone',
      state: 'active',
      peer_pub: '',
      approved_pub: '',
      wrapped_vk: wrapped(),
      created_at: new Date().toISOString(),
      expires_at: '',
      last_seen_at: new Date().toISOString(),
    }],
    items: [{
      id: importItemId,
      item_key_wrapped: wrapped(),
      payload: wrapped(64),
      kind: 'private_note',
      vk_version: 1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }],
  };
  const importRequest = body =>
    fetch(`${bridgeBase}/api/flaxia/vault/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  assert.equal((await importRequest({ ...importPayload, user_id: 'someone-else' })).status, 401);
  const firstImport = await importRequest(importPayload);
  assert.equal(firstImport.status, 200, await firstImport.clone().text());
  assert.deepEqual(await firstImport.json(), { success: true, imported: true, vk_version: 1 });
  const secondImport = await importRequest(importPayload);
  assert.equal(secondImport.status, 200);
  assert.deepEqual(await secondImport.json(), { success: true, imported: false, vk_version: 1 });
  const conflictImport = await importRequest({
    ...importPayload,
    keys: { ...envelope(), vk_version: 1 },
  });
  assert.equal(conflictImport.status, 409);
  assert.equal((await conflictImport.json()).error, 'vault_import_conflict');
  const importedKeys = await fetch(`${bridgeBase}/api/flaxia/vault`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant: importGrant, user_id: importUser.id, method: 'GET', path: '/keys' }),
  });
  assert.equal(importedKeys.status, 200);
  const imported = await importedKeys.json();
  assert.equal(imported.enabled, true);
  assert.deepEqual(imported.devices.map(device => device.id), [importDeviceId]);
  const importedItems = await fetch(`${bridgeBase}/api/flaxia/vault`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant: importGrant,
      user_id: importUser.id,
      method: 'GET',
      path: '/items',
      query: { kind: 'private_note' },
    }),
  });
  assert.equal(importedItems.status, 200);
  const importedInventory = await importedItems.json();
  assert.equal(importedInventory.items.length, 1);
  assert.equal(importedInventory.items[0].id, importItemId);
});
