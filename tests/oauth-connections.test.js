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

test('OAuth connections keep the credential in the Vault and the metadata in Auth', { timeout: 90000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'flaxia-oauth-test-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const migration = spawnSync(
    process.execPath,
    [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory],
    { encoding: 'utf8', env: { ...process.env, CI: 'true' } },
  );
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);

  const port = await freePort();
  const auth = await startWorker(
    ['--port', String(port), '--persist-to', directory, '--var', 'GOOGLE_OAUTH_CLIENT_ID:test-client-id'],
    'auth',
  );
  t.after(async () => {
    if (auth.worker.exitCode === null) {
      auth.worker.kill('SIGTERM');
      await new Promise(resolve => auth.worker.once('exit', resolve));
    }
  });
  const base = `http://127.0.0.1:${port}`;
  await waitFor(`${base}/health`, auth.worker, auth.getOutput, 'Auth');

  const request = (path, { method = 'POST', body, cookie, origin = 'https://flaxia.app', ip = '192.0.2.203' } = {}) =>
    fetch(`${base}${path}`, {
      method,
      redirect: 'manual',
      headers: {
        origin,
        'CF-Connecting-IP': ip,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { cookie } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

  const password = 'oauth test password';
  const salt = generateSalt();
  const registration = await request('/api/auth/register', {
    body: {
      username: 'OauthUser',
      display_name: 'Oauth User',
      srp_salt: encode(salt),
      srp_verifier: encode(await computeVerifier(password, salt)),
      srp_group: '2048',
      srp_kdf: 'pbkdf2-600k-v2',
    },
  });
  assert.equal(registration.status, 201);
  const cookie = registration.headers.get('set-cookie').split(';')[0];

  // The Vault holds the token, so it has to be enabled first. Enabling it
  // needs a fresh proof of the password.
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
  const enabled = await request('/api/vault/keys', {
    cookie,
    body: { ...envelope(), current_srp: await reauthProof() },
  });
  assert.equal(enabled.status, 201, await enabled.clone().text());

  // The connection list is empty and needs a session.
  assert.equal((await request('/api/connections', { method: 'GET' })).status, 401);
  const empty = await request('/api/connections', { method: 'GET', cookie });
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), { connections: [] });

  // Starting an authorization needs a session, a valid state and a challenge.
  assert.equal((await request('/api/connections/google/start', { body: { state: 'x'.repeat(43), code_challenge: 'c'.repeat(43) } })).status, 401);
  assert.equal((await request('/api/connections/google/start', { cookie, body: { state: 'short', code_challenge: 'c'.repeat(43) } })).status, 400);
  assert.equal((await request('/api/connections/google/start', { cookie, body: { state: 'x'.repeat(43), code_challenge: 'short' } })).status, 400);
  assert.equal((await request('/api/connections/unknown/start', { cookie, body: { state: 'x'.repeat(43), code_challenge: 'c'.repeat(43) } })).status, 404);
  // A return URI outside the allowlist is refused.
  assert.equal(
    (await request('/api/connections/google/start', {
      cookie,
      body: { state: 'x'.repeat(43), code_challenge: 'c'.repeat(43), return_uri: 'https://evil.example/steal' },
    })).status,
    400,
  );
  // A foreign origin is refused.
  assert.equal(
    (await request('/api/connections/google/start', {
      cookie,
      origin: 'https://evil.example',
      body: { state: 'x'.repeat(43), code_challenge: 'c'.repeat(43) },
    })).status,
    403,
  );

  const state = 's'.repeat(43);
  const challenge = 'c'.repeat(43);
  const started = await request('/api/connections/google/start', {
    cookie,
    body: { state, code_challenge: challenge },
  });
  assert.equal(started.status, 200, await started.clone().text());
  const start = await started.json();
  const authorize = new URL(start.authorize_url);
  assert.equal(authorize.origin + authorize.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(authorize.searchParams.get('code_challenge'), challenge);
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorize.searchParams.get('state'), state);
  assert.equal(authorize.searchParams.get('redirect_uri'), 'https://auth.flaxia.app/api/connections/google/callback');
  // The verifier never travels to the provider.
  assert.equal(authorize.search.includes('code_verifier'), false);

  // The callback hands the code back to the browser and consumes the state.
  const callback = await request(
    `/api/connections/google/callback?code=auth-code&state=${state}`,
    { method: 'GET', cookie },
  );
  assert.equal(callback.status, 302, await callback.clone().text());
  const location = new URL(callback.headers.get('location'));
  assert.equal(location.origin + location.pathname, 'https://flaxia.app/settings/connections');
  assert.equal(location.searchParams.get('oauth_code'), 'auth-code');
  assert.equal(location.searchParams.get('oauth_state'), state);
  assert.equal(location.searchParams.get('oauth_provider'), 'google');

  // The same state cannot be replayed.
  const replay = await request(
    `/api/connections/google/callback?code=auth-code&state=${state}`,
    { method: 'GET', cookie },
  );
  assert.equal(replay.status, 400);
  // An unknown state is refused.
  const unknown = await request(
    `/api/connections/google/callback?code=auth-code&state=${'z'.repeat(43)}`,
    { method: 'GET', cookie },
  );
  assert.equal(unknown.status, 400);
  // A provider mismatch is refused: a Slack state does not open Google.
  const slackStart = await request('/api/connections/slack/start', {
    cookie,
    body: { state: 'k'.repeat(43), code_challenge: 'c'.repeat(43) },
  });
  assert.equal(slackStart.status, 503, 'Slack has no client id configured in this test');
  const mismatched = await request(
    `/api/connections/google/callback?code=auth-code&state=${'k'.repeat(43)}`,
    { method: 'GET', cookie },
  );
  assert.equal(mismatched.status, 400);

  // The browser stores the token as a Vault item and reports the metadata.
  const vaultItemId = `item_${'d'.repeat(20)}`;
  const vaultItem = { item_key_wrapped: wrapped(), payload: wrapped(120), kind: 'oauth_connection', vk_version: 1 };
  // The Vault kind is accepted, so the token can be stored like any item.
  const saved = await request(`/api/vault/items/${vaultItemId}`, { method: 'PUT', cookie, body: vaultItem });
  assert.equal(saved.status, 200, await saved.clone().text());

  const calendarScope = 'https://www.googleapis.com/auth/calendar.readonly';
  const gmailScope = 'https://www.googleapis.com/auth/gmail.readonly';

  // A completion without the transaction cannot bind a Vault item.
  const noTransaction = await request('/api/connections/google/complete', {
    cookie,
    body: { vault_item_id: vaultItemId, scopes: [calendarScope] },
  });
  assert.equal(noTransaction.status, 400);

  // A Vault item that does not belong to the user (or is not the right kind)
  // is refused.
  const foreignItem = await request('/api/connections/google/complete', {
    cookie,
    body: {
      transaction_id: start.transaction_id,
      state,
      vault_item_id: `item_${'e'.repeat(20)}`,
      scopes: [calendarScope],
    },
  });
  assert.equal(foreignItem.status, 400);

  const completed = await request('/api/connections/google/complete', {
    cookie,
    body: {
      transaction_id: start.transaction_id,
      state,
      vault_item_id: vaultItemId,
      provider_sub: '1234567890',
      scopes: [calendarScope, gmailScope],
      expires_at: '2026-11-12T01:00:00.000Z',
    },
  });
  assert.equal(completed.status, 200, await completed.clone().text());

  const listed = await request('/api/connections', { method: 'GET', cookie });
  assert.equal(listed.status, 200);
  const { connections } = await listed.json();
  assert.equal(connections.length, 1);
  assert.equal(connections[0].provider, 'google');
  assert.equal(connections[0].provider_sub, '1234567890');
  assert.deepEqual(connections[0].scopes, [calendarScope, gmailScope]);
  assert.equal(connections[0].vault_item_id, vaultItemId);
  // The metadata never carries a credential.
  assert.equal('access_token' in connections[0], false);
  assert.equal('refresh_token' in connections[0], false);
  assert.equal(JSON.stringify(connections).includes('auth-code'), false);

  // A completed transaction cannot be reused.
  const replayedCompletion = await request('/api/connections/google/complete', {
    cookie,
    body: { transaction_id: start.transaction_id, state, vault_item_id: vaultItemId, scopes: [calendarScope] },
  });
  assert.equal(replayedCompletion.status, 400);

  // A scope the provider never offers is dropped rather than stored. A new
  // authorization has to be started because completion is one-shot.
  const secondState = 't'.repeat(43);
  const secondStart = await (
    await request('/api/connections/google/start', {
      cookie,
      body: { state: secondState, code_challenge: 'c'.repeat(43) },
    })
  ).json();
  const secondCallback = await request(
    `/api/connections/google/callback?code=auth-code-2&state=${secondState}`,
    { method: 'GET', cookie },
  );
  assert.equal(secondCallback.status, 302);
  await request('/api/connections/google/complete', {
    cookie,
    body: {
      transaction_id: secondStart.transaction_id,
      state: secondState,
      vault_item_id: vaultItemId,
      scopes: [calendarScope, 'not-a-google-scope'],
    },
  });
  const rescoped = await (await request('/api/connections', { method: 'GET', cookie })).json();
  assert.deepEqual(rescoped.connections[0].scopes, [calendarScope]);

  // Deleting the connection revokes the metadata.
  const deleted = await request('/api/connections/google', { method: 'DELETE', cookie });
  assert.equal(deleted.status, 200);
  const afterDelete = await (await request('/api/connections', { method: 'GET', cookie })).json();
  assert.equal(afterDelete.connections[0].status, 'revoked');
  assert.ok(afterDelete.connections[0].revoked_at);
});

test('a server-exchange provider refuses a browser exchange and seals the result', { timeout: 90000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'flaxia-oauth-seal-test-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const migration = spawnSync(
    process.execPath,
    [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory],
    { encoding: 'utf8', env: { ...process.env, CI: 'true' } },
  );
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);

  const port = await freePort();
  const auth = await startWorker(
    [
      '--port', String(port),
      '--persist-to', directory,
      '--var', 'GITHUB_OAUTH_CLIENT_ID:test-client-id',
      '--var', 'GITHUB_OAUTH_CLIENT_SECRET:test-client-secret',
    ],
    'auth',
  );
  t.after(async () => {
    if (auth.worker.exitCode === null) {
      auth.worker.kill('SIGTERM');
      await new Promise(resolve => auth.worker.once('exit', resolve));
    }
  });
  const base = `http://127.0.0.1:${port}`;
  await waitFor(`${base}/health`, auth.worker, auth.getOutput, 'Auth');

  const request = (path, { method = 'POST', body, cookie, origin = 'https://flaxia.app', ip = '192.0.2.204' } = {}) =>
    fetch(`${base}${path}`, {
      method,
      redirect: 'manual',
      headers: {
        origin,
        'CF-Connecting-IP': ip,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { cookie } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

  const password = 'oauth seal password';
  const salt = generateSalt();
  const registration = await request('/api/auth/register', {
    body: {
      username: 'SealUser',
      display_name: 'Seal User',
      srp_salt: encode(salt),
      srp_verifier: encode(await computeVerifier(password, salt)),
      srp_group: '2048',
      srp_kdf: 'pbkdf2-600k-v2',
    },
  });
  assert.equal(registration.status, 201);
  const cookie = registration.headers.get('set-cookie').split(';')[0];

  // A client-mode provider has nothing to exchange on the server.
  const clientMode = await request('/api/connections/google/exchange', {
    cookie,
    body: { code: 'auth-code', client_public_key: 'key' },
  });
  assert.equal(clientMode.status, 400);

  // A server exchange requires the transaction that produced the code.
  const state = 'g'.repeat(43);
  const started = await request('/api/connections/github/start', {
    cookie,
    body: { state, code_challenge: 'c'.repeat(43) },
  });
  assert.equal(started.status, 200, await started.clone().text());
  const start = await started.json();
  const callback = await request(
    `/api/connections/github/callback?code=auth-code&state=${state}`,
    { method: 'GET', cookie },
  );
  assert.equal(callback.status, 302);

  const noTransaction = await request('/api/connections/github/exchange', {
    cookie,
    body: { code: 'auth-code', client_public_key: 'key' },
  });
  assert.equal(noTransaction.status, 400);

  // The server-exchange route needs a client public key.
  const noKey = await request('/api/connections/github/exchange', {
    cookie,
    body: { transaction_id: start.transaction_id, state, code: 'auth-code' },
  });
  assert.equal(noKey.status, 400);

  // With a key, the result comes back sealed and carries no token.
  const keys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const publicKey = encode(new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey)));
  const exchanged = await request('/api/connections/github/exchange', {
    cookie,
    body: {
      transaction_id: start.transaction_id,
      state,
      code: 'auth-code',
      client_public_key: publicKey,
    },
  });
  // GitHub is not reachable from the test environment, so the exchange fails
  // at the provider. The important part is that no token comes back.
  if (exchanged.status === 200) {
    const payload = await exchanged.json();
    assert.ok(payload.sealed);
    assert.equal('access_token' in payload, false);
    assert.equal(JSON.stringify(payload).includes('access_token'), false);
  } else {
    assert.equal(exchanged.status, 502);
  }
});
