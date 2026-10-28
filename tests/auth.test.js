import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { generateSalt, computeVerifier, clientStep1, clientStep2, verifyServerProof } from '../src/srp.ts';

const wrangler = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
const encode = bytes => Buffer.from(bytes).toString('base64');
const decode = text => new Uint8Array(Buffer.from(text, 'base64'));
const syncSecret = 'test-secret-for-legacy-sync-32-bytes-minimum';

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

test('authentication API with a local D1 database', { timeout: 60000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'flaxia-auth-test-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const migration = spawnSync(process.execPath, [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);
  const legacySalt = generateSalt();
  const legacyVerifier = await computeVerifier('legacy password', legacySalt, 'sha256-v1');
  const seedSql = `INSERT INTO users (id, username, email, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES ('legacy-id', 'LegacyUser', 'legacy@example.com', '${encode(legacySalt)}', '${encode(legacyVerifier)}', '2048', 'sha256-v1'); INSERT INTO users (id, username, srp_salt, srp_verifier, frozen_at) VALUES ('frozen-id', 'FrozenUser', '${encode(legacySalt)}', '${encode(legacyVerifier)}', '2026-01-01T00:00:00.000Z'); INSERT INTO users (id, username, password_hash) VALUES ('needs-upgrade', 'OldUser', 'old-hash'); INSERT INTO users (id, username, password_hash, frozen_at) VALUES ('frozen-legacy', 'FrozenLegacy', 'old-hash', '2026-01-01T00:00:00.000Z')`;
  const seed = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'flaxia-auth-prod', '--local', '--persist-to', directory, '--command', seedSql], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(seed.status, 0, seed.stdout + seed.stderr);
  const port = await freePort();
  const worker = spawn(process.execPath, [wrangler, 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--persist-to', directory, '--var', `LEGACY_SYNC_SECRET:${syncSecret}`], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } });
  let output = '';
  worker.stdout.on('data', data => { output += data; });
  worker.stderr.on('data', data => { output += data; });
  t.after(async () => { if (worker.exitCode === null) { worker.kill('SIGTERM'); await new Promise(resolve => worker.once('exit', resolve)); } });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${base}/health`)).ok) { ready = true; break; } } catch {}
    if (worker.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, `Worker failed to start: ${output}`);
  const request = (path, { method = 'POST', body, cookie, origin = 'https://flaxia.app', ip = '192.0.2.1' } = {}) => fetch(`${base}${path}`, {
    method, headers: { origin, 'CF-Connecting-IP': ip, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const preflight = await fetch(`${base}/api/auth/register`, { method: 'OPTIONS', headers: { Origin: 'https://flaxia.app', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'https://flaxia.app');
  assert.equal(preflight.headers.get('access-control-allow-credentials'), 'true');
  const deniedPreflight = await fetch(`${base}/api/auth/register`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
  assert.notEqual(deniedPreflight.headers.get('access-control-allow-origin'), 'https://evil.example');
  const password = 'a strong test password';
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt);
  const registration = { username: 'TestUser', srp_salt: encode(salt), srp_verifier: encode(verifier), srp_group: '2048', srp_kdf: 'pbkdf2-600k-v2' };
  for (const body of [null, {}, { ...registration, password: 'plaintext' }, { ...registration, srp_verifier: 'AA==' }, { ...registration, srp_verifier: encode(new Uint8Array(256).fill(255)) }, { ...registration, srp_salt: ` ${registration.srp_salt}` }, { ...registration, srp_kdf: 'unknown' }, { ...registration, username: 'invalid name' }, { ...registration, username: 'a'.repeat(21) }]) {
    assert.equal((await request('/api/auth/register', { body, ip: '192.0.2.10' })).status, 400);
  }
  assert.equal((await request('/api/auth/register', { body: registration, origin: 'https://evil.example' })).status, 403);
  assert.equal((await request('/api/auth/register', { body: registration, origin: '' })).status, 403);
  assert.equal((await request('/api/auth/register', { body: { ...registration, srp_kdf: 'sha256-v1' } })).status, 400);
  const registered = await request('/api/auth/register', { body: { ...registration, display_name: 'Test User' } });
  assert.equal(registered.status, 201);
  assert.equal(registered.headers.get('access-control-allow-origin'), 'https://flaxia.app');
  assert.equal(registered.headers.get('access-control-allow-credentials'), 'true');
  assert.equal(registered.headers.get('cache-control'), 'no-store');
  assert.match(registered.headers.get('set-cookie'), /__Host-flaxia_session=.*HttpOnly.*Secure/i);
  const registeredUser = (await registered.json()).user;
  assert.equal(registeredUser.username, 'TestUser');
  assert.equal(registeredUser.display_name, 'Test User');
  assert.equal('email' in registeredUser, false);
  assert.equal((await request('/api/auth/register', { body: { ...registration, username: 'testuser' } })).status, 409);
  assert.equal((await request('/api/auth/me', { method: 'GET' })).status, 401);
  const start = await request('/api/auth/login/start', { body: { username: 'testuser' } });
  assert.equal(start.status, 200);
  const challenge = await start.json();
  assert.equal(challenge.srp_kdf, 'pbkdf2-600k-v2');
  const first = await clientStep1(password, decode(challenge.salt));
  const proof = await clientStep2(password, decode(challenge.salt), first.a, decode(challenge.B));
  const body = { challenge_id: challenge.challenge_id, A: encode(proof.A), M1: encode(proof.M1) };
  const login = await request('/api/auth/login/verify', { body });
  assert.equal(login.status, 200);
  const result = await login.json();
  assert.equal(await verifyServerProof(proof.A, proof.M1, proof.K, decode(result.M2)), true);
  assert.equal(result.user.username, 'TestUser');
  assert.equal(result.user.display_name, 'Test User');
  assert.equal(result.user.id, registeredUser.id);
  assert.equal('email' in result.user, false);
  const cookie = login.headers.get('set-cookie');
  assert.match(cookie, /__Host-flaxia_session=/);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /Secure/i);
  assert.equal((await request('/api/auth/login/verify', { body })).status, 401);
  const me = await request('/api/auth/me', { method: 'GET', cookie: cookie.split(';')[0] });
  assert.equal(me.status, 200);
  assert.equal((await me.json()).user.id, result.user.id);
  const session = cookie.split(';')[0];
  assert.equal((await request('/api/auth/reauth/start')).status, 401);
  async function reauthProof() {
    const response = await request('/api/auth/reauth/start', { cookie: session });
    assert.equal(response.status, 200);
    const challenge = await response.json();
    const first = await clientStep1(password, decode(challenge.salt));
    const finish = await clientStep2(password, decode(challenge.salt), first.a, decode(challenge.B), challenge.srp_kdf);
    return { challenge_id: challenge.challenge_id, A: encode(finish.A), M1: encode(finish.M1) };
  }
  const reauth = await reauthProof();
  assert.equal((await (await request('/api/auth/reauth/verify', { cookie: session, body: reauth })).json()).valid, true);
  assert.equal((await (await request('/api/auth/reauth/verify', { cookie: session, body: reauth })).json()).valid, false);
  const newSalt = generateSalt();
  const newVerifier = await computeVerifier(password, newSalt);
  const update = { srp_salt: encode(newSalt), srp_verifier: encode(newVerifier), srp_group: '2048', srp_kdf: 'pbkdf2-600k-v2' };
  assert.equal((await request('/api/auth/upgrade-srp', { cookie: session, body: update })).status, 400);
  assert.equal((await request('/api/auth/upgrade-srp', { cookie: session, body: { ...update, current_srp: await reauthProof() } })).status, 200);
  const logout = await request('/api/auth/logout', { cookie: cookie.split(';')[0] });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/i);
  assert.equal((await request('/api/auth/me', { method: 'GET', cookie: cookie.split(';')[0] })).status, 401);
  const wrongStart = await (await request('/api/auth/login/start', { body: { username: 'TestUser' } })).json();
  const wrongFirst = await clientStep1('wrong password', decode(wrongStart.salt));
  const wrongProof = await clientStep2('wrong password', decode(wrongStart.salt), wrongFirst.a, decode(wrongStart.B));
  assert.equal((await request('/api/auth/login/verify', { body: { challenge_id: wrongStart.challenge_id, A: encode(wrongProof.A), M1: encode(wrongProof.M1) } })).status, 401);
  const legacyStart = await request('/api/auth/login/start', { body: { username: 'legacyuser' }, ip: '192.0.2.12' });
  assert.equal(legacyStart.status, 200);
  const legacy = await legacyStart.json();
  assert.equal(legacy.srp_kdf, 'sha256-v1');
  const legacyFirst = await clientStep1('legacy password', decode(legacy.salt));
  const legacyProof = await clientStep2('legacy password', decode(legacy.salt), legacyFirst.a, decode(legacy.B), legacy.srp_kdf);
  const legacyLogin = await request('/api/auth/login/verify', { body: { challenge_id: legacy.challenge_id, A: encode(legacyProof.A), M1: encode(legacyProof.M1) }, ip: '192.0.2.12' });
  assert.equal(legacyLogin.status, 200);
  assert.equal((await legacyLogin.json()).user.id, 'legacy-id');
  const frozen = await (await request('/api/auth/login/start', { body: { username: 'FrozenUser' }, ip: '192.0.2.12' })).json();
  const frozenFirst = await clientStep1('legacy password', decode(frozen.salt));
  const frozenProof = await clientStep2('legacy password', decode(frozen.salt), frozenFirst.a, decode(frozen.B), frozen.srp_kdf);
  assert.equal((await request('/api/auth/login/verify', { body: { challenge_id: frozen.challenge_id, A: encode(frozenProof.A), M1: encode(frozenProof.M1) }, ip: '192.0.2.12' })).status, 403);
  const convertedSalt = generateSalt();
  const converted = { user_id: 'needs-upgrade', salt: encode(convertedSalt), verifier: encode(await computeVerifier('converted password', convertedSalt)), group: '2048', kdf: 'pbkdf2-600k-v2' };
  const raw = JSON.stringify(converted);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(syncSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = Buffer.from(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${raw}`))).toString('base64url');
  const sync = (data, time = timestamp, mac = signature) => fetch(`${base}/api/internal/legacy-sync`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Flaxia-Timestamp': time, 'X-Flaxia-Signature': mac }, body: data });
  assert.equal((await sync(JSON.stringify({ ...converted, user_id: 'legacy-id' }))).status, 401);
  assert.equal((await sync(raw, String(Number(timestamp) - 500))).status, 401);
  assert.equal((await sync(raw)).status, 200);
  assert.equal((await sync(raw)).status, 200);
  const signedSync = async data => {
    const signedBody = JSON.stringify(data);
    const signedMac = Buffer.from(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${signedBody}`))).toString('base64url');
    return sync(signedBody, timestamp, signedMac);
  };
  assert.equal((await signedSync({ ...converted, user_id: 'legacy-id' })).status, 409);
  assert.equal((await signedSync({ ...converted, user_id: 'frozen-legacy' })).status, 409);
  assert.equal((await signedSync({ ...converted, user_id: 'missing' })).status, 409);
  const stored = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'flaxia-auth-prod', '--local', '--persist-to', directory, '--command', "SELECT length(password_hash) AS hash_length FROM users WHERE id = 'needs-upgrade'", '--json'], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(stored.status, 0, stored.stderr);
  assert.equal(JSON.parse(stored.stdout)[0].results[0].hash_length, 0);
  const convertedStart = await request('/api/auth/login/start', { body: { username: 'OldUser' }, ip: '192.0.2.13' });
  assert.equal(convertedStart.status, 200);
  const convertedChallenge = await convertedStart.json();
  const convertedFirst = await clientStep1('converted password', decode(convertedChallenge.salt));
  const convertedProof = await clientStep2('converted password', decode(convertedChallenge.salt), convertedFirst.a, decode(convertedChallenge.B));
  const convertedLogin = await request('/api/auth/login/verify', { body: { challenge_id: convertedChallenge.challenge_id, A: encode(convertedProof.A), M1: encode(convertedProof.M1) }, ip: '192.0.2.13' });
  assert.equal(convertedLogin.status, 200);
  assert.equal((await convertedLogin.json()).user.id, 'needs-upgrade');
  for (let i = 0; i < 4; i++) assert.equal((await request('/api/auth/login/start', { body: { username: 'legacyuser' }, ip: `192.0.2.${30 + i}` })).status, 200);
  assert.equal((await request('/api/auth/login/start', { body: { username: 'legacyuser' }, ip: '192.0.2.39' })).status, 429);
  for (let i = 0; i < 20; i++) assert.notEqual((await request('/api/auth/login/start', { body: { username: 'missing' }, ip: '192.0.2.9' })).status, 429);
  assert.equal((await request('/api/auth/login/start', { body: { username: 'missing' }, ip: '192.0.2.9' })).status, 429);
});
