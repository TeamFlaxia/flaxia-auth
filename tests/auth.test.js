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
  const seedSql = `INSERT INTO users (id, username, email, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES ('legacy-id', 'LegacyUser', 'legacy@example.com', '${encode(legacySalt)}', '${encode(legacyVerifier)}', '2048', 'sha256-v1'); INSERT INTO users (id, username, srp_salt, srp_verifier, frozen_at) VALUES ('frozen-id', 'FrozenUser', '${encode(legacySalt)}', '${encode(legacyVerifier)}', '2026-01-01T00:00:00.000Z')`;
  const seed = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'flaxia-auth-prod', '--local', '--persist-to', directory, '--command', seedSql], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(seed.status, 0, seed.stdout + seed.stderr);
  const port = await freePort();
  const worker = spawn(process.execPath, [wrangler, 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--persist-to', directory], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } });
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
  const password = 'a strong test password';
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt);
  const registration = { username: 'TestUser', srp_salt: encode(salt), srp_verifier: encode(verifier), srp_group: '2048', srp_kdf: 'pbkdf2-600k-v2' };
  for (const body of [null, {}, { ...registration, password: 'plaintext' }, { ...registration, srp_verifier: 'AA==' }, { ...registration, srp_kdf: 'unknown' }, { ...registration, username: 'invalid name' }, { ...registration, username: 'a'.repeat(21) }, { ...registration, email: 'invalid' }]) {
    assert.equal((await request('/api/auth/register', { body, ip: '192.0.2.10' })).status, 400);
  }
  assert.equal((await request('/api/auth/register', { body: { ...registration, username: 'with_email', email: '  Mixed@Example.COM  ' }, ip: '192.0.2.11' })).status, 201);
  assert.equal((await request('/api/auth/register', { body: { ...registration, username: 'other', email: 'mixed@example.com' }, ip: '192.0.2.11' })).status, 409);
  assert.equal((await request('/api/auth/register', { body: registration, origin: 'https://evil.example' })).status, 403);
  assert.equal((await request('/api/auth/register', { body: { ...registration, srp_kdf: 'sha256-v1' } })).status, 400);
  assert.equal((await request('/api/auth/register', { body: registration })).status, 201);
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
  assert.equal(result.user.email, null);
  const cookie = login.headers.get('set-cookie');
  assert.match(cookie, /__Host-flaxia_session=/);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /Secure/i);
  assert.equal((await request('/api/auth/login/verify', { body })).status, 401);
  const me = await request('/api/auth/me', { method: 'GET', cookie: cookie.split(';')[0] });
  assert.equal(me.status, 200);
  assert.equal((await me.json()).user.id, result.user.id);
  assert.equal((await request('/api/auth/logout', { cookie: cookie.split(';')[0] })).status, 200);
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
  assert.equal((await request('/api/auth/login/start', { body: { username: 'FrozenUser' }, ip: '192.0.2.12' })).status, 401);
  for (let i = 0; i < 20; i++) assert.notEqual((await request('/api/auth/login/start', { body: { username: 'missing' }, ip: '192.0.2.9' })).status, 429);
  assert.equal((await request('/api/auth/login/start', { body: { username: 'missing' }, ip: '192.0.2.9' })).status, 429);
});
