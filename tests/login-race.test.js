import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { generateSalt, computeVerifier, clientStep1, clientStep2 } from '../src/srp.ts';

const wrangler = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
const enc = value => Buffer.from(value).toString('base64');
const dec = value => new Uint8Array(Buffer.from(value, 'base64'));

test('login cannot create a session after its verifier was replaced and sessions revoked', { timeout: 60000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'auth-login-race-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const migration = spawnSync(process.execPath, [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);
  const server = createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const worker = spawn(process.execPath, [wrangler, 'dev', '--local', '--config', 'tests/fixtures/login-race.jsonc', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0', '--persist-to', directory], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } });
  let output = '';
  worker.stdout.on('data', data => { output += data; });
  worker.stderr.on('data', data => { output += data; });
  t.after(async () => { if (worker.exitCode === null) { worker.kill('SIGTERM'); await new Promise(resolve => worker.once('exit', resolve)); } });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(base + '/health')).ok) { ready = true; break; } } catch {}
    if (worker.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready, output);
  const post = (path, body, headers = {}) => fetch(base + path, {
    method: 'POST', headers: { Origin: 'https://flaxia.app', 'CF-Connecting-IP': '192.0.2.80', 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const password = 'old race-test password';
  const salt = generateSalt();
  const verifier = await computeVerifier(password, salt);
  const registration = await post('/api/auth/register', { username: 'RaceLogin', srp_salt: enc(salt), srp_verifier: enc(verifier), srp_group: '2048', srp_kdf: 'pbkdf2-600k-v2' });
  assert.equal(registration.status, 201, await registration.clone().text());
  const start = await post('/api/auth/login/start', { username: 'RaceLogin' });
  assert.equal(start.status, 200, await start.clone().text());
  const hs = await start.json();
  const first = await clientStep1(password, dec(hs.salt));
  const proof = await clientStep2(password, dec(hs.salt), first.a, dec(hs.B), hs.srp_kdf);
  const replacementSalt = generateSalt();
  const replacementVerifier = await computeVerifier('new race-test password', replacementSalt);
  const login = await post('/api/auth/login/verify', { challenge_id: hs.challenge_id, A: enc(proof.A), M1: enc(proof.M1) }, { 'X-Test-Replacement': `${enc(replacementSalt)}:${enc(replacementVerifier)}` });
  assert.equal(login.headers.get('X-Test-Interleaved'), 'yes', 'The credential replacement must actually run');
  assert.equal(login.status, 401, 'A verifier replaced during verification must not issue a session');
  assert.equal(login.headers.get('set-cookie'), null);
});
