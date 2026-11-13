import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';

const wrangler = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
const b64url = bytes => Buffer.from(bytes).toString('base64url');

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function waitForHealth(base, process, label) {
  let output = '';
  process.stdout.on('data', data => { output += data; });
  process.stderr.on('data', data => { output += data; });
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    if (process.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail(`${label} failed to start: ${output}`);
}

test('OAuth 2.0 / OpenID Connect provider', { timeout: 90000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'flaxia-auth-oauth-'));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  const migration = spawnSync(process.execPath, [wrangler, 'd1', 'migrations', 'apply', 'flaxia-auth-prod', '--local', '--persist-to', directory], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(migration.status, 0, migration.stdout + migration.stderr);
  const seedSql = `INSERT INTO users (id, username, display_name, email) VALUES ('oauth-user', 'OAuthUser', 'OAuth User', 'oauth@example.com');
    INSERT INTO users (id, username, display_name, email, frozen_at) VALUES ('frozen-user', 'FrozenOAuth', 'Frozen OAuth', 'frozen@example.com', '2026-01-01T00:00:00.000Z');
    INSERT INTO sessions (id, user_id, expires_at) VALUES ('oauth-session', 'oauth-user', '2099-01-01T00:00:00.000Z'), ('frozen-session', 'frozen-user', '2099-01-01T00:00:00.000Z');`;
  const seed = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'flaxia-auth-prod', '--local', '--persist-to', directory, '--command', seedSql], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
  assert.equal(seed.status, 0, seed.stdout + seed.stderr);

  const port = await freePort();
  const worker = spawn(process.execPath, [wrangler, 'dev', '--local', '--name', 'flaxia-auth-oauth-test', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0', '--persist-to', directory], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } });
  t.after(async () => { if (worker.exitCode === null) { worker.kill('SIGTERM'); await new Promise(resolve => worker.once('exit', resolve)); } });
  const base = `http://127.0.0.1:${port}`;
  await waitForHealth(base, worker, 'Worker');

  const bridgePort = await freePort();
  const bridgeProxy = spawn(process.execPath, [wrangler, 'dev', '--local', '--config', 'tests/fixtures/bridge-proxy-oauth.jsonc', '--ip', '127.0.0.1', '--port', String(bridgePort), '--inspector-port', '0'], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CI: 'true' } });
  t.after(async () => { if (bridgeProxy.exitCode === null) { bridgeProxy.kill('SIGTERM'); await new Promise(resolve => bridgeProxy.once('exit', resolve)); } });
  const bridgeBase = `http://127.0.0.1:${bridgePort}`;
  await waitForHealth(bridgeBase, bridgeProxy, 'Service binding');

  const ip = '192.0.2.60';
  const cookie = '__Host-flaxia_session=oauth-session';
  const get = (path, headers = {}) => fetch(`${base}${path}`, { headers: { 'CF-Connecting-IP': ip, ...headers }, redirect: 'manual' });
  const form = (path, fields, headers = {}) => fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip, ...headers },
    body: new URLSearchParams(fields).toString(),
  });
  const bridgePost = (path, body) => fetch(`${bridgeBase}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const query = sql => {
    const result = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'flaxia-auth-prod', '--local', '--persist-to', directory, '--command', sql], { encoding: 'utf8', env: { ...process.env, CI: 'true' } });
    assert.equal(result.status, 0, result.stderr);
  };

  async function authorize(options = {}) {
    const {
      clientId = 'test-client',
      redirectUri = 'https://client.example/callback',
      scope = 'openid profile email offline_access',
      state = 'state-123',
      nonce = 'nonce-456',
      sessionCookie = cookie,
      challengeMethod = 'S256',
      prompt,
    } = options;
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: challengeMethod,
    });
    if (prompt) params.set('prompt', prompt);
    const response = await get(`/oauth/authorize?${params}`, sessionCookie ? { cookie: sessionCookie } : {});
    return { response, verifier, challenge };
  }

  const redirectOf = response => new URL(response.headers.get('location'));

  // ── Client registration (trusted service binding) ─────────────────────────
  const confidentialResponse = await bridgePost('/api/flaxia/oauth/clients', {
    client_id: 'test-client',
    client_name: 'Test Client',
    redirect_uris: ['https://client.example/callback'],
    is_confidential: true,
    allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
  });
  assert.equal(confidentialResponse.status, 201);
  const confidentialClient = await confidentialResponse.json();
  assert.equal(confidentialClient.client_id, 'test-client');
  assert.equal(confidentialClient.is_confidential, true);
  assert.equal(confidentialClient.pkce_required, true);
  assert.match(confidentialClient.client_secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await bridgePost('/api/flaxia/oauth/clients', { client_id: 'test-client', redirect_uris: ['https://client.example/callback'] })).status, 409);
  assert.equal((await bridgePost('/api/flaxia/oauth/clients', { client_id: 'bad-http', redirect_uris: ['http://example.com/callback'] })).status, 400);
  assert.equal((await bridgePost('/api/flaxia/oauth/clients', { client_id: 'bad-fragment', redirect_uris: ['https://client.example/callback#fragment'] })).status, 400);
  assert.equal((await bridgePost('/api/flaxia/oauth/clients', { client_id: 'bad-scheme', redirect_uris: ['ftp://client.example/callback'] })).status, 400);

  const publicResponse = await bridgePost('/api/flaxia/oauth/clients', {
    client_id: 'public-client',
    client_name: 'Public Client',
    redirect_uris: ['http://localhost:3000/callback'],
    is_confidential: false,
    allowed_scopes: ['openid', 'profile'],
  });
  assert.equal(publicResponse.status, 201);
  const publicClient = await publicResponse.json();
  assert.equal(publicClient.is_confidential, false);
  assert.equal('client_secret' in publicClient, false);

  // ── Discovery and JWKS ────────────────────────────────────────────────────
  const discoveryResponse = await get('/.well-known/openid-configuration');
  assert.equal(discoveryResponse.status, 200);
  const metadata = await discoveryResponse.json();
  assert.equal(metadata.issuer, 'https://auth.flaxia.app');
  assert.equal(metadata.authorization_endpoint, 'https://auth.flaxia.app/oauth/authorize');
  assert.equal(metadata.token_endpoint, 'https://auth.flaxia.app/oauth/token');
  assert.equal(metadata.userinfo_endpoint, 'https://auth.flaxia.app/oauth/userinfo');
  assert.equal(metadata.jwks_uri, 'https://auth.flaxia.app/oauth/jwks');
  assert.equal(metadata.revocation_endpoint, 'https://auth.flaxia.app/oauth/revoke');
  assert.deepEqual(metadata.scopes_supported, ['openid', 'profile', 'email', 'offline_access']);
  assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
  assert.equal(metadata.id_token_signing_alg_values_supported[0], 'RS256');
  assert.equal((await get('/.well-known/oauth-authorization-server')).status, 200);

  // ── Authorization code + PKCE ─────────────────────────────────────────────
  const auth = await authorize();
  assert.equal(auth.response.status, 302);
  const authRedirect = redirectOf(auth.response);
  assert.equal(`${authRedirect.origin}${authRedirect.pathname}`, 'https://client.example/callback');
  assert.equal(authRedirect.searchParams.get('state'), 'state-123');
  const code = authRedirect.searchParams.get('code');
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(auth.response.headers.get('cache-control'), 'no-store');

  const tokenResponse = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
    code_verifier: auth.verifier,
  });
  assert.equal(tokenResponse.status, 200);
  assert.equal(tokenResponse.headers.get('cache-control'), 'no-store');
  const tokens = await tokenResponse.json();
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.expires_in, 3600);
  assert.match(tokens.access_token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(tokens.refresh_token, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(tokens.id_token);

  // The signing key is created on first use and published through JWKS.
  const jwksResponse = await get('/oauth/jwks');
  assert.equal(jwksResponse.status, 200);
  const jwks = await jwksResponse.json();
  assert.equal(jwks.keys.length, 1);
  const jwk = jwks.keys[0];
  assert.equal(jwk.kty, 'RSA');
  assert.equal(jwk.use, 'sig');
  assert.equal(jwk.alg, 'RS256');
  assert.equal(jwk.d, undefined);

  const idParts = tokens.id_token.split('.');
  assert.equal(idParts.length, 3);
  const idHeader = JSON.parse(Buffer.from(idParts[0], 'base64url').toString());
  const idPayload = JSON.parse(Buffer.from(idParts[1], 'base64url').toString());
  assert.equal(idHeader.alg, 'RS256');
  assert.equal(idHeader.kid, jwk.kid);
  assert.equal(idPayload.iss, 'https://auth.flaxia.app');
  assert.equal(idPayload.sub, 'oauth-user');
  assert.equal(idPayload.aud, 'test-client');
  assert.equal(idPayload.nonce, 'nonce-456');
  assert.ok(idPayload.exp > Math.floor(Date.now() / 1000));
  const verifyKey = await crypto.subtle.importKey('jwk', { ...jwk, key_ops: ['verify'] }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', verifyKey, Buffer.from(idParts[2], 'base64url'), new TextEncoder().encode(`${idParts[0]}.${idParts[1]}`)), true);

  // ── UserInfo ──────────────────────────────────────────────────────────────
  const userinfoResponse = await get('/oauth/userinfo', { Authorization: `Bearer ${tokens.access_token}` });
  assert.equal(userinfoResponse.status, 200);
  const claims = await userinfoResponse.json();
  assert.equal(claims.sub, 'oauth-user');
  assert.equal(claims.preferred_username, 'OAuthUser');
  assert.equal(claims.name, 'OAuth User');
  assert.equal(claims.email, 'oauth@example.com');
  assert.equal(claims.email_verified, false);
  assert.equal((await get('/oauth/userinfo')).status, 401);
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${'x'.repeat(43)}` })).status, 401);

  // ── Single-use code ──────────────────────────────────────────────────────
  const reused = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
    code_verifier: auth.verifier,
  });
  assert.equal(reused.status, 400);
  assert.equal((await reused.json()).error, 'invalid_grant');

  // A failed PKCE check does not consume the code.
  const pkceAuth = await authorize({ state: 'pkce' });
  const pkceCode = redirectOf(pkceAuth.response).searchParams.get('code');
  const wrongVerifier = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: pkceCode,
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
    code_verifier: b64url(crypto.getRandomValues(new Uint8Array(32))),
  });
  assert.equal(wrongVerifier.status, 400);
  assert.equal((await wrongVerifier.json()).error, 'invalid_grant');
  const retry = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: pkceCode,
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
    code_verifier: pkceAuth.verifier,
  });
  assert.equal(retry.status, 200);

  // ── Refresh token rotation and reuse detection ────────────────────────────
  const refreshResponse = await form('/oauth/token', {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
  });
  assert.equal(refreshResponse.status, 200);
  const rotated = await refreshResponse.json();
  assert.notEqual(rotated.refresh_token, tokens.refresh_token);
  assert.notEqual(rotated.access_token, tokens.access_token);
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${rotated.access_token}` })).status, 200);

  // Revoking the access token makes UserInfo fail.
  assert.equal((await form('/oauth/revoke', { token: rotated.access_token, client_id: 'test-client', client_secret: confidentialClient.client_secret })).status, 200);
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${rotated.access_token}` })).status, 401);

  // Revoking a refresh token also revokes the access tokens issued with it.
  const secondRefresh = await (await form('/oauth/token', {
    grant_type: 'refresh_token',
    refresh_token: rotated.refresh_token,
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
  })).json();
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${secondRefresh.access_token}` })).status, 200);
  assert.equal((await form('/oauth/revoke', { token: secondRefresh.refresh_token, client_id: 'test-client', client_secret: confidentialClient.client_secret })).status, 200);
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${secondRefresh.access_token}` })).status, 401);

  // Reusing an already-rotated refresh token revokes the whole family.
  const reuse = await form('/oauth/token', {
    grant_type: 'refresh_token',
    refresh_token: rotated.refresh_token,
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
  });
  assert.equal(reuse.status, 400);
  assert.equal((await reuse.json()).error, 'invalid_grant');

  // ── Public client (no secret, PKCE only) ──────────────────────────────────
  const publicAuth = await authorize({ clientId: 'public-client', redirectUri: 'http://localhost:3000/callback', scope: 'openid profile' });
  assert.equal(publicAuth.response.status, 302);
  const publicCode = redirectOf(publicAuth.response).searchParams.get('code');
  const publicTokenResponse = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: publicCode,
    redirect_uri: 'http://localhost:3000/callback',
    client_id: 'public-client',
    code_verifier: publicAuth.verifier,
  });
  assert.equal(publicTokenResponse.status, 200);
  const publicTokens = await publicTokenResponse.json();
  assert.equal(publicTokens.token_type, 'Bearer');
  assert.equal('refresh_token' in publicTokens, false);
  const publicClaims = await (await get('/oauth/userinfo', { Authorization: `Bearer ${publicTokens.access_token}` })).json();
  assert.equal(publicClaims.sub, 'oauth-user');
  assert.equal(publicClaims.preferred_username, 'OAuthUser');
  assert.equal('email' in publicClaims, false);

  // ── Client revocation ─────────────────────────────────────────────────────
  assert.equal((await bridgePost('/api/flaxia/oauth/clients/revoke', { client_id: 'public-client' })).status, 200);
  assert.equal((await bridgePost('/api/flaxia/oauth/clients/revoke', { client_id: 'public-client' })).status, 200);
  assert.equal((await get('/oauth/userinfo', { Authorization: `Bearer ${publicTokens.access_token}` })).status, 401);
  const revokedAuthorize = await authorize({ clientId: 'public-client', redirectUri: 'http://localhost:3000/callback' });
  assert.equal(revokedAuthorize.response.status, 400);
  assert.equal((await revokedAuthorize.response.json()).error, 'invalid_client');

  // ── Authorization error handling ──────────────────────────────────────────
  const unknownClient = await get(`/oauth/authorize?${new URLSearchParams({
    client_id: 'unknown-client',
    redirect_uri: 'https://client.example/callback',
    response_type: 'code',
    scope: 'openid',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  })}`);
  assert.equal(unknownClient.status, 400);
  assert.equal((await unknownClient.json()).error, 'invalid_client');

  const evilRedirect = await get(`/oauth/authorize?${new URLSearchParams({
    client_id: 'test-client',
    redirect_uri: 'https://evil.example/callback',
    response_type: 'code',
    scope: 'openid',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  })}`);
  assert.equal(evilRedirect.status, 400);
  assert.equal(evilRedirect.headers.get('location'), null);

  const missingOpenid = await authorize({ scope: 'profile' });
  assert.equal(missingOpenid.response.status, 302);
  assert.equal(redirectOf(missingOpenid.response).searchParams.get('error'), 'invalid_scope');

  const plainPkce = await authorize({ challengeMethod: 'plain' });
  assert.equal(plainPkce.response.status, 302);
  assert.equal(redirectOf(plainPkce.response).searchParams.get('error'), 'invalid_request');

  const noSession = await authorize({ sessionCookie: null, prompt: 'none' });
  assert.equal(noSession.response.status, 302);
  assert.equal(redirectOf(noSession.response).searchParams.get('error'), 'login_required');

  const frozen = await authorize({ sessionCookie: '__Host-flaxia_session=frozen-session' });
  assert.equal(frozen.response.status, 302);
  assert.equal(redirectOf(frozen.response).searchParams.get('error'), 'login_required');

  const wrongSecret = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: 'A'.repeat(43),
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: 'wrong',
    code_verifier: 'A'.repeat(43),
  });
  assert.equal(wrongSecret.status, 401);
  assert.equal((await wrongSecret.json()).error, 'invalid_client');

  const unsupportedGrant = await form('/oauth/token', { grant_type: 'client_credentials', client_id: 'test-client', client_secret: confidentialClient.client_secret });
  assert.equal(unsupportedGrant.status, 400);
  assert.equal((await unsupportedGrant.json()).error, 'unsupported_grant_type');

  const refreshOnlyClient = await bridgePost('/api/flaxia/oauth/clients', {
    client_id: 'refresh-only-client',
    client_name: 'Refresh Only',
    redirect_uris: ['https://refresh.example/callback'],
    is_confidential: false,
    allowed_scopes: ['openid'],
    grant_types: ['refresh_token'],
  });
  assert.equal(refreshOnlyClient.status, 201);
  const refreshOnlyAuth = await authorize({ clientId: 'refresh-only-client', redirectUri: 'https://refresh.example/callback' });
  assert.equal(refreshOnlyAuth.response.status, 302);
  assert.equal(redirectOf(refreshOnlyAuth.response).searchParams.get('error'), 'unauthorized_client');

  const otherPublic = await bridgePost('/api/flaxia/oauth/clients', {
    client_id: 'other-public-client',
    client_name: 'Other Public',
    redirect_uris: ['http://localhost:3001/callback'],
    is_confidential: false,
    allowed_scopes: ['openid'],
  });
  assert.equal(otherPublic.status, 201);
  const boundAuth = await authorize({ state: 'bound' });
  const boundCode = redirectOf(boundAuth.response).searchParams.get('code');
  const wrongClientCode = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: boundCode,
    redirect_uri: 'https://client.example/callback',
    client_id: 'other-public-client',
    code_verifier: boundAuth.verifier,
  });
  assert.equal(wrongClientCode.status, 400);
  assert.equal((await wrongClientCode.json()).error, 'invalid_grant');

  // ── Expired authorization code ────────────────────────────────────────────
  const expiredAuth = await authorize({ state: 'expired' });
  const expiredCode = redirectOf(expiredAuth.response).searchParams.get('code');
  const expiredHash = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expiredCode))));
  query(`UPDATE oauth_authorization_codes SET expires_at = '2000-01-01T00:00:00.000Z' WHERE code_hash = '${expiredHash}'`);
  const expiredToken = await form('/oauth/token', {
    grant_type: 'authorization_code',
    code: expiredCode,
    redirect_uri: 'https://client.example/callback',
    client_id: 'test-client',
    client_secret: confidentialClient.client_secret,
    code_verifier: expiredAuth.verifier,
  });
  assert.equal(expiredToken.status, 400);
  assert.equal((await expiredToken.json()).error, 'invalid_grant');

  // ── Signing key rotation ──────────────────────────────────────────────────
  const rotateResponse = await bridgePost('/api/flaxia/oauth/keys/rotate', {});
  assert.equal(rotateResponse.status, 200);
  const rotatedKey = await rotateResponse.json();
  assert.match(rotatedKey.kid, /^[A-Za-z0-9_-]{43}$/);
  const jwksAfterRotate = await (await get('/oauth/jwks')).json();
  assert.equal(jwksAfterRotate.keys.length, 2);
  assert.equal((await bridgePost('/api/flaxia/oauth/keys/revoke', { kid: jwk.kid })).status, 200);
  assert.equal((await bridgePost('/api/flaxia/oauth/keys/revoke', { kid: jwk.kid })).status, 404);
  const jwksAfterRevoke = await (await get('/oauth/jwks')).json();
  assert.equal(jwksAfterRevoke.keys.length, 1);
  assert.equal(jwksAfterRevoke.keys[0].kid, rotatedKey.kid);
});
