// OAuth 2.0 / OpenID Connect provider.
//
// The authorization server is Flaxia Auth itself. Relying parties register
// through the trusted Flaxia service binding, then use the standard
// authorization-code + PKCE flow. ID tokens are RS256 JWTs; the signing key is
// generated on first use and stored in D1 (Cloudflare encrypts D1 at rest).
//
// Scope of this implementation:
//   - authorization_code (PKCE S256 required for every client)
//   - refresh_token with rotation and reuse detection
//   - ID token (iss/sub/aud/exp/iat/nonce)
//   - UserInfo, JWKS, discovery, revocation
// Client registration and signing-key rotation are handled by the trusted
// service-binding routes registered in createOAuthBridgeApp.
import { Context, Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { bodyLimit } from 'hono/body-limit';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { cookieName, sessionUser, User } from './session';
import { constantTimeEqual, expiry, random, requestIp, rateLimit, sha256url } from './util';
import { corsAnyOrigin, corsRegisteredOrigins } from './oauth/cors';

const ISSUER = 'https://auth.flaxia.app';
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 86400;
const CODE_TTL_SECONDS = 60;
const KNOWN_SCOPES = ['openid', 'profile', 'email', 'offline_access'];
const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'];

type OAuthClient = {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string;
  redirect_uris: string;
  allowed_scopes: string;
  is_confidential: number;
  pkce_required: number;
  grant_types: string;
  created_at: string;
  revoked_at: string | null;
};

type OAuthCode = {
  code_hash: string;
  client_id: string;
  user_id: string;
  session_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  state: string | null;
  nonce: string | null;
  expires_at: string;
  consumed_at: string | null;
};

type OAuthRefreshToken = {
  token_hash: string;
  client_id: string;
  user_id: string;
  session_id: string;
  scope: string;
  expires_at: string;
  revoked_at: string | null;
};

type IssuedTokens = {
  access_token: string;
  token_type: 'Bearer';
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  scope: string;
};

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function parseJsonStringArray(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch { return []; }
}

function basicAuth(c: { req: { header(name: string): string | undefined } }): { clientId: string; secret: string } | null {
  const header = c.req.header('Authorization');
  if (!header || !header.startsWith('Basic ')) return null;
  try {
    const decoded = atob(header.slice('Basic '.length));
    const separator = decoded.indexOf(':');
    if (separator < 0) return null;
    // RFC 6749: the credentials are application/x-www-form-urlencoded.
    const decode = (value: string) => decodeURIComponent(value.replace(/\+/g, ' '));
    return { clientId: decode(decoded.slice(0, separator)), secret: decode(decoded.slice(separator + 1)) };
  } catch { return null; }
}

async function clientFor(db: D1Database, clientId: string): Promise<OAuthClient | null> {
  if (!clientId || clientId.length > 128) return null;
  return db.prepare('SELECT * FROM oauth_clients WHERE client_id = ? AND revoked_at IS NULL').bind(clientId).first<OAuthClient>();
}

async function authenticateClient(db: D1Database, clientId: string, clientSecret: string): Promise<OAuthClient | null> {
  const client = await clientFor(db, clientId);
  if (!client) return null;
  if (client.is_confidential) {
    if (!clientSecret || !client.client_secret_hash) return null;
    return constantTimeEqual(await sha256url(clientSecret), client.client_secret_hash) ? client : null;
  }
  // Public clients authenticate with their client_id only; PKCE is mandatory.
  return client;
}

async function importSigningKey(privateJwk: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', JSON.parse(privateJwk) as JsonWebKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

async function signingKey(db: D1Database): Promise<{ kid: string; key: CryptoKey }> {
  const active = await db.prepare('SELECT kid, private_jwk FROM oauth_signing_keys WHERE revoked_at IS NULL ORDER BY created_at DESC LIMIT 1').first<{ kid: string; private_jwk: string }>();
  if (active) return { kid: active.kid, key: await importSigningKey(active.private_jwk) };
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey) as JsonWebKey;
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey) as JsonWebKey;
  const kid = await sha256url(JSON.stringify(publicJwk));
  await db.prepare('INSERT OR IGNORE INTO oauth_signing_keys (kid, public_jwk, private_jwk, created_at) VALUES (?, ?, ?, ?)')
    .bind(kid, JSON.stringify(publicJwk), JSON.stringify(privateJwk), new Date().toISOString()).run();

  // Two requests may generate a key at the same time. `INSERT OR IGNORE`
  // leaves the first row in place, so sign with the key that is actually
  // published instead of the losing in-memory pair. Otherwise the ID token
  // names a `kid` that JWKS does not contain.
  const stored = await db.prepare('SELECT kid, private_jwk FROM oauth_signing_keys WHERE kid = ?')
    .bind(kid).first<{ kid: string; private_jwk: string }>();
  if (!stored) throw new Error('OAuth signing key could not be initialized');
  return { kid: stored.kid, key: await importSigningKey(stored.private_jwk) };
}

async function issueTokens(db: D1Database, client: OAuthClient, user: User, sessionId: string, scope: string, nonce: string | null, withRefresh: boolean): Promise<IssuedTokens> {
  const scopes = scope.split(' ').filter(Boolean);
  // Sign before persisting anything: a signing failure must not leave
  // unusable tokens behind.
  let idToken: string | null = null;
  if (scopes.includes('openid')) {
    const { kid, key } = await signingKey(db);
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const payload: Record<string, unknown> = { iss: ISSUER, sub: user.id, aud: client.client_id, iat: now, exp: now + ACCESS_TOKEN_TTL_SECONDS };
    if (nonce) payload.nonce = nonce;
    const encoded = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(new TextEncoder().encode(JSON.stringify(payload)))}`;
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(encoded));
    idToken = `${encoded}.${b64url(new Uint8Array(signature))}`;
  }

  const accessToken = random();
  const accessHash = await sha256url(accessToken);
  let refreshToken: string | null = null;
  let refreshHash: string | null = null;
  if (withRefresh) {
    refreshToken = random();
    refreshHash = await sha256url(refreshToken);
  }
  const statements = [
    db.prepare('INSERT INTO oauth_access_tokens (token_hash, client_id, user_id, session_id, scope, refresh_token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(accessHash, client.client_id, user.id, sessionId, scope, refreshHash, expiry(ACCESS_TOKEN_TTL_SECONDS * 1000)),
  ];
  if (refreshHash) {
    statements.push(
      db.prepare('INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, session_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(refreshHash, client.client_id, user.id, sessionId, scope, expiry(REFRESH_TOKEN_TTL_SECONDS * 1000)),
    );
  }
  await db.batch(statements);
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
    ...(idToken ? { id_token: idToken } : {}),
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope,
  };
}

async function revokeFamily(db: D1Database, clientId: string, userId: string, sessionId: string): Promise<void> {
  const now = new Date().toISOString();
  await db.batch([
    db.prepare('UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE client_id = ? AND user_id = ? AND session_id = ? AND revoked_at IS NULL').bind(now, clientId, userId, sessionId),
    db.prepare('UPDATE oauth_access_tokens SET revoked_at = ? WHERE client_id = ? AND user_id = ? AND session_id = ? AND revoked_at IS NULL').bind(now, clientId, userId, sessionId),
  ]);
}

type OAuthContext = Context<{ Bindings: Env }>;

function jsonError(c: OAuthContext, status: ContentfulStatusCode, error: string, description?: string): Response {
  c.header('Cache-Control', 'no-store');
  return c.json({ error, ...(description ? { error_description: description } : {}) }, status);
}

export function createOAuthApp(): Hono<{ Bindings: Env }> {
  const oauth = new Hono<{ Bindings: Env }>();
  oauth.use('/.well-known/*', corsAnyOrigin);
  oauth.use('/oauth/jwks', corsAnyOrigin);
  oauth.use('/oauth/token', corsRegisteredOrigins);
  oauth.use('/oauth/userinfo', corsRegisteredOrigins);
  oauth.use('/oauth/revoke', corsRegisteredOrigins);
  oauth.use('/oauth/token', bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'Request too large' }, 413) }));
  oauth.use('/oauth/revoke', bodyLimit({ maxSize: 2048, onError: c => c.json({ error: 'Request too large' }, 413) }));
  oauth.use('/oauth/userinfo', bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'Request too large' }, 413) }));

  const discovery = {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/oauth/jwks`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: SUPPORTED_GRANT_TYPES,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: KNOWN_SCOPES,
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    id_token_encryption_alg_values_supported: [],
    userinfo_signing_alg_values_supported: [],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'preferred_username', 'name', 'email', 'email_verified'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    display_values_supported: ['page'],
  };
  const discoveryHandler = (c: OAuthContext) => {
    c.header('Cache-Control', 'public, max-age=3600');
    return c.json(discovery);
  };
  oauth.get('/.well-known/openid-configuration', discoveryHandler);
  oauth.get('/.well-known/oauth-authorization-server', discoveryHandler);

  oauth.get('/oauth/jwks', async c => {
    const keys = await c.env.DB.prepare('SELECT kid, public_jwk FROM oauth_signing_keys WHERE revoked_at IS NULL ORDER BY created_at DESC').all<{ kid: string; public_jwk: string }>();
    c.header('Cache-Control', 'public, max-age=3600');
    return c.json({ keys: keys.results.map(row => ({ ...JSON.parse(row.public_jwk) as Record<string, unknown>, use: 'sig', alg: 'RS256', kid: row.kid })) });
  });

  oauth.get('/oauth/authorize', async c => {
    const query = new URL(c.req.url).searchParams;
    const clientId = query.get('client_id') ?? '';
    const requestedUri = query.get('redirect_uri') ?? '';
    const responseType = query.get('response_type') ?? '';
    const scopeParam = query.get('scope') ?? '';
    const state = query.get('state') ?? '';
    const nonce = query.get('nonce') ?? '';
    const challenge = query.get('code_challenge') ?? '';
    const challengeMethod = query.get('code_challenge_method') ?? '';

    const invalid = (error: string, description: string) => jsonError(c, 400, error, description);
    const redirectError = (uri: string, error: string, description: string) => {
      const target = new URL(uri);
      target.searchParams.set('error', error);
      target.searchParams.set('error_description', description);
      if (state) target.searchParams.set('state', state);
      return c.redirect(target.toString(), 302);
    };

    if (!clientId) return invalid('invalid_request', 'client_id is required');
    const client = await clientFor(c.env.DB, clientId);
    if (!client) return invalid('invalid_client', 'unknown client_id');
    const registeredUris = parseJsonStringArray(client.redirect_uris);
    let redirectUri: string;
    if (!requestedUri) {
      if (registeredUris.length !== 1) return invalid('invalid_request', 'redirect_uri is required');
      redirectUri = registeredUris[0];
    } else {
      // Exact match only: never redirect to an unregistered URI.
      if (!registeredUris.includes(requestedUri)) return invalid('invalid_request', 'redirect_uri is not registered');
      redirectUri = requestedUri;
    }
    if (responseType !== 'code') return redirectError(redirectUri, 'unsupported_response_type', 'only code is supported');
    if (!parseJsonStringArray(client.grant_types).includes('authorization_code')) return redirectError(redirectUri, 'unauthorized_client', 'authorization_code grant is not allowed for this client');
    const scopes = scopeParam.split(' ').filter(Boolean);
    const allowedScopes = parseJsonStringArray(client.allowed_scopes);
    if (!scopes.includes('openid')) return redirectError(redirectUri, 'invalid_scope', 'openid scope is required');
    if (scopes.some(scope => !KNOWN_SCOPES.includes(scope))) return redirectError(redirectUri, 'invalid_scope', 'unsupported scope');
    if (scopes.some(scope => !allowedScopes.includes(scope))) return redirectError(redirectUri, 'invalid_scope', 'scope not allowed for this client');
    if (!challenge) return redirectError(redirectUri, 'invalid_request', 'code_challenge is required');
    if (challengeMethod !== 'S256') return redirectError(redirectUri, 'invalid_request', 'code_challenge_method must be S256');
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) return redirectError(redirectUri, 'invalid_request', 'invalid code_challenge');
    if (state.length > 1024) return redirectError(redirectUri, 'invalid_request', 'state is too long');
    if (nonce.length > 1024) return redirectError(redirectUri, 'invalid_request', 'nonce is too long');

    if (await rateLimit(c.env.DB, `oauth-authorize:ip:${requestIp(c)}`, 60)) return jsonError(c, 429, 'rate_limited', 'too many requests');

    const sessionToken = getCookie(c, cookieName);
    const user = await sessionUser(c.env.DB, sessionToken);
    if (!user || !sessionToken) return redirectError(redirectUri, 'login_required', 'authentication required');

    const code = random();
    const now = new Date().toISOString();
    await c.env.DB.prepare('DELETE FROM oauth_authorization_codes WHERE expires_at <= ?').bind(now).run();
    await c.env.DB.prepare(`INSERT INTO oauth_authorization_codes
      (code_hash, client_id, user_id, session_id, redirect_uri, code_challenge, code_challenge_method, scope, state, nonce, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 'S256', ?, ?, ?, ?)`)
      .bind(await sha256url(code), client.client_id, user.id, sessionToken, redirectUri, challenge, scopes.join(' '), state || null, nonce || null, expiry(CODE_TTL_SECONDS * 1000)).run();

    const target = new URL(redirectUri);
    target.searchParams.set('code', code);
    if (state) target.searchParams.set('state', state);
    c.header('Cache-Control', 'no-store');
    return c.redirect(target.toString(), 302);
  });

  oauth.post('/oauth/token', async c => {
    const contentType = c.req.header('Content-Type') ?? '';
    if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) return jsonError(c, 400, 'invalid_request', 'expected application/x-www-form-urlencoded');
    let form: URLSearchParams;
    try { form = new URLSearchParams(await c.req.text()); } catch { return jsonError(c, 400, 'invalid_request', 'invalid body'); }
    const grantType = form.get('grant_type') ?? '';
    const basic = basicAuth(c);
    const clientId = form.get('client_id') ?? basic?.clientId ?? '';
    const clientSecret = form.get('client_secret') ?? basic?.secret ?? '';

    if (await rateLimit(c.env.DB, `oauth-token:ip:${requestIp(c)}`, 60)) return jsonError(c, 429, 'rate_limited', 'too many requests');
    const client = await authenticateClient(c.env.DB, clientId, clientSecret);
    if (!client) return jsonError(c, 401, 'invalid_client', 'client authentication failed');
    if (await rateLimit(c.env.DB, `oauth-token:client:${client.client_id}`, 120)) return jsonError(c, 429, 'rate_limited', 'too many requests');
    if (grantType !== 'authorization_code' && grantType !== 'refresh_token') return jsonError(c, 400, 'unsupported_grant_type', 'only authorization_code and refresh_token are supported');
    if (!parseJsonStringArray(client.grant_types).includes(grantType)) return jsonError(c, 400, 'unauthorized_client', 'grant type is not allowed for this client');

    const invalidGrant = () => jsonError(c, 400, 'invalid_grant', 'grant is invalid or expired');
    const now = new Date().toISOString();

    if (grantType === 'authorization_code') {
      const code = form.get('code') ?? '';
      const redirectUri = form.get('redirect_uri') ?? '';
      const verifier = form.get('code_verifier') ?? '';
      if (!code || !redirectUri || !verifier) return invalidGrant();
      const codeHash = await sha256url(code);
      const stored = await c.env.DB.prepare(`SELECT * FROM oauth_authorization_codes
        WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND consumed_at IS NULL AND expires_at > ?`)
        .bind(codeHash, client.client_id, redirectUri, now).first<OAuthCode>();
      if (!stored) return invalidGrant();
      // PKCE: compare the derived challenge, not the verifier.
      if (!constantTimeEqual(await sha256url(verifier), stored.code_challenge)) return invalidGrant();
      // Consume exactly once, even if two exchanges race.
      const consumed = await c.env.DB.prepare('UPDATE oauth_authorization_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL').bind(now, codeHash).run();
      if (consumed.meta.changes !== 1) return invalidGrant();
      const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(stored.user_id).first<User>();
      const session = await c.env.DB.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ? AND expires_at > ?').bind(stored.session_id, stored.user_id, now).first<{ id: string }>();
      if (!user || user.frozen_at || !session) return invalidGrant();
      const tokens = await issueTokens(c.env.DB, client, user, session.id, stored.scope, stored.nonce, stored.scope.split(' ').includes('offline_access'));
      c.header('Cache-Control', 'no-store');
      c.header('Pragma', 'no-cache');
      return c.json(tokens);
    }

    if (grantType === 'refresh_token') {
      const token = form.get('refresh_token') ?? '';
      if (!token) return invalidGrant();
      const tokenHash = await sha256url(token);
      const stored = await c.env.DB.prepare('SELECT * FROM oauth_refresh_tokens WHERE token_hash = ? AND client_id = ?').bind(tokenHash, client.client_id).first<OAuthRefreshToken>();
      if (!stored || stored.expires_at <= now) return invalidGrant();
      if (stored.revoked_at) {
        // Refresh token reuse after rotation: revoke the whole family.
        await revokeFamily(c.env.DB, client.client_id, stored.user_id, stored.session_id);
        return invalidGrant();
      }
      const requested = (form.get('scope') ?? '').split(' ').filter(Boolean);
      if (requested.length) {
        const granted = stored.scope.split(' ');
        if (requested.some(scope => !granted.includes(scope))) return jsonError(c, 400, 'invalid_scope', 'requested scope exceeds granted scope');
      }
      const scope = requested.length ? requested.join(' ') : stored.scope;
      const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(stored.user_id).first<User>();
      const session = await c.env.DB.prepare('SELECT id FROM sessions WHERE id = ? AND user_id = ? AND expires_at > ?').bind(stored.session_id, stored.user_id, now).first<{ id: string }>();
      if (!user || user.frozen_at || !session) return invalidGrant();
      // Rotate: the presented refresh token and its access tokens stop working.
      await c.env.DB.batch([
        c.env.DB.prepare('UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').bind(now, tokenHash),
        c.env.DB.prepare('UPDATE oauth_access_tokens SET revoked_at = ? WHERE refresh_token_hash = ? AND revoked_at IS NULL').bind(now, tokenHash),
      ]);
      const tokens = await issueTokens(c.env.DB, client, user, session.id, scope, null, true);
      c.header('Cache-Control', 'no-store');
      c.header('Pragma', 'no-cache');
      return c.json(tokens);
    }

    return jsonError(c, 400, 'unsupported_grant_type', 'only authorization_code and refresh_token are supported');
  });

  const bearerToken = (c: OAuthContext): string | null => {
    const header = c.req.header('Authorization');
    if (!header || !header.startsWith('Bearer ')) return null;
    const token = header.slice('Bearer '.length).trim();
    return token || null;
  };

  const userinfo = async (c: OAuthContext, token: string | null): Promise<Response> => {
    if (await rateLimit(c.env.DB, `oauth-userinfo:ip:${requestIp(c)}`, 120)) return jsonError(c, 429, 'rate_limited', 'too many requests');
    if (!token) {
      c.header('WWW-Authenticate', 'Bearer');
      return jsonError(c, 401, 'invalid_token', 'missing bearer token');
    }
    const now = new Date().toISOString();
    const row = await c.env.DB.prepare(`SELECT a.*, u.username, u.display_name, u.email
      FROM oauth_access_tokens a JOIN users u ON u.id = a.user_id
      WHERE a.token_hash = ? AND a.revoked_at IS NULL AND a.expires_at > ?`)
      .bind(await sha256url(token), now).first<OAuthRefreshToken & { username: string; display_name: string; email: string | null }>();
    if (!row || row.revoked_at) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return jsonError(c, 401, 'invalid_token', 'token is invalid or expired');
    }
    const client = await clientFor(c.env.DB, row.client_id);
    if (!client) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return jsonError(c, 401, 'invalid_token', 'token client is no longer available');
    }
    const scopes = row.scope.split(' ');
    if (!scopes.includes('openid')) return jsonError(c, 403, 'insufficient_scope', 'openid scope is required');
    const claims: Record<string, unknown> = { sub: row.user_id };
    if (scopes.includes('profile')) {
      claims.preferred_username = row.username;
      claims.name = row.display_name;
    }
    // Email is not verified by this service, so never claim email_verified=true.
    if (scopes.includes('email') && row.email) {
      claims.email = row.email;
      claims.email_verified = false;
    }
    c.header('Cache-Control', 'no-store');
    return c.json(claims);
  };

  oauth.get('/oauth/userinfo', async c => userinfo(c, bearerToken(c)));
  oauth.post('/oauth/userinfo', async c => {
    let body: URLSearchParams | null = null;
    try { body = new URLSearchParams(await c.req.text()); } catch { /* fall through to header */ }
    return userinfo(c, bearerToken(c) ?? body?.get('access_token') ?? null);
  });

  oauth.post('/oauth/revoke', async c => {
    const contentType = c.req.header('Content-Type') ?? '';
    if (!contentType.toLowerCase().includes('application/x-www-form-urlencoded')) return jsonError(c, 400, 'invalid_request', 'expected application/x-www-form-urlencoded');
    let form: URLSearchParams;
    try { form = new URLSearchParams(await c.req.text()); } catch { return jsonError(c, 400, 'invalid_request', 'invalid body'); }
    if (await rateLimit(c.env.DB, `oauth-revoke:ip:${requestIp(c)}`, 60)) return jsonError(c, 429, 'rate_limited', 'too many requests');
    const basic = basicAuth(c);
    const clientId = form.get('client_id') ?? basic?.clientId ?? '';
    const clientSecret = form.get('client_secret') ?? basic?.secret ?? '';
    const client = await authenticateClient(c.env.DB, clientId, clientSecret);
    if (!client) return jsonError(c, 401, 'invalid_client', 'client authentication failed');
    const token = form.get('token') ?? '';
    if (!token) return jsonError(c, 400, 'invalid_request', 'token is required');
    const tokenHash = await sha256url(token);
    const now = new Date().toISOString();
    const refresh = await c.env.DB.prepare('SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash = ? AND client_id = ?').bind(tokenHash, client.client_id).first();
    if (refresh) {
      await c.env.DB.batch([
        c.env.DB.prepare('UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').bind(now, tokenHash),
        c.env.DB.prepare('UPDATE oauth_access_tokens SET revoked_at = ? WHERE refresh_token_hash = ? AND revoked_at IS NULL').bind(now, tokenHash),
      ]);
      return c.json({});
    }
    await c.env.DB.prepare('UPDATE oauth_access_tokens SET revoked_at = ? WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL').bind(now, tokenHash, client.client_id).run();
    // RFC 7009: respond 200 even when the token is unknown.
    return c.json({});
  });

  return oauth;
}

// Redirect URIs must be absolute and fragment-free. HTTP is allowed only for
// loopback development so production clients cannot be tricked into accepting
// insecure redirects.
function isValidRedirectUri(uri: string): boolean {
  if (uri.length === 0 || uri.length > 2048 || uri.includes('#')) return false;
  let parsed: URL;
  try { parsed = new URL(uri); } catch { return false; }
  // Userinfo in a redirect URI is a phishing aid and never needed.
  if (parsed.username || parsed.password) return false;
  if (parsed.protocol === 'http:' && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')) return true;
  return parsed.protocol === 'https:' && parsed.hostname.length > 0;
}

// Trusted Flaxia service-binding administration for OAuth clients and signing
// keys. Only the Flaxia application can reach these routes.
export function createOAuthBridgeApp(): Hono<{ Bindings: Env }> {
  const admin = new Hono<{ Bindings: Env }>();

  admin.post('/api/flaxia/oauth/clients', bodyLimit({ maxSize: 2048 }), async c => {
    c.header('Cache-Control', 'no-store');
    let body: Record<string, unknown>;
    try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
    const redirectUris = body.redirect_uris;
    if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 20 ||
        !redirectUris.every(uri => typeof uri === 'string' && isValidRedirectUri(uri))) return c.json({ error: 'Invalid redirect URI' }, 400);
    const clientId = typeof body.client_id === 'string' && body.client_id ? body.client_id : random();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(clientId)) return c.json({ error: 'Invalid client ID' }, 400);
    const confidential = body.is_confidential === true;
    const clientName = typeof body.client_name === 'string' && body.client_name.length <= 100 ? body.client_name : clientId;
    const allowedScopes = Array.isArray(body.allowed_scopes) && body.allowed_scopes.length > 0 &&
        body.allowed_scopes.every(scope => typeof scope === 'string' && KNOWN_SCOPES.includes(scope))
      ? body.allowed_scopes
      : KNOWN_SCOPES;
    const grantTypes = Array.isArray(body.grant_types) && body.grant_types.length > 0 &&
        body.grant_types.every(grant => typeof grant === 'string' && SUPPORTED_GRANT_TYPES.includes(grant))
      ? body.grant_types
      : SUPPORTED_GRANT_TYPES;
    const secret = confidential ? random() : null;
    const secretHash = secret ? await sha256url(secret) : null;
    try {
      const result = await c.env.DB.prepare(`INSERT INTO oauth_clients
        (client_id, client_secret_hash, client_name, redirect_uris, allowed_scopes, is_confidential, pkce_required, grant_types)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)`)
        .bind(clientId, secretHash, clientName, JSON.stringify(redirectUris), JSON.stringify(allowedScopes), confidential ? 1 : 0, JSON.stringify(grantTypes)).run();
      if (result.meta.changes !== 1) return c.json({ error: 'Client already exists' }, 409);
    } catch { return c.json({ error: 'Client already exists' }, 409); }
    return c.json({
      client_id: clientId,
      ...(secret ? { client_secret: secret } : {}),
      client_name: clientName,
      redirect_uris: redirectUris,
      allowed_scopes: allowedScopes,
      is_confidential: confidential,
      pkce_required: true,
      grant_types: grantTypes,
    }, 201);
  });

  admin.post('/api/flaxia/oauth/clients/revoke', bodyLimit({ maxSize: 512 }), async c => {
    c.header('Cache-Control', 'no-store');
    let body: { client_id?: unknown };
    try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
    if (!body || typeof body.client_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(body.client_id)) return c.json({ error: 'Invalid request' }, 400);
    const now = new Date().toISOString();
    await c.env.DB.batch([
      c.env.DB.prepare('UPDATE oauth_clients SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL').bind(now, body.client_id),
      c.env.DB.prepare('DELETE FROM oauth_authorization_codes WHERE client_id = ?').bind(body.client_id),
      c.env.DB.prepare('DELETE FROM oauth_access_tokens WHERE client_id = ?').bind(body.client_id),
      c.env.DB.prepare('DELETE FROM oauth_refresh_tokens WHERE client_id = ?').bind(body.client_id),
    ]);
    return c.json({ success: true });
  });

  admin.post('/api/flaxia/oauth/keys/rotate', bodyLimit({ maxSize: 512 }), async c => {
    c.header('Cache-Control', 'no-store');
    const pair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey) as JsonWebKey;
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey) as JsonWebKey;
    const kid = await sha256url(JSON.stringify(publicJwk));
    await c.env.DB.prepare('INSERT OR IGNORE INTO oauth_signing_keys (kid, public_jwk, private_jwk, created_at) VALUES (?, ?, ?, ?)')
      .bind(kid, JSON.stringify(publicJwk), JSON.stringify(privateJwk), new Date().toISOString()).run();
    return c.json({ kid });
  });

  admin.post('/api/flaxia/oauth/keys/revoke', bodyLimit({ maxSize: 512 }), async c => {
    c.header('Cache-Control', 'no-store');
    let body: { kid?: unknown };
    try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
    if (!body || typeof body.kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(body.kid)) return c.json({ error: 'Invalid request' }, 400);
    const result = await c.env.DB.prepare('UPDATE oauth_signing_keys SET revoked_at = ? WHERE kid = ? AND revoked_at IS NULL').bind(new Date().toISOString(), body.kid).run();
    return result.meta.changes === 1 ? c.json({ success: true }) : c.json({ error: 'Key not found' }, 404);
  });

  return admin;
}
