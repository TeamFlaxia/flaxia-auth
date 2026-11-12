// The OAuth connection routes.
//
// Two rules shape everything here:
//
//   1. Auth never holds a token. A browser-reachable provider exchanges the
//      code itself and encrypts the result into the Vault. For a provider
//      that refuses cross-origin calls, Auth performs the exchange and seals
//      the result to a client public key, so the plaintext exists in memory
//      for one request and is never stored.
//
//   2. The callback carries no credential. It carries the authorization code
//      and the state, both of which are single-use and short-lived.

import { getCookie } from 'hono/cookie';
import { getProvider } from './registry.ts';
import { hashState, isValidCodeVerifier, isValidState, newTransaction, transactionExpired, transactionFromRow } from './flow.ts';
import { parseConnectionMetadata } from './store.ts';
import { sealTo } from './seal.ts';

export interface ConnectionEnv {
  DB: D1Database;
  [key: string]: unknown;
}

export interface ConnectionContext {
  env: ConnectionEnv;
  req: { header(name: string): string | undefined; url: string; method: string; json(): Promise<unknown> };
  cookie: (name: string) => string | undefined;
  json: (body: unknown, status?: number) => Response;
  redirect: (location: string) => Response;
  rateLimit: (key: string, limit: number) => Promise<boolean>;
  sessionUser: (token: string | undefined) => Promise<{ id: string } | null>;
  random: () => string;
}

const AUTH_ORIGIN = 'https://auth.flaxia.app';
const CALLBACK_PATH = '/api/connections';
/** Where the browser returns after an authorization. */
const RETURN_URIS = [
  'https://flaxia.app/settings/connections',
  'http://localhost:3000/settings/connections',
  'http://localhost:8787/settings/connections',
  'http://localhost:8788/settings/connections',
] as const;

const returnUriAllowed = (value: unknown): value is string =>
  typeof value === 'string' && (RETURN_URIS as readonly string[]).includes(value);

const providerId = (value: string | undefined): string | null => {
  if (!value) return null;
  const provider = getProvider(value);
  return provider ? provider.id : null;
};

const callbackUri = (provider: string): string => `${AUTH_ORIGIN}${CALLBACK_PATH}/${provider}/callback`;

/** The PKCE challenge for a verifier, base64url without padding. */
const codeChallenge = async (verifier: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
};

const clientIdFor = (env: ConnectionEnv, providerId: string): string | null => {
  const provider = getProvider(providerId);
  if (!provider) return null;
  if (provider.publicClientId) return provider.publicClientId;
  if (!provider.clientIdEnv) return null;
  const value = (env as Record<string, unknown>)[provider.clientIdEnv];
  return typeof value === 'string' && value.length > 0 ? value : null;
};

/**
 * Handle `POST /api/connections/:provider/start`.
 *
 * The browser sends the PKCE challenge and the state it generated. Auth
 * records their hashes and answers with the provider authorization URL.
 */
export async function handleStart(ctx: ConnectionContext, providerParam: string | undefined): Promise<Response> {
  const provider = providerId(providerParam);
  if (!provider) return ctx.json({ error: 'Unknown provider' }, 404);
  const session = ctx.cookie('__Host-flaxia_session');
  const user = await ctx.sessionUser(session);
  if (!user || !session) return ctx.json({ error: 'Unauthenticated' }, 401);
  if (await ctx.rateLimit(`oauth-start:user:${user.id}`, 20)) return ctx.json({ error: 'Too many requests' }, 429);

  let body: { state?: unknown; code_challenge?: unknown; return_uri?: unknown };
  try {
    const parsed = await ctx.req.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return ctx.json({ error: 'Invalid request' }, 400);
    body = parsed as { state?: unknown; code_challenge?: unknown; return_uri?: unknown };
  } catch {
    return ctx.json({ error: 'Invalid request' }, 400);
  }
  const { state, code_challenge: challenge } = body;
  if (!isValidState(state)) return ctx.json({ error: 'Invalid request' }, 400);
  if (typeof challenge !== 'string' || challenge.length < 43 || challenge.length > 128) {
    return ctx.json({ error: 'Invalid request' }, 400);
  }
  const returnUri = body.return_uri === undefined ? RETURN_URIS[0] : body.return_uri;
  if (!returnUriAllowed(returnUri)) return ctx.json({ error: 'Invalid return URI' }, 400);

  const clientId = clientIdFor(ctx.env, provider);
  if (!clientId) return ctx.json({ error: 'Provider is not configured' }, 503);

  const transaction = await newTransaction({
    userId: user.id,
    provider,
    state,
    redirectUri: callbackUri(provider),
    returnUri,
  });
  const now = new Date().toISOString();
  await ctx.env.DB.prepare('DELETE FROM oauth_transactions WHERE expires_at <= ?').bind(now).run();
  await ctx.env.DB.prepare(
    `INSERT INTO oauth_transactions (id, user_id, provider, state_hash, code_verifier_hash, redirect_uri, return_uri, expires_at)
     VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`,
  )
    .bind(transaction.id, user.id, provider, transaction.state_hash, transaction.redirect_uri, transaction.return_uri, transaction.expires_at)
    .run();

  const definition = getProvider(provider)!;
  const url = new URL(definition.authorizeUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', transaction.redirect_uri);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('scope', definition.scopes.join(' '));
  for (const [key, value] of Object.entries(definition.extraAuthParams ?? {})) {
    url.searchParams.set(key, value);
  }
  return ctx.json({ authorize_url: url.toString(), transaction_id: transaction.id });
}

/**
 * Handle `GET /api/connections/:provider/callback`.
 *
 * The state is matched against the stored transaction, which is consumed
 * exactly once. A mismatch, an expiry or a replay all fail the same way.
 */
export async function handleCallback(ctx: ConnectionContext, providerParam: string | undefined, query: URLSearchParams): Promise<Response> {
  const provider = providerId(providerParam);
  if (!provider) return ctx.json({ error: 'Unknown provider' }, 404);
  const state = query.get('state');
  const code = query.get('code');
  if (!isValidState(state)) return ctx.json({ error: 'Invalid state' }, 400);

  const now = new Date().toISOString();
  const row = await ctx.env.DB.prepare(
    `SELECT id, user_id, provider, state_hash, code_verifier_hash, redirect_uri, return_uri, expires_at, consumed_at
     FROM oauth_transactions WHERE state_hash = ? LIMIT 1`,
  ).bind(await hashState(state)).first();
  const transaction = transactionFromRow(row);
  if (!transaction || transaction.provider !== provider) return ctx.json({ error: 'Invalid state' }, 400);
  if (transaction.consumed_at !== null || transactionExpired(transaction, now)) {
    return ctx.json({ error: 'Invalid state' }, 400);
  }
  // Consume the transaction atomically. A second callback with the same state
  // finds nothing to consume and fails.
  const consumed = await ctx.env.DB.prepare(
    `UPDATE oauth_transactions SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
  ).bind(now, transaction.id, now).run();
  if (consumed.meta.changes !== 1) return ctx.json({ error: 'Invalid state' }, 400);

  const error = query.get('error');
  const returnUri = transaction.return_uri ?? RETURN_URIS[0];
  if (error) {
    const target = new URL(returnUri);
    target.searchParams.set('oauth_error', error.slice(0, 64));
    return ctx.redirect(target.toString());
  }
  if (!code || code.length > 512) {
    const target = new URL(returnUri);
    target.searchParams.set('oauth_error', 'missing_code');
    return ctx.redirect(target.toString());
  }
  // The code and the transaction id travel back to the browser, which
  // performs the exchange. No credential is involved.
  const target = new URL(returnUri);
  target.searchParams.set('oauth_code', code);
  target.searchParams.set('oauth_state', state);
  target.searchParams.set('oauth_provider', provider);
  target.searchParams.set('oauth_transaction', transaction.id);
  return ctx.redirect(target.toString());
}

/**
 * Handle `GET /api/connections`.
 *
 * The list carries metadata only. The token lives in the Vault as an
 * encrypted item, so nothing here is a credential.
 */
export async function handleList(ctx: ConnectionContext): Promise<Response> {
  const session = ctx.cookie('__Host-flaxia_session');
  const user = await ctx.sessionUser(session);
  if (!user || !session) return ctx.json({ error: 'Unauthenticated' }, 401);
  const rows = await ctx.env.DB.prepare(
    `SELECT id, provider, provider_sub, scopes, status, vault_item_id, expires_at, refresh_expires_at, last_used_at, revoked_at, created_at, updated_at
     FROM oauth_connections WHERE user_id = ? ORDER BY created_at`,
  ).bind(user.id).all();
  const connections = (rows.results ?? [])
    .map(parseConnectionMetadata)
    .filter((row): row is NonNullable<typeof row> => row !== null);
  return ctx.json({ connections });
}

/**
 * Handle `POST /api/connections/:provider/exchange`.
 *
 * Only for a provider whose token endpoint refuses a browser request. Auth
 * performs the exchange and seals the result to the client's public key, so
 * the token is never stored in a form Auth could read again.
 */
export async function handleExchange(ctx: ConnectionContext, providerParam: string | undefined, body: Record<string, unknown>): Promise<Response> {
  const provider = providerId(providerParam);
  if (!provider) return ctx.json({ error: 'Unknown provider' }, 404);
  const definition = getProvider(provider)!;
  if (definition.mode !== 'server_exchange') return ctx.json({ error: 'Provider is not server-exchanged' }, 400);
  const session = ctx.cookie('__Host-flaxia_session');
  const user = await ctx.sessionUser(session);
  if (!user || !session) return ctx.json({ error: 'Unauthenticated' }, 401);
  if (await ctx.rateLimit(`oauth-exchange:user:${user.id}`, 20)) return ctx.json({ error: 'Too many requests' }, 429);

  const code = body.code;
  const clientPublicKey = body.client_public_key;
  if (typeof code !== 'string' || code.length === 0 || code.length > 512) {
    return ctx.json({ error: 'Invalid request' }, 400);
  }
  if (typeof clientPublicKey !== 'string' || clientPublicKey.length === 0) {
    return ctx.json({ error: 'Invalid request' }, 400);
  }
  const clientId = clientIdFor(ctx.env, provider);
  if (!clientId) return ctx.json({ error: 'Provider is not configured' }, 503);

  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    redirect_uri: callbackUri(provider),
  });
  const verifier = body.code_verifier;
  if (isValidCodeVerifier(verifier)) params.set('code_verifier', verifier);
  const clientSecret = definition.clientSecretEnv
    ? (ctx.env as Record<string, unknown>)[definition.clientSecretEnv]
    : undefined;
  if (typeof clientSecret === 'string' && clientSecret.length > 0) params.set('client_secret', clientSecret);

  let response: Response;
  try {
    response = await fetch(definition.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
  } catch {
    return ctx.json({ error: 'Provider is unreachable' }, 502);
  }
  const text = await response.text();
  if (!response.ok) return ctx.json({ error: 'Provider rejected the exchange' }, 502);
  let token: unknown;
  try { token = JSON.parse(text); } catch { return ctx.json({ error: 'Provider returned an invalid response' }, 502); }
  if (!token || typeof token !== 'object') return ctx.json({ error: 'Provider returned an invalid response' }, 502);

  let sealed: Awaited<ReturnType<typeof sealTo>>;
  try {
    sealed = await sealTo(new TextEncoder().encode(text), clientPublicKey);
  } catch {
    return ctx.json({ error: 'Invalid client public key' }, 400);
  }
  return ctx.json({ sealed });
}

/**
 * Handle `POST /api/connections/:provider/complete`.
 *
 * The browser encrypted the token with its Vault key and stored it as an
 * `oauth_connection` item. Auth records the metadata and links the item. The
 * payload is never sent here.
 */
export async function handleComplete(ctx: ConnectionContext, providerParam: string | undefined, body: Record<string, unknown>): Promise<Response> {
  const provider = providerId(providerParam);
  if (!provider) return ctx.json({ error: 'Unknown provider' }, 404);
  const session = ctx.cookie('__Host-flaxia_session');
  const user = await ctx.sessionUser(session);
  if (!user || !session) return ctx.json({ error: 'Unauthenticated' }, 401);
  if (await ctx.rateLimit(`oauth-complete:user:${user.id}`, 20)) return ctx.json({ error: 'Too many requests' }, 429);

  const vaultItemId = body.vault_item_id;
  if (typeof vaultItemId !== 'string' || vaultItemId.length === 0 || vaultItemId.length > 64) {
    return ctx.json({ error: 'Invalid request' }, 400);
  }
  const providerSub = body.provider_sub;
  const scopes = Array.isArray(body.scopes) ? body.scopes : [];
  const definition = getProvider(provider)!;
  const allowed = new Set(definition.scopes);
  const requested = scopes.filter((scope): scope is string =>
    typeof scope === 'string' && allowed.has(scope));
  const now = new Date().toISOString();
  const id = `conn_${ctx.random().replace(/[^A-Za-z0-9]/g, '').slice(0, 32).padEnd(20, '0')}`;
  await ctx.env.DB.prepare(
    `INSERT INTO oauth_connections (id, user_id, provider, provider_sub, scopes, status, vault_item_id, expires_at, refresh_expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, provider) DO UPDATE SET
       id = excluded.id,
       provider_sub = excluded.provider_sub,
       scopes = excluded.scopes,
       status = 'active',
       vault_item_id = excluded.vault_item_id,
       expires_at = excluded.expires_at,
       refresh_expires_at = excluded.refresh_expires_at,
       revoked_at = NULL,
       updated_at = excluded.updated_at`,
  )
    .bind(
      id,
      user.id,
      provider,
      typeof providerSub === 'string' && providerSub.length > 0 ? providerSub.slice(0, 512) : null,
      JSON.stringify(requested),
      vaultItemId,
      typeof body.expires_at === 'string' ? body.expires_at.slice(0, 40) : null,
      typeof body.refresh_expires_at === 'string' ? body.refresh_expires_at.slice(0, 40) : null,
      now,
      now,
    )
    .run();
  return ctx.json({ success: true });
}

/**
 * Handle `DELETE /api/connections/:provider`.
 *
 * The Vault item is deleted by the browser, because only the browser can
 * produce a valid deletion. Auth drops the metadata so the connection no
 * longer appears.
 */
export async function handleDelete(ctx: ConnectionContext, providerParam: string | undefined): Promise<Response> {
  const provider = providerId(providerParam);
  if (!provider) return ctx.json({ error: 'Unknown provider' }, 404);
  const session = ctx.cookie('__Host-flaxia_session');
  const user = await ctx.sessionUser(session);
  if (!user || !session) return ctx.json({ error: 'Unauthenticated' }, 401);
  const now = new Date().toISOString();
  await ctx.env.DB.prepare(
    `UPDATE oauth_connections SET status = 'revoked', revoked_at = ?, updated_at = ? WHERE user_id = ? AND provider = ?`,
  ).bind(now, now, user.id, provider).run();
  await ctx.env.DB.prepare('DELETE FROM oauth_transactions WHERE user_id = ? AND provider = ?').bind(user.id, provider).run();
  return ctx.json({ success: true });
}
