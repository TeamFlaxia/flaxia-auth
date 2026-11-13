// CORS for the OAuth / OIDC endpoints.
//
// The authorization endpoint is a top-level navigation and needs no CORS.
// The token, UserInfo and revocation endpoints are called directly by public
// browser clients, so their origins are limited to the origins of the
// redirect URIs registered for a live client. Discovery and JWKS are public
// documents and may be read from any origin.
import type { Context, Next } from 'hono';

type OAuthContext = Context<{ Bindings: Env }>;

const FIRST_PARTY_ORIGIN = 'https://flaxia.app';

/** Origins of the redirect URIs of every live OAuth client. */
export async function registeredClientOrigins(db: D1Database): Promise<Set<string>> {
  const origins = new Set<string>([FIRST_PARTY_ORIGIN]);
  const rows = await db
    .prepare('SELECT redirect_uris FROM oauth_clients WHERE revoked_at IS NULL')
    .all<{ redirect_uris: string }>();
  for (const row of rows.results ?? []) {
    let uris: unknown;
    try {
      uris = JSON.parse(row.redirect_uris);
    } catch {
      continue;
    }
    if (!Array.isArray(uris)) continue;
    for (const uri of uris) {
      if (typeof uri !== 'string') continue;
      try {
        origins.add(new URL(uri).origin);
      } catch {
        // A malformed registered URI simply contributes no origin.
      }
    }
  }
  return origins;
}

function applyRegisteredHeaders(c: OAuthContext, origin: string): void {
  c.header('Access-Control-Allow-Origin', origin);
  c.header('Vary', 'Origin');
  c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  c.header('Access-Control-Max-Age', '600');
}

/**
 * CORS for endpoints called by browser clients. Only an origin that belongs
 * to a registered redirect URI is reflected; credentials are not allowed
 * because none of these endpoints use cookies.
 */
export async function corsRegisteredOrigins(c: OAuthContext, next: Next): Promise<Response | void> {
  const origin = c.req.header('Origin');
  if (!origin) {
    await next();
    return;
  }

  // Always vary on Origin so a shared cache cannot serve one client's CORS
  // decision to another.
  c.header('Vary', 'Origin');
  const allowed = (await registeredClientOrigins(c.env.DB)).has(origin);
  if (c.req.method === 'OPTIONS') {
    if (allowed) applyRegisteredHeaders(c, origin);
    return c.body(null, 204);
  }
  await next();
  if (allowed) applyRegisteredHeaders(c, origin);
}

/** CORS for public discovery/JWKS documents. */
export async function corsAnyOrigin(c: OAuthContext, next: Next): Promise<Response | void> {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type');
  c.header('Access-Control-Max-Age', '600');
  if (c.req.method === 'OPTIONS') return c.body(null, 204);
  await next();
}
