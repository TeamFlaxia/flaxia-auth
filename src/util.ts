// Shared primitives for the Auth Worker and the OAuth/OIDC provider.
// Kept free of request handling so both modules can use them.

export const enc = (data: Uint8Array) => btoa(String.fromCharCode(...data));
export const dec = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
export const random = () => enc(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
export const sha256url = async (value: string) => enc(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
export const expiry = (ms: number) => new Date(Date.now() + ms).toISOString();

export async function rateLimit(db: D1Database, key: string, limit: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const result = await db.prepare(`INSERT INTO auth_rate_limits (key, window_start, attempts) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET attempts = CASE WHEN window_start <= ? - 60 THEN 1 ELSE attempts + 1 END,
    window_start = CASE WHEN window_start <= ? - 60 THEN ? ELSE window_start END RETURNING attempts`)
    .bind(key, now, now, now, now).first<{ attempts: number }>();
  return !result || result.attempts > limit;
}

export function requestIp(c: { req: { header(name: string): string | undefined } }): string {
  const value = c.req.header('CF-Connecting-IP') ?? 'unknown';
  return value.length <= 64 && /^[0-9a-fA-F:.]+$/.test(value) ? value : 'invalid';
}

// Constant-time comparison of two strings. Used for secret and PKCE checks
// where the values are already hashes, so length is not a secret.
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
