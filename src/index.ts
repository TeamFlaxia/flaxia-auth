import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';
import { computeVerifier, generateSalt, isCreatableSrpKdf, isSupportedSrpKdf, isValidVerifier, serverStep1, serverStep2 } from './srp';
import { originAllowed } from './origin';

const app = new Hono<{ Bindings: Env }>();
const enc = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const dec = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const validCredentials = (salt: string, verifier: string): boolean => {
  try {
    const s = dec(salt), v = dec(verifier);
    return s.length === 16 && enc(s) === salt && enc(v) === verifier && isValidVerifier(v);
  } catch { return false; }
};
const random = () => enc(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const expiry = (ms: number) => new Date(Date.now() + ms).toISOString();
const cookieName = '__Host-flaxia_session';
const cookieOptions = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/' };

type User = { id: string; username: string; display_name: string; password_hash: string; srp_salt: string | null; srp_verifier: string | null; srp_kdf: string | null; frozen_at: string | null };
type Handshake = { user_id: string; b_scalar: string; b_pub: string };
type SrpProof = { challenge_id?: unknown; A?: unknown; M1?: unknown };

async function rateLimit(db: D1Database, key: string, limit: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const result = await db.prepare(`INSERT INTO auth_rate_limits (key, window_start, attempts) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET attempts = CASE WHEN window_start <= ? - 60 THEN 1 ELSE attempts + 1 END,
    window_start = CASE WHEN window_start <= ? - 60 THEN ? ELSE window_start END RETURNING attempts`)
    .bind(key, now, now, now, now).first<{ attempts: number }>();
  return !result || result.attempts > limit;
}

async function verifyLegacyPassword(password: string, stored: string): Promise<boolean> {
  let combined: Uint8Array;
  try { combined = dec(stored); } catch { return false; }
  if (combined.length !== 48 || enc(combined) !== stored) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const actual = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: combined.slice(0, 16) as BufferSource, iterations: 100_000 }, key, 256));
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= actual[i] ^ combined[i + 16];
  return difference === 0;
}

async function sessionUser(db: D1Database, token: string | undefined): Promise<User | null> {
  if (!token) return null;
  return db.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > ? AND u.frozen_at IS NULL').bind(token, new Date().toISOString()).first<User>();
}

async function verifyProof(db: D1Database, user: User, input: unknown): Promise<boolean> {
  if (!input || typeof input !== 'object') return false;
  const proof = input as SrpProof;
  if (typeof proof.challenge_id !== 'string' || proof.challenge_id.length > 64 || typeof proof.A !== 'string' || proof.A.length > 400 || typeof proof.M1 !== 'string' || proof.M1.length > 64 || !user.srp_verifier) return false;
  const hs = await db.prepare('DELETE FROM srp_handshakes WHERE id = ? AND user_id = ? AND expires_at > ? RETURNING user_id, b_scalar, b_pub').bind(proof.challenge_id, user.id, new Date().toISOString()).first<Handshake>();
  if (!hs) return false;
  try {
    const A = dec(proof.A), M1 = dec(proof.M1);
    return A.length === 256 && M1.length === 32 && !!(await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(user.srp_verifier), M1));
  } catch { return false; }
}
app.get('/health', c => c.json({ service: 'flaxia-auth', status: 'ok' }));

app.use('/api/auth/*', cors({ origin: origin => originAllowed(origin) ? origin : '', credentials: true, allowMethods: ['GET', 'POST', 'OPTIONS'], allowHeaders: ['Content-Type'] }));
app.use('/api/auth/*', bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'Request too large' }, 413) }));
app.use('/api/auth/*', async (c, next) => {
  c.header('Cache-Control', 'no-store');
  if (c.req.method !== 'GET' && !originAllowed(c.req.header('Origin'))) return c.json({ error: 'Invalid origin' }, 403);
  const ip = c.req.header('CF-Connecting-IP');
  if (!ip) return c.json({ error: 'Authentication unavailable' }, 503);
  if (await rateLimit(c.env.DB, `${c.req.path}:ip:${ip}`, 20)) return c.json({ error: 'Too many requests' }, 429);
  await next();
});

app.post('/api/auth/register', async c => {
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  const { username, srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if (body.display_name !== undefined && (typeof body.display_name !== 'string' || body.display_name.length === 0 || body.display_name.length > 50)) return c.json({ error: 'Invalid display name' }, 400);
  if ('password' in body || typeof username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(username) || typeof salt !== 'string' || typeof verifier !== 'string' || salt.length > 32 || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf)) return c.json({ error: 'Invalid registration' }, 400);
  if (!validCredentials(salt, verifier)) return c.json({ error: 'Invalid registration' }, 400);
  try {
    const user = { id: random(), username, display_name: typeof body.display_name === 'string' ? body.display_name : username };
    const token = random();
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO users (id, username, display_name, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(user.id, username, user.display_name, salt, verifier, group, kdf),
      c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiry(7 * 86400000)),
    ]);
    setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
    return c.json({ user }, 201);
  } catch { return c.json({ error: 'Registration failed' }, 409); }
});

// This temporary endpoint accepts a password only for pre-SRP accounts.
// Successful verification immediately replaces the old hash with an SRP verifier.
app.post('/api/auth/login/legacy', async c => {
  let body: { username?: unknown; password?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(body.username) || typeof body.password !== 'string' || body.password.length === 0 || body.password.length > 1024) return c.json({ error: 'Invalid request' }, 400);
  if (await rateLimit(c.env.DB, `legacy-login:user:${body.username.toLowerCase()}`, 5)) return c.json({ error: 'Too many requests' }, 429);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').bind(body.username).first<User>();
  if (!user || user.srp_salt !== null || user.srp_verifier !== null || !user.password_hash || !await verifyLegacyPassword(body.password, user.password_hash)) return c.json({ error: 'Invalid credentials' }, 401);
  if (user.frozen_at) return c.json({ error: 'account_frozen', username: user.username }, 403);
  const salt = generateSalt();
  const verifier = await computeVerifier(body.password, salt, 'pbkdf2-600k-v2');
  const updated = await c.env.DB.prepare("UPDATE users SET srp_salt = ?, srp_verifier = ?, srp_group = '2048', srp_kdf = 'pbkdf2-600k-v2', password_hash = '' WHERE id = ? AND password_hash = ? AND srp_salt IS NULL AND srp_verifier IS NULL AND frozen_at IS NULL RETURNING id, username, display_name")
    .bind(enc(salt), enc(verifier), user.id, user.password_hash).first<{ id: string; username: string; display_name: string }>();
  if (!updated) return c.json({ error: 'Invalid credentials' }, 401);
  const token = random();
  await c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(token, updated.id, expiry(7 * 86400000)).run();
  setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
  return c.json({ user: updated });
});

app.post('/api/auth/login/start', async c => {
  let body: { username?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  const byUsername = typeof body.username === 'string' && /^[a-zA-Z0-9_]{1,20}$/.test(body.username);
  if (!byUsername) return c.json({ error: 'Invalid credentials' }, 400);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').bind(body.username).first<User>();
  if (user && user.srp_salt === null && user.srp_verifier === null && user.password_hash) return c.json({ srp: false });
  if (!user?.srp_salt || !user.srp_verifier || !isSupportedSrpKdf(user.srp_kdf ?? 'sha256-v1')) return c.json({ error: 'Invalid credentials' }, 401);
  if (await rateLimit(c.env.DB, `login-start:user:${user.id}`, 5)) return c.json({ error: 'Too many requests' }, 429);
  const { B, b } = await serverStep1(dec(user.srp_salt), dec(user.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at) VALUES (?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000)).run();
  return c.json({ srp: true, challenge_id: challenge, salt: user.srp_salt, B: enc(B), srp_kdf: user.srp_kdf ?? 'sha256-v1' });
});

app.post('/api/auth/login/verify', async c => {
  let body: { challenge_id?: unknown; A?: unknown; M1?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  if (typeof body.challenge_id !== 'string' || body.challenge_id.length > 64 || typeof body.A !== 'string' || body.A.length > 400 || typeof body.M1 !== 'string' || body.M1.length > 64) return c.json({ error: 'Invalid request' }, 400);
  const hs = await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE id = ? AND expires_at > ? RETURNING user_id, b_scalar, b_pub').bind(body.challenge_id, new Date().toISOString()).first<{ user_id: string; b_scalar: string; b_pub: string }>();
  if (!hs) return c.json({ error: 'Invalid credentials' }, 401);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(hs.user_id).first<User>();
  if (!user?.srp_verifier) return c.json({ error: 'Invalid credentials' }, 401);
  try {
    const A = dec(body.A), M1 = dec(body.M1);
    if (A.length !== 256 || M1.length !== 32) return c.json({ error: 'Invalid credentials' }, 401);
    const proof = await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(user.srp_verifier), M1);
    if (!proof) return c.json({ error: 'Invalid credentials' }, 401);
    if (user.frozen_at) return c.json({ error: 'account_frozen', username: user.username, M2: enc(proof.M2) }, 403);
    const token = random();
    await c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiry(7 * 86400000)).run();
    setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
    return c.json({ M2: enc(proof.M2), user: { id: user.id, username: user.username, display_name: user.display_name } });
  } catch { return c.json({ error: 'Invalid credentials' }, 401); }
});

app.get('/api/auth/me', async c => {
  const token = getCookie(c, cookieName);
  if (!token) return c.json({ error: 'Unauthenticated' }, 401);
  const user = await c.env.DB.prepare('SELECT u.id, u.username, u.display_name FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > ? AND u.frozen_at IS NULL').bind(token, new Date().toISOString()).first();
  return user ? c.json({ user }) : c.json({ error: 'Unauthenticated' }, 401);
});

app.post('/api/auth/reauth/start', async c => {
  const user = await sessionUser(c.env.DB, getCookie(c, cookieName));
  if (!user) return c.json({ error: 'Unauthenticated' }, 401);
  if (await rateLimit(c.env.DB, `reauth-start:user:${user.id}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  if (!user.srp_salt || !user.srp_verifier || !isSupportedSrpKdf(user.srp_kdf ?? 'sha256-v1')) return c.json({ error: 'SRP not available' }, 400);
  const { B, b } = await serverStep1(dec(user.srp_salt), dec(user.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at) VALUES (?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000)).run();
  return c.json({ challenge_id: challenge, salt: user.srp_salt, B: enc(B), srp_kdf: user.srp_kdf ?? 'sha256-v1' });
});

app.post('/api/auth/reauth/verify', async c => {
  const user = await sessionUser(c.env.DB, getCookie(c, cookieName));
  if (!user) return c.json({ error: 'Unauthenticated' }, 401);
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  return c.json({ valid: await verifyProof(c.env.DB, user, body) });
});

app.post('/api/auth/upgrade-srp', async c => {
  const user = await sessionUser(c.env.DB, getCookie(c, cookieName));
  if (!user) return c.json({ error: 'Unauthenticated' }, 401);
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || !body.current_srp) return c.json({ error: 'Current password proof is required' }, 400);
  const { srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if (typeof salt !== 'string' || salt.length > 32 || typeof verifier !== 'string' || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf)) return c.json({ error: 'Invalid SRP parameters' }, 400);
  if (!validCredentials(salt, verifier)) return c.json({ error: 'Invalid SRP parameters' }, 400);
  if (!await verifyProof(c.env.DB, user, body.current_srp)) return c.json({ error: 'Current password is incorrect' }, 401);
  const updated = await c.env.DB.prepare('UPDATE users SET srp_salt = ?, srp_verifier = ?, srp_group = ?, srp_kdf = ?, password_hash = ? WHERE id = ? AND srp_verifier = ? AND srp_salt = ?').bind(salt, verifier, group, kdf, '', user.id, user.srp_verifier, user.srp_salt).run();
  if (!updated.meta.changes) return c.json({ error: 'Credentials changed' }, 409);
  return c.json({ success: true });
});
app.post('/api/auth/logout', async c => {
  const token = getCookie(c, cookieName);
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
  deleteCookie(c, cookieName, cookieOptions);
  return c.json({ success: true });
});

export default app;
