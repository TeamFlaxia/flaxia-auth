import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';
import { isCreatableSrpKdf, isSupportedSrpKdf, serverStep1, serverStep2 } from './srp';

const app = new Hono<{ Bindings: Env }>();
const enc = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const dec = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const random = () => enc(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const expiry = (ms: number) => new Date(Date.now() + ms).toISOString();
const cookieName = '__Host-flaxia_session';
const cookieOptions = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/' };
const originAllowed = (origin: string | undefined) => origin === 'https://id.flaxia.app' || origin === 'https://flaxia.app';

type User = { id: string; username: string; email: string | null; srp_salt: string | null; srp_verifier: string | null; srp_kdf: string | null; frozen_at: string | null };
app.get('/health', c => c.json({ service: 'flaxia-auth', status: 'ok' }));

app.use('/api/auth/*', cors({ origin: origin => originAllowed(origin) ? origin : '', credentials: true, allowMethods: ['GET', 'POST', 'OPTIONS'], allowHeaders: ['Content-Type'] }));
app.use('/api/auth/*', bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'Request too large' }, 413) }));
app.use('/api/auth/*', async (c, next) => {
  c.header('Cache-Control', 'no-store');
  if (c.req.method !== 'GET' && !originAllowed(c.req.header('Origin'))) return c.json({ error: 'Invalid origin' }, 403);
  const ip = c.req.header('CF-Connecting-IP');
  if (!ip) return c.json({ error: 'Authentication unavailable' }, 503);
  const key = `${c.req.path}:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const result = await c.env.DB.prepare(`INSERT INTO auth_rate_limits (key, window_start, attempts) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET attempts = CASE WHEN window_start <= ? - 60 THEN 1 ELSE attempts + 1 END,
    window_start = CASE WHEN window_start <= ? - 60 THEN ? ELSE window_start END RETURNING attempts`)
    .bind(key, now, now, now, now).first<{ attempts: number }>();
  if (!result || result.attempts > 20) return c.json({ error: 'Too many requests' }, 429);
  await next();
});

app.post('/api/auth/register', async c => {
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  const { username, email, srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if ('password' in body || typeof username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(username) || (email != null && (typeof email !== 'string' || email.trim().length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()))) || typeof salt !== 'string' || typeof verifier !== 'string' || salt.length > 32 || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf)) return c.json({ error: 'Invalid registration' }, 400);
  try {
    const v = dec(verifier);
    if (dec(salt).length !== 16 || v.length !== 256 || v.every(x => x === 0)) return c.json({ error: 'Invalid registration' }, 400);
  } catch { return c.json({ error: 'Invalid registration' }, 400); }
  try {
    await c.env.DB.prepare('INSERT INTO users (id, username, email, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(random(), username, typeof email === 'string' ? email.trim().toLowerCase() : null, salt, verifier, group, kdf).run();
  } catch { return c.json({ error: 'Registration failed' }, 409); }
  return c.json({ ok: true }, 201);
});

app.post('/api/auth/login/start', async c => {
  let body: { username?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  if (typeof body.username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(body.username)) return c.json({ error: 'Invalid credentials' }, 400);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').bind(body.username).first<User>();
  if (!user?.srp_salt || !user.srp_verifier || user.frozen_at || !isSupportedSrpKdf(user.srp_kdf ?? 'sha256-v1')) return c.json({ error: 'Invalid credentials' }, 401);
  const { B, b } = await serverStep1(dec(user.srp_salt), dec(user.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at) VALUES (?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000)).run();
  return c.json({ challenge_id: challenge, salt: user.srp_salt, B: enc(B), srp_kdf: user.srp_kdf ?? 'sha256-v1' });
});

app.post('/api/auth/login/verify', async c => {
  let body: { challenge_id?: unknown; A?: unknown; M1?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  if (typeof body.challenge_id !== 'string' || body.challenge_id.length > 64 || typeof body.A !== 'string' || body.A.length > 400 || typeof body.M1 !== 'string' || body.M1.length > 64) return c.json({ error: 'Invalid request' }, 400);
  const hs = await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE id = ? AND expires_at > ? RETURNING user_id, b_scalar, b_pub').bind(body.challenge_id, new Date().toISOString()).first<{ user_id: string; b_scalar: string; b_pub: string }>();
  if (!hs) return c.json({ error: 'Invalid credentials' }, 401);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ? AND frozen_at IS NULL').bind(hs.user_id).first<User>();
  if (!user?.srp_verifier) return c.json({ error: 'Invalid credentials' }, 401);
  try {
    const A = dec(body.A), M1 = dec(body.M1);
    if (A.length !== 256 || M1.length !== 32) return c.json({ error: 'Invalid credentials' }, 401);
    const proof = await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(user.srp_verifier), M1);
    if (!proof) return c.json({ error: 'Invalid credentials' }, 401);
    const token = random();
    await c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiry(7 * 86400000)).run();
    setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
    return c.json({ M2: enc(proof.M2), user: { id: user.id, username: user.username, email: user.email } });
  } catch { return c.json({ error: 'Invalid credentials' }, 401); }
});

app.get('/api/auth/me', async c => {
  const token = getCookie(c, cookieName);
  if (!token) return c.json({ error: 'Unauthenticated' }, 401);
  const user = await c.env.DB.prepare('SELECT u.id, u.username, u.email FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > ? AND u.frozen_at IS NULL').bind(token, new Date().toISOString()).first();
  return user ? c.json({ user }) : c.json({ error: 'Unauthenticated' }, 401);
});
app.post('/api/auth/logout', async c => {
  const token = getCookie(c, cookieName);
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
  deleteCookie(c, cookieName, cookieOptions);
  return c.json({ ok: true });
});

export default app;
