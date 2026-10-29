import { Hono } from 'hono';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { bodyLimit } from 'hono/body-limit';
import { computeVerifier, generateSalt, isCreatableSrpKdf, isSupportedSrpKdf, isValidVerifier, serverStep1, serverStep2 } from './srp';
import { originAllowed } from './origin';

const app = new Hono<{ Bindings: Env }>();
const bridge = new Hono<{ Bindings: Env }>();
const enc = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const dec = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const validCredentials = (salt: string, verifier: string): boolean => {
  try {
    const s = dec(salt), v = dec(verifier);
    return s.length === 16 && enc(s) === salt && enc(v) === verifier && isValidVerifier(v);
  } catch { return false; }
};
const random = () => enc(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const sha256url = async (value: string) => enc(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const expiry = (ms: number) => new Date(Date.now() + ms).toISOString();
const cookieName = '__Host-flaxia_session';
const cookieOptions = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/' };

type User = { id: string; username: string; display_name: string; password_hash: string; srp_salt: string | null; srp_verifier: string | null; srp_group: string | null; srp_kdf: string | null; frozen_at: string | null };
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

function requestIp(c: { req: { header(name: string): string | undefined } }): string {
  const value = c.req.header('CF-Connecting-IP') ?? 'unknown';
  return value.length <= 64 && /^[0-9a-fA-F:.]+$/.test(value) ? value : 'invalid';
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

async function verifyProof(db: D1Database, user: User, input: unknown, purpose: 'session-reauth' | 'grant-reauth', binding: string): Promise<boolean> {
  if (!input || typeof input !== 'object') return false;
  const proof = input as SrpProof;
  if (typeof proof.challenge_id !== 'string' || proof.challenge_id.length > 64 || typeof proof.A !== 'string' || proof.A.length > 400 || typeof proof.M1 !== 'string' || proof.M1.length > 64 || !user.srp_verifier) return false;
  const hs = await db.prepare('DELETE FROM srp_handshakes WHERE id = ? AND user_id = ? AND purpose = ? AND binding_hash = ? AND expires_at > ? RETURNING user_id, b_scalar, b_pub').bind(proof.challenge_id, user.id, purpose, await sha256url(binding), new Date().toISOString()).first<Handshake>();
  if (!hs) return false;
  try {
    const A = dec(proof.A), M1 = dec(proof.M1);
    return A.length === 256 && M1.length === 32 && !!(await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(user.srp_verifier), M1));
  } catch { return false; }
}
app.get('/health', c => c.json({ service: 'flaxia-auth', status: 'ok' }));

async function credentialStamp(db: D1Database, userId: string): Promise<string | null> {
  const user = await db.prepare('SELECT srp_salt, srp_verifier, srp_group, srp_kdf FROM users WHERE id = ? AND frozen_at IS NULL').bind(userId).first<User>();
  if (!user?.srp_salt || !user.srp_verifier || !user.srp_group) return null;
  return sha256url(JSON.stringify([user.srp_salt, user.srp_verifier, user.srp_group, user.srp_kdf ?? 'sha256-v1']));
}

async function userForGrant(db: D1Database, grant: unknown): Promise<User | null> {
  if (typeof grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(grant)) return null;
  return db.prepare(`SELECT u.* FROM flaxia_session_grants g
    JOIN sessions s ON s.id = g.session_id AND s.user_id = g.user_id
    JOIN users u ON u.id = g.user_id
    WHERE g.token_hash = ? AND s.expires_at > ? AND u.frozen_at IS NULL`).bind(await sha256url(grant), new Date().toISOString()).first<User>();
}

// A one-time code is bound to a client-generated verifier, so intercepting it
// alone cannot create a Flaxia session.
bridge.get('/health', c => c.json({ status: 'ok' }));
// The caller is the trusted Flaxia service binding. Repeating a request is
// safe after a timeout; a conflicting identity is never modified or linked.
bridge.post('/api/flaxia/provision', bodyLimit({ maxSize: 2048 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  const { user_id: id, username, display_name: display, srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id) ||
      typeof username !== 'string' || !/^[A-Za-z0-9_]{1,20}$/.test(username) ||
      typeof display !== 'string' || display.length < 1 || display.length > 50 ||
      typeof salt !== 'string' || typeof verifier !== 'string' || salt.length > 32 || verifier.length > 400 ||
      group !== '2048' || !isCreatableSrpKdf(kdf) || !validCredentials(salt, verifier)) return c.json({ error: 'Invalid request' }, 400);
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT OR IGNORE INTO users (id, username, display_name, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, username, display, salt, verifier, group, kdf),
    c.env.DB.prepare(`INSERT OR IGNORE INTO flaxia_credential_guards (user_id)
      SELECT id FROM users WHERE id = ? AND username = ? COLLATE BINARY AND display_name = ? AND srp_salt = ? AND srp_verifier = ? AND srp_group = ? AND srp_kdf = ? AND frozen_at IS NULL`).bind(id, username, display, salt, verifier, group, kdf),
  ]);
  const matches = await c.env.DB.prepare(`SELECT 1 AS ok FROM users u JOIN flaxia_credential_guards g ON g.user_id = u.id
    WHERE u.id = ? AND u.username = ? COLLATE BINARY AND u.display_name = ? AND u.srp_salt = ? AND u.srp_verifier = ? AND u.srp_group = ? AND u.srp_kdf = ? AND u.frozen_at IS NULL`).bind(id, username, display, salt, verifier, group, kdf).first();
  return matches ? c.json({ success: true }) : c.json({ error: 'Identity conflict' }, 409);
});
bridge.post('/api/flaxia/exchange', bodyLimit({ maxSize: 1024 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { code?: unknown; verifier?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || typeof body.code !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.code) || typeof body.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.verifier)) return c.json({ error: 'Invalid request' }, 400);
  const codeHash = await sha256url(body.code);
  const challenge = await sha256url(body.verifier);
  const now = new Date().toISOString();
  const grant = random();
  const grantHash = await sha256url(grant);
  const result = await c.env.DB.batch([
    c.env.DB.prepare(`INSERT INTO flaxia_session_grants (token_hash, session_id, user_id)
      SELECT ?, c.session_id, c.user_id FROM flaxia_authorization_codes c
      JOIN sessions s ON s.id = c.session_id AND s.user_id = c.user_id
      JOIN users u ON u.id = c.user_id
      WHERE c.code_hash = ? AND c.challenge = ? AND c.expires_at > ? AND s.expires_at > ? AND u.frozen_at IS NULL
        AND COALESCE(u.srp_salt, '') <> '' AND COALESCE(u.srp_verifier, '') <> '' AND COALESCE(u.srp_group, '') <> ''`)
      .bind(grantHash, codeHash, challenge, now, now),
    c.env.DB.prepare('INSERT OR IGNORE INTO flaxia_credential_guards (user_id) SELECT user_id FROM flaxia_session_grants WHERE token_hash = ?').bind(grantHash),
    c.env.DB.prepare('DELETE FROM flaxia_authorization_codes WHERE code_hash = ? AND challenge = ?').bind(codeHash, challenge),
  ]);
  if (result[0].meta.changes !== 1) return c.json({ error: 'Invalid authorization' }, 401);
  const user = await c.env.DB.prepare('SELECT g.user_id, u.username, u.display_name, u.email FROM flaxia_session_grants g JOIN users u ON u.id = g.user_id WHERE g.token_hash = ?').bind(grantHash).first<{ user_id: string; username: string; display_name: string; email: string | null }>();
  if (!user) return c.json({ error: 'Invalid authorization' }, 401);
  const stamp = await credentialStamp(c.env.DB, user.user_id);
  if (!stamp) {
    await c.env.DB.prepare('DELETE FROM flaxia_session_grants WHERE token_hash = ?').bind(grantHash).run();
    return c.json({ error: 'Invalid authorization' }, 401);
  }
  const legacy = await c.env.DB.prepare('SELECT fingerprint FROM flaxia_legacy_fingerprints WHERE user_id = ? AND expires_at > ?').bind(user.user_id, new Date().toISOString()).first<{ fingerprint: string }>();
  return c.json({ user_id: user.user_id, username: user.username, display_name: user.display_name, email: user.email, grant, credential_stamp: stamp, legacy_stamp: legacy?.fingerprint ?? null });
});

bridge.post('/api/flaxia/introspect', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant)) return c.json({ error: 'Invalid request' }, 400);
  const hash = await sha256url(body.grant);
  const user = await c.env.DB.prepare(`SELECT g.user_id, s.expires_at FROM flaxia_session_grants g
    JOIN sessions s ON s.id = g.session_id AND s.user_id = g.user_id
    JOIN users u ON u.id = g.user_id
    WHERE g.token_hash = ? AND s.expires_at > ? AND u.frozen_at IS NULL`).bind(hash, new Date().toISOString()).first<{ user_id: string; expires_at: string }>();
  if (!user) return c.json({ error: 'Invalid authorization' }, 401);
  const stamp = await credentialStamp(c.env.DB, user.user_id);
  return stamp ? c.json({ user_id: user.user_id, expires_at: user.expires_at, credential_stamp: stamp }) : c.json({ error: 'Invalid authorization' }, 401);
});

// Once the consumer durably links the Auth ID, its legacy credential
// fingerprint is no longer needed and is removed immediately.
bridge.post('/api/flaxia/link-complete', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  await c.env.DB.prepare('DELETE FROM flaxia_legacy_fingerprints WHERE user_id = ?').bind(user.id).run();
  return c.json({ success: true });
});

// Revokes only this application's grant; other grants and the Auth session
// remain available. Deleting an already-revoked grant is idempotent.
bridge.post('/api/flaxia/revoke', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant)) return c.json({ error: 'Invalid request' }, 400);
  await c.env.DB.prepare('DELETE FROM flaxia_session_grants WHERE token_hash = ?').bind(await sha256url(body.grant)).run();
  return c.json({ success: true });
});

bridge.post('/api/flaxia/revoke-user', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.user_id !== 'string' || body.user_id.length < 1 || body.user_id.length > 128) return c.json({ error: 'Invalid request' }, 400);
  await c.env.DB.prepare('DELETE FROM flaxia_session_grants WHERE user_id = ?').bind(body.user_id).run();
  return c.json({ success: true });
});

bridge.post('/api/flaxia/credentials/prepare', bodyLimit({ maxSize: 4096 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return c.json({ error: 'Invalid request' }, 400);
  const { operation, grant, user_id: userId, srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if (typeof operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(operation) || typeof grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(grant) || typeof userId !== 'string' || userId.length < 1 || userId.length > 128 || typeof salt !== 'string' || typeof verifier !== 'string' || salt.length > 32 || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf) || !validCredentials(salt, verifier)) return c.json({ error: 'Invalid request' }, 400);
  const operationHash = await sha256url(operation), grantHash = await sha256url(grant);
  const target = await sha256url(JSON.stringify([salt, verifier, group, kdf]));
  const prior = await c.env.DB.prepare('SELECT user_id, grant_hash, target_stamp, state FROM flaxia_credential_changes WHERE operation_hash = ?').bind(operationHash).first<{ user_id: string; grant_hash: string; target_stamp: string; state: string }>();
  if (prior) return prior.state !== 'cancelled' && prior.user_id === userId && prior.grant_hash === grantHash && prior.target_stamp === target ? c.json({ success: true, target_stamp: target }) : c.json({ error: 'Operation conflict' }, 409);
  const user = await userForGrant(c.env.DB, grant);
  if (!user || user.id !== userId || !user.srp_verifier || !user.srp_salt) return c.json({ error: 'Invalid authorization' }, 401);
  const proof = body.current_srp as SrpProof | null;
  if (!proof || typeof proof.challenge_id !== 'string' || proof.challenge_id.length > 64 || typeof proof.A !== 'string' || proof.A.length > 400 || typeof proof.M1 !== 'string' || proof.M1.length > 64) return c.json({ error: 'Invalid proof' }, 400);
  const now = new Date().toISOString();
  const recovery = body.recovery === true;
  const factor = recovery ? await c.env.DB.prepare('SELECT srp_salt, srp_verifier FROM auth_recovery_factors WHERE user_id = ?').bind(user.id).first<{ srp_salt: string; srp_verifier: string }>() : null;
  if (recovery && !factor) return c.json({ error: 'Invalid proof' }, 401);
  const purpose = recovery ? 'grant-recovery' : 'grant-reauth';
  const hs = await c.env.DB.prepare('SELECT user_id, b_scalar, b_pub FROM srp_handshakes WHERE id = ? AND user_id = ? AND purpose = ? AND binding_hash = ? AND expires_at > ?').bind(proof.challenge_id, user.id, purpose, grantHash, now).first<Handshake>();
  if (!hs) return c.json({ error: 'Invalid proof' }, 401);
  try {
    const A = dec(proof.A), M1 = dec(proof.M1);
    if (A.length !== 256 || M1.length !== 32 || !await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(factor?.srp_verifier ?? user.srp_verifier), M1)) return c.json({ error: 'Invalid proof' }, 401);
  } catch { return c.json({ error: 'Invalid proof' }, 401); }
  try {
    const result = await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM srp_handshakes WHERE id = ? AND user_id = ? AND purpose = ? AND binding_hash = ? AND expires_at > ?').bind(proof.challenge_id, user.id, purpose, grantHash, now),
      c.env.DB.prepare(`INSERT INTO flaxia_credential_changes (operation_hash, user_id, grant_hash, expected_salt, expected_verifier, new_salt, new_verifier, new_group, new_kdf, target_stamp, state, recovery_token)
        SELECT ?, u.id, ?, u.srp_salt, u.srp_verifier, ?, ?, ?, ?, ?, 'prepared', ? FROM users u
        JOIN flaxia_session_grants g ON g.user_id = u.id JOIN sessions s ON s.id = g.session_id AND s.user_id = u.id
        WHERE changes() = 1 AND u.id = ? AND u.frozen_at IS NULL AND u.srp_salt = ? AND u.srp_verifier = ? AND g.token_hash = ? AND s.expires_at > ?
          AND (? = 0 OR EXISTS (SELECT 1 FROM auth_recovery_factors f WHERE f.user_id = u.id AND f.srp_salt = ? AND f.srp_verifier = ?))`)
        .bind(operationHash, grantHash, salt, verifier, group, kdf, target, body.recoverable === true ? operation : null, user.id, user.srp_salt, user.srp_verifier, grantHash, now, recovery ? 1 : 0, factor?.srp_salt ?? null, factor?.srp_verifier ?? null),
    ]);
    if (result[0].meta.changes !== 1 || result[1].meta.changes !== 1) return c.json({ error: 'Credentials or session changed' }, 409);
    return c.json({ success: true, target_stamp: target });
  } catch { return c.json({ error: 'Credential change already pending' }, 409); }
});

bridge.post('/api/flaxia/credentials/commit', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation) || typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant) || typeof body.user_id !== 'string' || body.user_id.length < 1 || body.user_id.length > 128) return c.json({ error: 'Invalid request' }, 400);
  const operationHash = await sha256url(body.operation), grantHash = await sha256url(body.grant);
  const caller = await userForGrant(c.env.DB, body.grant);
  if (!caller || caller.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const job = await c.env.DB.prepare('SELECT * FROM flaxia_credential_changes WHERE operation_hash = ? AND user_id = ?').bind(operationHash, body.user_id).first<{ user_id: string; state: string; expected_salt: string | null; expected_verifier: string | null; new_salt: string | null; new_verifier: string | null; new_group: string | null; new_kdf: string | null; target_stamp: string }>();
  if (!job) return c.json({ error: 'Operation not found' }, 404);
  if (job.state === 'committed') return c.json({ success: true, target_stamp: job.target_stamp });
  const result = await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET srp_salt = ?, srp_verifier = ?, srp_group = ?, srp_kdf = ?, password_hash = ? WHERE id = ? AND frozen_at IS NULL AND srp_salt = ? AND srp_verifier = ? AND EXISTS (SELECT 1 FROM flaxia_credential_changes WHERE operation_hash = ? AND state = 'prepared' AND target_stamp = ?) AND EXISTS (SELECT 1 FROM flaxia_session_grants g JOIN sessions s ON s.id = g.session_id AND s.user_id = g.user_id WHERE g.token_hash = ? AND g.user_id = users.id AND s.expires_at > ?)")
      .bind(job.new_salt, job.new_verifier, job.new_group, job.new_kdf, '', job.user_id, job.expected_salt, job.expected_verifier, operationHash, job.target_stamp, grantHash, new Date().toISOString()),
    c.env.DB.prepare("UPDATE flaxia_credential_changes SET state = 'committed', expected_salt = NULL, expected_verifier = NULL, new_salt = NULL, new_verifier = NULL, new_group = NULL, new_kdf = NULL WHERE operation_hash = ? AND state = 'prepared' AND changes() = 1").bind(operationHash),
    c.env.DB.prepare("DELETE FROM flaxia_legacy_fingerprints WHERE user_id = ? AND EXISTS (SELECT 1 FROM flaxia_credential_changes WHERE operation_hash = ? AND state = 'committed')").bind(job.user_id, operationHash),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id != COALESCE((SELECT session_id FROM flaxia_session_grants WHERE token_hash = ?), '') AND EXISTS (SELECT 1 FROM flaxia_credential_changes WHERE operation_hash = ? AND state = 'committed')").bind(job.user_id, grantHash, operationHash),
  ]);
  if (result[1].meta.changes !== 1) return c.json({ error: 'Credentials changed' }, 409);
  return c.json({ success: true, target_stamp: job.target_stamp });
});

// A retry can establish whether a timed-out prepare reached Auth without
// storing verifiers or a session grant in the consuming application's DB.
bridge.post('/api/flaxia/credentials/status', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation) || typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant) || typeof body.user_id !== 'string') return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const operationHash = await sha256url(body.operation);
  const job = await c.env.DB.prepare('SELECT state, target_stamp FROM flaxia_credential_changes WHERE operation_hash = ? AND user_id = ?').bind(operationHash, user.id).first<{ state: string; target_stamp: string }>();
  return job ? c.json(job) : c.json({ error: 'Operation not found' }, 404);
});

bridge.post('/api/flaxia/credentials/pending', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const job = await c.env.DB.prepare("SELECT recovery_token FROM flaxia_credential_changes WHERE user_id = ? AND state IN ('prepared', 'committed') AND recovery_token IS NOT NULL").bind(user.id).first<{ recovery_token: string }>();
  return c.json({ operation: job?.recovery_token ?? null });
});

bridge.post('/api/flaxia/credentials/ack', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation)) return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const hash = await sha256url(body.operation);
  const result = await c.env.DB.prepare("UPDATE flaxia_credential_changes SET recovery_token = NULL WHERE operation_hash = ? AND user_id = ? AND state = 'committed'").bind(hash, user.id).run();
  return result.meta.changes === 1 ? c.json({ success: true }) : c.json({ error: 'Operation not found' }, 404);
});

bridge.post('/api/flaxia/credentials/cancel', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation) || typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant) || typeof body.user_id !== 'string' || body.user_id.length < 1 || body.user_id.length > 128) return c.json({ error: 'Invalid request' }, 400);
  const operationHash = await sha256url(body.operation), grantHash = await sha256url(body.grant);
  const caller = await userForGrant(c.env.DB, body.grant);
  if (!caller || caller.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  await c.env.DB.batch([
    c.env.DB.prepare("INSERT OR IGNORE INTO flaxia_credential_changes (operation_hash, user_id, grant_hash, target_stamp, state) SELECT ?, id, ?, '', 'cancelled' FROM users WHERE id = ?").bind(operationHash, grantHash, body.user_id),
    c.env.DB.prepare("UPDATE flaxia_credential_changes SET state = 'cancelled', recovery_token = NULL, expected_salt = NULL, expected_verifier = NULL, new_salt = NULL, new_verifier = NULL, new_group = NULL, new_kdf = NULL WHERE operation_hash = ? AND user_id = ? AND state = 'prepared'").bind(operationHash, body.user_id),
  ]);
  const remaining = await c.env.DB.prepare('SELECT state, grant_hash, user_id FROM flaxia_credential_changes WHERE operation_hash = ?').bind(operationHash).first<{ state: string; grant_hash: string; user_id: string }>();
  return remaining?.state === 'cancelled' && remaining.user_id === body.user_id ? c.json({ success: true }) : c.json({ error: 'Operation cannot be cancelled' }, 409);
});

// The app can abandon a stale, not-yet-applied operation using its hash.
// This tombstone prevents an original delayed prepare from arriving later.
bridge.post('/api/flaxia/credentials/cancel-hash', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash) || typeof body.grant !== 'string') return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const grantHash = await sha256url(body.grant);
  await c.env.DB.batch([
    c.env.DB.prepare("INSERT OR IGNORE INTO flaxia_credential_changes (operation_hash, user_id, grant_hash, target_stamp, state) VALUES (?, ?, ?, '', 'cancelled')").bind(body.operation_hash, user.id, grantHash),
    c.env.DB.prepare("UPDATE flaxia_credential_changes SET state = 'cancelled', recovery_token = NULL, expected_salt = NULL, expected_verifier = NULL, new_salt = NULL, new_verifier = NULL, new_group = NULL, new_kdf = NULL WHERE operation_hash = ? AND user_id = ? AND state = 'prepared'").bind(body.operation_hash, user.id),
  ]);
  const job = await c.env.DB.prepare('SELECT state FROM flaxia_credential_changes WHERE operation_hash = ? AND user_id = ?').bind(body.operation_hash, user.id).first<{ state: string }>();
  return job?.state === 'cancelled' ? c.json({ success: true }) : c.json({ error: 'Operation cannot be cancelled' }, 409);
});

bridge.post('/api/flaxia/email/change', bodyLimit({ maxSize: 2048 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown; email?: unknown; current_srp?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash) || typeof body.grant !== 'string' || typeof body.email !== 'string' || body.email.length > 254 || body.email !== body.email.trim().toLowerCase() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const targetHash = await sha256url(body.email);
  const prior = await c.env.DB.prepare('SELECT user_id, target_hash, state FROM flaxia_email_changes WHERE operation_hash = ?').bind(body.operation_hash).first<{ user_id: string; target_hash: string; state: string }>();
  if (prior) return prior.user_id === user.id && prior.state === 'committed' && prior.target_hash === targetHash ? c.json({ success: true }) : c.json({ error: 'Operation conflict' }, 409);
  if (!await verifyProof(c.env.DB, user, body.current_srp, 'grant-reauth', body.grant)) return c.json({ error: 'Current password is incorrect' }, 401);
  const grantHash = await sha256url(body.grant);
  try {
    const result = await c.env.DB.batch([
      c.env.DB.prepare("UPDATE users SET email = ? WHERE id = ? AND frozen_at IS NULL AND srp_salt IS ? AND srp_verifier IS ? AND NOT EXISTS (SELECT 1 FROM flaxia_email_changes WHERE operation_hash = ?) AND EXISTS (SELECT 1 FROM flaxia_session_grants g JOIN sessions s ON s.id = g.session_id AND s.user_id = g.user_id WHERE g.token_hash = ? AND g.user_id = users.id AND s.expires_at > ?)").bind(body.email, user.id, user.srp_salt, user.srp_verifier, body.operation_hash, grantHash, new Date().toISOString()),
      c.env.DB.prepare("INSERT INTO flaxia_email_changes (operation_hash, user_id, target_hash, state) SELECT ?, ?, ?, 'committed' WHERE changes() = 1").bind(body.operation_hash, user.id, targetHash),
    ]);
    return result[1].meta.changes === 1 ? c.json({ success: true }) : c.json({ error: 'Operation conflict' }, 409);
  } catch { return c.json({ error: 'Email already in use' }, 409); }
});

bridge.post('/api/flaxia/email/status', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash)) return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const job = await c.env.DB.prepare('SELECT state, target_hash FROM flaxia_email_changes WHERE operation_hash = ? AND user_id = ?').bind(body.operation_hash, user.id).first<{ state: string; target_hash: string }>();
  return job ? c.json(job) : c.json({ error: 'Operation not found' }, 404);
});

bridge.post('/api/flaxia/email/cancel', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash)) return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  await c.env.DB.prepare("INSERT OR IGNORE INTO flaxia_email_changes (operation_hash, user_id, target_hash, state, expires_at) VALUES (?, ?, '', 'cancelled', ?)").bind(body.operation_hash, user.id, expiry(86400000)).run();
  const job = await c.env.DB.prepare('SELECT state FROM flaxia_email_changes WHERE operation_hash = ? AND user_id = ?').bind(body.operation_hash, user.id).first<{ state: string }>();
  return job?.state === 'cancelled' ? c.json({ success: true }) : c.json({ error: 'Operation already committed' }, 409);
});

bridge.post('/api/flaxia/email/ack', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash)) return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  await c.env.DB.prepare("DELETE FROM flaxia_email_changes WHERE operation_hash = ? AND user_id = ? AND state = 'committed'").bind(body.operation_hash, user.id).run();
  return c.json({ success: true });
});

// An opaque operation token makes a completed deletion safely retryable after
// a lost response. Receipts contain hashes and do not reference deleted users.
bridge.post('/api/flaxia/delete', bodyLimit({ maxSize: 2048 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation?: unknown; grant?: unknown; user_id?: unknown; current_srp?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation) ||
      typeof body.grant !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.grant) ||
      typeof body.user_id !== 'string' || body.user_id.length < 1 || body.user_id.length > 128) return c.json({ error: 'Invalid request' }, 400);
  const operationHash = await sha256url(body.operation);
  const grantHash = await sha256url(body.grant);
  const userHash = await sha256url(body.user_id);
  const receipt = await c.env.DB.prepare('SELECT user_hash, grant_hash FROM flaxia_deletion_receipts WHERE operation_hash = ?').bind(operationHash).first<{ user_hash: string; grant_hash: string }>();
  if (receipt) return receipt.user_hash === userHash && receipt.grant_hash === grantHash ? c.json({ success: true }) : c.json({ error: 'Operation conflict' }, 409);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const proof = body.current_srp as SrpProof | null;
  if (!proof || typeof proof.challenge_id !== 'string' || proof.challenge_id.length > 64 || typeof proof.A !== 'string' || proof.A.length > 400 || typeof proof.M1 !== 'string' || proof.M1.length > 64 || !user.srp_verifier) return c.json({ error: 'Current password is incorrect' }, 401);
  const now = new Date().toISOString();
  const bindingHash = await sha256url(body.grant);
  const handshake = await c.env.DB.prepare("SELECT user_id, b_scalar, b_pub FROM srp_handshakes WHERE id = ? AND user_id = ? AND purpose = 'grant-reauth' AND binding_hash = ? AND expires_at > ?").bind(proof.challenge_id, user.id, bindingHash, now).first<Handshake>();
  if (!handshake) return c.json({ error: 'Current password is incorrect' }, 401);
  try {
    const A = dec(proof.A), M1 = dec(proof.M1);
    if (A.length !== 256 || M1.length !== 32 || !await serverStep2(A, dec(handshake.b_pub), BigInt(handshake.b_scalar), dec(user.srp_verifier), M1)) return c.json({ error: 'Current password is incorrect' }, 401);
  } catch { return c.json({ error: 'Current password is incorrect' }, 401); }
  const result = await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM srp_handshakes WHERE id = ? AND user_id = ? AND purpose = 'grant-reauth' AND binding_hash = ? AND expires_at > ?").bind(proof.challenge_id, user.id, bindingHash, now),
    c.env.DB.prepare(`INSERT OR IGNORE INTO flaxia_deletion_receipts (operation_hash, user_hash, grant_hash, created_at)
      SELECT ?, ?, ?, ? FROM users u JOIN flaxia_session_grants g ON g.user_id = u.id
      JOIN sessions s ON s.id = g.session_id AND s.user_id = u.id
      WHERE changes() = 1 AND u.id = ? AND u.frozen_at IS NULL AND u.srp_salt = ? AND u.srp_verifier = ? AND g.token_hash = ? AND s.expires_at > ?
        AND NOT EXISTS (SELECT 1 FROM flaxia_credential_changes p WHERE p.user_id = u.id AND p.state = 'prepared')
        AND NOT EXISTS (SELECT 1 FROM flaxia_deletion_cancellations d WHERE d.operation_hash = ?)`)
      .bind(operationHash, userHash, grantHash, now, user.id, user.srp_salt, user.srp_verifier, grantHash, now, operationHash),
    c.env.DB.prepare('DELETE FROM users WHERE id = ? AND changes() = 1').bind(user.id),
  ]);
  if (result[0].meta.changes !== 1 || result[1].meta.changes !== 1 || result[2].meta.changes < 1) return c.json({ error: 'Credentials or session changed' }, 409);
  return c.json({ success: true });
});

bridge.post('/api/flaxia/delete/cancel-hash', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash) || typeof body.grant !== 'string') return c.json({ error: 'Invalid request' }, 400);
  const user = await userForGrant(c.env.DB, body.grant);
  if (!user || user.id !== body.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const userHash = await sha256url(user.id);
  await c.env.DB.prepare('INSERT OR IGNORE INTO flaxia_deletion_cancellations (operation_hash, user_hash, expires_at) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM flaxia_deletion_receipts WHERE operation_hash = ?)').bind(body.operation_hash, userHash, expiry(86400000), body.operation_hash).run();
  const row = await c.env.DB.prepare('SELECT user_hash FROM flaxia_deletion_cancellations WHERE operation_hash = ?').bind(body.operation_hash).first<{ user_hash: string }>();
  return row?.user_hash === userHash ? c.json({ success: true }) : c.json({ error: 'Deletion already completed' }, 409);
});

// Service-only query lets Flaxia finish deleting app data after Auth deleted
// the account and revoked its grant, without storing that grant in Flaxia D1.
bridge.post('/api/flaxia/delete/status', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { operation_hash?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.operation_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.operation_hash) || typeof body.user_id !== 'string' || body.user_id.length < 1 || body.user_id.length > 128) return c.json({ error: 'Invalid request' }, 400);
  const receipt = await c.env.DB.prepare('SELECT user_hash FROM flaxia_deletion_receipts WHERE operation_hash = ?').bind(body.operation_hash).first<{ user_hash: string }>();
  return c.json({ deleted: !!receipt && receipt.user_hash === await sha256url(body.user_id) });
});

bridge.post('/api/flaxia/reauth/start', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  if (await rateLimit(c.env.DB, `flaxia-reauth:user:${user.id}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  if (!user.srp_salt || !user.srp_verifier || !isSupportedSrpKdf(user.srp_kdf ?? 'sha256-v1')) return c.json({ error: 'SRP not available' }, 400);
  const { B, b } = await serverStep1(dec(user.srp_salt), dec(user.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at, purpose, binding_hash) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000), 'grant-reauth', await sha256url(body.grant as string)).run();
  return c.json({ challenge_id: challenge, salt: user.srp_salt, B: enc(B), srp_kdf: user.srp_kdf ?? 'sha256-v1' });
});

bridge.post('/api/flaxia/recovery/enroll', bodyLimit({ maxSize: 4096 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown; salt?: unknown; verifier?: unknown; kdf?: unknown; current_srp?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id || typeof body.grant !== 'string') return c.json({ error: 'Invalid authorization' }, 401);
  if (typeof body.salt !== 'string' || typeof body.verifier !== 'string' || !isCreatableSrpKdf(body.kdf) || !validCredentials(body.salt, body.verifier)) return c.json({ error: 'Invalid recovery verifier' }, 400);
  if (!await verifyProof(c.env.DB, user, body.current_srp, 'grant-reauth', body.grant)) return c.json({ error: 'Current password is incorrect' }, 401);
  const grantHash = await sha256url(body.grant);
  const result = await c.env.DB.batch([
    c.env.DB.prepare(`INSERT INTO auth_recovery_factors (user_id, srp_salt, srp_verifier, srp_kdf)
    SELECT u.id, ?, ?, ? FROM users u JOIN flaxia_session_grants g ON g.user_id = u.id JOIN sessions s ON s.id = g.session_id AND s.user_id = u.id
    WHERE u.id = ? AND u.frozen_at IS NULL AND u.srp_salt IS ? AND u.srp_verifier IS ? AND g.token_hash = ? AND s.expires_at > ?
    ON CONFLICT(user_id) DO UPDATE SET srp_salt = excluded.srp_salt, srp_verifier = excluded.srp_verifier, srp_kdf = excluded.srp_kdf`)
    .bind(body.salt, body.verifier, body.kdf, user.id, user.srp_salt, user.srp_verifier, grantHash, new Date().toISOString()),
    c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id != COALESCE((SELECT session_id FROM flaxia_session_grants WHERE token_hash = ?), '') AND changes() = 1").bind(user.id, grantHash),
    c.env.DB.prepare("DELETE FROM srp_handshakes WHERE user_id = ? AND purpose IN ('recovery-login', 'grant-recovery') AND EXISTS (SELECT 1 FROM auth_recovery_factors WHERE user_id = ? AND srp_salt = ? AND srp_verifier = ?)").bind(user.id, user.id, body.salt, body.verifier),
  ]);
  return result[0].meta.changes === 1 ? c.json({ success: true }) : c.json({ error: 'Credentials or session changed' }, 409);
});

bridge.post('/api/flaxia/recovery/status', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  const factor = await c.env.DB.prepare('SELECT 1 FROM auth_recovery_factors WHERE user_id = ?').bind(user.id).first();
  return c.json({ enrolled: !!factor });
});

bridge.post('/api/flaxia/recovery/reauth/start', bodyLimit({ maxSize: 512 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id || typeof body.grant !== 'string') return c.json({ error: 'Invalid authorization' }, 401);
  if (await rateLimit(c.env.DB, `flaxia-recovery:user:${user.id}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  const factor = await c.env.DB.prepare('SELECT srp_salt, srp_verifier, srp_kdf FROM auth_recovery_factors WHERE user_id = ?').bind(user.id).first<{ srp_salt: string; srp_verifier: string; srp_kdf: string }>();
  if (!factor || !isSupportedSrpKdf(factor.srp_kdf)) return c.json({ error: 'Recovery unavailable' }, 401);
  const { B, b } = await serverStep1(dec(factor.srp_salt), dec(factor.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at, purpose, binding_hash) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000), 'grant-recovery', await sha256url(body.grant)).run();
  return c.json({ challenge_id: challenge, salt: factor.srp_salt, B: enc(B), srp_kdf: factor.srp_kdf });
});

bridge.post('/api/flaxia/reauth/verify', bodyLimit({ maxSize: 2048 }), async c => {
  c.header('Cache-Control', 'no-store');
  let body: { grant?: unknown; user_id?: unknown; challenge_id?: unknown; A?: unknown; M1?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const user = await userForGrant(c.env.DB, body?.grant);
  if (!user || user.id !== body?.user_id) return c.json({ error: 'Invalid authorization' }, 401);
  return c.json({ valid: await verifyProof(c.env.DB, user, body, 'grant-reauth', body.grant as string) });
});

export class FlaxiaBridge extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    return bridge.fetch(request, this.env, this.ctx);
  }
}

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
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : body.email;
  if (email !== undefined && (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return c.json({ error: 'Invalid email' }, 400);
  if (body.display_name !== undefined && (typeof body.display_name !== 'string' || body.display_name.length === 0 || body.display_name.length > 50)) return c.json({ error: 'Invalid display name' }, 400);
  if ('password' in body || typeof username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(username) || typeof salt !== 'string' || typeof verifier !== 'string' || salt.length > 32 || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf)) return c.json({ error: 'Invalid registration' }, 400);
  if (!validCredentials(salt, verifier)) return c.json({ error: 'Invalid registration' }, 400);
  try {
    const user = { id: random(), username, display_name: typeof body.display_name === 'string' ? body.display_name : username };
    const token = random();
    await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO users (id, username, display_name, email, srp_salt, srp_verifier, srp_group, srp_kdf) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(user.id, username, user.display_name, email ?? null, salt, verifier, group, kdf),
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
  const saltEncoded = enc(salt), verifierEncoded = enc(verifier);
  const legacyStamp = await sha256url(JSON.stringify(['legacy', user.password_hash]));
  const token = random();
  const result = await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO flaxia_legacy_fingerprints (user_id, fingerprint, expires_at) SELECT id, ?, ? FROM users WHERE id = ? AND password_hash = ? AND srp_salt IS NULL AND srp_verifier IS NULL AND frozen_at IS NULL').bind(legacyStamp, expiry(90 * 86400000), user.id, user.password_hash),
    c.env.DB.prepare('INSERT OR IGNORE INTO flaxia_credential_guards (user_id) SELECT user_id FROM flaxia_legacy_fingerprints WHERE user_id = ?').bind(user.id),
    c.env.DB.prepare("UPDATE users SET srp_salt = ?, srp_verifier = ?, srp_group = '2048', srp_kdf = 'pbkdf2-600k-v2', password_hash = '' WHERE id = ? AND password_hash = ? AND srp_salt IS NULL AND srp_verifier IS NULL AND frozen_at IS NULL")
      .bind(saltEncoded, verifierEncoded, user.id, user.password_hash),
    c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) SELECT ?, id, ? FROM users WHERE id = ? AND srp_salt = ? AND srp_verifier = ?').bind(token, expiry(7 * 86400000), user.id, saltEncoded, verifierEncoded),
  ]);
  if (result[0].meta.changes !== 1 || result[2].meta.changes !== 1 || result[3].meta.changes !== 1) return c.json({ error: 'Invalid credentials' }, 401);
  setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
  return c.json({ user: { id: user.id, username: user.username, display_name: user.display_name } });
});

app.post('/api/auth/recovery/start', async c => {
  if (await rateLimit(c.env.DB, `recovery-login:ip:${requestIp(c)}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  let body: { username?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.username !== 'string' || !/^[a-zA-Z0-9_]{1,20}$/.test(body.username)) return c.json({ error: 'Invalid request' }, 400);
  if (await rateLimit(c.env.DB, `recovery-login:user:${body.username.toLowerCase()}`, 5)) return c.json({ error: 'Too many requests' }, 429);
  const user = await c.env.DB.prepare('SELECT u.id, f.srp_salt, f.srp_verifier, f.srp_kdf FROM users u JOIN auth_recovery_factors f ON f.user_id = u.id WHERE u.username = ? COLLATE NOCASE AND u.frozen_at IS NULL').bind(body.username).first<{ id: string; srp_salt: string; srp_verifier: string; srp_kdf: string }>();
  // Do not expose whether the username exists or has a recovery factor.
  const dummyVerifier = new Uint8Array(256); dummyVerifier[255] = 2;
  const usable = user && isSupportedSrpKdf(user.srp_kdf) ? user : null;
  const salt = usable ? dec(usable.srp_salt) : crypto.getRandomValues(new Uint8Array(16));
  const verifier = usable ? dec(usable.srp_verifier) : dummyVerifier;
  const { B, b } = await serverStep1(salt, verifier);
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  if (usable) await c.env.DB.prepare("INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at, purpose) VALUES (?, ?, ?, ?, ?, 'recovery-login')").bind(challenge, usable.id, b.toString(), enc(B), expiry(300000)).run();
  return c.json({ challenge_id: challenge, salt: enc(salt), B: enc(B), srp_kdf: usable?.srp_kdf ?? 'pbkdf2-600k-v2' });
});

app.post('/api/auth/recovery/verify', async c => {
  if (await rateLimit(c.env.DB, `recovery-verify:ip:${requestIp(c)}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  let body: { challenge_id?: unknown; A?: unknown; M1?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.challenge_id !== 'string' || body.challenge_id.length > 64 || typeof body.A !== 'string' || body.A.length > 400 || typeof body.M1 !== 'string' || body.M1.length > 64) return c.json({ error: 'Invalid request' }, 400);
  const hs = await c.env.DB.prepare("DELETE FROM srp_handshakes WHERE id = ? AND purpose = 'recovery-login' AND expires_at > ? RETURNING user_id, b_scalar, b_pub").bind(body.challenge_id, new Date().toISOString()).first<Handshake>();
  if (!hs) return c.json({ error: 'Recovery unavailable' }, 401);
  const factor = await c.env.DB.prepare('SELECT u.username, u.display_name, f.srp_salt, f.srp_verifier FROM users u JOIN auth_recovery_factors f ON f.user_id = u.id WHERE u.id = ? AND u.frozen_at IS NULL').bind(hs.user_id).first<{ username: string; display_name: string; srp_salt: string; srp_verifier: string }>();
  if (!factor) return c.json({ error: 'Recovery unavailable' }, 401);
  try {
    const A = dec(body.A), M1 = dec(body.M1);
    if (A.length !== 256 || M1.length !== 32) return c.json({ error: 'Recovery unavailable' }, 401);
    const proof = await serverStep2(A, dec(hs.b_pub), BigInt(hs.b_scalar), dec(factor.srp_verifier), M1);
    if (!proof) return c.json({ error: 'Recovery unavailable' }, 401);
    const token = random();
    const result = await c.env.DB.batch([
      c.env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) SELECT ?, u.id, ? FROM users u JOIN auth_recovery_factors f ON f.user_id = u.id WHERE u.id = ? AND u.frozen_at IS NULL AND f.srp_salt = ? AND f.srp_verifier = ?').bind(token, expiry(7 * 86400000), hs.user_id, factor.srp_salt, factor.srp_verifier),
      c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ? AND changes() = 1').bind(hs.user_id, token),
      c.env.DB.prepare('DELETE FROM srp_handshakes WHERE user_id = ? AND changes() = 1').bind(hs.user_id),
    ]);
    if (result[0].meta.changes !== 1) return c.json({ error: 'Recovery unavailable' }, 401);
    setCookie(c, cookieName, token, { ...cookieOptions, maxAge: 7 * 86400 });
    return c.json({ M2: enc(proof.M2), user: { id: hs.user_id, username: factor.username, display_name: factor.display_name } });
  } catch { return c.json({ error: 'Recovery unavailable' }, 401); }
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
  const hs = await c.env.DB.prepare("DELETE FROM srp_handshakes WHERE id = ? AND purpose = 'login' AND expires_at > ? RETURNING user_id, b_scalar, b_pub").bind(body.challenge_id, new Date().toISOString()).first<{ user_id: string; b_scalar: string; b_pub: string }>();
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

app.post('/api/auth/flaxia/authorize', async c => {
  if (c.req.header('Origin') !== 'https://flaxia.app') return c.json({ error: 'Invalid origin' }, 403);
  const session = getCookie(c, cookieName);
  const user = await sessionUser(c.env.DB, session);
  if (!user || !session) return c.json({ error: 'Unauthenticated' }, 401);
  if (await rateLimit(c.env.DB, `flaxia-authorize:user:${user.id}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  let body: { challenge?: unknown };
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body.challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.challenge)) return c.json({ error: 'Invalid request' }, 400);
  const code = random();
  await c.env.DB.prepare('DELETE FROM flaxia_authorization_codes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare(`DELETE FROM flaxia_session_grants WHERE token_hash IN (
    SELECT g.token_hash FROM flaxia_session_grants g JOIN sessions s ON s.id = g.session_id WHERE s.expires_at <= ? LIMIT 100
  )`).bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO flaxia_authorization_codes (code_hash, challenge, session_id, user_id, expires_at) VALUES (?, ?, ?, ?, ?)').bind(await sha256url(code), body.challenge, session, user.id, expiry(60000)).run();
  return c.json({ code });
});

app.post('/api/auth/reauth/start', async c => {
  const session = getCookie(c, cookieName);
  const user = await sessionUser(c.env.DB, session);
  if (!user || !session) return c.json({ error: 'Unauthenticated' }, 401);
  if (await rateLimit(c.env.DB, `reauth-start:user:${user.id}`, 10)) return c.json({ error: 'Too many requests' }, 429);
  if (!user.srp_salt || !user.srp_verifier || !isSupportedSrpKdf(user.srp_kdf ?? 'sha256-v1')) return c.json({ error: 'SRP not available' }, 400);
  const { B, b } = await serverStep1(dec(user.srp_salt), dec(user.srp_verifier));
  const challenge = random();
  await c.env.DB.prepare('DELETE FROM srp_handshakes WHERE expires_at <= ?').bind(new Date().toISOString()).run();
  await c.env.DB.prepare('INSERT INTO srp_handshakes (id, user_id, b_scalar, b_pub, expires_at, purpose, binding_hash) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(challenge, user.id, b.toString(), enc(B), expiry(300000), 'session-reauth', await sha256url(session)).run();
  return c.json({ challenge_id: challenge, salt: user.srp_salt, B: enc(B), srp_kdf: user.srp_kdf ?? 'sha256-v1' });
});

app.post('/api/auth/reauth/verify', async c => {
  const session = getCookie(c, cookieName);
  const user = await sessionUser(c.env.DB, session);
  if (!user || !session) return c.json({ error: 'Unauthenticated' }, 401);
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  return c.json({ valid: await verifyProof(c.env.DB, user, body, 'session-reauth', session) });
});

app.post('/api/auth/upgrade-srp', async c => {
  const session = getCookie(c, cookieName);
  const user = await sessionUser(c.env.DB, session);
  if (!user || !session) return c.json({ error: 'Unauthenticated' }, 401);
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body) || !body.current_srp) return c.json({ error: 'Current password proof is required' }, 400);
  const { srp_salt: salt, srp_verifier: verifier, srp_group: group, srp_kdf: kdf } = body;
  if (typeof salt !== 'string' || salt.length > 32 || typeof verifier !== 'string' || verifier.length > 400 || group !== '2048' || !isCreatableSrpKdf(kdf)) return c.json({ error: 'Invalid SRP parameters' }, 400);
  if (!validCredentials(salt, verifier)) return c.json({ error: 'Invalid SRP parameters' }, 400);
  if (!await verifyProof(c.env.DB, user, body.current_srp, 'session-reauth', session)) return c.json({ error: 'Current password is incorrect' }, 401);
  const updated = await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET srp_salt = ?, srp_verifier = ?, srp_group = ?, srp_kdf = ?, password_hash = ? WHERE id = ? AND srp_verifier = ? AND srp_salt = ? AND NOT EXISTS (SELECT 1 FROM flaxia_credential_guards WHERE user_id = users.id)').bind(salt, verifier, group, kdf, '', user.id, user.srp_verifier, user.srp_salt),
    c.env.DB.prepare('DELETE FROM flaxia_legacy_fingerprints WHERE user_id = ? AND changes() = 1 AND EXISTS (SELECT 1 FROM users WHERE id = ? AND srp_salt = ? AND srp_verifier = ?)').bind(user.id, user.id, salt, verifier),
  ]);
  if (!updated[0].meta.changes) return c.json({ error: 'Credentials changed or linked to Flaxia' }, 409);
  return c.json({ success: true });
});
app.post('/api/auth/logout', async c => {
  const token = getCookie(c, cookieName);
  if (token) await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
  deleteCookie(c, cookieName, cookieOptions);
  return c.json({ success: true });
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM flaxia_authorization_codes WHERE expires_at <= ?').bind(now),
      env.DB.prepare('DELETE FROM flaxia_legacy_fingerprints WHERE expires_at <= ?').bind(now),
      env.DB.prepare('DELETE FROM flaxia_deletion_cancellations WHERE expires_at <= ?').bind(now),
      env.DB.prepare("DELETE FROM flaxia_email_changes WHERE state = 'cancelled' AND expires_at <= ?").bind(now),
      env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
    ]);
  },
};

