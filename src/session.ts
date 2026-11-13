// Session cookie and authenticated-user lookup shared by the Auth API and the
// OAuth authorization endpoint.

export const cookieName = '__Host-flaxia_session';
export const cookieOptions = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/' };

export type User = {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  password_hash: string;
  srp_salt: string | null;
  srp_verifier: string | null;
  srp_group: string | null;
  srp_kdf: string | null;
  frozen_at: string | null;
};

export async function sessionUser(db: D1Database, token: string | undefined): Promise<User | null> {
  if (!token) return null;
  return db.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > ? AND u.frozen_at IS NULL').bind(token, new Date().toISOString()).first<User>();
}
