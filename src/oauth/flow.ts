// The authorization half of an OAuth connection.
//
// The browser drives the flow: it generates the PKCE verifier and the state,
// keeps both, and sends the resulting code challenge to Auth. Auth records a
// transaction with the *hashes* only, so a database dump cannot be replayed
// against a provider.
//
//   browser                          Auth                         provider
//     │  start (challenge, verifier)   │                              │
//     ├───────────────────────────────►│  store hash(state/verifier) │
//     │  authorize URL                 │                              │
//     │◄───────────────────────────────┤                              │
//     │──────────────────────────────────────────────────────────────►│
//     │◄──────────────────────────────────────────────────────────────┤
//     │  callback (code, state)        │                              │
//     │─────────────────────────────────────────────►│ verify + consume │
//
// The callback never carries a credential. What happens next differs per
// provider mode: a browser-reachable provider exchanges the code itself and
// encrypts the token into the Vault, while Auth performs the exchange for a
// provider that refuses cross-origin calls and seals the result back.

import { getProvider } from './registry.ts';

const STATE_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const TRANSACTION_TTL_MS = 10 * 60 * 1000;

export interface OAuthTransaction {
  id: string;
  user_id: string;
  provider: string;
  state_hash: string;
  code_verifier_hash: string | null;
  redirect_uri: string;
  return_uri: string | null;
  expires_at: string;
  consumed_at: string | null;
  exchanged_at: string | null;
  completed_at: string | null;
}

export interface NewTransaction {
  userId: string;
  provider: string;
  state: string;
  codeVerifier?: string | null;
  redirectUri: string;
  returnUri?: string | null;
  now?: number;
}

export const isValidState = (value: unknown): value is string =>
  typeof value === 'string' && STATE_PATTERN.test(value);

export const isValidCodeVerifier = (value: unknown): value is string =>
  typeof value === 'string' && CODE_VERIFIER_PATTERN.test(value);

const encode = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

/**
 * Hash a state value. The stored form is a lookup key, so it must be
 * deterministic, but the clear value never reaches the database.
 */
export async function hashState(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return encode(new Uint8Array(digest));
}

const transactionId = (): string => `tx_${encode(crypto.getRandomValues(new Uint8Array(24)))}`;

/**
 * Create a transaction for a pending authorization. The state and the PKCE
 * verifier are stored hashed; the browser keeps the originals.
 */
export async function newTransaction(input: NewTransaction): Promise<OAuthTransaction> {
  const provider = getProvider(input.provider);
  if (!provider) throw new Error('Unknown OAuth provider');
  const now = input.now ?? Date.now();
  return {
    id: transactionId(),
    user_id: input.userId,
    provider: input.provider,
    state_hash: await hashState(input.state),
    code_verifier_hash:
      typeof input.codeVerifier === 'string' && isValidCodeVerifier(input.codeVerifier)
        ? await hashState(input.codeVerifier)
        : null,
    redirect_uri: input.redirectUri,
    return_uri: input.returnUri ?? null,
    expires_at: new Date(now + TRANSACTION_TTL_MS).toISOString(),
    consumed_at: null,
    exchanged_at: null,
    completed_at: null,
  };
}

export const transactionExpired = (transaction: OAuthTransaction, now: string): boolean =>
  transaction.expires_at <= now;

const record = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

/** Rebuild a transaction from a stored row, rejecting a row that is not usable. */
export function transactionFromRow(value: unknown): OAuthTransaction | null {
  const row = record(value);
  if (!row) return null;
  const provider = row.provider;
  if (typeof provider !== 'string' || !getProvider(provider)) return null;
  const expiresAt = row.expires_at;
  if (typeof expiresAt !== 'string' || !Number.isFinite(Date.parse(expiresAt))) return null;
  const stamp = (value: unknown): string | null | undefined => {
    if (value === null || value === undefined) return null;
    return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : undefined;
  };
  const consumedAt = stamp(row.consumed_at);
  const exchangedAt = stamp(row.exchanged_at);
  const completedAt = stamp(row.completed_at);
  if (consumedAt === undefined || exchangedAt === undefined || completedAt === undefined) return null;
  const stateHash = row.state_hash;
  const verifierHash = row.code_verifier_hash;
  if (typeof stateHash !== 'string' || stateHash.length === 0) return null;
  if (verifierHash !== null && verifierHash !== undefined && typeof verifierHash !== 'string') return null;
  return {
    id: typeof row.id === 'string' ? row.id : '',
    user_id: typeof row.user_id === 'string' ? row.user_id : '',
    provider,
    state_hash: stateHash,
    code_verifier_hash: typeof verifierHash === 'string' ? verifierHash : null,
    redirect_uri: typeof row.redirect_uri === 'string' ? row.redirect_uri : '',
    return_uri: typeof row.return_uri === 'string' ? row.return_uri : null,
    expires_at: expiresAt,
    consumed_at: consumedAt,
    exchanged_at: exchangedAt,
    completed_at: completedAt,
  };
}
