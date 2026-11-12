// Connection metadata for third-party OAuth providers.
//
// Everything in this module is metadata. A token never passes through here:
// the credentials live in `vault_items` as an `oauth_connection` item,
// encrypted client-side, and Auth can neither read nor use them. The helpers
// below therefore strip anything that looks like a credential before a row
// leaves the database.

import { getProvider } from './registry.ts';

export const CONNECTION_STATUSES = ['active', 'revoked'] as const;
export type ConnectionStatus = (typeof CONNECTION_STATUSES)[number];

export interface ConnectionMetadata {
  id: string;
  provider: string;
  provider_sub: string | null;
  scopes: string[];
  status: ConnectionStatus;
  vault_item_id: string | null;
  expires_at: string | null;
  refresh_expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
}

const CONNECTION_ID_PATTERN = /^conn_[A-Za-z0-9_-]{20,40}$/;
const PROVIDER_SUB_PATTERN = /^[^\s\x00-\x1f\x7f]{1,512}$/;
const SCOPE_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;

export const isValidConnectionId = (value: unknown): value is string =>
  typeof value === 'string' && CONNECTION_ID_PATTERN.test(value);

export const isValidProviderSub = (value: unknown): value is string =>
  typeof value === 'string' && PROVIDER_SUB_PATTERN.test(value);

export const isValidScopeList = (value: unknown): value is string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every(scope => typeof scope === 'string' && SCOPE_PATTERN.test(scope));

/** Trim, drop empties, de-duplicate and sort a scope list. */
export const normalizeScopes = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];
  const scopes = new Set<string>();
  for (const scope of value) {
    if (typeof scope !== 'string') continue;
    const trimmed = scope.trim();
    if (trimmed.length === 0 || trimmed.length > 64) continue;
    if (!SCOPE_PATTERN.test(trimmed)) continue;
    scopes.add(trimmed);
  }
  return [...scopes].sort();
};

/**
 * Parse a stored scope list. Scopes are provider-specific strings, so the
 * registry cannot validate them; only the shape is checked.
 */
export const parseScopeList = (value: unknown): string[] => {
  let raw: unknown = value;
  if (typeof value === 'string') {
    try {
      raw = JSON.parse(value);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(raw)) return [];
  return normalizeScopes(raw);
};

/**
 * Parse a stored provider list. Unknown ids are dropped rather than stored,
 * so a row can never name a provider the registry does not know.
 */
export const parseProviderList = (value: unknown): string[] => {
  let raw: unknown = value;
  if (typeof value === 'string') {
    try {
      raw = JSON.parse(value);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(raw)) return [];
  const providers = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    if (!getProvider(entry)) continue;
    providers.add(entry);
  }
  return [...providers].sort();
};

const record = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

const timestamp = (value: unknown): string | null =>
  typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) ? value : null;

const optionalTimestamp = (value: unknown): string | null | undefined => {
  if (value === null || value === undefined) return null;
  const parsed = timestamp(value);
  return parsed === null ? undefined : parsed;
};

/**
 * Turn a database row into connection metadata. A row that does not match
 * the expected shape is rejected instead of being repaired, so a malformed
 * value can never be shown to the user as a valid connection.
 */
export const connectionRow = (value: unknown): ConnectionMetadata | null => {
  const row = record(value);
  if (!row) return null;
  const id = row.id;
  const provider = row.provider;
  if (!isValidConnectionId(id)) return null;
  if (typeof provider !== 'string' || !getProvider(provider)) return null;
  const status = row.status;
  if (typeof status !== 'string' || !(CONNECTION_STATUSES as readonly string[]).includes(status)) return null;
  const scopes = parseScopeList(row.scopes);
  const providerSub = row.provider_sub === null || row.provider_sub === undefined
    ? null
    : isValidProviderSub(row.provider_sub) ? row.provider_sub : null;
  const vaultItemId = row.vault_item_id === null || row.vault_item_id === undefined
    ? null
    : typeof row.vault_item_id === 'string' ? row.vault_item_id : null;
  const expiresAt = optionalTimestamp(row.expires_at);
  const refreshExpiresAt = optionalTimestamp(row.refresh_expires_at);
  const lastUsedAt = optionalTimestamp(row.last_used_at);
  const revokedAt = optionalTimestamp(row.revoked_at);
  if (expiresAt === undefined || refreshExpiresAt === undefined || lastUsedAt === undefined || revokedAt === undefined) {
    return null;
  }
  const createdAt = timestamp(row.created_at);
  const updatedAt = timestamp(row.updated_at);
  if (!createdAt || !updatedAt) return null;
  return {
    id,
    provider,
    provider_sub: providerSub,
    scopes,
    status: status as ConnectionStatus,
    vault_item_id: vaultItemId,
    expires_at: expiresAt,
    refresh_expires_at: refreshExpiresAt,
    last_used_at: lastUsedAt,
    revoked_at: revokedAt,
    created_at: createdAt,
    updated_at: updatedAt,
  };
};

/**
 * Strip a row down to the fields that may be shown to a client. This is the
 * only shape that leaves the server, so a credential can never ride along
 * with the metadata by accident.
 */
export const parseConnectionMetadata = (value: unknown): ConnectionMetadata | null => {
  const row = connectionRow(value);
  if (!row) return null;
  return {
    id: row.id,
    provider: row.provider,
    provider_sub: row.provider_sub,
    scopes: row.scopes,
    status: row.status,
    vault_item_id: row.vault_item_id,
    expires_at: row.expires_at,
    refresh_expires_at: row.refresh_expires_at,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
};
