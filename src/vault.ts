// Personal Vault storage for Flaxia Auth.
//
// The server stores wrapped key material and nothing else: no password, no
// KEK/REK/VK, no recovery phrase. Handlers shape-check the opaque strings so a
// malformed value is rejected early, but they can never interpret one. The
// allowlists in this module are the entire server-side "understanding" of the
// data.
//
// Auth owns the credential and the Vault envelope together, so a password
// change can re-wrap VK in the same transaction that replaces the verifier.
// Flaxia no longer needs to stage Vault changes in its own D1.

export interface VaultResult {
  status: number;
  body: Record<string, unknown>;
}

export interface VaultRequest {
  db: D1Database;
  userId: string;
  method: string;
  /** Path below /api/vault, for example "/keys" or "/items/abc". */
  path: string;
  query: URLSearchParams;
  body: unknown;
  /**
   * Consumes a one-time SRP proof of the current password. Session callers bind
   * it to the session token; service-bound callers bind it to the Auth grant.
   */
  verifyCurrentSrp: (proof: unknown) => Promise<boolean>;
}

interface VaultEnvelopeRow {
  salt: string;
  recovery_salt: string;
  kdf_params: string;
  wrapped_vk: string;
  recovery_blob: string;
  vk_version: number;
}

interface DeviceRow {
  id: string;
  user_id: string;
  label: string;
  state: 'pending' | 'active';
  peer_pub: string;
  approved_pub: string;
  wrapped_vk: string;
  created_at: string;
  expires_at: string;
  last_seen_at: string | null;
}

export const VAULT_KDF_MIN_ITERATIONS = 100_000;
export const VAULT_KDF_MAX_ITERATIONS = 10_000_000;
export const PAIRING_ID_PATTERN = /^[A-Za-z0-9_-]{16,40}$/;

const MAX_ACTIVE_DEVICES = 10;
const MAX_VAULT_ITEM_CIPHERTEXT_CHARS = 128_000;
const MAX_VAULT_ITEMS = 200;
const MAX_VAULT_STORAGE_CHARS = 5_000_000;
const VAULT_ITEM_KINDS = new Set(['post_autosave', 'post_draft', 'private_note', 'personal_setting']);
const DEFAULT_PAIRING_TTL_SECONDS = 600;
const NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function isValidB64(value: unknown, bytes?: number, maxLength = 2_048): boolean {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return false;
  try {
    const binary = atob(value);
    if (btoa(binary) !== value) return false;
    return bytes === undefined ? binary.length > 0 : binary.length === bytes;
  } catch {
    return false;
  }
}

export function isValidVaultKdfParams(value: unknown): boolean {
  const params = record(value);
  if (!params || params.alg !== 'PBKDF2-SHA256') return false;
  const iterations = params.iterations;
  return (
    typeof iterations === 'number' &&
    Number.isInteger(iterations) &&
    iterations >= VAULT_KDF_MIN_ITERATIONS &&
    iterations <= VAULT_KDF_MAX_ITERATIONS
  );
}

export function isValidWrappedKey(value: unknown, maxLength = 200_000): value is string {
  if (typeof value !== 'string' || value.length > maxLength) return false;
  const parts = value.split('.');
  if (parts.length !== 2 || !isValidB64(parts[0], 12) || !isValidB64(parts[1])) return false;
  try {
    // AES-GCM appends a 16-byte tag, so a shorter ciphertext cannot be valid.
    return atob(parts[1]).length >= 16;
  } catch {
    return false;
  }
}

export function isValidVaultItemId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{10,40}$/.test(value);
}

function isValidLabel(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length >= 1 && value.trim().length <= 40;
}

function isVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

function hasProofShape(proof: unknown): boolean {
  const value = record(proof);
  return Boolean(value?.challenge_id && value.A && value.M1);
}

function pairingExpiry(ttlSeconds: unknown): string {
  const requested =
    typeof ttlSeconds === 'number' && Number.isFinite(ttlSeconds)
      ? Math.floor(ttlSeconds)
      : DEFAULT_PAIRING_TTL_SECONDS;
  const ttl = Math.min(Math.max(requested, 1), DEFAULT_PAIRING_TTL_SECONDS);
  return new Date(Date.now() + ttl * 1000).toISOString();
}

/** A 192-bit opaque id. It fits the shared pairing-id shape used by the client. */
function deviceId(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

function validateEnvelope(body: Record<string, unknown>): string | null {
  if (!isValidB64(body.salt, 16)) return 'Invalid vault salt';
  if (!isValidB64(body.recovery_salt, 16)) return 'Invalid recovery salt';
  if (!isValidVaultKdfParams(body.kdf_params)) return 'Unsupported vault KDF parameters';
  if (!isValidWrappedKey(body.wrapped_vk)) return 'Invalid wrapped vault key';
  if (!isValidWrappedKey(body.recovery_blob)) return 'Invalid recovery blob';
  return null;
}

async function readEnvelope(db: D1Database, userId: string): Promise<VaultEnvelopeRow | null> {
  return db
    .prepare(
      `SELECT salt, recovery_salt, kdf_params, wrapped_vk, recovery_blob, vk_version
       FROM vault_keys WHERE user_id = ?`,
    )
    .bind(userId)
    .first<VaultEnvelopeRow>();
}

async function readDevices(
  db: D1Database,
  userId: string,
): Promise<Array<{ id: string; label: string; state: string; created_at: string }>> {
  const result = await db
    .prepare('SELECT id, label, state, created_at FROM device_keys WHERE user_id = ? ORDER BY created_at')
    .bind(userId)
    .all<{ id: string; label: string; state: string; created_at: string }>();
  return result.results ?? [];
}

async function readDevice(db: D1Database, userId: string, id: string): Promise<DeviceRow | null> {
  return db.prepare('SELECT * FROM device_keys WHERE id = ? AND user_id = ?').bind(id, userId).first<DeviceRow>();
}

function isExpired(row: DeviceRow): boolean {
  return row.expires_at <= new Date().toISOString();
}

export async function handleVaultRequest(request: VaultRequest): Promise<VaultResult> {
  const { db, userId, method, query, body, verifyCurrentSrp } = request;
  const path = request.path;
  const input = record(body) ?? {};

  // ─── Envelope ──────────────────────────────────────────────────────────────
  if (path === '/keys') {
    if (method === 'GET') {
      const row = await readEnvelope(db, userId);
      if (!row) return { status: 200, body: { enabled: false } };
      let kdfParams: unknown;
      try {
        kdfParams = JSON.parse(row.kdf_params);
      } catch {
        return { status: 500, body: { error: 'Vault envelope is malformed' } };
      }
      return {
        status: 200,
        body: {
          enabled: true,
          salt: row.salt,
          recovery_salt: row.recovery_salt,
          kdf_params: kdfParams,
          wrapped_vk: row.wrapped_vk,
          recovery_blob: row.recovery_blob,
          vk_version: row.vk_version,
          devices: await readDevices(db, userId),
        },
      };
    }

    if (method === 'POST') {
      const envelopeError = validateEnvelope(input);
      if (envelopeError) return { status: 400, body: { error: envelopeError } };
      if (!hasProofShape(input.current_srp)) {
        return { status: 400, body: { error: 'Current password proof is required' } };
      }
      if (!(await verifyCurrentSrp(input.current_srp))) {
        return { status: 401, body: { error: 'Current password is incorrect' } };
      }
      if (await readEnvelope(db, userId)) return { status: 409, body: { error: 'Vault already enabled' } };

      const newDeviceId = input.device_id;
      const newDeviceLabel = input.device_label;
      if (newDeviceId !== undefined || newDeviceLabel !== undefined) {
        if (
          !(typeof newDeviceId === 'string' && PAIRING_ID_PATTERN.test(newDeviceId)) ||
          !isValidLabel(newDeviceLabel)
        ) {
          return { status: 400, body: { error: 'Invalid device registration' } };
        }
      }

      const statements = [
        db
          .prepare(
            `INSERT INTO vault_keys (user_id, salt, recovery_salt, kdf_params, wrapped_vk, recovery_blob, vk_version)
             VALUES (?, ?, ?, ?, ?, ?, 1)`,
          )
          .bind(
            userId,
            input.salt as string,
            input.recovery_salt as string,
            JSON.stringify(input.kdf_params),
            input.wrapped_vk as string,
            input.recovery_blob as string,
          ),
      ];
      if (typeof newDeviceId === 'string' && typeof newDeviceLabel === 'string') {
        // The id is client-generated; never displace another account's row.
        statements.push(
          db
            .prepare(
              `INSERT OR IGNORE INTO device_keys (id, user_id, label, state, peer_pub, wrapped_vk, expires_at, last_seen_at)
               VALUES (?, ?, ?, 'active', '', '', '', ${NOW_SQL})`,
            )
            .bind(newDeviceId, userId, newDeviceLabel),
        );
      }
      const results = await db.batch(statements);
      if (results.some(result => !result.success)) {
        return { status: 500, body: { error: 'Failed to enable vault' } };
      }
      return { status: 201, body: { enabled: true, vk_version: 1, device_id: newDeviceId ?? null } };
    }

    if (method === 'PUT') {
      const envelopeError = validateEnvelope(input);
      if (envelopeError) return { status: 400, body: { error: envelopeError } };
      if (!isVersion(input.vk_version)) return { status: 400, body: { error: 'Invalid vault key version' } };
      if (!hasProofShape(input.current_srp)) {
        return { status: 400, body: { error: 'Current password proof is required' } };
      }
      if (!(await verifyCurrentSrp(input.current_srp))) {
        return { status: 401, body: { error: 'Current password is incorrect' } };
      }
      const current = await readEnvelope(db, userId);
      if (!current) return { status: 404, body: { error: 'Vault not enabled' } };
      if (input.vk_version !== current.vk_version) {
        return { status: 409, body: { error: 'Vault key version conflict' } };
      }

      const version = input.vk_version;
      const results = await db.batch([
        db
          .prepare(
            `UPDATE vault_keys
             SET salt = ?, recovery_salt = ?, kdf_params = ?, wrapped_vk = ?, recovery_blob = ?,
                 vk_version = vk_version + 1, updated_at = ${NOW_SQL}
             WHERE user_id = ? AND vk_version = ?`,
          )
          .bind(
            input.salt as string,
            input.recovery_salt as string,
            JSON.stringify(input.kdf_params),
            input.wrapped_vk as string,
            input.recovery_blob as string,
            userId,
            version,
          ),
        db
          .prepare(
            `UPDATE vault_items SET vk_version = ?, updated_at = ${NOW_SQL}
             WHERE user_id = ? AND vk_version = ?
               AND EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ?)`,
          )
          .bind(version + 1, userId, version, userId, version + 1),
      ]);
      if (results.some(result => !result.success)) {
        return { status: 500, body: { error: 'Failed to update vault keys' } };
      }
      if (results[0].meta.changes === 0) {
        return { status: 409, body: { error: 'Vault key version conflict' } };
      }
      return { status: 200, body: { enabled: true, vk_version: version + 1 } };
    }

    return { status: 405, body: { error: 'Method not allowed' } };
  }

  if (path === '/keys/revoke-device') {
    if (method !== 'POST') return { status: 405, body: { error: 'Method not allowed' } };
    const envelopeError = validateEnvelope(input);
    if (envelopeError) return { status: 400, body: { error: envelopeError } };
    if (!isVersion(input.vk_version)) return { status: 400, body: { error: 'Invalid vault key version' } };
    if (!hasProofShape(input.current_srp)) {
      return { status: 400, body: { error: 'Current password proof is required' } };
    }
    if (!PAIRING_ID_PATTERN.test(String(input.device_id ?? ''))) {
      return { status: 400, body: { error: 'Invalid device registration' } };
    }
    if (!PAIRING_ID_PATTERN.test(String(input.current_device_id ?? ''))) {
      return { status: 400, body: { error: 'Invalid current device id' } };
    }
    if (input.device_id === input.current_device_id) {
      return { status: 400, body: { error: 'Cannot revoke the current device' } };
    }
    if (!Array.isArray(input.item_keys) || input.item_keys.length > MAX_VAULT_ITEMS) {
      return { status: 400, body: { error: 'Invalid vault item keys' } };
    }
    const itemKeys = input.item_keys as Array<{
      item_id?: unknown;
      item_key_wrapped?: unknown;
      item_key_wrapped_before?: unknown;
    }>;
    if (
      itemKeys.some(
        item =>
          !record(item) ||
          !isValidVaultItemId(item.item_id) ||
          !isValidWrappedKey(item.item_key_wrapped) ||
          !isValidWrappedKey(item.item_key_wrapped_before),
      )
    ) {
      return { status: 400, body: { error: 'Invalid vault item keys' } };
    }
    const submittedItemIds = itemKeys.map(item => item.item_id as string);
    if (new Set(submittedItemIds).size !== submittedItemIds.length) {
      return { status: 400, body: { error: 'Invalid vault item keys' } };
    }

    const current = await readEnvelope(db, userId);
    if (!current) return { status: 404, body: { error: 'Vault not enabled' } };
    const inventory = await db
      .prepare('SELECT id FROM vault_items WHERE user_id = ?')
      .bind(userId)
      .all<{ id: string }>();
    const existingItemIds = (inventory.results ?? []).map(item => item.id);
    if (
      existingItemIds.length !== submittedItemIds.length ||
      existingItemIds.some(itemId => !submittedItemIds.includes(itemId))
    ) {
      return { status: 409, body: { error: 'Vault item key inventory is incomplete' } };
    }
    if (!(await verifyCurrentSrp(input.current_srp))) {
      return { status: 401, body: { error: 'Current password is incorrect' } };
    }

    const version = input.vk_version;
    const itemInventorySnapshot = JSON.stringify(
      itemKeys.map(item => ({
        item_id: item.item_id,
        item_key_wrapped_before: item.item_key_wrapped_before,
      })),
    );
    const statements: D1PreparedStatement[] = [
      db
        .prepare(
          `UPDATE vault_keys
           SET salt = ?, recovery_salt = ?, kdf_params = ?, wrapped_vk = ?, recovery_blob = ?,
               vk_version = vk_version + 1, updated_at = ${NOW_SQL}
           WHERE user_id = ? AND vk_version = ?
             AND EXISTS (SELECT 1 FROM device_keys WHERE user_id = ? AND id = ?)
             AND (SELECT COUNT(*) FROM vault_items WHERE user_id = ?) = ?
             AND NOT EXISTS (
               SELECT 1 FROM vault_items AS current_item
               WHERE current_item.user_id = ?
                 AND NOT EXISTS (
                   SELECT 1 FROM json_each(?) AS requested_item
                   WHERE json_extract(requested_item.value, '$.item_id') = current_item.id
                     AND json_extract(requested_item.value, '$.item_key_wrapped_before') = current_item.item_key_wrapped
                     AND current_item.vk_version = ?
                 )
             )`,
        )
        .bind(
          input.salt as string,
          input.recovery_salt as string,
          JSON.stringify(input.kdf_params),
          input.wrapped_vk as string,
          (input.recovery_blob ?? current.recovery_blob) as string,
          userId,
          version,
          userId,
          String(input.device_id),
          userId,
          itemKeys.length,
          userId,
          itemInventorySnapshot,
          version,
        ),
    ];
    for (const item of itemKeys) {
      statements.push(
        db
          .prepare(
            `UPDATE vault_items SET item_key_wrapped = ?, vk_version = ?, updated_at = ${NOW_SQL}
             WHERE user_id = ? AND id = ? AND item_key_wrapped = ? AND vk_version = ?
               AND EXISTS (
                 SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ? AND wrapped_vk = ?
               )`,
          )
          .bind(
            item.item_key_wrapped as string,
            version + 1,
            userId,
            item.item_id as string,
            item.item_key_wrapped_before as string,
            version,
            userId,
            version + 1,
            input.wrapped_vk as string,
          ),
      );
    }
    statements.push(
      db
        .prepare(
          `DELETE FROM device_keys
           WHERE user_id = ? AND id <> ?
             AND EXISTS (
               SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ? AND wrapped_vk = ?
             )
             AND EXISTS (SELECT 1 FROM device_keys WHERE user_id = ? AND id = ?)`,
        )
        .bind(
          userId,
          String(input.current_device_id),
          userId,
          version + 1,
          input.wrapped_vk as string,
          userId,
          String(input.device_id),
        ),
    );

    const results = await db.batch(statements);
    if (results.some(result => !result.success)) {
      return { status: 500, body: { error: 'Failed to revoke device' } };
    }
    if ((results[0].meta?.changes ?? 0) === 0) {
      const latest = await readEnvelope(db, userId);
      if (!latest) return { status: 404, body: { error: 'Vault not enabled' } };
      if (latest.vk_version !== version) {
        return { status: 409, body: { error: 'Vault key version conflict' } };
      }
      const target = await db
        .prepare('SELECT id FROM device_keys WHERE user_id = ? AND id = ?')
        .bind(userId, String(input.device_id))
        .first();
      if (!target) return { status: 404, body: { error: 'Pairing not found' } };
      return { status: 409, body: { error: 'Vault item key inventory changed' } };
    }
    if ((results[results.length - 1].meta?.changes ?? 0) === 0) {
      return { status: 404, body: { error: 'Pairing not found' } };
    }
    return { status: 200, body: { enabled: true, vk_version: version + 1 } };
  }

  // ─── Items ─────────────────────────────────────────────────────────────────
  if (path === '/items') {
    if (method === 'GET') {
      const kind = query.get('kind');
      if (kind !== null && !VAULT_ITEM_KINDS.has(kind)) {
        return { status: 400, body: { error: 'Invalid vault item kind' } };
      }
      const statement = kind
        ? db
            .prepare(
              `SELECT id, item_key_wrapped, payload, kind, vk_version, created_at, updated_at
               FROM vault_items WHERE user_id = ? AND kind = ? ORDER BY created_at`,
            )
            .bind(userId, kind)
        : db
            .prepare(
              `SELECT id, item_key_wrapped, kind, vk_version, created_at, updated_at
               FROM vault_items WHERE user_id = ? ORDER BY created_at`,
            )
            .bind(userId);
      const result = await statement.all();
      return { status: 200, body: { items: result.results ?? [] } };
    }

    if (method === 'DELETE') {
      const kind = query.get('kind');
      const version = Number(query.get('vk_version'));
      if (!kind || !VAULT_ITEM_KINDS.has(kind)) {
        return { status: 400, body: { error: 'Invalid vault item kind' } };
      }
      if (!isVersion(version)) return { status: 400, body: { error: 'Invalid vault key version' } };
      const removed = await db
        .prepare(
          `DELETE FROM vault_items WHERE user_id = ? AND kind = ? AND vk_version = ?
           AND EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ?)`,
        )
        .bind(userId, kind, version, userId, version)
        .run();
      if (!removed.success) return { status: 500, body: { error: 'Failed to delete vault items' } };
      if (removed.meta.changes === 0) {
        const envelope = await readEnvelope(db, userId);
        if (!envelope) return { status: 404, body: { error: 'Vault not enabled' } };
        if (envelope.vk_version !== version) {
          return { status: 409, body: { error: 'Vault key version conflict' } };
        }
      }
      return { status: 200, body: { ok: true, deleted: removed.meta.changes } };
    }

    return { status: 405, body: { error: 'Method not allowed' } };
  }

  const itemMatch = /^\/items\/([^/]+)$/.exec(path);
  if (itemMatch) {
    const id = itemMatch[1] ?? '';
    if (!isValidVaultItemId(id)) return { status: 400, body: { error: 'Invalid vault item id' } };

    if (method === 'PUT') {
      if (
        !isValidWrappedKey(input.item_key_wrapped) ||
        typeof input.payload !== 'string' ||
        input.payload.length > MAX_VAULT_ITEM_CIPHERTEXT_CHARS ||
        !isValidWrappedKey(input.payload) ||
        typeof input.kind !== 'string' ||
        !VAULT_ITEM_KINDS.has(input.kind) ||
        !isVersion(input.vk_version)
      ) {
        return { status: 400, body: { error: 'Invalid vault item' } };
      }

      const result = await db
        .prepare(
          `INSERT INTO vault_items (user_id, id, item_key_wrapped, payload, kind, vk_version)
           SELECT ?, ?, ?, ?, ?, ?
           WHERE EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ?)
             AND (
               EXISTS (SELECT 1 FROM vault_items WHERE user_id = ? AND id = ?)
               OR (SELECT COUNT(*) FROM vault_items WHERE user_id = ?) < ${MAX_VAULT_ITEMS}
             )
             AND (
               (SELECT COALESCE(SUM(length(item_key_wrapped) + length(payload)), 0)
                FROM vault_items WHERE user_id = ? AND id <> ?)
               + length(?) + length(?) <= ${MAX_VAULT_STORAGE_CHARS}
             )
           ON CONFLICT(user_id, id) DO UPDATE SET
             item_key_wrapped = excluded.item_key_wrapped,
             payload = excluded.payload,
             kind = excluded.kind,
             vk_version = excluded.vk_version,
             updated_at = ${NOW_SQL}`,
        )
        .bind(
          userId,
          id,
          input.item_key_wrapped,
          input.payload,
          input.kind,
          input.vk_version,
          userId,
          input.vk_version,
          userId,
          id,
          userId,
          userId,
          id,
          input.payload,
          input.item_key_wrapped,
        )
        .run();
      if (!result.success) return { status: 500, body: { error: 'Failed to save vault item' } };
      if (result.meta.changes === 0) {
        const envelope = await readEnvelope(db, userId);
        if (!envelope) return { status: 404, body: { error: 'Vault not enabled' } };
        if (envelope.vk_version === input.vk_version) {
          const limits = await db
            .prepare(
              `SELECT COUNT(*) AS total, COALESCE(SUM(length(item_key_wrapped) + length(payload)), 0) AS chars
               FROM vault_items WHERE user_id = ? AND id <> ?`,
            )
            .bind(userId, id)
            .first<{ total: number; chars: number }>();
          const existing = await db
            .prepare('SELECT id FROM vault_items WHERE user_id = ? AND id = ?')
            .bind(userId, id)
            .first();
          if (
            (!existing && (limits?.total ?? 0) >= MAX_VAULT_ITEMS) ||
            (limits?.chars ?? 0) + input.payload.length + input.item_key_wrapped.length > MAX_VAULT_STORAGE_CHARS
          ) {
            return { status: 409, body: { error: 'Vault item storage limit reached' } };
          }
        }
        return { status: 409, body: { error: 'Vault key version conflict' } };
      }
      return { status: 200, body: { id, kind: input.kind, vk_version: input.vk_version } };
    }

    if (method === 'DELETE') {
      const version = Number(query.get('vk_version'));
      if (!isVersion(version)) return { status: 400, body: { error: 'Invalid vault key version' } };
      const removed = await db
        .prepare(
          `DELETE FROM vault_items WHERE user_id = ? AND id = ? AND vk_version = ?
           AND EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ? AND vk_version = ?)`,
        )
        .bind(userId, id, version, userId, version)
        .run();
      if (!removed.success) return { status: 500, body: { error: 'Failed to delete vault item' } };
      if (removed.meta.changes === 0) {
        const envelope = await readEnvelope(db, userId);
        if (!envelope) return { status: 404, body: { error: 'Vault not enabled' } };
        if (envelope.vk_version !== version) {
          return { status: 409, body: { error: 'Vault key version conflict' } };
        }
        return { status: 404, body: { error: 'Vault item not found' } };
      }
      return { status: 200, body: { ok: true } };
    }

    return { status: 405, body: { error: 'Method not allowed' } };
  }

  // ─── QR device pairing ─────────────────────────────────────────────────────
  if (path === '/devices') {
    if (method === 'POST') {
      if (!isValidLabel(input.label)) return { status: 400, body: { error: 'Invalid device label' } };
      if (!isValidB64(input.peer_pub, 32)) return { status: 400, body: { error: 'Invalid pairing public key' } };
      if (!(await readEnvelope(db, userId))) return { status: 409, body: { error: 'vault_not_enabled' } };

      // Reap abandoned QRs before enforcing the live-device cap.
      await db
        .prepare(`DELETE FROM device_keys WHERE user_id = ? AND state = 'pending' AND expires_at < ${NOW_SQL}`)
        .bind(userId)
        .run();
      const active = await db
        .prepare("SELECT COUNT(*) AS n FROM device_keys WHERE user_id = ? AND state = 'active'")
        .bind(userId)
        .first<{ n: number }>();
      if ((active?.n ?? 0) >= MAX_ACTIVE_DEVICES) {
        return { status: 409, body: { error: 'Device limit reached' } };
      }

      const id = deviceId();
      const inserted = await db
        .prepare(
          `INSERT INTO device_keys (id, user_id, label, state, peer_pub, wrapped_vk, expires_at)
           VALUES (?, ?, ?, 'pending', ?, '', ?)`,
        )
        .bind(id, userId, input.label.trim(), input.peer_pub, pairingExpiry(input.ttl_seconds))
        .run();
      if (!inserted.success) return { status: 500, body: { error: 'Failed to start pairing' } };
      const row = await readDevice(db, userId, id);
      return { status: 201, body: { id, expires_at: row?.expires_at ?? null } };
    }

    if (method === 'GET') {
      const result = await db
        .prepare(
          `SELECT id, label, state, created_at, expires_at, last_seen_at
           FROM device_keys WHERE user_id = ? ORDER BY created_at DESC`,
        )
        .bind(userId)
        .all<Pick<DeviceRow, 'id' | 'label' | 'state' | 'created_at' | 'expires_at' | 'last_seen_at'>>();
      return { status: 200, body: { devices: result.results ?? [] } };
    }

    return { status: 405, body: { error: 'Method not allowed' } };
  }

  const approveMatch = /^\/devices\/([^/]+)\/approve$/.exec(path);
  if (approveMatch) {
    if (method !== 'POST') return { status: 405, body: { error: 'Method not allowed' } };
    if (!isValidB64(input.approved_pub, 32)) return { status: 400, body: { error: 'Invalid pairing public key' } };
    if (!isValidB64(input.peer_pub, 32)) return { status: 400, body: { error: 'Invalid QR public key' } };
    if (!isValidWrappedKey(input.wrapped_vk)) return { status: 400, body: { error: 'Invalid wrapped vault key' } };

    const id = approveMatch[1] ?? '';
    const row = await readDevice(db, userId, id);
    if (!row) return { status: 404, body: { error: 'Pairing not found' } };
    if (row.state !== 'pending') return { status: 409, body: { error: 'pairing_already_used' } };
    if (isExpired(row)) return { status: 410, body: { error: 'pairing_expired' } };
    // The QR carries the joiner's public key; approval must prove possession.
    if (input.peer_pub !== row.peer_pub) return { status: 403, body: { error: 'pairing_peer_mismatch' } };

    const updated = await db
      .prepare(
        `UPDATE device_keys
         SET state = 'active', approved_pub = ?, wrapped_vk = ?, last_seen_at = ${NOW_SQL}
         WHERE id = ? AND user_id = ? AND state = 'pending' AND peer_pub = ?`,
      )
      .bind(input.approved_pub as string, input.wrapped_vk as string, id, userId, input.peer_pub as string)
      .run();
    if (!updated.success || updated.meta.changes === 0) {
      return { status: 409, body: { error: 'pairing_already_used' } };
    }
    return { status: 200, body: { ok: true } };
  }

  const deviceMatch = /^\/devices\/([^/]+)$/.exec(path);
  if (deviceMatch) {
    const id = deviceMatch[1] ?? '';
    if (method === 'GET') {
      const row = await readDevice(db, userId, id);
      if (!row) return { status: 404, body: { error: 'Pairing not found' } };
      if (row.state === 'pending') {
        if (isExpired(row)) {
          return { status: 200, body: { id: row.id, state: 'expired', expires_at: row.expires_at } };
        }
        return {
          status: 200,
          body: { id: row.id, state: 'pending', label: row.label, expires_at: row.expires_at },
        };
      }
      return {
        status: 200,
        body: {
          id: row.id,
          state: 'active',
          label: row.label,
          approved_pub: row.approved_pub,
          wrapped_vk: row.wrapped_vk,
        },
      };
    }

    if (method === 'DELETE') {
      const row = await readDevice(db, userId, id);
      if (!row) return { status: 404, body: { error: 'Pairing not found' } };
      if (row.state !== 'pending') {
        return {
          status: 403,
          body: { error: 'Active devices must be revoked with password proof and vault key rotation' },
        };
      }
      const removed = await db
        .prepare("DELETE FROM device_keys WHERE id = ? AND user_id = ? AND state = 'pending'")
        .bind(id, userId)
        .run();
      if (!removed.success || removed.meta.changes === 0) {
        return { status: 404, body: { error: 'Pairing not found' } };
      }
      return { status: 200, body: { ok: true } };
    }

    return { status: 405, body: { error: 'Method not allowed' } };
  }

  return { status: 404, body: { error: 'Not found' } };
}

// ─── Transitional import from Flaxia-owned storage ───────────────────────────
//
// Before Auth owned the Vault, Flaxia stored the same opaque envelopes in its
// own D1. The import endpoint copies those rows once, on the first Vault
// request after cutover. It never sees a secret: every field is the wrapped
// value the client originally produced. The operation is idempotent, so a
// lost response or a concurrent first request cannot corrupt the result.

const MAX_IMPORT_DEVICES = 50;

export interface VaultImportPayload {
  keys: Record<string, unknown>;
  devices?: unknown;
  items?: unknown;
}

function timestamp(value: unknown, { empty = false } = {}): string | null {
  if (value === undefined || value === null) return empty ? '' : null;
  if (empty && value === '') return '';
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) ? value : null;
}

function importDevice(value: unknown): Record<string, unknown> | null {
  const device = record(value);
  if (!device) return null;
  if (!isValidLabel(device.label)) return null;
  if (!PAIRING_ID_PATTERN.test(String(device.id ?? ''))) return null;
  if (device.state !== 'pending' && device.state !== 'active') return null;
  const peer = device.peer_pub ?? '';
  const approved = device.approved_pub ?? '';
  const wrapped = device.wrapped_vk ?? '';
  if (peer !== '' && !isValidB64(peer, 32)) return null;
  if (approved !== '' && !isValidB64(approved, 32)) return null;
  if (wrapped !== '' && !isValidWrappedKey(wrapped)) return null;
  if (device.state === 'pending' && (typeof peer !== 'string' || peer === '')) return null;
  const createdAt = timestamp(device.created_at);
  const expiresAt = timestamp(device.expires_at, { empty: true });
  const lastSeen = timestamp(device.last_seen_at, { empty: true });
  if (!createdAt || expiresAt === null || lastSeen === null) return null;
  return {
    id: device.id,
    label: (device.label as string).trim(),
    state: device.state,
    peer_pub: peer,
    approved_pub: approved,
    wrapped_vk: wrapped,
    created_at: createdAt,
    expires_at: expiresAt,
    last_seen_at: lastSeen === '' ? null : lastSeen,
  };
}

function importItem(value: unknown): Record<string, unknown> | null {
  const item = record(value);
  if (!item) return null;
  if (!isValidVaultItemId(item.id)) return null;
  if (!isValidWrappedKey(item.item_key_wrapped)) return null;
  if (typeof item.payload !== 'string' || item.payload.length > MAX_VAULT_ITEM_CIPHERTEXT_CHARS) return null;
  if (!isValidWrappedKey(item.payload)) return null;
  if (typeof item.kind !== 'string' || !VAULT_ITEM_KINDS.has(item.kind)) return null;
  if (!isVersion(item.vk_version)) return null;
  const createdAt = timestamp(item.created_at);
  const updatedAt = timestamp(item.updated_at);
  if (!createdAt || !updatedAt) return null;
  return {
    id: item.id,
    item_key_wrapped: item.item_key_wrapped,
    payload: item.payload,
    kind: item.kind,
    vk_version: item.vk_version,
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

export async function importVault(
  db: D1Database,
  userId: string,
  value: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const payload = record(value) as VaultImportPayload | null;
  if (!payload) return { status: 400, body: { error: 'Invalid vault import' } };
  const keys = record(payload.keys);
  if (!keys) return { status: 400, body: { error: 'Invalid vault import' } };
  const envelopeError = validateEnvelope(keys);
  if (envelopeError) return { status: 400, body: { error: envelopeError } };
  if (!isVersion(keys.vk_version)) return { status: 400, body: { error: 'Invalid vault key version' } };

  const rawDevices = payload.devices ?? [];
  const rawItems = payload.items ?? [];
  if (!Array.isArray(rawDevices) || rawDevices.length > MAX_IMPORT_DEVICES) {
    return { status: 400, body: { error: 'Invalid vault devices' } };
  }
  if (!Array.isArray(rawItems) || rawItems.length > MAX_VAULT_ITEMS) {
    return { status: 400, body: { error: 'Invalid vault items' } };
  }
  const devices = rawDevices.map(importDevice);
  const items = rawItems.map(importItem);
  if (devices.some(device => !device) || items.some(item => !item)) {
    return { status: 400, body: { error: 'Invalid vault import' } };
  }
  const deviceIds = new Set(devices.map(device => device?.id));
  const itemIds = new Set(items.map(item => item?.id));
  if (deviceIds.size !== devices.length || itemIds.size !== items.length) {
    return { status: 400, body: { error: 'Invalid vault import' } };
  }
  const storage = (items as Array<Record<string, unknown>>).reduce(
    (total, item) => total + (item.payload as string).length + (item.item_key_wrapped as string).length,
    0,
  );
  if (storage > MAX_VAULT_STORAGE_CHARS) return { status: 400, body: { error: 'Vault item storage limit reached' } };

  const kdfParams = JSON.stringify(keys.kdf_params);
  const existing = await readEnvelope(db, userId);
  if (existing) {
    const sameEnvelope =
      existing.salt === keys.salt &&
      existing.recovery_salt === keys.recovery_salt &&
      existing.kdf_params === kdfParams &&
      existing.wrapped_vk === keys.wrapped_vk &&
      existing.recovery_blob === keys.recovery_blob &&
      existing.vk_version === keys.vk_version;
    if (!sameEnvelope) return { status: 409, body: { error: 'vault_import_conflict' } };
  }

  const match = 'EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ? AND salt = ? AND wrapped_vk = ? AND vk_version = ?)';
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        `INSERT INTO vault_keys (user_id, salt, recovery_salt, kdf_params, wrapped_vk, recovery_blob, vk_version, created_at, updated_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM vault_keys WHERE user_id = ?)`,
      )
      .bind(
        userId,
        keys.salt as string,
        keys.recovery_salt as string,
        kdfParams,
        keys.wrapped_vk as string,
        keys.recovery_blob as string,
        keys.vk_version as number,
        timestamp(keys.created_at) ?? new Date().toISOString(),
        timestamp(keys.updated_at) ?? new Date().toISOString(),
        userId,
      ),
  ];
  if (devices.length > 0) {
    statements.push(
      db
        .prepare(
          `INSERT OR IGNORE INTO device_keys (id, user_id, label, state, peer_pub, approved_pub, wrapped_vk, created_at, expires_at, last_seen_at)
           SELECT json_extract(value, '$.id'), ?, json_extract(value, '$.label'), json_extract(value, '$.state'),
             json_extract(value, '$.peer_pub'), json_extract(value, '$.approved_pub'), json_extract(value, '$.wrapped_vk'),
             json_extract(value, '$.created_at'), json_extract(value, '$.expires_at'), json_extract(value, '$.last_seen_at')
           FROM json_each(?) WHERE ${match}`,
        )
        .bind(userId, JSON.stringify(devices), userId, keys.salt as string, keys.wrapped_vk as string, keys.vk_version as number),
    );
  }
  if (items.length > 0) {
    statements.push(
      db
        .prepare(
          `INSERT OR IGNORE INTO vault_items (id, user_id, item_key_wrapped, payload, kind, vk_version, created_at, updated_at)
           SELECT json_extract(value, '$.id'), ?, json_extract(value, '$.item_key_wrapped'), json_extract(value, '$.payload'),
             json_extract(value, '$.kind'), json_extract(value, '$.vk_version'), json_extract(value, '$.created_at'), json_extract(value, '$.updated_at')
           FROM json_each(?) WHERE ${match}`,
        )
        .bind(userId, JSON.stringify(items), userId, keys.salt as string, keys.wrapped_vk as string, keys.vk_version as number),
    );
  }

  const stable = async (): Promise<Record<string, unknown> | null> => {
    const current = await readEnvelope(db, userId);
    if (
      current &&
      current.salt === keys.salt &&
      current.recovery_salt === keys.recovery_salt &&
      current.kdf_params === kdfParams &&
      current.wrapped_vk === keys.wrapped_vk &&
      current.recovery_blob === keys.recovery_blob &&
      current.vk_version === keys.vk_version
    ) {
      return { vk_version: current.vk_version };
    }
    return null;
  };

  try {
    const results = await db.batch(statements);
    if (results.some(result => !result.success)) {
      return { status: 500, body: { error: 'Failed to import vault' } };
    }
    if ((results[0].meta.changes ?? 0) !== 1) {
      const current = await stable();
      if (!current) return { status: 409, body: { error: 'vault_import_conflict' } };
      return { status: 200, body: { success: true, imported: false, vk_version: current.vk_version } };
    }
    return { status: 200, body: { success: true, imported: true, vk_version: keys.vk_version } };
  } catch {
    // A concurrent import can win the single-flight race; its rows are the
    // same opaque values, so report the stable state rather than failing.
    const current = await stable();
    if (current) return { status: 200, body: { success: true, imported: false, vk_version: current.vk_version } };
    return { status: 409, body: { error: 'vault_import_conflict' } };
  }
}

/**
 * Validate a password-change rewrap against the stored envelope.
 *
 * Auth applies this in the same transaction that replaces the verifier. Returns
 * an error string, or null when the rewrap is safe to apply.
 */
export async function validateVaultRewrap(
  db: D1Database,
  userId: string,
  value: unknown,
): Promise<{ error: string; status: number } | null> {
  const envelope = await readEnvelope(db, userId);
  if (!envelope) {
    return value === undefined ? null : { error: 'No vault is enabled', status: 400 };
  }
  const rewrap = record(value);
  if (!rewrap) return { error: 'vault_rewrap_required', status: 409 };
  if (!isValidB64(rewrap.salt, 16)) return { error: 'Invalid vault salt', status: 400 };
  if (!isValidVaultKdfParams(rewrap.kdf_params)) {
    return { error: 'Unsupported vault KDF parameters', status: 400 };
  }
  if (!isValidWrappedKey(rewrap.wrapped_vk)) return { error: 'Invalid wrapped vault key', status: 400 };
  if (!isVersion(rewrap.vk_version)) return { error: 'Invalid vault key version', status: 400 };
  if (rewrap.vk_version !== envelope.vk_version) {
    return { error: 'vault_key_version_conflict', status: 409 };
  }
  return null;
}
