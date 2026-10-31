# Flaxia authentication migration

Flaxia Auth D1 is the authority for passwords, recovery factors, sessions,
grant revocation and the Personal Vault envelope. Flaxia D1 remains the
application database for profiles, content and, during the transitional
period, any Vault rows created before the Auth-owned store was deployed. In
direct authority mode, Flaxia D1 does not retain password verifiers, SRP
handshakes, Auth grants or recovery codes. It keeps only a profile-to-Auth
link and hashed, retryable operation records. New Vault writes go through Auth
at `/api/vault/*` or the service-bound `/api/flaxia/vault` proxy; no Vault
secret or wrapped item is copied into Flaxia during a credential change.

## Vault cutover

When `AUTH_AUTHORITY_MODE=flaxia-auth`, Flaxia's existing `/api/vault/*`
routes become a proxy to Auth. The first request for a user who still has rows
in Flaxia D1 copies the envelope, device rows and encrypted items through
`POST /api/flaxia/vault/import`. The import is idempotent, rejects a different
existing envelope, and the local rows are deleted only after Auth confirms the
same envelope. Everything transferred is already client-wrapped ciphertext;
the password, KEK, REK, VK, item keys and recovery phrase never leave the
browser.

Password changes consult the Auth-owned version and send the encrypted rewrap
with the prepared credential change. Auth applies the verifier, envelope and
item-version bump in one transaction. Flaxia no longer stages a rewrap for an
Auth-owned Vault; the old `flaxia_direct_vault_changes` and
`flaxia_auth_credential_jobs.vault_json` paths remain only for accounts that
have not completed the import.

## Account migration

Existing accounts link only when the Auth identity and Flaxia profile refer to
the same account and their credential fingerprints match. The exchange uses a
credential proof; names and email addresses alone never link accounts. A
successful link purges the Flaxia verifier, legacy hash, local sessions, SRP
handshakes, Auth grant snapshots and provisioning snapshot. Auth deletes the
legacy fingerprint at link completion. Repeating an exchange after an
interrupted request is safe.

The service-bound provisioning endpoint can copy a local SRP verifier to Auth
for a retry-safe migration. It does not overwrite an existing Auth identity.
A provisioning guard pauses local credential changes and deletion until the
first successful Auth exchange links and purges the account. Keep authority
mode disabled until inventory confirms every eligible account is linked, each
user has an Auth recovery factor, and clients use the Auth login. Accounts
whose local password is no longer available as an SRP verifier, whose Auth and
Flaxia identities conflict, or whose fingerprints expired require verified
account recovery before rollout. Matching a username or email is never enough.
The current deployment has no automated two-account merge path; keep those
accounts out of the rollout until a separately verified process resolves them.

## Registration and recovery

New registration creates the credential only in Auth. The authenticated Auth
identity creates or links its Flaxia application profile; a conflicting
username or email fails closed. Existing users enroll an independent,
browser-generated 256-bit recovery code while they still know their password.
Auth stores only the SRP salt and verifier for that code. Recovery verifies the
code through SRP, revokes prior Auth sessions and outstanding handshakes, and
lets the user set a new password. The browser separately uses the Vault
recovery phrase to rewrap the Vault key. Neither recovery secret is sent to
Flaxia or Auth.

## Credential and email changes

Password changes require an Auth SRP proof. Auth stores the new verifier and a
short-lived recovery capability. The browser sends the encrypted Vault rewrap
with the same operation; Auth applies the new verifier, the VK rewrap and the
item-version bump in one D1 transaction, then revokes other sessions. Retries
reconcile either side after a timeout; cancellation tombstones prevent an old
delayed request from applying later. A successful change deletes the legacy
fingerprint immediately. Flaxia no longer needs to stage the rewrap in its own
database for new Vault rows; that staging path remains only for pre-migration
rows that have not been copied to Auth yet.

Email changes reserve the new Flaxia profile address, then update Auth after
SRP proof. A hashed Auth receipt lets Flaxia finish the profile update after a
lost reply. Email is not a recovery factor and is not treated as verified.

## Deletion

Deletion requires an Auth SRP proof. Auth records a hashed receipt and revokes
the grant. Flaxia's deletion job stores a user ID and operation hash, then
removes application data atomically after Auth confirms the receipt. The
browser and scheduled Worker can retry. Cancellation tombstones prevent a
delayed delete after cancellation. Unreferenced profile images enter a durable
R2 deletion outbox; references are blocked while an object is queued, failed
deletes retry, and successful deletion removes the outbox row. Account
deletion cascades the Auth recovery verifier and removes any fingerprint.

## Fingerprint retention and purge

Legacy fingerprints are sensitive password-derived values that support the
one-time legacy credential comparison. Migration 0006 sets a 90-day expiry;
existing rows receive 90 days from the migration. Exchanges reject expired
fingerprints immediately, while the hourly Auth Worker cron physically deletes
expired rows. Linking, a successful credential change and account deletion
delete the fingerprint earlier.

Keep backups containing fingerprints for no longer than 90 days from the
backup date. Verify the storage provider's backup-retention setting before
rollout; application code cannot delete provider-managed backups. Before
connecting a restored database to any Worker, apply migrations and purge
expired rows on the isolated restore:

```sql
DELETE FROM flaxia_legacy_fingerprints
WHERE expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
```

Confirm the following count is zero before opening traffic:

```sql
SELECT count(*) FROM flaxia_legacy_fingerprints
WHERE expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
```

For an emergency purge, run the same delete and count check against the live
database. After every affected account has migrated or has a verified recovery
path, the entire table can be purged with `DELETE FROM
flaxia_legacy_fingerprints`; confirm it is empty and stop old Worker versions
before reopening service. Record the purge and verify the hourly cron is
healthy. A cron failure delays physical cleanup but does not extend exchange
validity.

## Rollback and release gate

Do not roll back to a Worker that accepts Flaxia-local credentials after an
account's local verifier has been purged. A rollback must preserve Auth as the
credential authority or restore access through the verified Auth recovery
flow. Keep authority mode disabled until migration inventory, backup expiry,
scheduled Worker bindings and independent security review are verified.
These operational and identity-conflict gates are not established by the code
changes alone.
