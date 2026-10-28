# Flaxia authentication migration

Migration 0004 installs a database guard before the new Worker is deployed. During that interval, the old Worker's legacy conversion fails rather than deleting the only copy of a legacy hash. Deploy the new Worker promptly and monitor errors; affected users can retry after deployment. Do not remove the guard while old Worker versions or in-flight requests can still write. Rollbacks must preserve this rule.

The guard cannot recover hashes already removed before migration 0004. Before enabling the Flaxia integration, compare the Auth and Flaxia credential states and identify accounts already converted to SRP without a matching legacy fingerprint. Resolve those accounts through a separately verified recovery process; do not silently treat them as matching. Confirm the plan for new registrations, password changes and account deletion across both services before making Auth authoritative.

Legacy fingerprints are sensitive password-derived data. They are removed on credential change or account deletion. Migration 0006 sets a 90-day expiry from creation (existing rows receive 90 days from migration). The exchange rejects expired fingerprints even before the hourly cleanup deletes them. After expiry, affected users need a separately verified recovery process. Monitor expiry and complete account migration before the deadline. Restrict database and backup access and cover backups in the retention decision.

An hourly Worker cron deletes expired authorization codes and Auth sessions; grants attached to deleted sessions are removed by foreign-key cascade. Monitor cron failures and database growth. A failed cron delays physical cleanup but does not extend authorization validity.

## Restore and removal procedure

The live database retains each fingerprint for at most 90 days from its creation; existing rows receive a 90-day window when migration 0006 is applied. Hourly cleanup removes expired rows, and exchanges refuse them immediately at expiry. Restrict backups containing these rows to the same administrators as the live Auth database and expire each backup no later than 90 days after the backup is taken. Record and verify the storage provider's backup deletion configuration; the application cannot erase provider-managed backups.

Before a restored database is connected to any Worker, apply all migrations and run this on the isolated restored database:

```sql
DELETE FROM flaxia_legacy_fingerprints
WHERE expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
```

Then confirm `SELECT count(*) FROM flaxia_legacy_fingerprints WHERE expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` returns zero. Run the same deletion on the live database for an emergency purge, followed by the count check. For early removal of all fingerprints after the transition is complete, use `DELETE FROM flaxia_legacy_fingerprints` and confirm the table is empty; this immediately disables legacy account matching. Do not perform this early purge until affected users have a verified recovery path. Record the purge and make sure no old Worker remains active before reopening the service.

Migration 0007 records users whose Auth credentials may be shared with Flaxia. Legacy conversion and successful code redemption record this guard atomically, and existing grants and fingerprints are backfilled. The standalone Auth SRP upgrade rejects guarded users until a coordinated credential-change flow exists; the record survives grant and fingerprint cleanup. A redeemed code can create the guard even if Flaxia later rejects the exchange. Accounts whose grants and fingerprints were already removed before migration cannot be identified by this backfill and require separate inventory before rollout. This guard is a temporary safety measure, not a completed password-change or recovery flow.
