# Flaxia authentication migration

Migration 0004 installs a database guard before the new Worker is deployed. During that interval, the old Worker's legacy conversion fails rather than deleting the only copy of a legacy hash. Deploy the new Worker promptly and monitor errors; affected users can retry after deployment. Do not remove the guard while old Worker versions or in-flight requests can still write. Rollbacks must preserve this rule.

The guard cannot recover hashes already removed before migration 0004. Before enabling the Flaxia integration, compare the Auth and Flaxia credential states and identify accounts already converted to SRP without a matching legacy fingerprint. Resolve those accounts through a separately verified recovery process; do not silently treat them as matching. Confirm the plan for new registrations, password changes and account deletion across both services before making Auth authoritative.

Legacy fingerprints are sensitive password-derived data. They are removed on credential change or account deletion. Migration 0006 sets a 90-day expiry from creation (existing rows receive 90 days from migration). The exchange rejects expired fingerprints even before the hourly cleanup deletes them. After expiry, affected users need a separately verified recovery process. Monitor expiry and complete account migration before the deadline. Restrict database and backup access and cover backups in the retention decision.

An hourly Worker cron deletes expired authorization codes and Auth sessions; grants attached to deleted sessions are removed by foreign-key cascade. Monitor cron failures and database growth. A failed cron delays physical cleanup but does not extend authorization validity.
