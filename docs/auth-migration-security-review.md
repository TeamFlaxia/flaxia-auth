# Auth migration security review

Status: release blocking. This review covers the draft integration and does not replace independent review or production verification.

## Findings

1. Credential updates across Auth and Flaxia are not atomic. Auth's SRP upgrade can change its verifier independently; Flaxia still compares its copied credential and can have a vault wrapped under the previous password. A failure between writes can prevent login or strand a vault envelope. Auth-backed password changes remain blocked until a retryable, durable protocol coordinates the verifier and the version-checked vault rewrap across both databases. Test crashes and timeouts at every step and concurrent changes.
2. Registration creates independent identities in Auth and Flaxia. An equal username is not proof of identity; never auto-link accounts by username or email. Registration needs a server-validated binding and a recoverable provisioning protocol.
3. Account deletion is blocked for Auth sessions. Local-only deletion would leave the Auth account and other grants valid; deleting Auth first can make a partial local deletion impossible to retry. A durable, authenticated deletion state machine must revoke access before cleanup and safely resume after failure.
4. Recovery of an account whose copied credentials diverged has no verified identity proof. The Vault recovery phrase decrypts Vault keys locally; the server cannot treat it as an account authentication factor. A separate authenticated recovery design is required, and must not send the recovery phrase to either server.
5. Legacy fingerprints permit offline guesses against a password-derived hash if the Auth database is exposed. Migration 0006 limits active use and storage to 90 days; restoring an older backup can reintroduce rows, so expired rows must be purged immediately after restore, before service is enabled. Backups require restricted access and a documented expiration schedule. Expiry makes legacy matching unavailable; keep the existing Flaxia login and a verified recovery path available until migration is complete.
6. Grant tokens are stored in plaintext in Flaxia D1, because they must be presented to Auth. A database reader can use them against the private bridge if it also controls the binding; restrict database and service-binding access, and do not log grant tokens. Auth stores only grant hashes.

Existing mitigations include verifier-bound one-time codes, service-binding-only bridge endpoints, grant/session-bound reauthentication, session revocation checks, origin checks, and Vault version checks. These do not resolve the findings above. Keep authority mode disabled and both PRs in draft until the lifecycle protocol, recovery, operational migration, and independent review are complete.
