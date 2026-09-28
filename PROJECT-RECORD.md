# GoreeCloud Identity — Project Record

## September 27, 2026 — Account lifecycle 0.2 candidate

- Added `internal/account` with explicit active, deactivated, and deleted lifecycle states.
- Deactivation and reactivation are reversible/idempotent domain transitions.
- Permanent deletion requires an explicit confirmation flag and moves to a terminal deleted state.
- Deleted accounts reject later lifecycle transitions.
- Unknown operations fail closed; logout-like operations are deliberately not account lifecycle transitions.
- Extended repository governance to require the lifecycle source and negative-path tests.

### Verification boundary

This is a non-persistent Development domain model. It does not create, store, deactivate, reactivate, or delete real accounts or user data; does not revoke sessions/devices; and does not establish authentication, production identity authority, or Stable status.


## Current verified state

- **Repository:** `GoreeCloud/identity`
- **Repository ID:** `1391515397`
- **Default branch:** `main`
- **Lifecycle:** Development
- **Initial repository state:** placeholder README only
- **Current candidate state:** bounded Go service foundation plus repository-local governance records

## September 27, 2026 — Development foundation

The repository gained its first executable Development source:

- Go service entry point;
- explicit loopback-only operational listener configuration;
- health and readiness endpoints;
- bounded HTTP server resources and graceful shutdown;
- deterministic unit tests and exact-source CI;
- a fail-closed registration-policy primitive with tests. It is not connected to an account-creation endpoint and creates no identities by itself.

The repository also gained an initial project specification based on the verified Identity product role and current GoreeCloud governance. No prior authoritative Identity project-specification file was located in the connected migration-source records during this baseline.

## Authority boundary

GoreeCloud Identity is intended to become the authoritative identity and authentication decision service. GoreeCloud Vault remains authoritative for protected credentials, passkeys, authentication secrets, recovery material, and application secrets.

## Verification boundary

This milestone is Development source evidence only. It does not establish user authentication, token/session authority, credential storage, production deployment, production acceptance, Release Candidate status, or Stable status.
