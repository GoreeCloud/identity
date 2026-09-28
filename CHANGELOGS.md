# GoreeCloud Identity — Changelogs

## 2026-09-27 — Development foundation

- Replaced the placeholder repository baseline with a bounded Development service foundation.
- Added loopback-only operational configuration, health/readiness endpoints, bounded HTTP server limits, graceful shutdown, unit tests, and exact-source CI.
- Established the repository-local project specification and identity/Vault authority boundary.
- Added architecture, security, privacy, feature-lifecycle, and platform-integration records.
- Added a fail-closed registration-policy primitive with tests; it is not connected to an account-creation endpoint.
- No authentication, token, session, credential, production, or Stable capability is established by this milestone.

## 2026-09-27 — Registration policy hardening

- Added a tested fail-closed registration-policy primitive.
- Public registration is denied by default and allowed only when explicitly enabled.
- Administrator provisioning requires an explicit grant; invitation provisioning requires a valid invitation; unknown methods deny.
- The primitive is not connected to an account-creation endpoint and establishes no authentication, credential, session, token, production, or Stable authority.


## 2026-09-27 — Account lifecycle 0.2 candidate

- Added a non-persistent account lifecycle state machine with active, deactivated, and deleted states.
- Added reversible and idempotent deactivation/reactivation.
- Added explicit confirmation-gated permanent deletion and terminal deleted-state enforcement.
- Added fail-closed handling for unknown states and operations, including logout-like operations that belong to separate session/device controls.
- Added deterministic unit tests and repository-governance checks for the lifecycle boundary.
- No persistent account mutation, data deletion, authentication, session/token authority, production deployment, or Stable claim is established.
