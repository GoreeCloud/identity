# GoreeCloud Identity — Project Specifications

## Document status

- **Product:** GoreeCloud Identity
- **Repository:** `GoreeCloud/identity`
- **Lifecycle:** Development
- **Authority:** Repository-local project specification
- **Reconciled:** September 27, 2026

No prior authoritative GoreeCloud Identity project-specification file was located in the connected migration-source records during this baseline. This specification records the verified product role and current governance boundaries without claiming unrecovered historical implementation.

## Purpose

GoreeCloud Identity is the planned authoritative identity and authentication decision service for GoreeCloud applications and services. It will provide consistent principal identity, authentication state, sessions, delegated authority, device/service identity context, and standards-based federation while remaining self-hosted, privacy-first, and interoperable.

GoreeCloud Vault remains authoritative for protected credentials, passkeys, authentication secrets, recovery material, and application secrets. Identity must request authorized Vault operations rather than become a competing protected credential store.

## Current Development boundary

The current repository implements a loopback-only operational service foundation with health/readiness endpoints, configuration validation, tests, CI, and a bounded registration-policy primitive. The policy defaults public registration to disabled, permits administrator-authorized or valid-invitation provisioning inputs, and fails closed for unknown methods. It is not connected to an account-creation endpoint and creates no identities. The repository does not authenticate users, store credentials, issue tokens, create sessions, expose federation endpoints, enroll passkeys, process multi-factor authentication, or authorize application actions.

## Target capability areas

Planned areas include user, service, and device identities; standards-based authentication and federation; secure sessions and revocation; passkey and multi-factor authentication integration; account recovery; roles, groups, delegated authority, and application registration; privacy-minimized audit events; administration APIs and Glaze UI; directory interoperability where justified; and secure backup, recovery, migration, and portability.

## Security and privacy requirements

Security-bearing authentication, session, recovery, and signing-key behavior requires explicit design and review before production authority is accepted. Identity must use established libraries and reviewed standards rather than custom cryptographic primitives.

Identity data must be minimized. Applications should receive only claims needed for an authorized purpose. Logs and telemetry must not contain reusable credentials, protected authenticator material, recovery secrets, or unnecessary personal data.

## Platform integration

The product must evaluate all applicable Integral Platform Systems: GoreeCloud Manager, Privacy Shield, Wardveil Security, Everkeep, Glaze UI, GoreeCloud Mesh, GoreeCloud Identity as the producer authority, GoreeCloud Policy, and GoreeCloud Observability.

GoreeCloud Sync remains separately governed and is not a tenth Integral Platform System.

## Release boundary

Source presence, passing CI, or a running process does not establish production authentication authority. Production approval requires exact-revision evidence, security/privacy review, recovery and rollback evidence, platform integration acceptance, target-environment validation, and an explicit release lifecycle decision.

## Account creation baseline

Hosted GoreeCloud account creation must be administrator-controlled or invitation-based by default. Public registration is an explicit administrative option, never an implication of public reachability. If registration-policy state is missing, malformed, stale, or unknown, account creation must fail closed to the invite-only/administrator-controlled posture. UI state must not be the enforcement boundary; service APIs must enforce the authoritative policy.


## Account lifecycle baseline

Account lifecycle must remain distinct from session and device controls. Deactivation is reversible and does not equal permanent deletion. Reactivation restores the active account lifecycle state. Permanent deletion is an explicit, confirmation-gated terminal transition and must not be inferred from logout, session revocation, device removal, ordinary deactivation, inactivity, or UI state.

The current Development implementation models only these lifecycle transitions in memory. It does not persist account state or execute deletion of credentials, files, backups, audit records, or other data. Future persistence and deletion execution must define retention, legal/operational exceptions where applicable, Everkeep recovery boundaries, privacy evidence, and irreversible deletion semantics before production acceptance.
