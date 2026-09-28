# GoreeCloud Identity

GoreeCloud Identity is the planned privacy-first, self-hosted identity and authentication authority for GoreeCloud applications and services.

> **Current status:** Active Development. The repository contains a bounded Go service foundation with loopback-only operational health/readiness endpoints, configuration validation, tests, and CI. It does not yet authenticate users, issue sessions or tokens, store credentials, or provide production identity authority.

## Authority boundary

Identity owns identity and authentication decisions. GoreeCloud Vault remains authoritative for protected credentials, passkeys, authentication secrets, recovery material, and application secrets. Identity must integrate with Vault rather than create a competing secret store.

## Development foundation

The current service listens only on explicit loopback addresses through `GOREECLOUD_IDENTITY_ADMIN_LISTEN`, defaulting to `127.0.0.1:8860`. It exposes only `/healthz` and `/readyz`.

## Documentation

- [Project specifications](PROJECT-SPECIFICATIONS.md)
- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [Privacy](PRIVACY.md)
- [Implemented features](IMPLEMENTED-FEATURES.md)
- [Planned features](PLANNED-FEATURES.md)
- [Project record](PROJECT-RECORD.md)
- [Changelog](CHANGELOGS.md)

No production, release-candidate, or Stable status is established.
