# GoreeCloud Identity

GoreeCloud Identity is the planned privacy-first, self-hosted identity and authentication authority for GoreeCloud applications and services.

> **Current status:** Active Development. The repository contains a bounded Go service foundation plus a tested fail-closed registration-policy primitive. Public registration is disabled by default; explicit administrator or valid-invitation paths can be represented. The service does not yet authenticate users, issue sessions or tokens, store credentials, create accounts, or provide production identity authority.

## Authority boundary

Identity owns identity and authentication decisions. GoreeCloud Vault remains authoritative for protected credentials, passkeys, authentication secrets, recovery material, and application secrets. Identity must integrate with Vault rather than create a competing secret store.

## Development foundation

The current service listens only on explicit loopback addresses through `GOREECLOUD_IDENTITY_ADMIN_LISTEN`, defaulting to `127.0.0.1:8860`. It exposes only `/healthz` and `/readyz`. The registration-policy code is a domain primitive and is not connected to an HTTP account-creation endpoint.

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
