# GoreeCloud Identity — Architecture

**Status:** Initial development architecture; runtime integration and threat-model acceptance pending.

## Trust boundaries

The Keycloak realm named `goreecloud` is the authoritative issuer for its tenant. PostgreSQL stores identity state behind a private container network. A browser connects to loopback-only Keycloak in development. The local administrator creates applications and user accounts manually; no default public client or privileged product user is imported.

Keycloak supplies upstream identity protocols and account consoles. GoreeCloud authors compose configuration, a theme, setup checks and a separate policy-example library. Do not confuse the latter with a security enforcement point: `evaluate()` requires authenticated subject metadata obtained after full token verification by a reputable OIDC library.

## Production target (not implemented)

- Dedicated hardened Keycloak runtime behind approved HTTPS termination; strict hostname, reverse-proxy and forwarding-header verification.
- Secure secrets, explicit operator recovery, database backups with tested restores, isolation and patch automation.
- OIDC integration with GoreeCloud Gateway and application-level authorization enforcement.
- SAML and LDAP federation as appropriate, without replicating third-party credentials into an unreviewed store.
- MFA/passkey enrollment, self-service, secure recovery and restricted administrative access.
- Federated identity and privileged/remote access connectors introduced separately after protocol and license reviews.

## Design source

The [GoreeCloud UI](https://github.com/GoreeCloud/gc-ui) repository is the authority for semantic CSS roles (`--gc-*`), 4px spacing increments and 12/18/26/36px corner progression. The current login theme is an initial implementation and has **not** been screenshot-audited against desktop/mobile and accessibility acceptance requirements.

## Risks and invariants

1. One issuer per authority boundary; no conflicting parallel identity stores.
2. Protect client secrets, signing keys and session material; never commit any secrets.
3. Explicit deny by default for resources; issuer, audience and signature validation is mandatory before policies.
4. Do not accept trusted client IP addresses from arbitrary user-controlled forwarding headers.
5. No production rollout without owner-approved cutover, rollback, backups, security review and app-level compatibility testing.
