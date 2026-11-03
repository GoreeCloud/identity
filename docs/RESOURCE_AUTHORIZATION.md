# GoreeCloud Identity — Pinned issuer JWKS and API resource authorization

**Maturity:** development-only original Python libraries. Not deployed to GoreeCloud Gateway, no production API listener, and no claim of complete Zero Trust enforcement.

This integration joins the existing RS256 OAuth bearer-token verifier and explicit deny-by-default policy engine without accepting a JWT-supplied signing-key URI or untrusted resource permissions.

## Trust boundaries

- `goreecloud_identity.jwks_trust.PinnedIssuerKeys` takes an **administrator-configured issuer**, not an incoming JWT claim, request Host, proxy header, user ID, tenant ID or untrusted URL.
- The key source is exactly `{issuer}/protocol/openid-connect/certs` over verified HTTPS, except for the explicitly pinned `http://localhost:8080/realms/goreecloud` development issuer. The HTTP client rejects redirects, ignores system proxy settings, caps reads at 256 KiB and times out after five seconds.
- The response must be a bounded public JWKS with a unique, supported RS256 RSA signing key of at least 2048 bits. Private material, duplicate signing-key IDs, malformed keys and unknown signing IDs are rejected. Unrelated public encryption or other-algorithm keys are ignored.
- Keys are cached for a configurable **30–900 seconds** (default 300 seconds); an unknown signing key can trigger a refresh from the same pinned issuer at most once per 30 seconds by default, rather than making an unlimited number of network requests. Expired or failed refreshes do not silently accept stale signing keys.
- A signing-key cache is **not** a revocation service. For disabled users, compromised credentials or sessions, design a Keycloak-supported online revocation/introspection/short-token-lifetime strategy before production integration.

## Authorization boundary

`goreecloud_identity.resource_server.ResourceAuthorizer` validates the JWT's expected RS256 signature, issuer, resource audience, authorized OAuth client (`azp`), token class `Bearer`, issuance/expiration/lifetime and mandatory scopes. It then converts the verified token to a trusted subject and evaluates explicit resource policies. Any failed authentication is a generic denial. A cryptographically correct token does not grant access absent an allow rule, and an explicit deny overrides allow.

`ResourceIdentityConfig` binds a trusted issuer, audience, client, tenant and required scopes. Verified [PR #14](https://github.com/GoreeCloud/identity/pull/14) now rejects tokens missing a matching signed `goreecloud_tenant` claim (149 tests and Keycloak CI passed). Applications must separately verify resource ownership; a matching tenant claim is not blanket permission. Client IP must come from a trusted peer or validated proxy, not arbitrary forwarded headers.

Policies and trust roots must be privileged application configuration, not computed from request/query/authorization-header fields.

## Verified disposable Keycloak CI evidence

On November 3, 2026, [GitHub Actions run 41720284851](https://github.com/GoreeCloud/identity/actions/runs/41720284851) completed successfully with **142 Python tests** and the real disposable Keycloak public-JWKS retrieval smoke: pinned issuer, RS256 key cache reuse, unknown key rejection, synthetic browser login, actual localhost HTTP cookie/CSRF/logout, database restoration and cleanup. [PR #11](https://github.com/GoreeCloud/identity/pull/11) merged as `8d9ffd21c322fba2be361ddc352d35326d4e76b8`.

These results verify a development integration, **not** a deployed Gateway resource server, key revocation or production token-introspection service.

## Verification

Local tests generate disposable RS256 signing keys and signed JWTs in memory. They cover trusted signing keys and key rotation, cache/refresh rate limiting, unknown/duplicate/private/undersized keys, issuer pinning, signature/audience/client confusion, expiry, required scopes, tenant isolation, role and group policy enforcement, default deny and explicit-deny priority.

GitHub's disposable CI Keycloak runtime invokes `scripts/smoke_jwks_trust.py` to confirm the pinned public key retrieval against actual Keycloak, cache reuse and unknown-key rejection. Adding this script is **not proof** of a passing integration test; only inspect the completed GitHub Actions run before claiming success.

## Still required before Gateway or production

- An independently reviewed Go or other supported server integration with trusted issuer and audience configuration, secure token transport, request authentication and application permissions.
- Trusted key rotation under outages, offline access and eventual-compromise scenarios; tested operational procedures.
- Token introspection/revocation, short token lifetimes, privilege changes, group/tenant membership synchronization, audit events, metrics and incident response.
- Safe client IP attribution and reverse-proxy boundaries.
- Dedicated production HTTPS infrastructure with secrets management, tested backups/restore and permissions.
- Real user MFA/passkeys, UI acceptance, and consent/access governance as appropriate.

See [authorization issue #2](https://github.com/GoreeCloud/identity/issues/2). No VPN, Gateway, DNS or VPS service has been modified by this integration code.
