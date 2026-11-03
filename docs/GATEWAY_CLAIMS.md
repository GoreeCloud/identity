# GoreeCloud Identity — Gateway access-token claim contract

**Maturity:** Verified **disposable CI integration test**, not production SSO, Gateway deployment, or a permanent Keycloak realm configuration.

## Verified result

On **November 3, 2026**, [GitHub Actions run 41737527198](https://github.com/GoreeCloud/identity/actions/runs/41737527198) completed successfully on the merged-tenant-fix branch with **161 Python unit tests**. Disposable Keycloak 26.8.1 issued a real Authorization Code + S256 PKCE access token carrying the exact synthetic Gateway resource audience, authorized OAuth client, required scope, realm role, and signed tenant claim. The access token passed issuer/JWKS/RS256 verification, and validation for a different resource audience was denied.

The CI run also passed OIDC discovery, browser login, in-process session rotation, real localhost HTTP cookie/CSRF/logout, Keycloak container restart, and an isolated PostgreSQL archive/restore. [PR #12](https://github.com/GoreeCloud/identity/pull/12) merged the contract into Identity.

## Disposable-only fixture

`scripts/prepare_ci_login_fixture.py` starts from the checked-in empty-user/empty-client development realm and generates one randomly credentialed **CI-only** user and one public browser client with an exact `127.0.0.1` callback. It disables implicit, direct-password, and service-account grants and requires S256 PKCE.

The client is restricted to the `gateway-reader` realm role, with `fullScopeAllowed=false`. A minimal `basic` scope contributes the signed OAuth access-token subject, `profile` satisfies the OIDC browser request, and `gateway:read` contributes only the synthetic resource audience `goreecloud-gateway-console`, realm role, and `goreecloud_tenant=family` in access-token claims. No real user or production tenant is involved.

The temporary realm is imported only into ephemeral localhost Keycloak and PostgreSQL containers in a GitHub-hosted runner. Test credentials are stored in a private temporary file, never committed or printed, and are deleted during CI cleanup; the checked-in realm file is restored.

## Verification boundary

`scripts/smoke_gateway_claims.py` performs the real code exchange, verifies its ID token and OAuth access token using trusted issuer keys and a strict audience/client/tenant/scope policy, checks the Gateway role, and confirms wrong-audience denial. Diagnostics report only fixed failure categories and never raw tokens, claims, callback URLs, or credentials.

This verifies **Identity issuing the intended resource token**. It does **not** demonstrate a running Go Gateway accepting it. Gateway's optional Go OIDC verifier remains disabled by default; there is no deployed PKCE web/Android login, production HTTPS, shared session storage, live revocation, incident key rotation, or independently verified resource ownership.

**Next acceptance:** Exercise the actual [Gateway Go verifier](https://github.com/GoreeCloud/gateway/issues/14) with a test-issued token over a correctly configured trusted HTTPS issuer, test negative cases, then separately review deployment, rollback and operational security.

Related: [Identity issue #2](https://github.com/GoreeCloud/identity/issues/2) and [Gateway issue #14](https://github.com/GoreeCloud/gateway/issues/14).
