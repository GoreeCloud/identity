# Disposable OIDC login integration test

**Classification:** GitHub-hosted, CI-only end-to-end authentication verification. Not an application, production login page, production identity deployment or permission to change existing services.

## Verified CI evidence

**November 3, 2026:** [GitHub Actions run 41659751802](https://github.com/GoreeCloud/identity/actions/runs/41659751802) completed successfully after [PR #8](https://github.com/GoreeCloud/identity/pull/8) introduced an actual synthetic browser login, Authorization Code + S256 PKCE exchange, and signed ID-token check. All 84 offline tests passed, as did disposable Keycloak startup, OIDC discovery, identity login, restart, PostgreSQL restore, container shutdown and synthetic-credential cleanup. Merged to `main` as `51e33abbece18f4f56ad99101222d03476d42531`.

This is evidence for the disposable CI authentication path only, **not** for secure production browser sessions, MFA, or Gateway SSO.

## Test scope

The CI job exercises the real Keycloak realm loaded in disposable containers. Immediately before container startup, `scripts/prepare_ci_login_fixture.py` adds exactly one public OIDC client and one randomly credentialed synthetic user to the runner's checked-out development realm. The committed `realm/goreecloud-realm.json` remains unchanged.

The public test client has exact redirect URI `http://127.0.0.1:8765/oidc/callback`, Authorization Code enabled, S256 PKCE required, and direct-password, implicit, service-account and client-secret grants disabled. The client uses the development-only issuer `http://localhost:8080/realms/goreecloud`, which is bound to loopback by Docker Compose.

After Keycloak starts, `scripts/smoke_login.py`:

1. Validates strict OIDC discovery and obtains signing keys from the configured issuer.
2. Generates a fresh authorization code request with random state, nonce and S256 PKCE verifier.
3. Uses a local cookie jar to submit the synthetic credentials to the **real Keycloak browser login form** (not the OAuth resource-owner password grant).
4. Intercepts the callback redirect without sending any request to the non-existent callback listener.
5. Exchanges the authorization code at Keycloak's pinned local token endpoint with the original PKCE verifier.
6. Verifies the returned ID token's RS256 signature and expected issuer, client audience, nonce and expiry through the in-memory browser-session manager.\n7. Confirms the pre-login session cookie was rotated away, the authenticated session is present, its CSRF token verifies, and local logout removes it. The test still does not serve HTTP application cookies to a real browser. Only high-level pass/fail results are printed.

Redirects and form actions are restricted to the local realm and login-action paths. JSON responses and HTML are size-bounded, network timeouts are finite, redirects from the transport layer are disabled, and proxy environment variables are ignored.

Keycloak 26 may mark its browser authentication cookies `Secure` even for its localhost development server. The **CI-only** browser adapter makes a narrowly scoped secure-context exception for `http://localhost:8080`, matching browser localhost behavior while rejecting that exception for other HTTP origins. This never changes Keycloak's cookies, transport settings, or any real application cookie policy.

All fixture secrets exist only on the disposable runner, in an owner-readable temporary file and temporary realm import representation. No live account, real email address, secret, token, login callback URL, browser HTML or production hostname should be displayed in CI output or published as an artifact.

A separate **CI socket-level HTTP smoke** in `scripts/smoke_http_app.py` exercises the loopback WSGI demonstration with the same disposable synthetic Keycloak fixture: actual HTTP `Set-Cookie` delivery, login callback, authenticated session, rejected invalid CSRF logout and verified local logout. This adds an HTTP interface test, but does not make the app publicly deployed or production-ready.

## Safety and scope restrictions

- The fixture generator checks that the process is inside GoreeCloud's GitHub CI and that Docker Compose declares the expected loopback Keycloak listener, unexposed PostgreSQL service, development startup command and local hostname. It refuses any nonempty users or OAuth clients in the original realm.
- No test script is intended to run on production/VPS hosts. Do not weaken these guards to make a test pass.
- GitHub Actions stops the temporary containers and deletes generated fixture credentials, then restores the original realm JSON in its ephemeral working copy.
- A passing test proves the disposable synthetic user could complete one actual browser-form Authorization Code + PKCE exchange. It **does not** test reusable server-side browser sessions, production HTTPS, MFA, Gateway integration, Android, persistent refresh/logout, token revocation, key rotation, audit retention or production disaster recovery.
- Keycloak imports are not a general-purpose backup or migration strategy. Production recoverability remains independently tracked.

## Next application integration

Integrate a server-side relying party with strict secure/HttpOnly/SameSite browser cookies, session-id rotation, CSRF protections, signed-in session persistence, logout and revocation, tenant/resource policy enforcement, and tested key rotation. Integrate GoreeCloud Gateway's existing Go console only through a reviewed compatibility adapter; never remove its current bearer-token safeguards before a verified cutover.

**Tracking:** [OIDC issue #2](https://github.com/GoreeCloud/identity/issues/2), [recovery issue #1](https://github.com/GoreeCloud/identity/issues/1), and [MFA/UI issue #3](https://github.com/GoreeCloud/identity/issues/3).
