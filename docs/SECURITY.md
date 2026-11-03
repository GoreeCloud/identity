# Security and production acceptance gate

**Current classification: DEVELOPMENT ONLY. Never expose compose port 8080 beyond localhost.**

## Before any real deployment

- [ ] Select a real hostname, DNS ownership and TLS termination; Keycloak production start mode, strict proxy headers and trusted intermediaries.
- [ ] Replace bootstrap administration patterns with a controlled operator credential/recovery plan; configure MFA for administrators.
- [ ] Store database and bootstrap credentials in approved secret storage, not cleartext env files copied to servers.
- [ ] Configure verified SMTP before enabling password recovery and email verification.
- [ ] Configure OIDC clients with exact redirect URIs, minimal scopes, PKCE, confidential-client restrictions where appropriate, and session policies.
- [ ] Integrate and verify the offline-tested [in-memory browser session primitive](BROWSER_SESSIONS.md) behind a real HTTPS application boundary; test delivered Secure/HttpOnly/SameSite cookies, actual browser CSRF/session rotation, callback replay, multi-process safety, account logout and revocation. The code alone does not establish any deployed HTTP session service.
- [ ] Replace the [loopback-only HTTP test example](LOOPBACK_HTTP.md) with a reviewed production service before any public access. Real HTTPS, distributed sessions, rate limits, auditability and GoreeCloud UI acceptance remain unverified.
- [ ] Audit trusted JWKS acquisition and rotation, issuer/audience/client restrictions, API authorization and live revocation requirements before integrating the optional token verifier.
- [ ] Review and load-test the optional [pinned-issuer JWKS cache](RESOURCE_AUTHORIZATION.md) with real application key rotation and issuer outages. Offline and CI development tests do not establish production revocation or Keycloak Gateway integration.
- [ ] Perform browser-based end-to-end authentication, logout, revocation, CSRF and account-recovery tests. The synthetic CI form-login test is not a substitute for real app sessions, logout or revocation acceptance.
- [ ] Test realm import behavior, upgrades, restores and rollback using non-production identity data.
- [ ] Encrypt and restore-test persistent production database backups; document recovery point and recovery time objectives. The CI-only disposable restore smoke is not a substitute.
- [ ] Secure database and internal management ports and protect metrics.
- [ ] Review Keycloak version advisories and image digests; add dependency/container scanning.
- [ ] Verify per-tenant authorization isolation; no role name alone grants cross-tenant access.
- [ ] Review logs for privacy, retention, least privilege and detection efficacy.
- [ ] Verify login theme with mobile/desktop, keyboard, screen reader, dark/light and contrast testing.
- [ ] Set up CI integration tests for OIDC discovery, login, MFA, refresh, revocation and failure scenarios.
- [ ] Review third-party licenses and founder's GoreeCloud-owned source license.
- [ ] Approve production deployment and a safe cutover explicitly.

## Local-dev safety

- Compose binds Keycloak to `127.0.0.1` only.
- PostgreSQL is not published as a host port.
- Secret generator writes `.env` with owner-only permissions and refuses to overwrite it.
- Realm bootstrap disables public signup and brute-force protection is enabled.
- Password reset is OFF until an email gateway is safely configured.
- No actual user accounts, API clients or shared secrets are checked into Git.

**Limitation:** Passing source unit tests does not validate the Keycloak binary, container configuration, upstream dependencies, MFA, security of forwarded headers or real production readiness.
