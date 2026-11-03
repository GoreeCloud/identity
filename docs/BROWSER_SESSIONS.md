# GoreeCloud Identity — Server-side browser session primitive

**Status:** Development-only Python integration component, not a deployed login website or production session manager.

The `goreecloud_identity.browser_sessions.BrowserSessionManager` provides a **single-process, in-memory** session and OIDC transaction store for one statically trusted Keycloak realm/client. It depends on the existing Authorization Code + S256 PKCE and signed ID-token verifier; it does not create an HTTP listener, publish a route, replace Gateway authentication or store persistent user credentials.

## Behaviors implemented and tested

- Every login starts with a cryptographically random, short-lived browser cookie and a separate PKCE state, nonce and verifier stored **only on the server**.
- The session cookie is `__Host-gc_identity_session`; every response sets **Secure**, **HttpOnly**, **SameSite=Lax**, **Path=/**, no Domain, and an explicit Max-Age.
- Only the SHA-256 digest of the browser session token is indexed in the in-memory store.
- The callback must present the original cookie and valid OIDC state. The manager atomically consumes the pending transaction **before** contacting the token endpoint, preventing replay and concurrent double redemption.
- A successfully verified identity causes the browser session identifier to rotate. The old pre-login cookie is no longer authorized.
- Pending transactions expire after 5 minutes. Authenticated sessions have an absolute maximum age of 30 minutes, without silent extension.
- Each authenticated session holds a distinct random CSRF token; the store keeps only its digest. `verify_csrf` applies constant-time comparison and refuses unauthenticated, expired or ambiguous browser cookies.
- Logout removes the local authenticated session and sends an expired host-only browser cookie.
- A bounded, lock-protected store rejects new sessions when capacity is exhausted; expired records are pruned on access.

## Required HTTP integration

A future GoreeCloud Identity web application must place the returned `set_cookie` string in an actual `Set-Cookie` response header. It must pass the browser's Cookie request header and complete callback URL into the manager. The CSRF token must be included in a trusted server-rendered form or other approved mechanism—not copied to a cookie or exposed in URLs.

The caller must enforce HTTPS, trustworthy proxy headers, strict input bounds, access controls, session renewal rules, safe redirects, logs free of tokens, throttling, browser-origin/CSRF rules, account-level logout and revocation, user deletion/logout propagation, and secure failure handling. A verified identity is **not** permission to access an application resource.

## Not production-ready

This module stores sessions in **one Python process**. It cannot survive process restarts, coordinate multiple instances, revoke every session for a user, enforce distributed rate limits or use production secret storage. It has no HTTP API, cookie delivery, frontend, database-backed store, Gateway Go adapter or Android integration. These require separate review, testing, backup/recovery and deployment controls.

All tests are synthetic, local and offline; they cover replay prevention, wrong-browser callbacks, session fixation, CSRF, idle-less hard expiry, invalid cookie headers, capacity limits and logout. The disposable Keycloak CI login test also exercises this manager **in-process** against the real synthetic authorization-code exchange, checking session rotation, CSRF acceptance and local logout. It does **not** deliver the cookie through a real web server or prove a deployed browser-facing session service.

**Tracking:** [OIDC integration issue #2](https://github.com/GoreeCloud/identity/issues/2). No production deployment is authorized by this module.
