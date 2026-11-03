# GoreeCloud Identity — OIDC relying-party development contract

**Status:** Development-only Authorization Code + PKCE core and ID-token validation. No browser session server, registered application, live user login, or Gateway SSO has been deployed.

## What the module provides

The original Python module `src/goreecloud_identity/oidc.py` validates a trusted, explicitly configured Keycloak realm issuer and exact OIDC discovery endpoints. It constructs Authorization Code requests with random CSRF state, nonce, and S256 PKCE challenge; checks callback URI, state, issuer parameter, expiration, and single use; exchanges a code through the pinned token endpoint; and validates RS256-signed ID tokens, audience, nonce, lifetime, authorized party, and optional access-token hash using PyJWT/cryptography.

The `StrictTransport` has no proxy-environment inheritance, does not follow redirects, uses finite timeouts and bounded JSON responses, and only permits fixed realm-scoped discovery, JWKS and token endpoints. Signing keys must originate from the designated trusted issuer, not token headers or incoming user data.

## Integration requirements

- A web application's **server-side** session must store each `PendingFlow` privately and bind it to the requesting browser. It must use secure, HttpOnly, SameSite cookies, rotate the session at sign-in, and prevent session fixation. The module does **not** implement session storage or cookies.
- A deployment must register its exact client ID and redirect URI with Keycloak; the module does not provision clients or users. Local HTTP is allowed only for the explicit loopback development issuer and redirect pair.
- The returned `VerifiedIdentity` establishes identity, **not resource authorization**. Enforce application roles/scopes/tenant isolation separately; continue using short-lived tokens, logout, and appropriate revocation.
- Production must introduce protected server-side sessions, reliable JWKS caching and rotation, trusted proxy configuration, HTTPS, error handling and end-to-end browser tests. Do not store OAuth tokens or PKCE verifiers in client-side storage or logs.
- The Gateway console remains a separate Go service protected by its existing static bearer token. This Python library does not replace its authentication mechanism.

## Verification boundaries

Unit tests use generated synthetic RSA signing keys and a stubbed token endpoint to validate success, replay prevention, malformed callbacks, issuer/audience/nonce confusion, expiry, token type, signing-key restrictions and PKCE URL construction. Such tests do not establish successful browser login or that a real Keycloak client exchange succeeds. An end-to-end Keycloak client registration, login and callback test remains required in [issue #2](https://github.com/GoreeCloud/identity/issues/2).

**Production readiness: NOT ESTABLISHED.** No VPS, DNS, Caddy/Gateway or identity services are modified by these files.
