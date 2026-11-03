# GoreeCloud Identity — Loopback-only HTTP login example

**Classification:** disposable development example / integration proof, **not a public GoreeCloud Identity web application**, supported reverse proxy, or production BFF.

The example in `src/goreecloud_identity/loopback_app.py` uses Python's standard WSGI HTTP interface to exercise the existing Keycloak Authorization Code + S256 PKCE relying-party and in-process server-side browser-session manager. The listener, when explicitly launched, binds **127.0.0.1:8765 only** and expects the exact local Keycloak issuer at **http://localhost:8080/realms/goreecloud**. The demo requires its test client to be registered separately; the repository's disposable GitHub CI fixture is the only automated client registration provided.

## Routes

| Method / route | Intended behavior |
| --- | --- |
| `GET /` | Shows a local sign-in link, or an authenticated subject and one-use CSRF-protected logout form |
| `GET /login` | Creates server-stored OIDC state/nonce/PKCE verifier, redirects to Keycloak, emits a Secure, HttpOnly, SameSite=Lax, host-only pre-login session cookie |
| `GET /oidc/callback` | Validates the browser's bound transaction, exchanges the Keycloak code, verifies the signed ID token and rotates to a new authenticated session cookie |
| `GET /session` | Returns a minimal no-store JSON authentication status and subject; it is **not** a resource authorization API |
| `POST /logout` | Requires exact loopback Origin plus a session-bound CSRF token; revokes the **local in-memory session** and expires the browser cookie |

Unknown routes, unsupported methods, non-loopback peers, unexpected Host, forwarded proxy headers, malformed callback parameters, duplicate session cookies and invalid CSRF attempts fail closed. No JWTs, refresh tokens, access tokens or PKCE verifiers are stored in browser cookies or printed to logs. The WSGI request handler suppresses request-line logging to avoid leaking authorization codes from callback URLs. Responses use no-store caching, `nosniff`, clickjacking and restrictive Content Security Policy headers.

The in-memory session store now supports issuing fresh per-page CSRF tokens to a server-rendered form while retaining only their SHA-256 digests. Rendering a new form invalidates the previous form's token. The login flow is single-use and rotates identifiers after successful verification.

## Verification

- `python3 -m unittest discover -s tests -v` exercises status codes, cookies, session rotation, per-request CSRF, unauthorized/malformed requests, callback replay, peer/host/proxy restrictions and logout with synthetic verified identities.
- `scripts/smoke_http_app.py` starts a **real loopback HTTP listener in an ephemeral GitHub Actions runner**, uses a randomly credentialed synthetic CI Keycloak user/client, performs the actual Keycloak browser-form Authorization Code + S256 PKCE exchange, checks HTTP `Set-Cookie` headers, verifies authenticated `GET /session`, denies logout with a wrong CSRF token, accepts correct CSRF and verifies logout invalidates the session.
- The CI script checks the authorized GitHub CI environment before creating its listener, prints no secrets and shuts down its HTTP server afterward. Only verified *completed* CI runs establish runtime results; committing the workflow alone does not.

## Strict limitations

**Do not expose this example through a VPS, production hostname, proxy, Kubernetes ingress or other internet-facing interface.** It uses local plaintext HTTP because both endpoints are loopback only; production requires reviewed HTTPS, trusted session cookies and proxy configuration, a shared/persistent session store, bounded login attempts, expiry and cleanup, account-level logout/revocation, key rotation, audit logging, resource authorization, actual browser accessibility and GoreeCloud UI acceptance. It has no persistent recovery, production user-management UI, MFA/passkey enrollment, Gateway Go adapter, or Android implementation.

The displayed example page is deliberately minimal and **does not meet GoreeCloud UI visual acceptance**. It must not be presented as the finished GoreeCloud Identity web application.

**Tracking:** [OIDC/app integration #2](https://github.com/GoreeCloud/identity/issues/2), [production recovery #1](https://github.com/GoreeCloud/identity/issues/1), [MFA and UI #3](https://github.com/GoreeCloud/identity/issues/3).
