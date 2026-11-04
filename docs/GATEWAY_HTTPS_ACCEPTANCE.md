# Disposable HTTPS Keycloak → Gateway Go acceptance

**Status:** Prepared CI configuration only. This document does **not** assert a completed Keycloak-to-Go integration.

## Verified prerequisites

- [Identity PR #12](https://github.com/GoreeCloud/identity/pull/12) and [CI run 41737527198](https://github.com/GoreeCloud/identity/actions/runs/41737527198) proved that disposable Keycloak issues signed OAuth resource tokens with the Gateway audience, authorized client, `gateway:read` scope, `gateway-reader` role, and `goreecloud_tenant=family`.
- [Identity PR #15](https://github.com/GoreeCloud/identity/pull/15) and [CI run 41738382885](https://github.com/GoreeCloud/identity/actions/runs/41738382885) proved that the Python verifier rejects those actual tokens under wrong audience/client/tenant/scope, ID-token substitution, missing signing keys and signature changes.
- The Go Gateway verifier intentionally requires **HTTPS issuer pinning**. The existing Identity CI uses localhost HTTP, so these results are **not** proof of acceptance inside the running Gateway Go resource server.

## Isolated HTTPS acceptance design

[Gateway draft PR #20](https://github.com/GoreeCloud/gateway/pull/20) adds a Go `keycloak_integration`-tagged test, gated to authorized GoreeCloud Identity CI. [Identity draft PR #16](https://github.com/GoreeCloud/identity/pull/16) adds `ci/keycloak-https.compose.yaml` to bind only `127.0.0.1:8443`, pin `KC_HOSTNAME=https://localhost:8443`, and load a short-lived TLS certificate for the disposable Keycloak container.

An authorized runner-only companion fixture still needs to generate synthetic S256-only credentials, register the exact callback, issue access and ID tokens using actual Authorization Code + PKCE, trust the local self-signed certificate without disabling TLS validation, and pass private token files to the Go test. **That fixture write was blocked by connected safety checks and remains unimplemented.** Do not reconstruct credentials from logs or use real identities as a shortcut.

### Separate confidential material

Keep temporary Keycloak TLS certificate/key mounts in `/tmp/goreecloud-keycloak-https-certs`; expose only the certificate and synthetic token test fixtures to the Go test from `/tmp/goreecloud-keycloak-gateway-ci`. Keycloak's UID must be able to read the mounted private key without world-readable permissions. The Go harness requires regular non-symlink fixture files with permissions no broader than owner-only. Remove both directories after the disposable CI run; never commit their contents.

### Required acceptance

1. Exact synthetic HTTPS issuer and signed JWKS verified with test-scoped CA trust; TLS verification **enabled**.
2. Actual Gateway Go verifier accepts a correctly scoped, issuer-pinned Keycloak access token through the read-only console route. The legacy static bearer token remains functional.
3. ID-token substitution, signature modification, wrong resource audience, OAuth client or signed tenant, missing/invalid bearer, and insecure issuer are denied.
4. Exact branch commit and GitHub Actions run both green. Record failure categories only, never signed tokens, callbacks, credentials or user identifiers.
5. No global system trust modification, public ingress, VPS, DNS, live Keycloak tenants, Gateway deployment or production OIDC enablement.

**Still not production-ready:** Online revocation, user/session lifecycle, application-level resource ownership, Android/web authorization-code clients, MFA/passkeys, distributed persistence, operational recovery and GoreeCloud UI acceptance.

Tracking: [Identity issue #2](https://github.com/GoreeCloud/identity/issues/2), [Gateway issue #14](https://github.com/GoreeCloud/gateway/issues/14).
