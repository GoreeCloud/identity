# Access-token verification contract

**Maturity:** isolated backend verification helper (development); not yet connected to a running web application.

The `goreecloud_identity.tokens.verify_access_token` function validates **OAuth bearer access tokens**, not OIDC ID tokens. It delegates RSA signature verification to PyJWT and checks explicit issuer, intended resource audience, issuing OAuth client (`azp`), token type, expiration, issuance time, scope, and maximum lifetime. A successful result is a `VerifiedAccess` object containing an authenticated `Subject` for a separate access-policy decision.

## Mandatory caller responsibilities

- **Trust root:** obtain the JWKS only from a deployment-approved Keycloak issuer using verified HTTPS and trusted network configuration. Never trust a token-provided `jku`, `x5u`, `kid` URL or unverified token payload to choose the issuer/JWKS. Cache keys with bounded refresh and rotation behavior.
- **Identity boundary:** configure the exact issuer (including realm), resource-server audience, OAuth client (`azp`), and tenant identifier as application settings, not values taken from HTTP request headers or JWT claims.
- **Resource policy:** call the independent authorization engine after cryptographic verification, applying least privilege and tenant isolation. A valid signature alone is not permission to act.
- **Transport:** only accept tokens over HTTPS. Never log full tokens, auth headers or private keys.
- **Revocation:** offline JWT verification cannot detect all revoked or terminated sessions until expiry. Use short-lived tokens and appropriate live revocation/introspection when an application's threat model requires immediate disablement.
- **Multi-tenancy (unverified; acceptance blocked):** the current development helper assigns a configured tenant to its verified subject **without requiring a matching signed tenant claim**. Signed tokens missing the tenant claim or carrying a different tenant have passed isolated negative tests. Do **not** rely on this Python helper for tenant authorization until [security issue #13](https://github.com/GoreeCloud/identity/issues/13) is resolved with positive and negative tests and completed CI. A configured tenant alone does not prove the authenticated user belongs to it; consuming services must independently validate resource ownership.
- **Token class:** Keycloak-style access-token payload must include `typ=Bearer` and `azp`. Other vendors/formats require an explicitly reviewed adapter.
- **Risk:** never use for browser sign-in, OIDC auth-code/PKCE, refresh-token processing, or service-client login. A separate well-tested relying-party implementation remains necessary.

## Local verification

Use a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-auth.txt
python -m unittest discover -s tests -v
```

The tests generate ephemeral RSA key material in memory and exercise both acceptance and rejection of signed tokens. No test fixture contains a real credential.

The low-level `verify_access_token` function still requires the caller to supply independently trusted JWKS. An **optional new** [PinnedIssuerKeys and ResourceAuthorizer adapter](RESOURCE_AUTHORIZATION.md) now retrieves keys only from a configured Keycloak issuer, with bounded freshness, unique RS256 signing-key constraints and explicit deny-by-default authorization. The adapter is not deployed to any production application; short token lifetimes, revocation, verified tenant ownership and operational key rotation remain necessary.
