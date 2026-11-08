# Original Python authorization adapter — internal development packaging

**Status:** Installability check for an original development library. **NOT a public Python distribution, license grant, production SSO integration, or release.**

## What is packaged

The `pyproject.toml` source build discovers only Python modules under `src/goreecloud_identity/` (policy, token verification, pinned issuer JWKS and resource authorization, plus existing OIDC/session helpers). It does **not** vendor or package Keycloak binaries, a realm dump, PostgreSQL images, login themes, source secrets or real user data. The package is deliberately named `goreecloud-identity-resource-dev` and given temporary version `0.0.0` to avoid implying a supported SDK/release. Its optional cryptographic library dependency is pinned exactly to `PyJWT[crypto]==2.15.1`, matching `requirements-auth.txt`.

For private, local development in a checked-out source tree:

```sh
python -m pip install -r requirements-auth.txt
python -m pip install --no-deps -e .
python -c "from goreecloud_identity.resource_server import ResourceAuthorizer; print('development import ok')"
```

GitHub CI runs an editable-install smoke and then the current test suite in the disposable runner. A successful import does not verify a production OIDC or Analytics integration.

## Licensing is still blocked

No root `LICENSE` exists at this baseline. A repository-specific founder decision and rights review are mandatory under the canonical GoreeCloud licensing policy: copyrighted original files and any third-party material must be reviewed and a correct license/attributions committed. **Do not publish wheels, register a package name publicly, redistribute or tell downstream apps to copy these modules until [issue #17](https://github.com/GoreeCloud/identity/issues/17) is resolved.** Package metadata intentionally contains no `license` field and is not an alternative to an actual license. No CI upload or deployment step is added.

## Still required before downstream Analytics integration

After licensing and provenance review, establish a real pinned version and reproducible dependency installation, review exported public API stability, validate resource-server token signature/issuer/audience/client/signed tenant, implement independently verified site ownership and per-action checks in Analytics, and test real disposable Keycloak OIDC sessions, key rotation, revocation, HTTPS and BFF/CSRF boundaries. The adapter is not a login server or access gateway.
