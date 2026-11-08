# GoreeCloud Identity

**Status: early development / non-production foundation (November 3, 2026).**

GoreeCloud Identity is a privacy-first, self-hosted identity and access management platform for GoreeCloud services and third-party applications. Its target scope includes SSO, OIDC/OAuth 2.0, SAML, user and group management, MFA, passwordless authentication, identity federation, application protection, Zero Trust policies, secure remote access, provisioning, and auditability.

**What exists today:** a reproducible **local-only development** identity engine based on upstream Keycloak, PostgreSQL persistence, a GoreeCloud-branded login theme, a small original deny-by-default authorization policy module, security-focused configuration checks, unit tests, and CI. Keycloak's upstream functionality is a dependency, **not** GoreeCloud-authored functionality. Most of the 32 product capability areas are not yet integrated or validated.

## Architecture

- **Identity authority:** Keycloak (a single authoritative realm and database per identity boundary).
- **Database:** PostgreSQL persisted in a private Docker volume.
- **UI:** GoreeCloud login theme using the [GoreeCloud UI](https://github.com/GoreeCloud/gc-ui) semantic design conventions. Visual acceptance is pending actual browser screenshots and accessibility review.
- **Original code:** `src/goreecloud_identity/policy.py` demonstrates deny-by-default, tenant-scoped, explicit role/group and network-policy decisions **only for trusted, already-authenticated subject context**. It is not an OAuth token validator or an independent identity provider.
- **Integrations:** planned via supported OIDC/SAML, and protected application gateway interfaces. Do not treat proposed features as implemented.

## Original Python resource adapter — development install, licensing unresolved

For isolated **internal development**, the original `goreecloud_identity` Python authorization helper modules can now be installed from this source tree with `python -m pip install --no-deps -e .` after installing `requirements-auth.txt`. The metadata intentionally uses a `0.0.0` development version, **does not declare any software license, and is not a public release**. Its mere presence does not permit redistribution by third parties. Do not publish a wheel to a public package index, ship it downstream, or claim the repository is open-source licensed until the separate license and third-party provenance review in [issue #17](https://github.com/GoreeCloud/identity/issues/17) is completed. Review [development packaging guardrails](docs/DEVELOPMENT_ADAPTER_PACKAGING.md) before integration. Neither this editable install nor the Keycloak development runtime establishes production SSO.

## Start locally (development only)

Requires Python 3.11+, Docker Engine and the Docker Compose plugin. Run these commands in a checked-out repository:

```sh
python3 scripts/init_env.py
python3 scripts/check_config.py
docker compose up -d
```

This creates a private, generated `.env` file (never commit it), then starts the development server **bound to loopback at http://localhost:8080**, not accessible to remote users. Open http://localhost:8080/admin/ and authenticate with the bootstrap user `admin` and the secret in your local `.env`. The imported realm is **goreecloud**. Create dedicated users and clients through the administration console. The initial realm intentionally does not create public clients, users, user credentials, or secrets.

> **Do not put this compose configuration on a public VPS or internet-facing interface.** It uses Keycloak `start-dev`, local HTTP, and local bootstrap credentials. A separate production deployment profile requires HTTPS, proxy/hostname hardening, email recovery configuration, secure secret handling, backup/restore rehearsal, and a security review. There is no production deployment in this repository.

To stop without deleting persistent data: `docker compose down`. **Do not** use `down --volumes` unless you explicitly intend to erase the identity database and have a verified recoverable backup.

## Tests

Use an isolated virtual environment for the optional access-token verification dependency:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-auth.txt
python -m unittest discover -s tests -v
python scripts/check_config.py
```

The development-only [OIDC Authorization Code + PKCE relying-party core](docs/OIDC_RELYING_PARTY.md) implements issuer-bound discovery, S256 challenges, state/nonce, code exchange and signed ID-token validation. Disposable GitHub CI has verified a real synthetic Keycloak browser login. The repository still does **not** provide production user login, persistent browser sessions, real application SSO, or Gateway integration.

The optional [RS256 bearer-token verification helper](docs/TOKEN_VERIFICATION.md) tests issuer, audience, signer, client, token type, lifetime and scopes using a trusted externally supplied JWKS. It is not yet integrated with any application, and it does **not** fetch or establish trust in signing keys by itself. Do not treat it as a deployed access gateway or browser SSO implementation.

GitHub-hosted CI performs offline checks, disposable runtime OIDC discovery/restart checks and a **CI-only** PostgreSQL backup/restore smoke into a separately created database. A [CI-only synthetic browser-form login test](docs/CI_E2E_LOGIN.md) now attempts a real Authorization Code + S256 PKCE exchange against a disposable client and user. This is not the application-side secure session implementation or a public deployment. The backup script refuses execution outside the expected GitHub Actions context; this is **not** a production backup policy or disaster-recovery plan. CI success must be verified against actual run results before being claimed.

The [development-only server-side browser session primitive](docs/BROWSER_SESSIONS.md) binds one-time OIDC/PKCE transactions to Secure/HttpOnly/SameSite host-only cookies, rotates identifiers after login, enforces hard expiry and CSRF checks, and supports local logout. A [loopback-only WSGI HTTP example](docs/LOOPBACK_HTTP.md) demonstrates cookie delivery and protected logout using a short-lived in-memory session. Its real localhost socket and synthetic Keycloak login integration passed [CI run 41718513319](https://github.com/GoreeCloud/identity/actions/runs/41718513319) with 111 tests. This is **not** a production BFF, Gateway integration or finished GoreeCloud UI web application.

A [pinned-issuer signing-key cache and resource authorization adapter](docs/RESOURCE_AUTHORIZATION.md) now joins exact Keycloak JWKS retrieval to the existing RS256 access-token verification and explicit deny-by-default role/group/IP policies.

**Tenant-claim boundary verified in development:** [PR #14](https://github.com/GoreeCloud/identity/pull/14) now requires the RS256-verified access token's signed `goreecloud_tenant` claim to match independently configured resource tenancy. Missing, conflicting and malformed claims are rejected; [CI run 41732128857](https://github.com/GoreeCloud/identity/actions/runs/41732128857) passed 149 Python tests and disposable Keycloak runtime checks. This is **not** production tenant-resource ownership enforcement, global token revocation, or a live Gateway rollout. The independent Go Gateway OIDC adapter remains disabled by default.
 Its 142-test suite and [real disposable Keycloak key-source check](https://github.com/GoreeCloud/identity/actions/runs/41720284851) passed. It is an original **Python development component**, not a deployed Gateway or Zero Trust access service. Token revocation and production key-rotation acceptance remain outstanding.

A [CI-only Gateway token claim contract](docs/GATEWAY_CLAIMS.md) creates a synthetic scoped Keycloak client, realm role and tenant/audience protocol mappers **only in the disposable CI runner**. [CI run 41737527198](https://github.com/GoreeCloud/identity/actions/runs/41737527198) **passed 161 tests**, including a real Keycloak authorization-code access token verified for the configured Gateway audience, client, scope, role and signed tenant. It does not establish production Gateway sign-in, live token revocation or web/Android PKCE clients.

## Project documents

- [Capability and implementation matrix](docs/CAPABILITIES.md)
- [Architecture and threat boundaries](docs/ARCHITECTURE.md)
- [Production acceptance checklist](docs/SECURITY.md)
- [Dependency provenance](THIRD_PARTY.md)

**Licensing:** GoreeCloud-authored files have no license grant until the owner selects one. Keycloak and PostgreSQL retain their upstream licenses. Do not import Authentik Enterprise or other proprietary functionality without a separate license review.

**GoreeCloud Identity — One Identity. Unified Access. Complete Control.**
