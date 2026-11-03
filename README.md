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

The optional [RS256 bearer-token verification helper](docs/TOKEN_VERIFICATION.md) tests issuer, audience, signer, client, token type, lifetime and scopes using a trusted externally supplied JWKS. It is not yet integrated with any application, and it does **not** fetch or establish trust in signing keys by itself. Do not treat it as a deployed access gateway or browser SSO implementation.

GitHub-hosted CI performs offline checks, disposable runtime OIDC discovery/restart checks and a **CI-only** PostgreSQL backup/restore smoke into a separately created database. The backup script refuses execution outside the expected GitHub Actions context; this is **not** a production backup policy or disaster-recovery plan. CI success must be verified against actual run results before being claimed.

## Project documents

- [Capability and implementation matrix](docs/CAPABILITIES.md)
- [Architecture and threat boundaries](docs/ARCHITECTURE.md)
- [Production acceptance checklist](docs/SECURITY.md)
- [Dependency provenance](THIRD_PARTY.md)

**Licensing:** GoreeCloud-authored files have no license grant until the owner selects one. Keycloak and PostgreSQL retain their upstream licenses. Do not import Authentik Enterprise or other proprietary functionality without a separate license review.

**GoreeCloud Identity — One Identity. Unified Access. Complete Control.**
