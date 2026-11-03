# Third-party components and provenance

- **Keycloak** — upstream open-source identity and access management engine; Apache License 2.0. Official source: https://github.com/keycloak/keycloak and https://www.keycloak.org/.
- **PostgreSQL** — upstream database service; PostgreSQL License. Official source: https://www.postgresql.org/.
- **PyJWT** — optional MIT-licensed dependency for verified RS256 OAuth bearer-token signatures and claims (pinned to 2.15.1 in requirements-auth.txt); cryptography is installed through the PyJWT crypto extra. https://pypi.org/project/PyJWT/.
- **GoreeCloud UI** — separate GoreeCloud design authority: https://github.com/GoreeCloud/gc-ui.

The development Compose images are declared by explicit versions. No Authentik source or Authentik Enterprise implementation is bundled. GoreeCloud-authored code is original development work. A license for these authored files must be selected by the owner before representing them as open-source.
