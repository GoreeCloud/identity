# GoreeCloud Identity — Feature implementation inventory

**Canonical classification:** Product target inventory; not a verified implementation list.

The founder's 32 feature areas define the destination. This repository is the first development foundation and **does not claim all capabilities have been implemented**.

| Area | Present state | Next integration work |
| --- | --- | --- |
| 1. Core IAM | Keycloak upstream engine configured locally | End-to-end SSO validation, application inventory |
| 2. Protocols and standards | Upstream Keycloak supports many; no clients configured | OIDC smoke integration, SAML and SCIM compatibility tests |
| 3. Authentication methods | Upstream methods available; none provisioned | Passkey and password policy enrollment tests |
| 4. MFA | Upstream capability; not enforced on bootstrap | MFA enrollment, recovery and privileged access policy |
| 5. Authentication workflows | Keycloak upstream workflows | Visual GoreeCloud workflow administration |
| 6. Users and accounts | Keycloak upstream user directory | User portal and lifecycle APIs |
| 7. Groups, roles and directories | Keycloak upstream | Integration permissions and directory sync |
| 8. External IdPs | Not configured | Federated providers with scoped credentials |
| 9. Provisioning | Not integrated | SCIM inbound/outbound adapters |
| 10. Authorization | Original deny-by-default policy helper and development trusted JWT-to-resource adapter, offline tested | Production gateway enforcement, per-resource tenancy and revocation |
| 11. Zero Trust | No production enforcement | Condition evaluation and gateway integration |
| 12. Device identity | Not integrated | Certificates, trust attestations and compliance |
| 13. Applications and SSO | Auth-code/S256 PKCE client, synthetic Keycloak login verified in CI; localhost-only WSGI HTTP example and socket-level CI flow verified (run 41718513319) | Production-grade web app, stable session store, logout/revocation and Gateway SSO |
| 14. Identity proxy | Not implemented | GoreeCloud Gateway forward-auth integration |
| 15. Remote access | Not implemented | Audit Guacamole/SSH/RDP/VNC approach |
| 16. Self-service | Keycloak upstream account-console capability | GoreeCloud UI and secure recovery flow |
| 17. Multi-tenancy | One initial development realm | Tenant isolation and organizations |
| 18. API/machine identity | Upstream service accounts; RS256 verifier and pinned Keycloak JWKS (CI passed). Gateway-claim synthetic Keycloak authorization-code token test added (runtime pending) | Actual Gateway Go process acceptance, client grants, revocation and agent integration |
| 19. AI agents | Not implemented | Delegation, consent and actor attribution |
| 20. Privileged access | Not implemented | Least privilege, access requests and time limits |
| 21. Sessions/tokens/consent | Single-process server-side session primitive and localhost HTTP example (cookie delivery, rotation, CSRF, expiry, local logout); CI socket test passed (run 41718513319) | HTTPS application, persistent/distributed session store, revocation and production logout |
| 22. Auditing | Basic upstream event subsystem | Events, retention, protected monitoring |
| 23. Notifications | Not configured | Verified SMTP/webhook transport |
| 24. Developer extensions | Original Python policy library present | Authenticated APIs, SDKs and contract tests |
| 25. GoreeCloud UI | Initial login CSS theme | Visual/a11y acceptance and fuller portal |
| 26. Digital credentials | Not enabled | Evaluate Keycloak preview features and standards |
| 27. Infrastructure | Local-only Compose available | Production architecture, HA, secrets |
| 28. Backups/recovery | Database volume persists; CI-only disposable PostgreSQL archive/restore test added (results must be verified) | Encrypted off-host backup, production-safe recovery and restore drills |
| 29. Privacy/compliance | Protective local defaults | Threat model, audits, policy review |
| 30. GoreeCloud integrations | Not integrated | Gateway, VPN, DNS and app OIDC adapters |
| 31. Administration | Upstream admin console | GoreeCloud branded admin experience |
| 32. Architecture | Documented trust boundaries | Harden and test independent services |

## Priority gates

**P0:** Runtime startup test, secure bootstrap, development-only protections, signed release dependency review, database backup/restore. **P1:** End-to-end OIDC client with PKCE, MFA and passkey enrollment, browser/logout and gateway integration, tenant authorization tests. **P2:** SAML/LDAP/SCIM, domain and application management, self-service UI. **P3:** Remote access, AI agent delegation, approvals, verifiable credentials and scale-out architecture.

Enterprise-only Authentik functionality is not incorporated, relicensed, or represented as automatically available. Each third-party component requires an explicit license and technical integration review.
