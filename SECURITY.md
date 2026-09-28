# Security Policy — GoreeCloud Identity

## Status

GoreeCloud Identity is in active Development and is not production-ready or Stable. The current source exposes only loopback operational status endpoints and has no authentication authority.

## Current boundary

- only explicit loopback operational binding is accepted;
- no credential, authenticator, session, token, or recovery endpoint exists;
- no production network exposure is authorized by the current foundation;
- protected credential material belongs to GoreeCloud Vault rather than this service shell.

Authentication and session behavior requires explicit design review, tested authorization boundaries, supported standards and libraries, recovery planning, and target-environment acceptance before production authority is claimed.

Identity must fail closed on invalid security-sensitive configuration, use least privilege, minimize sensitive diagnostics, keep resource use bounded, and tie release-critical evidence to an exact source revision.

## Registration security baseline

The current registration-policy primitive fails closed. Public registration is disabled by default, administrator provisioning requires an explicit grant, invitation provisioning requires a valid invitation, and unknown registration methods are denied. This domain rule must remain enforced at the service/API boundary when account-creation endpoints are later introduced; hiding a UI control is not sufficient enforcement.
