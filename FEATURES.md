# GoreeCloud Identity — Features

## Current verified features

Current verified source provides a Development service foundation, a fail-closed registration-policy primitive, and a non-persistent account lifecycle state machine. Public registration is disabled by the policy zero value; administrator-authorized provisioning and valid invitation paths can be represented explicitly.

The lifecycle state machine models active, deactivated, and deleted states; deactivation/reactivation are reversible/idempotent, permanent deletion requires explicit confirmation, and deleted state is terminal. Logout-like operations are rejected by this lifecycle domain because session/device controls are separate.

The current source does not yet authenticate users, persist identities, execute deletion, issue sessions or tokens, enroll authenticators, recover accounts, or authorize applications.

## Planned product features

See [PLANNED-FEATURES.md](PLANNED-FEATURES.md) for capability families that remain unimplemented or unaccepted.
