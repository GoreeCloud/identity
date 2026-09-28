# GoreeCloud Identity — Architecture

## Status

Development architecture baseline. The current executable source is a loopback-only operational service shell. It does not implement authentication, credential storage, token issuance, session authority, federation, or application authorization.

## Current source boundary

Development 0.1 contains one Go service entry point, explicit loopback listener validation, health/readiness endpoints, bounded HTTP resources, graceful shutdown, tests, and CI.

## Planned layers

Future work should keep clear boundaries between principal identity, authentication orchestration, session/token services, authorization context, application registrations, administrative interfaces, audit evidence, persistence, and platform integrations.

Protected credentials and authenticators remain under GoreeCloud Vault authority. Identity may consume narrowly scoped Vault operations but must not persist duplicate plaintext or protected credential authorities.

## Exposure boundary

The current listener is loopback-only. Broader exposure requires separately reviewed authentication, authorization, transport protection, rate/resource controls, recovery, observability, and target-environment validation.

## Evidence rule

Source and CI are Development evidence only. They do not establish production identity authority, production deployment, or Stable status.
