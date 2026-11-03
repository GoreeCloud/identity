"""Minimal explicit, deny-by-default authorization for ALREADY-VERIFIED identities.

This module never authenticates users or validates OAuth access tokens. A caller MUST
verify issuer, signature, audience, expiration, tenant and token type using a trusted
OIDC library before constructing Subject. Do not deserialize untrusted JSON directly
into Subject and treat that as authentication.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Iterable, Literal


@dataclass(frozen=True)
class Subject:
    subject_id: str
    tenant_id: str
    authenticated: bool
    roles: frozenset[str] = field(default_factory=frozenset)
    groups: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AccessRequest:
    tenant_id: str
    resource: str
    action: str
    client_ip: str


@dataclass(frozen=True)
class PolicyRule:
    tenant_id: str
    resource: str
    action: str
    effect: Literal["allow", "deny"]
    roles: frozenset[str] = field(default_factory=frozenset)
    groups: frozenset[str] = field(default_factory=frozenset)
    cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.resource or not self.action:
            raise ValueError("a rule requires tenant, resource, and action")
        if self.effect not in ("allow", "deny"):
            raise ValueError("invalid rule effect")
        if not self.roles and not self.groups:
            raise ValueError("every rule needs explicit roles or groups")
        for cidr in self.cidrs:
            ip_network(cidr, strict=False)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def evaluate(
    subject: Subject, request: AccessRequest, rules: Iterable[PolicyRule]
) -> Decision:
    """Deny by default. Explicit deny overrides allow independent of rule order."""
    if not subject.authenticated or not subject.subject_id:
        return Decision(False, "unauthenticated")
    if not subject.tenant_id or subject.tenant_id != request.tenant_id:
        return Decision(False, "tenant_mismatch")
    if not request.resource or not request.action:
        return Decision(False, "invalid_request")
    try:
        address = ip_address(request.client_ip)
    except ValueError:
        return Decision(False, "invalid_client_ip")

    matched_allow = False
    for rule in rules:
        if (rule.tenant_id, rule.resource, rule.action) != (
            request.tenant_id, request.resource, request.action
        ):
            continue
        if not ((subject.roles & rule.roles) or (subject.groups & rule.groups)):
            continue
        if rule.cidrs and not any(
            address in ip_network(net, strict=False) for net in rule.cidrs
        ):
            continue
        if rule.effect == "deny":
            return Decision(False, "explicit_deny")
        matched_allow = True
    return Decision(matched_allow, "explicit_allow" if matched_allow else "no_matching_allow")
