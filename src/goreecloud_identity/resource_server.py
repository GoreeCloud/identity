"""Resource-server authorization using pinned issuer keys and explicit policies.

This adapter does NOT establish an HTTP server, accept unverified identity
headers, or replace a full session/revocation protocol. Applications must
supply trustworthy resource ownership, tenant and direct peer IP data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import jwt
from jwt.exceptions import PyJWTError

from .jwks_trust import PinnedIssuerKeys, JWKSUnavailable
from .policy import AccessRequest, Decision, PolicyRule, evaluate
from .tokens import VerificationError, verify_access_token


@dataclass(frozen=True)
class ResourceIdentityConfig:
    issuer: str
    audience: str
    authorized_party: str
    tenant_id: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        if any(not isinstance(v, str) or not v or len(v) > 512 for v in (
            self.issuer, self.audience, self.authorized_party, self.tenant_id
        )):
            raise ValueError("trusted resource identity settings are required")
        if not isinstance(self.scopes, frozenset) or not self.scopes or any(
            not isinstance(s, str) or not s or len(s) > 256 for s in self.scopes
        ):
            raise ValueError("invalid resource scopes")


class ResourceAuthorizer:
    """Deny by default; no network unless the pinned public key needs refresh."""

    def __init__(
        self,
        config: ResourceIdentityConfig,
        keys: PinnedIssuerKeys,
        policies: Iterable[PolicyRule],
    ):
        if config.issuer != keys.issuer:
            raise ValueError("authorization issuer and JWKS trust source mismatch")
        self.config = config
        self.keys = keys
        rules = tuple(policies)
        if len(rules) > 10000:
            raise ValueError("too many resource policies")
        self.rules = rules

    def authorize(self, bearer: str, request: AccessRequest) -> Decision:
        """Cryptographically verify user access first, evaluate privileges second.

        Never return raw JWT or signing keys to clients, logs or headers.
        Authorization failure intentionally returns only a generic reason.
        """
        if not isinstance(bearer, str) or not bearer or len(bearer) > 16384:
            return Decision(False, "authentication_failed")
        try:
            header = jwt.get_unverified_header(bearer)
            if header.get("alg") != "RS256":
                return Decision(False, "authentication_failed")
            kid = header.get("kid")
            jwks = self.keys.for_key(kid)
            verified = verify_access_token(
                bearer,
                issuer=self.config.issuer,
                audience=self.config.audience,
                authorized_party=self.config.authorized_party,
                tenant_id=self.config.tenant_id,
                jwks=jwks,
                required_scopes=self.config.scopes,
            )
        except (PyJWTError, VerificationError, JWKSUnavailable, ValueError, TypeError):
            return Decision(False, "authentication_failed")
        # The application MUST confirm the target resource belongs to the
        # trusted tenant. Caller-provided tenant strings do not prove ownership.
        return evaluate(verified.subject, request, self.rules)
