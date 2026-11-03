"""Strict offline verification of Keycloak-style OAuth 2.0 bearer access tokens.

Callers MUST obtain the JWKS from the exact configured issuer over an authenticated
transport, cache safely, and validate/refresh the trust source out of band. Do not
use this module for ID tokens or session cookies. Signature verification relies
on PyJWT/cryptography, not a custom crypto implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Iterable
from urllib.parse import urlsplit

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError

from .policy import Subject


class VerificationError(ValueError):
    """Untrusted token, unsuitable trust material, or authorization failure."""


@dataclass(frozen=True)
class VerifiedAccess:
    subject: Subject
    issuer: str
    audience: str
    authorized_party: str
    scopes: frozenset[str]


def _string_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or len(value) > 256:
        raise VerificationError(f"invalid {name} claim")
    if any(not isinstance(x, str) or not x or len(x) > 256 for x in value):
        raise VerificationError(f"invalid {name} entry")
    return frozenset(value)


def verify_access_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    authorized_party: str,
    tenant_id: str,
    jwks: Mapping[str, Any],
    required_scopes: Iterable[str] = (),
    max_lifetime_seconds: int = 3600,
) -> VerifiedAccess:
    """Verify an RS256 JWT against out-of-band trusted public keys.

    The caller sets issuer, audience, client ID and tenant_id through trusted
    application configuration, not from the token or incoming HTTP headers.
    An access token is not an identity provider: callers still enforce resource
    permissions and any online revocation/session requirements.
    """
    if any(not isinstance(x, str) or not x for x in (issuer, audience, authorized_party, tenant_id)):
        raise VerificationError("missing trusted identity configuration")
    try:
        origin = urlsplit(issuer)
        realm_path = origin.path.split("/realms/")
        issuer_is_well_formed = (
            bool(origin.hostname)
            and origin.username is None
            and origin.password is None
            and not origin.query
            and not origin.fragment
            and len(realm_path) == 2
            and bool(realm_path[1])
            and "/" not in realm_path[1]
        )
    except ValueError:
        issuer_is_well_formed = False
    if not issuer_is_well_formed or (
        origin.scheme != "https"
        and issuer != "http://localhost:8080/realms/goreecloud"
    ):
        raise VerificationError("invalid or non-HTTPS issuer")
    if not isinstance(token, str) or not token or len(token) > 16_384:
        raise VerificationError("invalid access token input")
    if not isinstance(max_lifetime_seconds, int) or not (1 <= max_lifetime_seconds <= 86400):
        raise VerificationError("invalid token lifetime policy")
    if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list):
        raise VerificationError("trusted JWKS is unavailable")

    try:
        header = jwt.get_unverified_header(token)
    except PyJWTError as error:
        raise VerificationError("invalid JWT header") from error
    if header.get("alg") != "RS256":
        raise VerificationError("unsupported signing algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 256:
        raise VerificationError("missing signing key identifier")

    candidates: list[Mapping[str, Any]] = []
    keys = jwks["keys"]
    if len(keys) > 128:
        raise VerificationError("excessive trusted JWK entries")
    for candidate in keys:
        if not isinstance(candidate, dict):
            raise VerificationError("invalid trusted JWK")
        if candidate.get("kid") != kid:
            continue
        if (
            candidate.get("kty") != "RSA"
            or candidate.get("use", "sig") != "sig"
            or candidate.get("alg", "RS256") != "RS256"
            or any(p in candidate for p in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
        ):
            raise VerificationError("unsafe signing key")
        candidates.append(candidate)
    if len(candidates) != 1:
        raise VerificationError("ambiguous or unknown signing key")

    try:
        signing_key = RSAAlgorithm.from_jwk(dict(candidates[0]))
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["iss", "aud", "sub", "iat", "exp"]},
            leeway=30,
        )
    except (PyJWTError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise VerificationError("JWT signature or registered claims invalid") from error

    if claims.get("typ") != "Bearer":
        raise VerificationError("ID token or unexpected token type rejected")
    if claims.get("azp") != authorized_party:
        raise VerificationError("unexpected authorized OAuth client")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise VerificationError("missing valid user subject")
    if any(type(claims.get(x)) is not int for x in ("iat", "exp")):
        raise VerificationError("non-integer issued/expiration time")
    if claims["exp"] <= claims["iat"] or claims["exp"] - claims["iat"] > max_lifetime_seconds:
        raise VerificationError("token lifetime exceeds policy")

    raw_scopes = claims.get("scope", "")
    if not isinstance(raw_scopes, str):
        raise VerificationError("invalid scope claim")
    scopes = frozenset(raw_scopes.split())
    required = frozenset(required_scopes)
    if any(not isinstance(scope, str) or not scope for scope in required) or not required <= scopes:
        raise VerificationError("required API scope missing")

    realm_access = claims.get("realm_access") or {}
    if not isinstance(realm_access, dict):
        raise VerificationError("invalid role container")
    roles = _string_set(realm_access.get("roles"), "roles")
    groups = _string_set(claims.get("groups"), "groups")
    return VerifiedAccess(
        subject=Subject(claims["sub"], tenant_id, True, roles, groups),
        issuer=issuer,
        audience=audience,
        authorized_party=authorized_party,
        scopes=scopes,
    )
