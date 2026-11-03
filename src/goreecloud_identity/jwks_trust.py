"""Pinned-issuer, bounded public-JWKS retrieval for GoreeCloud API resource servers.

Security boundary: issuer is trusted *operator configuration*, NEVER derived from
an incoming JWT, Host header, query parameter, user/tenant, token jku or x5u.
Only the configured Keycloak realm's HTTPS JWKS endpoint can be requested.
This helper does not implement live revocation or authorize resources by itself.
"""
from __future__ import annotations

import json
import re
from threading import RLock
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError

from .tokens import VerificationError


class JWKSUnavailable(VerificationError):
    """Pinned signing keys are absent, invalid, or cannot be refreshed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


_ID = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_LOCAL_ISSUER = "http://localhost:8080/realms/goreecloud"


def _validate_issuer(issuer: str) -> None:
    if not isinstance(issuer, str) or not 15 <= len(issuer) <= 2048:
        raise ValueError("a trusted issuer URI is required")
    try:
        url = urlsplit(issuer)
        realm_parts = url.path.split("/realms/")
        valid = (
            url.hostname is not None and url.username is None and url.password is None
            and not url.query and not url.fragment
            and len(realm_parts) == 2
            and bool(realm_parts[1])
            and "/" not in realm_parts[1]
            and not any(c in url.path for c in ("%", "\\"))
            and ".." not in url.path
        )
    except ValueError as err:
        raise ValueError("invalid trusted issuer URI") from err
    if not valid or (url.scheme != "https" and issuer != _LOCAL_ISSUER):
        raise ValueError("issuer requires verified HTTPS outside exact loopback development")


def validate_public_jwks(jwks: Any) -> dict[str, Any]:
    """Accept only safe, unique, RS256 public signing keys; ignore other key types.

    Any disclosure of private JWK material invalidates the entire response.
    Keycloak can legitimately publish non-signing and non-RS256 keys.
    """
    if not isinstance(jwks, dict):
        raise JWKSUnavailable("unexpected signing-key response")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not (1 <= len(keys) <= 128):
        raise JWKSUnavailable("invalid signing-key collection")
    clean: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            raise JWKSUnavailable("malformed public signing key")
        if any(k in key for k in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
            raise JWKSUnavailable("private key material in public signing keys")
        if key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
            continue
        kid = key.get("kid")
        if not isinstance(kid, str) or _ID.fullmatch(kid) is None or kid in seen:
            raise JWKSUnavailable("ambiguous RSA signing-key identifier")
        if not isinstance(key.get("n"), str) or not isinstance(key.get("e"), str):
            raise JWKSUnavailable("incomplete public RSA key")
        try:
            public = RSAAlgorithm.from_jwk(key)
            if public.key_size < 2048:
                raise JWKSUnavailable("RSA signing key is too small")
        except (PyJWTError, TypeError, ValueError, KeyError, AttributeError) as err:
            raise JWKSUnavailable("invalid RSA public key") from err
        clean.append(dict(key))
        seen.add(kid)
    if not clean:
        raise JWKSUnavailable("no trusted RS256 public signing keys")
    return {"keys": clean}


class PinnedIssuerKeys:
    """Lock-protected cache with finite freshness and unknown-key refresh rate limit."""

    def __init__(
        self,
        issuer: str,
        *,
        ttl_seconds: int = 300,
        unknown_kid_refresh_seconds: int = 30,
        clock=time.monotonic,
    ) -> None:
        _validate_issuer(issuer)
        if type(ttl_seconds) is not int or not (30 <= ttl_seconds <= 900):
            raise ValueError("JWKS TTL must be between 30 and 900 seconds")
        if (type(unknown_kid_refresh_seconds) is not int
                or not 10 <= unknown_kid_refresh_seconds <= ttl_seconds):
            raise ValueError("invalid unknown-key refresh interval")
        self.issuer = issuer
        self._url = issuer + "/protocol/openid-connect/certs"
        self._ttl = ttl_seconds
        self._unknown_refresh_seconds = unknown_kid_refresh_seconds
        self._clock = clock
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())
        self._lock = RLock()
        self._keys: dict[str, Any] | None = None
        self._expires_at = 0.0
        self._last_attempt = float("-inf")

    def _fetch(self) -> dict[str, Any]:
        request = Request(self._url, headers={"Accept": "application/json"}, method="GET")
        try:
            with self._opener.open(request, timeout=5) as response:
                if response.status != 200:
                    raise JWKSUnavailable("unexpected signing-key HTTP status")
                data = response.read(262145)
                if len(data) > 262144:
                    raise JWKSUnavailable("signing-key document too large")
                return validate_public_jwks(json.loads(data))
        except (HTTPError, URLError, OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
            raise JWKSUnavailable("failed to fetch pinned signing keys") from err

    def for_key(self, kid: str) -> dict[str, Any]:
        """Return currently trusted public keys; fail closed on fetch errors.

        Unrecognized kid may trigger one early fetch within cooldown, but only
        from the *same* configured issuer. If no matching key exists the
        downstream verifier must reject the token.
        """
        if not isinstance(kid, str) or _ID.fullmatch(kid) is None:
            raise JWKSUnavailable("invalid token signing-key identifier")
        now = self._clock()
        with self._lock:
            present = self._keys is not None and any(
                key["kid"] == kid for key in self._keys["keys"]
            )
            expired = self._keys is None or now >= self._expires_at
            retry_unknown = (
                not present and (now - self._last_attempt) >= self._unknown_refresh_seconds
            )
            if expired or retry_unknown:
                # Rate-limit every attempted refresh, even if the remote endpoint fails.
                self._last_attempt = now
                try:
                    fresh = self._fetch()
                except JWKSUnavailable:
                    # No stale fallback after expiry or unknown-key refresh.
                    # A previously trusted key is not silently accepted when
                    # the pinned issuer's current trust state is uncertain.
                    raise
                self._keys = fresh
                self._expires_at = now + self._ttl
            if self._keys is None or not any(key["kid"] == kid for key in self._keys["keys"]):
                raise JWKSUnavailable("signing-key identifier not trusted")
            return {"keys": [dict(key) for key in self._keys["keys"]]}

    def clear(self) -> None:
        """Administrative cache invalidation; does not revoke live user tokens."""
        with self._lock:
            self._keys = None
            self._expires_at = 0
