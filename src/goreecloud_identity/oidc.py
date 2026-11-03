"""Development OIDC Authorization Code + S256 PKCE relying-party core.

This library deliberately does NOT implement browser cookies, HTTP sessions,
refresh-token persistence, logout, or production gateway integration. The
application must bind each PendingFlow to a private server-side browser session.
Keycloak remains the authoritative identity provider. RS256 is verified by
PyJWT/cryptography; only standards-specified PKCE hashing is implemented here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import secrets
from threading import Lock
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError


class OIDCError(ValueError):
    """Flow or trust validation failure (never includes raw token material)."""


@dataclass(frozen=True)
class ClientConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    allow_local_dev: bool = False

    def __post_init__(self) -> None:
        if not self.client_id or len(self.client_id) > 200:
            raise OIDCError("client identifier required")
        try:
            iss, redirect = urlsplit(self.issuer), urlsplit(self.redirect_uri)
            issuer_parts = iss.path.split("/realms/")
            valid_issuer = (
                iss.hostname is not None and not iss.username and not iss.password
                and not iss.query and not iss.fragment and len(issuer_parts) == 2
                and issuer_parts[0] == "" and issuer_parts[1]
                and "/" not in issuer_parts[1]
            )
            valid_redirect = (
                redirect.hostname is not None and not redirect.username
                and not redirect.password and not redirect.query and not redirect.fragment
                and redirect.path and redirect.path != "/"
            )
        except ValueError as error:
            raise OIDCError("invalid OIDC URL") from error
        if not valid_issuer or not valid_redirect:
            raise OIDCError("invalid issuer or redirect URI")
        dev = self.allow_local_dev and (
            self.issuer == "http://localhost:8080/realms/goreecloud"
            and self.redirect_uri == "http://127.0.0.1:8765/oidc/callback"
        )
        if not dev and (iss.scheme != "https" or redirect.scheme != "https"):
            raise OIDCError("HTTPS required outside exact local development")
        if iss.scheme not in ("http", "https") or redirect.scheme not in ("http", "https"):
            raise OIDCError("unsupported URL scheme")


@dataclass(frozen=True)
class Metadata:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


def validate_metadata(document: Any, config: ClientConfig) -> Metadata:
    if not isinstance(document, dict) or document.get("issuer") != config.issuer:
        raise OIDCError("discovery issuer mismatch")
    expected = {
        "authorization_endpoint": config.issuer + "/protocol/openid-connect/auth",
        "token_endpoint": config.issuer + "/protocol/openid-connect/token",
        "jwks_uri": config.issuer + "/protocol/openid-connect/certs",
    }
    for key, endpoint in expected.items():
        if document.get(key) != endpoint:
            raise OIDCError("discovery endpoint mismatch")
    if not isinstance(document.get("response_types_supported"), list) or (
        "code" not in document["response_types_supported"]
    ):
        raise OIDCError("authorization code flow unavailable")
    supported = document.get("code_challenge_methods_supported")
    if not isinstance(supported, list) or "S256" not in supported:
        raise OIDCError("PKCE S256 not advertised")
    return Metadata(**expected)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


class StrictTransport:
    """Reads only trusted, fixed Keycloak endpoints; never follows redirects."""

    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _json(self, url: str, payload: bytes | None = None) -> dict[str, Any]:
        allowed = {
            self.config.issuer + "/.well-known/openid-configuration",
            self.config.issuer + "/protocol/openid-connect/certs",
            self.config.issuer + "/protocol/openid-connect/token",
        }
        if url not in allowed:
            raise OIDCError("unapproved OIDC endpoint")
        if payload is not None and url != self.config.issuer + "/protocol/openid-connect/token":
            raise OIDCError("unexpected POST destination")
        request = Request(
            url, data=payload,
            headers={
                "Accept": "application/json",
                **({"Content-Type": "application/x-www-form-urlencoded"} if payload is not None else {}),
            },
            method="POST" if payload is not None else "GET",
        )
        try:
            with self._opener.open(request, timeout=5) as response:
                if response.status != 200:
                    raise OIDCError("unexpected OIDC HTTP status")
                raw = response.read(262145)
                if len(raw) > 262144:
                    raise OIDCError("OIDC JSON response too large")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise OIDCError("invalid OIDC JSON document")
                return data
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as error:
            raise OIDCError("OIDC endpoint request rejected") from error

    def discovery(self) -> dict[str, Any]:
        data = self._json(self.config.issuer + "/.well-known/openid-configuration")
        validate_metadata(data, self.config)
        return data

    def jwks(self) -> dict[str, Any]:
        data = self._json(self.config.issuer + "/protocol/openid-connect/certs")
        if not isinstance(data.get("keys"), list) or not data["keys"] or len(data["keys"]) > 128:
            raise OIDCError("invalid trusted JWKS")
        return data

    def exchange(self, metadata: Metadata, code: str, verifier: str) -> dict[str, Any]:
        if metadata.token_endpoint != self.config.issuer + "/protocol/openid-connect/token":
            raise OIDCError("untrusted token endpoint")
        data = urlencode({
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "code": code,
            "code_verifier": verifier,
        }).encode("ascii")
        return self._json(metadata.token_endpoint, data)


@dataclass
class PendingFlow:
    state: str
    nonce: str
    verifier: str
    issued_at: float
    _used: bool = field(default=False, init=False, repr=False)
    _lock: Any = field(default_factory=Lock, init=False, repr=False)

    def consume(self, supplied_state: str, *, now: float | None = None) -> None:
        with self._lock:
            if self._used:
                raise OIDCError("authorization already consumed")
            if not isinstance(supplied_state, str) or not hmac.compare_digest(
                self.state, supplied_state
            ):
                raise OIDCError("authorization state mismatch")
            when = time.time() if now is None else now
            if not self.issued_at <= when <= self.issued_at + 300:
                raise OIDCError("authorization expired or not yet valid")
            self._used = True


@dataclass(frozen=True)
class VerifiedIdentity:
    sub: str
    issuer: str
    client_id: str
    issued_at: int
    expires_at: int


def begin_authorization(config: ClientConfig, metadata: Metadata) -> tuple[str, PendingFlow]:
    if metadata.authorization_endpoint != config.issuer + "/protocol/openid-connect/auth":
        raise OIDCError("untrusted authorization endpoint")
    flow = PendingFlow(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(48),
        issued_at=time.time(),
    )
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(flow.verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    query = urlencode({
        "response_type": "code", "client_id": config.client_id,
        "redirect_uri": config.redirect_uri, "scope": "openid profile",
        "state": flow.state, "nonce": flow.nonce, "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return metadata.authorization_endpoint + "?" + query, flow


def parse_callback(url: str, config: ClientConfig) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > 8192:
        raise OIDCError("invalid callback")
    actual, expected = urlsplit(url), urlsplit(config.redirect_uri)
    if (actual.scheme, actual.netloc, actual.path) != (
        expected.scheme, expected.netloc, expected.path
    ) or actual.fragment:
        raise OIDCError("callback redirect URI mismatch")
    try:
        params = parse_qs(actual.query, strict_parsing=True, keep_blank_values=True, max_num_fields=12)
    except ValueError as error:
        raise OIDCError("malformed callback parameters") from error
    if "error" in params:
        raise OIDCError("authorization provider rejected request")
    allowed = {"state", "code", "session_state", "iss"}
    if (not {"state", "code"} <= set(params) or not set(params) <= allowed
            or any(len(v) != 1 for v in params.values())):
        raise OIDCError("unexpected or repeated callback parameters")
    if "iss" in params and params["iss"][0] != config.issuer:
        raise OIDCError("authorization response issuer mismatch")
    if "session_state" in params and not (0 < len(params["session_state"][0]) <= 512):
        raise OIDCError("invalid provider session marker")
    state, code = params["state"][0], params["code"][0]
    if not (state and code and len(state) <= 256 and len(code) <= 2048):
        raise OIDCError("invalid callback state or code")
    return state, code


def _rsa_signing_key(token: str, jwks: Mapping[str, Any]) -> Any:
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise OIDCError("unsupported ID token algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise OIDCError("invalid ID token signing key ID")
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not (1 <= len(keys) <= 128):
            raise OIDCError("trusted signing keys unavailable")
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
        if len(matches) != 1:
            raise OIDCError("ambiguous signing key ID")
        key = matches[0]
        if (key.get("kty") != "RSA" or key.get("use", "sig") != "sig"
            or key.get("alg", "RS256") != "RS256"
            or any(x in key for x in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))):
            raise OIDCError("unsafe public signing key")
        return RSAAlgorithm.from_jwk(key)
    except (PyJWTError, ValueError, TypeError, KeyError) as error:
        raise OIDCError("invalid ID token signing key") from error


def validate_id_token(
    token: str, access_token: str, nonce: str, config: ClientConfig,
    jwks: Mapping[str, Any],
) -> VerifiedIdentity:
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise OIDCError("invalid ID token")
    if not isinstance(access_token, str) or not access_token:
        raise OIDCError("missing access token")
    try:
        claims = jwt.decode(
            token, _rsa_signing_key(token, jwks),
            algorithms=["RS256"], issuer=config.issuer,
            audience=config.client_id,
            options={"require": ["iss", "aud", "sub", "iat", "exp", "nonce"]},
            leeway=30,
        )
    except (PyJWTError, ValueError, TypeError) as error:
        raise OIDCError("invalid ID token signature or claims") from error
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise OIDCError("invalid authenticated subject")
    if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise OIDCError("ID token nonce mismatch")
    if type(claims["iat"]) is not int or type(claims["exp"]) is not int or (
        not 0 < claims["exp"] - claims["iat"] <= 3600
    ):
        raise OIDCError("ID token exceeds lifetime policy")
    aud = claims["aud"]
    if (isinstance(aud, list) and len(aud) > 1) or "azp" in claims:
        if claims.get("azp") != config.client_id:
            raise OIDCError("ID token authorized client mismatch")
    if "at_hash" in claims:
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode("ascii")).digest()[:16]
        ).rstrip(b"=").decode("ascii")
        if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(
            expected, claims["at_hash"]
        ):
            raise OIDCError("ID token access-token hash mismatch")
    return VerifiedIdentity(claims["sub"], config.issuer, config.client_id,
                            claims["iat"], claims["exp"])


def complete_authorization(
    config: ClientConfig,
    metadata: Metadata,
    flow: PendingFlow,
    callback_url: str,
    transport: StrictTransport,
    *,
    now: float | None = None,
) -> VerifiedIdentity:
    """One-time code exchange; browser-session binding remains caller's duty."""
    state, code = parse_callback(callback_url, config)
    flow.consume(state, now=now)
    if transport.config != config:
        raise OIDCError("mismatched trusted transport")
    jwks = transport.jwks()
    token = transport.exchange(metadata, code, flow.verifier)
    if token.get("token_type", "").lower() != "bearer":
        raise OIDCError("invalid token endpoint response type")
    return validate_id_token(
        token.get("id_token"), token.get("access_token"), flow.nonce,
        config, jwks,
    )
