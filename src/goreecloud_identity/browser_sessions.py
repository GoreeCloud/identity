"""Development server-side OIDC browser transaction/session manager.

No HTTP listener, no persistence, no production multi-process safety. Each
instance is for one statically configured trusted Keycloak client and realm.
The browser sees only a random, Secure/HttpOnly host-only session cookie;
PKCE verifier, OIDC nonce and verified identity stay server-side.

Application endpoints MUST enforce HTTPS, CSRF checks on state changes,
resource authorization, logout/revocation and trusted proxy headers.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from http.cookies import SimpleCookie
import hmac
import re
import secrets
from threading import RLock
import time
from typing import Callable

from .oidc import (
    ClientConfig, Metadata, OIDCError, PendingFlow, StrictTransport,
    VerifiedIdentity, begin_authorization, complete_authorization,
)

COOKIE_NAME = "__Host-gc_identity_session"
_COOKIE_VALUE = re.compile(r"[A-Za-z0-9_-]{50,128}\Z")
_CSRF_VALUE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_PENDING_TTL = 300
_SESSION_TTL = 1800


class BrowserSessionError(ValueError):
    """Invalid, expired or already-consumed browser transaction."""


@dataclass(frozen=True)
class LoginStart:
    authorization_url: str
    set_cookie: str


@dataclass(frozen=True)
class LoginCompleted:
    identity: VerifiedIdentity
    set_cookie: str
    csrf_token: str


@dataclass
class _Record:
    expires_at: float
    pending: PendingFlow | None = None
    identity: VerifiedIdentity | None = None
    csrf_digest: bytes | None = None


def _make_cookie(token: str, *, max_age: int) -> str:
    cookie = SimpleCookie()
    cookie[COOKIE_NAME] = token
    morsel = cookie[COOKIE_NAME]
    morsel["path"] = "/"
    morsel["secure"] = True
    morsel["httponly"] = True
    morsel["samesite"] = "Lax"
    morsel["max-age"] = str(max_age)
    if max_age == 0:
        morsel["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
    return cookie.output(header="").strip()


def _cookie_hash(cookie_header: str) -> bytes | None:
    if not isinstance(cookie_header, str) or len(cookie_header) > 4096:
        return None
    # Reject duplicate session names rather than trusting parser overwrite order.
    found: list[str] = []
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        name, value = item.strip().split("=", 1)
        if name == COOKIE_NAME:
            found.append(value)
    if len(found) != 1 or _COOKIE_VALUE.fullmatch(found[0]) is None:
        return None
    return sha256(found[0].encode("ascii")).digest()


def _token_key(token: str) -> bytes:
    return sha256(token.encode("ascii")).digest()


class BrowserSessionManager:
    """Bounded, lock-protected, one-process in-memory browser session store.

    This serves as a small integration primitive; production requires a robust
    shared session backend, failover, account/session revocation and deployment
    policy acceptance. The caller alone owns HTTPS transport and cookie delivery.
    """

    def __init__(
        self,
        config: ClientConfig,
        metadata: Metadata,
        transport: StrictTransport,
        *,
        max_sessions: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if transport.config != config:
            raise ValueError("transport and trusted client configuration mismatch")
        if not isinstance(max_sessions, int) or not (1 <= max_sessions <= 100_000):
            raise ValueError("invalid session capacity")
        self._config = config
        self._metadata = metadata
        self._transport = transport
        self._max_sessions = max_sessions
        self._clock = clock
        self._records: dict[bytes, _Record] = {}
        self._lock = RLock()

    def _prune_locked(self, now: float) -> None:
        for key in tuple(self._records):
            if now >= self._records[key].expires_at:
                del self._records[key]

    def start_login(self) -> LoginStart:
        url, flow = begin_authorization(self._config, self._metadata)
        token = secrets.token_urlsafe(48)
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self._max_sessions:
                raise BrowserSessionError("session capacity exhausted")
            self._records[_token_key(token)] = _Record(
                expires_at=now + _PENDING_TTL, pending=flow
            )
        return LoginStart(url, _make_cookie(token, max_age=_PENDING_TTL))

    def complete_login(self, cookie_header: str, callback_url: str) -> LoginCompleted:
        key = _cookie_hash(cookie_header)
        if key is None:
            raise BrowserSessionError("missing or ambiguous login session")
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            # Consume the pending transaction before any network operations.
            pending = self._records.pop(key, None)
        if pending is None or pending.pending is None or now >= pending.expires_at:
            raise BrowserSessionError("login transaction expired or consumed")
        verified = complete_authorization(
            self._config, self._metadata, pending.pending,
            callback_url, self._transport,
        )
        fresh_token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        new_now = self._clock()
        with self._lock:
            self._prune_locked(new_now)
            if len(self._records) >= self._max_sessions:
                raise BrowserSessionError("session capacity exhausted")
            self._records[_token_key(fresh_token)] = _Record(
                expires_at=new_now + _SESSION_TTL,
                identity=verified,
                csrf_digest=sha256(csrf.encode("ascii")).digest(),
            )
        return LoginCompleted(
            verified, _make_cookie(fresh_token, max_age=_SESSION_TTL), csrf
        )

    def get_identity(self, cookie_header: str) -> VerifiedIdentity | None:
        key = _cookie_hash(cookie_header)
        if key is None:
            return None
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            record = self._records.get(key)
            return record.identity if record is not None else None

    def issue_csrf(self, cookie_header: str) -> str | None:
        """Mint a fresh form CSRF token for an already authenticated session.

        The token is returned once to the trusted server-side HTTP renderer.
        Only its digest remains in this bounded in-process session store.
        Generating a new form invalidates the previous token.
        """
        key = _cookie_hash(cookie_header)
        if key is None:
            return None
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            record = self._records.get(key)
            if record is None or record.identity is None:
                return None
            token = secrets.token_urlsafe(32)
            record.csrf_digest = sha256(token.encode("ascii")).digest()
            return token

    def verify_csrf(self, cookie_header: str, submitted_token: str) -> bool:
        if (not isinstance(submitted_token, str) or
                _CSRF_VALUE.fullmatch(submitted_token) is None):
            return False
        key = _cookie_hash(cookie_header)
        if key is None:
            return False
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            record = self._records.get(key)
            if record is None or record.identity is None or record.csrf_digest is None:
                return False
            return hmac.compare_digest(
                record.csrf_digest, sha256(submitted_token.encode("utf-8")).digest()
            )

    def logout(self, cookie_header: str) -> str:
        key = _cookie_hash(cookie_header)
        if key is not None:
            with self._lock:
                self._records.pop(key, None)
        return _make_cookie("", max_age=0)
