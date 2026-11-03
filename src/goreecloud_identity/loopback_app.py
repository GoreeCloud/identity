"""Localhost-only WSGI demonstration of GoreeCloud Identity's PKCE session manager.

Not production middleware. No persistent sessions, external networking, TLS
termination, role authorization, MFA, revocation or real client integration.
Runs only through explicit local development CLI, binding 127.0.0.1:8765.
"""
from __future__ import annotations

from html import escape
from http import HTTPStatus
import json
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, make_server

from .browser_sessions import BrowserSessionManager
from .oidc import ClientConfig, OIDCError, StrictTransport, validate_metadata

HOST = "127.0.0.1:8765"
ORIGIN = "http://" + HOST
ISSUER = "http://localhost:8080/realms/goreecloud"
CALLBACK = ORIGIN + "/oidc/callback"
_BODY_LIMIT = 4096


class DemoConfigurationError(ValueError):
    """This demonstration is intentionally restricted to loopback dev."""


class LoopbackLoginApp:
    """Small stateless WSGI router backed by one in-memory session manager.

    Do not publish behind a proxy or expose to a network: HTTP is permitted
    only because this is an exact-localhost integration demonstration.
    """

    def __init__(self, manager: BrowserSessionManager, config: ClientConfig) -> None:
        if (
            config.issuer != ISSUER
            or config.redirect_uri != CALLBACK
            or not config.allow_local_dev
            or manager._config != config
        ):
            raise DemoConfigurationError("only the exact loopback development client is permitted")
        self.manager = manager
        self.config = config

    def _reply(self, start_response, status: HTTPStatus, body: bytes,
               *, content_type: str = "text/plain; charset=utf-8",
               extra: list[tuple[str, str]] | None = None):
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store, max-age=0"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy",
             "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ]
        headers.extend(extra or [])
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _html(self, start_response, status: HTTPStatus, body: str,
              *, extra: list[tuple[str, str]] | None = None):
        return self._reply(start_response, status, body.encode("utf-8"),
                           content_type="text/html; charset=utf-8", extra=extra)

    def __call__(self, environ, start_response):
        # Never trust X-Forwarded-* headers or expose this development app
        # through a real proxy. Both the peer and supplied Host are pinned.
        if (
            environ.get("REMOTE_ADDR") not in ("127.0.0.1", "::1")
            or environ.get("HTTP_HOST") != HOST
            or environ.get("wsgi.url_scheme") != "http"
            or any(key.startswith("HTTP_X_FORWARDED_") for key in environ)
        ):
            return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")

        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        query = environ.get("QUERY_STRING", "")
        cookie = environ.get("HTTP_COOKIE", "")
        if (not isinstance(cookie, str) or len(cookie) > 4096
                or not isinstance(query, str) or len(query) > 4096
                or path not in ("/", "/login", "/oidc/callback", "/session", "/logout")):
            return self._reply(start_response, HTTPStatus.NOT_FOUND, b"Not found")

        if path == "/login" and method == "GET":
            if query:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            try:
                started = self.manager.start_login()
            except Exception:
                return self._reply(start_response, HTTPStatus.SERVICE_UNAVAILABLE, b"Unavailable")
            return self._reply(
                start_response, HTTPStatus.FOUND, b"",
                extra=[("Location", started.authorization_url), ("Set-Cookie", started.set_cookie)],
            )

        if path == "/oidc/callback" and method == "GET":
            if not query:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Invalid login")
            try:
                # Fixed callback URL; never reconstruct from untrusted Host/forwarded headers.
                completed = self.manager.complete_login(cookie, CALLBACK + "?" + query)
            except (OIDCError, ValueError):
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Invalid login")
            return self._reply(
                start_response, HTTPStatus.SEE_OTHER, b"",
                extra=[("Location", "/"), ("Set-Cookie", completed.set_cookie)],
            )

        if path == "/session" and method == "GET":
            if query:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            identity = self.manager.get_identity(cookie)
            data = (
                {"authenticated": True, "subject": identity.sub}
                if identity is not None else {"authenticated": False}
            )
            status = HTTPStatus.OK if identity is not None else HTTPStatus.UNAUTHORIZED
            return self._reply(
                start_response, status, json.dumps(data).encode("utf-8"),
                content_type="application/json; charset=utf-8",
            )

        if path == "/" and method == "GET":
            if query:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            identity = self.manager.get_identity(cookie)
            if identity is None:
                return self._html(start_response, HTTPStatus.OK,
                    '<!doctype html><html lang="en"><meta charset="utf-8">'
                    '<title>GoreeCloud Identity · Local Demo</title>'
                    '<h1>GoreeCloud Identity</h1><p>Local development demonstration only.</p>'
                    '<p><a href="/login">Sign in</a></p></html>')
            csrf = self.manager.issue_csrf(cookie)
            if csrf is None:
                return self._reply(start_response, HTTPStatus.UNAUTHORIZED, b"Session expired")
            subject = escape(identity.sub, quote=True)
            token = escape(csrf, quote=True)
            return self._html(start_response, HTTPStatus.OK,
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                '<title>GoreeCloud Identity · Local Demo</title>'
                '<h1>GoreeCloud Identity</h1><p>Signed in as ' + subject + '</p>'
                '<form action="/logout" method="post">'
                '<label>End session <input type="hidden" name="csrf" value="' + token + '"></label>'
                '<button type="submit">Sign out</button></form></html>')

        if path == "/logout" and method == "POST":
            # Strict Origin check: never use missing/forged proxy headers as
            # a substitute for the session-bound CSRF token.
            if (query or environ.get("HTTP_ORIGIN") != ORIGIN
                    or environ.get("CONTENT_TYPE") != "application/x-www-form-urlencoded"):
                return self._reply(start_response, HTTPStatus.FORBIDDEN, b"Forbidden")
            length = environ.get("CONTENT_LENGTH", "")
            try:
                n = int(length)
            except (TypeError, ValueError):
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            if n < 1 or n > _BODY_LIMIT:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            body = environ["wsgi.input"].read(n)
            if len(body) != n:
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            try:
                values = parse_qs(body.decode("ascii"), strict_parsing=True,
                                  keep_blank_values=True, max_num_fields=2)
            except (UnicodeDecodeError, ValueError):
                return self._reply(start_response, HTTPStatus.BAD_REQUEST, b"Bad request")
            if set(values) != {"csrf"} or len(values["csrf"]) != 1:
                return self._reply(start_response, HTTPStatus.FORBIDDEN, b"Forbidden")
            if not self.manager.verify_csrf(cookie, values["csrf"][0]):
                return self._reply(start_response, HTTPStatus.FORBIDDEN, b"Forbidden")
            cleared = self.manager.logout(cookie)
            return self._reply(
                start_response, HTTPStatus.SEE_OTHER, b"",
                extra=[("Location", "/"), ("Set-Cookie", cleared)],
            )

        if (path in ("/login", "/oidc/callback", "/session", "/")
                and method not in ("GET",)) or (path == "/logout" and method != "POST"):
            return self._reply(start_response, HTTPStatus.METHOD_NOT_ALLOWED, b"Method not allowed")
        return self._reply(start_response, HTTPStatus.NOT_FOUND, b"Not found")


class QuietHandler(WSGIRequestHandler):
    """Prevent logging OIDC callback query parameters and authorization codes."""

    def log_message(self, format, *args):
        return None


def main() -> None:
    import sys
    if sys.argv != [sys.argv[0], "--local-development-only"]:
        raise SystemExit("This example requires --local-development-only and binds to loopback only")
    config = ClientConfig(ISSUER, "goreecloud-ci-public", CALLBACK, allow_local_dev=True)
    transport = StrictTransport(config)
    metadata = validate_metadata(transport.discovery(), config)
    app = LoopbackLoginApp(BrowserSessionManager(config, metadata, transport), config)
    print("Local development-only login demo on http://127.0.0.1:8765; no production protections")
    with make_server("127.0.0.1", 8765, app, handler_class=QuietHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
