"""Disposable CI-only browser-style OIDC Authorization Code + S256 PKCE smoke.

No production systems, real accounts, or persistent browser sessions. The only
HTTP target is the exact loopback Keycloak test instance. A final redirect to
the dummy callback address is parsed, NEVER followed or network-requested.
"""
from __future__ import annotations

from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.oidc import (
    ClientConfig, OIDCError, StrictTransport, begin_authorization,
    complete_authorization, validate_metadata,
)
from prepare_ci_login_fixture import (
    CLIENT_ID, CALLBACK_URI, SECRET_FILE, assert_ci_environment,
)

ISSUER = "http://localhost:8080/realms/goreecloud"
LOGIN_PREFIX = ISSUER + "/login-actions/"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        if tag != "form":
            return
        attributes = dict(attrs)
        if attributes.get("id") == "kc-form-login":
            self.action = attributes.get("action")


def assert_local_url(url: str, *, allow_callback: bool = False) -> None:
    if not isinstance(url, str) or len(url) > 8192:
        raise OIDCError("unexpected navigation URL")
    try:
        parsed = urlsplit(url)
        realm_path = "/realms/goreecloud"
        allowed_path = (
            parsed.path == realm_path + "/protocol/openid-connect/auth"
            or parsed.path.startswith(realm_path + "/login-actions/")
        )
        local = (parsed.scheme == "http" and parsed.hostname == "localhost"
                 and parsed.port == 8080 and parsed.username is None
                 and parsed.password is None and not parsed.fragment
                 and allowed_path and "%" not in parsed.path
                 and "\\\\" not in parsed.path
                 and all(segment not in (".", "..") for segment in parsed.path.split("/")))
    except ValueError as error:
        raise OIDCError("malformed navigation URL") from error
    if local or (allow_callback and url.startswith(CALLBACK_URI + "?")
                 and parsed.scheme == "http" and parsed.netloc == "127.0.0.1:8765"
                 and parsed.path == "/oidc/callback" and not parsed.fragment):
        return
    raise OIDCError("navigation outside local test identity blocked")


def read_response(opener, url: str, data: bytes | None = None):
    assert_local_url(url)
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {},
        method="POST" if data is not None else "GET",
    )
    try:
        response = opener.open(req, timeout=10)
    except HTTPError as error:
        response = error
    except (URLError, OSError) as error:
        raise OIDCError("local identity request failed") from error
    with response:
        status = response.status
        location = response.headers.get("Location")
        body = response.read(262145)
        if len(body) > 262144:
            raise OIDCError("identity HTML response too large")
        if not (200 <= status < 400):
            stage = "login_form_POST" if data is not None else "authorization_GET"
            raise OIDCError(f"local {stage} returned HTTP {status}")
        return status, location, body.decode("utf-8", errors="replace")


def authorize_browser(url: str, username: str, password: str) -> str:
    """Perform ONE synthetic password-form login; never use direct grant."""
    assert_local_url(url)
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), NoRedirect())
    current = url
    for _ in range(8):
        status, location, html = read_response(opener, current)
        if 300 <= status < 400:
            if not location:
                raise OIDCError("OIDC redirect is missing a location")
            target = urljoin(current, location)
            assert_local_url(target, allow_callback=True)
            if target.startswith(CALLBACK_URI + "?"):
                raise OIDCError("authorization succeeded without test user sign-in")
            current = target
            continue
        parser = LoginForm()
        parser.feed(html)
        if not parser.action:
            raise OIDCError("expected Keycloak login form not present")
        action = urljoin(current, parser.action)
        assert_local_url(action)
        if not action.startswith(LOGIN_PREFIX):
            raise OIDCError("unexpected login action")
        status, location, _ = read_response(
            opener, action,
            urlencode({"username": username, "password": password, "credentialId": ""}).encode("utf-8"),
        )
        if not (300 <= status < 400) or not location:
            raise OIDCError("synthetic browser login did not redirect")
        target = urljoin(action, location)
        assert_local_url(target, allow_callback=True)
        if target.startswith(CALLBACK_URI + "?"):
            return target
        current = target
        # On redirect after login, allow only further redirects to the callback.
        for _ in range(5):
            status, location, _ = read_response(opener, current)
            if not (300 <= status < 400) or not location:
                raise OIDCError("unexpected post-login page")
            target = urljoin(current, location)
            assert_local_url(target, allow_callback=True)
            if target.startswith(CALLBACK_URI + "?"):
                return target
            current = target
        raise OIDCError("too many post-login redirects")
    raise OIDCError("authorization never reached login form")


def main() -> None:
    assert_ci_environment()
    if not SECRET_FILE.is_file():
        raise OIDCError("CI-only fixture credentials unavailable")
    credentials = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    if credentials.get("client_id") != CLIENT_ID:
        raise OIDCError("unexpected synthetic OAuth client")
    config = ClientConfig(ISSUER, CLIENT_ID, CALLBACK_URI, allow_local_dev=True)
    transport = StrictTransport(config)
    metadata = validate_metadata(transport.discovery(), config)
    url, flow = begin_authorization(config, metadata)

    callback = authorize_browser(url, credentials["username"], credentials["password"])
    identity = complete_authorization(config, metadata, flow, callback, transport)
    if not identity.sub or identity.issuer != ISSUER or identity.client_id != CLIENT_ID:
        raise OIDCError("OIDC identity did not validate")
    print("PASS: disposable Keycloak browser-form login, code+S256 PKCE exchange, signed ID token")
    print("NOT TESTED: production sessions, MFA, logout, Gateway authorization or Android")


if __name__ == "__main__":
    try:
        main()
    except OIDCError as error:
        # Every OIDCError message in this module/core is a static, nonsensitive reason.
        # Never print HTTP responses, raw callback URLs, tokens or credentials.
        print(f"FAIL: local OIDC end-to-end smoke ({error})")
        raise SystemExit(1) from None
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"FAIL: local OIDC end-to-end smoke ({type(error).__name__})")
        raise SystemExit(1) from None
