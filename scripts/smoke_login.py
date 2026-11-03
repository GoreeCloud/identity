"""Disposable CI-only browser-style OIDC Authorization Code + S256 PKCE smoke.

No production systems, real accounts, or persistent browser sessions. The only
HTTP target is the exact loopback Keycloak test instance. A final redirect to
the dummy callback address is parsed, NEVER followed or network-requested.
"""
from __future__ import annotations

from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, parse_qs
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.oidc import (
    ClientConfig, OIDCError, StrictTransport, validate_metadata,
)
from goreecloud_identity.browser_sessions import BrowserSessionManager
from prepare_ci_login_fixture import (
    CLIENT_ID, CALLBACK_URI, SECRET_FILE, assert_ci_environment,
)

ISSUER = "http://localhost:8080/realms/goreecloud"
LOGIN_PREFIX = ISSUER + "/login-actions/"


class ExactLoopbackCookiePolicy(DefaultCookiePolicy):
    """Match browsers' secure-context exception only for the CI localhost origin.

    Keycloak 26 may mark AUTH_SESSION_ID and KC_RESTART Secure even on its
    localhost development HTTP listener. Python's standard cookie jar refuses
    to send Secure cookies over HTTP. This narrow exception is test-only:
    never apply to external hosts, real proxy traffic, or application sessions.
    """

    def return_ok_secure(self, cookie, request):
        try:
            parsed = urlsplit(request.full_url)
            exact_dev_origin = (
                parsed.scheme == "http"
                and parsed.hostname == "localhost"
                and parsed.port == 8080
                and parsed.username is None
                and parsed.password is None
            )
        except (AttributeError, ValueError):
            exact_dev_origin = False
        if cookie.secure and exact_dev_origin:
            return True
        return super().return_ok_secure(cookie, request)


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


def read_response(opener, url: str, data: bytes | None = None, referer: str | None = None):
    assert_local_url(url)
    if referer is not None:
        assert_local_url(referer)
    headers = ({} if data is None else {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://localhost:8080",
        "Referer": referer or "http://localhost:8080/realms/goreecloud/protocol/openid-connect/auth",
    })
    req = Request(
        url,
        data=data,
        headers=headers,
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
            message = body.lower()
            kind = ("cookie" if b"cookie" in message else
                    "expired" if b"expired" in message else
                    "invalid" if b"invalid" in message else "unclassified")
            raise OIDCError(f"local {stage} returned HTTP {status} ({kind})")
        return status, location, body.decode("utf-8", errors="replace")


def authorize_browser(url: str, username: str, password: str) -> str:
    """Perform ONE synthetic password-form login; never use direct grant."""
    assert_local_url(url)
    jar = CookieJar(policy=ExactLoopbackCookiePolicy())
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar), NoRedirect())
    current = url
    for _ in range(8):
        status, location, html = read_response(opener, current)
        if 300 <= status < 400:
            if not location:
                raise OIDCError("OIDC redirect is missing a location")
            target = urljoin(current, location)
            assert_local_url(target, allow_callback=True)
            if target.startswith(CALLBACK_URI + "?"):
                # The provider may reject a malformed CI client *before*
                # showing any login form. Show only a fixed, allowlisted OAuth
                # error category; never log callback query values or secrets.
                response_fields = parse_qs(urlsplit(target).query, keep_blank_values=True)
                errors = response_fields.get("error", [])
                permitted = {
                    "invalid_request", "invalid_scope", "unauthorized_client",
                    "access_denied", "login_required", "temporarily_unavailable",
                }
                category = errors[0] if len(errors) == 1 and errors[0] in permitted else "none"
                if category == "invalid_scope":
                    # The provider's description may include arbitrary text;
                    # print only trusted literals, never the description itself.
                    descriptions = response_fields.get("error_description", [])
                    raw_description = (
                        descriptions[0].lower() if len(descriptions) == 1 else ""
                    )
                    known_scopes = ("profile", "openid", "gateway:read", "roles", "email")
                    names = [name for name in known_scopes if name in raw_description]
                    category = "invalid_scope:" + (",".join(names) or "unspecified")
                raise OIDCError(f"pre-login callback before synthetic sign-in ({category})")
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
        try:
            status, location, _ = read_response(
                opener, action,
                urlencode({"username": username, "password": password, "credentialId": ""}).encode("utf-8"),
                referer=current,
            )
        except OIDCError as error:
            raise OIDCError(f"{error}; session_cookie_count={len(jar)}") from error
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
    manager = BrowserSessionManager(config, metadata, transport, max_sessions=8)
    pending = manager.start_login()
    original_cookie = pending.set_cookie.split(";", 1)[0]
    if manager.get_identity(original_cookie) is not None:
        raise OIDCError("anonymous login session unexpectedly authenticated")

    callback = authorize_browser(
        pending.authorization_url, credentials["username"], credentials["password"]
    )
    completed = manager.complete_login(original_cookie, callback)
    identity = completed.identity
    new_cookie = completed.set_cookie.split(";", 1)[0]
    if not identity.sub or identity.issuer != ISSUER or identity.client_id != CLIENT_ID:
        raise OIDCError("OIDC identity did not validate")
    if (new_cookie == original_cookie or manager.get_identity(original_cookie) is not None
            or manager.get_identity(new_cookie) != identity
            or not manager.verify_csrf(new_cookie, completed.csrf_token)):
        raise OIDCError("server-side browser session acceptance failed")
    manager.logout(new_cookie)
    if manager.get_identity(new_cookie) is not None:
        raise OIDCError("local browser session logout failed")
    print("PASS: synthetic Keycloak browser login, S256 PKCE exchange, verified ID token, in-process session rotation/CSRF/logout")
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
