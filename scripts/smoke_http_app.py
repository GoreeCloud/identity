"""GitHub CI-only end-to-end loopback HTTP session demo test.

Real HTTP on 127.0.0.1:8765 and real Keycloak authorization code exchange.
No browser app, production listener, external address, secrets or token logs.
"""
from __future__ import annotations

from html.parser import HTMLParser
from http.client import HTTPConnection
import json
from pathlib import Path
import sys
from threading import Thread
from urllib.parse import urlencode, urlsplit
from wsgiref.simple_server import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.browser_sessions import BrowserSessionManager
from goreecloud_identity.loopback_app import (
    CALLBACK, HOST, ORIGIN, ISSUER, LoopbackLoginApp, QuietHandler,
)
from goreecloud_identity.oidc import ClientConfig, StrictTransport, validate_metadata
from prepare_ci_login_fixture import (
    assert_ci_environment, SECRET_FILE, CLIENT_ID,
)
from smoke_login import authorize_browser


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("name") == "csrf":
            self.csrf = values.get("value")


def request(method: str, url: str, *, cookie: str = "", origin: str = "",
            body: str = "") -> tuple[int, dict[str, str], str]:
    if not url.startswith("/") or url.startswith("//") or len(url) > 8192:
        raise RuntimeError("unexpected HTTP route")
    headers = {"Host": HOST}
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn = HTTPConnection("127.0.0.1", 8765, timeout=8)
    try:
        conn.request(method, url, body=body.encode("ascii"), headers=headers)
        response = conn.getresponse()
        contents = response.read(262145)
        if len(contents) > 262144:
            raise RuntimeError("unexpectedly large demo response")
        return response.status, dict(response.getheaders()), contents.decode("utf-8")
    finally:
        conn.close()


def get_cookie(headers: dict[str, str]) -> str:
    value = headers.get("Set-Cookie", "")
    for required in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        if required not in value:
            raise RuntimeError("missing required browser cookie attribute")
    if "Domain=" in value:
        raise RuntimeError("unexpected cookie domain")
    return value.split(";", 1)[0]


def main() -> None:
    # Preflight before creating any listening socket, and never use a real user.
    assert_ci_environment()
    if not SECRET_FILE.is_file():
        raise RuntimeError("synthetic GitHub CI fixture missing")
    creds = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    if creds.get("client_id") != CLIENT_ID or not creds.get("username", "").startswith("gc-ci-"):
        raise RuntimeError("invalid synthetic fixture")
    config = ClientConfig(ISSUER, CLIENT_ID, CALLBACK, allow_local_dev=True)
    transport = StrictTransport(config)
    metadata = validate_metadata(transport.discovery(), config)
    manager = BrowserSessionManager(config, metadata, transport, max_sessions=8)
    app = LoopbackLoginApp(manager, config)

    with make_server("127.0.0.1", 8765, app, handler_class=QuietHandler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, headers, _ = request("GET", "/login")
            if status != 302:
                raise RuntimeError("authorization did not start")
            anonymous_cookie = get_cookie(headers)
            keycloak_url = headers["Location"]
            if not keycloak_url.startswith(ISSUER + "/protocol/openid-connect/auth?"):
                raise RuntimeError("untrusted authorization URL")

            callback = authorize_browser(keycloak_url, creds["username"], creds["password"])
            parsed = urlsplit(callback)
            if parsed.scheme != "http" or parsed.netloc != HOST or parsed.path != "/oidc/callback":
                raise RuntimeError("unexpected callback origin")
            status, headers, _ = request(
                "GET", parsed.path + "?" + parsed.query, cookie=anonymous_cookie
            )
            if status != 303 or headers.get("Location") != "/":
                raise RuntimeError("callback session was not established")
            authenticated_cookie = get_cookie(headers)
            if authenticated_cookie == anonymous_cookie:
                raise RuntimeError("session identifier not rotated")

            status, _, payload = request("GET", "/session", cookie=authenticated_cookie)
            if status != 200 or not json.loads(payload).get("authenticated"):
                raise RuntimeError("authenticated session not accessible")

            status, _, content = request("GET", "/", cookie=authenticated_cookie)
            form = FormParser()
            form.feed(content)
            if status != 200 or not form.csrf:
                raise RuntimeError("no protected CSRF logout form")

            status, _, _ = request("POST", "/logout", cookie=authenticated_cookie,
                                   origin=ORIGIN, body="csrf=invalid")
            if status != 403:
                raise RuntimeError("logout allowed without valid CSRF token")
            status, _, _ = request("GET", "/session", cookie=authenticated_cookie)
            if status != 200:
                raise RuntimeError("rejected CSRF attempt unexpectedly ended session")

            status, headers, _ = request(
                "POST", "/logout", cookie=authenticated_cookie,
                origin=ORIGIN, body=urlencode({"csrf": form.csrf}),
            )
            if status != 303 or "Max-Age=0" not in headers.get("Set-Cookie", ""):
                raise RuntimeError("session logout did not expire browser cookie")
            status, _, payload = request("GET", "/session", cookie=authenticated_cookie)
            if status != 401 or json.loads(payload).get("authenticated"):
                raise RuntimeError("session remained authenticated after logout")

            print("PASS: real loopback HTTP + Keycloak code/PKCE + server cookie rotation, CSRF and logout")
            print("NOT TESTED: production TLS, durable sessions, Gateway or Android")
        finally:
            server.shutdown()
            thread.join(timeout=8)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        # Avoid printing tokens, callback URLs, cookies, credentials or sensitive HTML.
        print(f"FAIL: isolated HTTP/SSO smoke ({type(error).__name__})")
        raise SystemExit(1) from None
