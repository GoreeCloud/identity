"""Network-free WSGI contract tests for the loopback-only login example."""
from html.parser import HTMLParser
from io import BytesIO
import json
from pathlib import Path
import re
import sys
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from goreecloud_identity.browser_sessions import BrowserSessionManager
from goreecloud_identity.loopback_app import (
    CALLBACK, HOST, ISSUER, ORIGIN, DemoConfigurationError, LoopbackLoginApp,
)
from goreecloud_identity.oidc import (
    ClientConfig, Metadata, OIDCError, VerifiedIdentity, parse_callback,
)


class DummyTransport:
    def __init__(self, config):
        self.config = config


class CSRFParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.value = None

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        d = dict(attrs)
        if d.get("name") == "csrf":
            self.value = d.get("value")


class WSGIContractTests(unittest.TestCase):
    def setUp(self):
        self.config = ClientConfig(ISSUER, "goreecloud-ci-public", CALLBACK, allow_local_dev=True)
        self.meta = Metadata(
            ISSUER + "/protocol/openid-connect/auth",
            ISSUER + "/protocol/openid-connect/token",
            ISSUER + "/protocol/openid-connect/certs",
        )
        self.manager = BrowserSessionManager(self.config, self.meta, DummyTransport(self.config))
        self.app = LoopbackLoginApp(self.manager, self.config)

    def request(self, method="GET", path="/", *, query="", cookie="", origin=None,
                form=None, host=HOST, peer="127.0.0.1", forwarded=None,
                ctype="application/x-www-form-urlencoded", length=None):
        body = b"" if form is None else form.encode("ascii")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "HTTP_HOST": host,
            "REMOTE_ADDR": peer,
            "HTTP_COOKIE": cookie,
            "CONTENT_TYPE": ctype,
            "CONTENT_LENGTH": str(len(body)) if length is None else length,
            "wsgi.input": BytesIO(body),
            "wsgi.url_scheme": "http",
        }
        if origin is not None:
            env["HTTP_ORIGIN"] = origin
        if forwarded is not None:
            env["HTTP_X_FORWARDED_HOST"] = forwarded
        result = []
        def respond(status, headers):
            result.append((status, dict(headers)))
        payload = b"".join(self.app(env, respond))
        status, headers = result[0]
        return int(status.split()[0]), headers, payload.decode("utf-8")

    def begin(self):
        status, h, _ = self.request(path="/login")
        self.assertEqual(status, 302)
        self.assertTrue(h["Location"].startswith(ISSUER + "/protocol/openid-connect/auth?"))
        return h["Set-Cookie"].split(";", 1)[0], parse_qs(urlsplit(h["Location"]).query)["state"][0]

    def fake_auth(self, config, meta, flow, callback, transport):
        state, _code = parse_callback(callback, config)
        flow.consume(state)
        return VerifiedIdentity("safe-subject-1", config.issuer, config.client_id,
                                int(time.time())-5, int(time.time())+300)

    def signed_in(self):
        pending, state = self.begin()
        with patch("goreecloud_identity.browser_sessions.complete_authorization",
                   side_effect=self.fake_auth):
            code, headers, _ = self.request(path="/oidc/callback",
                query="state="+state+"&code=synthetic",
                cookie=pending)
        self.assertEqual(code, 303)
        self.assertEqual(headers["Location"], "/")
        return pending, headers["Set-Cookie"].split(";", 1)[0]

    def test_landing_is_anonymous_and_has_headers(self):
        code, headers, body = self.request()
        self.assertEqual(code, 200)
        self.assertIn("/login", body)
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_login_sets_browser_cookie_and_keycloak_redirect(self):
        code, h, _ = self.request(path="/login")
        self.assertEqual(code, 302)
        for part in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(part, h["Set-Cookie"])
        self.assertNotIn("Domain=", h["Set-Cookie"])

    def test_signed_in_session_api_is_private_and_returns_subject(self):
        _, fresh = self.signed_in()
        anon, _, data = self.request(path="/session")
        self.assertEqual(anon, 401)
        self.assertFalse(json.loads(data)["authenticated"])
        signed, headers, data = self.request(path="/session", cookie=fresh)
        self.assertEqual(signed, 200)
        self.assertEqual(json.loads(data)["subject"], "safe-subject-1")
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")

    def test_login_rotates_and_old_cookie_cannot_access_private_info(self):
        pending, fresh = self.signed_in()
        self.assertNotEqual(pending, fresh)
        code, _, _ = self.request(path="/session", cookie=pending)
        self.assertEqual(code, 401)

    def test_logout_requires_origin_and_csrf(self):
        _, fresh = self.signed_in()
        status, _, html = self.request(path="/",cookie=fresh)
        self.assertEqual(status, 200)
        p = CSRFParser()
        p.feed(html)
        self.assertIsNotNone(p.value)
        code, _, _ = self.request(method="POST",path="/logout",cookie=fresh,form="csrf="+p.value)
        self.assertEqual(code, 403)
        code, _, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form="csrf=bad")
        self.assertEqual(code, 403)
        code, h, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form="csrf="+p.value)
        self.assertEqual(code, 303)
        self.assertIn("Max-Age=0", h["Set-Cookie"])
        code, _, _ = self.request(path="/session",cookie=fresh)
        self.assertEqual(code, 401)

    def test_form_csrf_refresh_invalidates_prior_token(self):
        _, fresh = self.signed_in()
        _, _, html1 = self.request(path="/", cookie=fresh)
        _, _, html2 = self.request(path="/", cookie=fresh)
        p1, p2 = CSRFParser(), CSRFParser()
        p1.feed(html1); p2.feed(html2)
        self.assertNotEqual(p1.value, p2.value)
        code, _, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form="csrf="+p1.value)
        self.assertEqual(code, 403)
        code, _, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form="csrf="+p2.value)
        self.assertEqual(code, 303)

    def test_callback_state_mismatch_never_authenticates(self):
        pending, _ = self.begin()
        with patch("goreecloud_identity.browser_sessions.complete_authorization",
                   side_effect=self.fake_auth):
            status, _, body = self.request(path="/oidc/callback",cookie=pending,
                                          query="state=wrong&code=synthetic")
        self.assertEqual(status, 400)
        self.assertNotIn("wrong", body)
        code, _, _ = self.request(path="/session", cookie=pending)
        self.assertEqual(code, 401)

    def test_bad_origin_forwarder_or_peer_fail_closed(self):
        for kw in ({"host": "localhost:8765"},
                   {"peer":"203.0.113.1"},
                   {"forwarded":"client.example"},
                   {"host":"evil.example"},
                   ):
            with self.subTest(kw=kw):
                code, _, _ = self.request(**kw)
                self.assertEqual(code, 400)

    def test_non_dev_relying_party_rejected(self):
        prod = ClientConfig("https://identity.example.test/realms/goreecloud",
                            "goreecloud-ci-public", "https://app.example.test/oidc/callback")
        with self.assertRaises(DemoConfigurationError):
            LoopbackLoginApp(BrowserSessionManager(prod,self.meta,DummyTransport(prod)),prod)

    def test_duplicate_csrf_or_malformed_body_rejected(self):
        _, fresh = self.signed_in()
        for form in ("csrf=x&csrf=y", "csrf=", "other=z", "csrf=%GG"):
            with self.subTest(form=form):
                status, _, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form=form)
                self.assertIn(status, (400,403))
        status, _, _ = self.request(method="POST",path="/logout",cookie=fresh,origin=ORIGIN,form="csrf=x",length="5000000")
        self.assertEqual(status, 400)

    def test_unexpected_method_and_route_rejected(self):
        self.assertEqual(self.request(method="POST",path="/login")[0],405)
        self.assertEqual(self.request(path="/missing")[0],404)
        self.assertEqual(self.request(path="/login",query="next=https://evil.test")[0],400)
        self.assertEqual(self.request(method="GET",path="/logout")[0],405)

    def test_insecure_session_cookie_never_appears_in_json(self):
        _, fresh = self.signed_in()
        _, _, body = self.request(path="/session",cookie=fresh)
        self.assertNotIn(fresh,body)


if __name__ == "__main__":
    unittest.main()
