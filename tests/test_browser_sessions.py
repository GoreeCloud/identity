"""Offline, synthetic browser-session security tests: no network calls."""
import secrets
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from goreecloud_identity.browser_sessions import (
    BrowserSessionError, BrowserSessionManager, COOKIE_NAME,
)
from goreecloud_identity.oidc import (
    ClientConfig, Metadata, OIDCError, VerifiedIdentity, parse_callback,
)


class FrozenClock:
    def __init__(self):
        self.now = time.monotonic()

    def __call__(self):
        return self.now


class StandInTransport:
    def __init__(self, config):
        self.config = config


class BrowserSessionTests(unittest.TestCase):
    def setUp(self):
        self.config = ClientConfig(
            "https://identity.example.test/realms/goreecloud",
            "gc-session-test",
            "https://app.example.test/oidc/callback",
        )
        self.metadata = Metadata(
            self.config.issuer + "/protocol/openid-connect/auth",
            self.config.issuer + "/protocol/openid-connect/token",
            self.config.issuer + "/protocol/openid-connect/certs",
        )
        self.clock = FrozenClock()
        self.manager = BrowserSessionManager(
            self.config, self.metadata,
            StandInTransport(self.config), clock=self.clock,
        )
        self.invocations = 0

    def start(self):
        result = self.manager.start_login()
        cookie_header = result.set_cookie.split(";", 1)[0]
        state = parse_qs(urlsplit(result.authorization_url).query)["state"][0]
        callback = self.config.redirect_uri + "?state=" + state + "&code=synthetic-code"
        return result, cookie_header, callback

    def fake_complete(self, config, metadata, flow, callback, transport):
        self.invocations += 1
        state, code = parse_callback(callback, config)
        flow.consume(state)
        if code != "synthetic-code":
            raise OIDCError("invalid synthetic code")
        return VerifiedIdentity("synthetic-user-1", config.issuer, config.client_id,
                                int(time.time()) - 10, int(time.time()) + 300)

    def finish(self, cookie, callback):
        with patch("goreecloud_identity.browser_sessions.complete_authorization",
                   side_effect=self.fake_complete):
            return self.manager.complete_login(cookie, callback)

    def test_cookie_has_host_only_secure_http_only_samesite(self):
        start, _, _ = self.start()
        val = start.set_cookie
        self.assertIn(COOKIE_NAME + "=", val)
        for bit in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=300"):
            self.assertIn(bit, val)
        self.assertNotIn("Domain=", val)

    def test_pending_session_is_not_authenticated(self):
        _, cookie, _ = self.start()
        self.assertIsNone(self.manager.get_identity(cookie))
        self.assertFalse(self.manager.verify_csrf(cookie, secrets.token_urlsafe(32)))

    def test_success_rotates_cookie_and_enables_csrf(self):
        _, cookie, callback = self.start()
        completed = self.finish(cookie, callback)
        fresh_cookie = completed.set_cookie.split(";", 1)[0]
        self.assertNotEqual(cookie, fresh_cookie)
        self.assertIsNone(self.manager.get_identity(cookie))
        self.assertEqual(self.manager.get_identity(fresh_cookie).sub, "synthetic-user-1")
        self.assertIn("Max-Age=1800", completed.set_cookie)
        self.assertTrue(self.manager.verify_csrf(fresh_cookie, completed.csrf_token))
        self.assertFalse(self.manager.verify_csrf(fresh_cookie, secrets.token_urlsafe(32)))
        self.assertFalse(self.manager.verify_csrf(cookie, completed.csrf_token))

    def test_one_time_callback_prevents_replay(self):
        _, cookie, callback = self.start()
        self.finish(cookie, callback)
        with self.assertRaises(BrowserSessionError):
            self.finish(cookie, callback)
        self.assertEqual(self.invocations, 1)

    def test_failed_callback_burns_transaction(self):
        _, cookie, callback = self.start()
        with self.assertRaises(OIDCError):
            self.finish(cookie, callback.replace("synthetic-code", "invalid"))
        with self.assertRaises(BrowserSessionError):
            self.finish(cookie, callback)
        self.assertEqual(self.invocations, 1)

    def test_callback_cannot_cross_browser_sessions(self):
        _, first_cookie, first_callback = self.start()
        _, second_cookie, _ = self.start()
        with self.assertRaises(OIDCError):
            self.finish(second_cookie, first_callback)
        with self.assertRaises(BrowserSessionError):
            self.finish(second_cookie, first_callback)
        self.assertEqual(self.finish(first_cookie, first_callback).identity.sub, "synthetic-user-1")

    def test_pending_expires(self):
        _, cookie, callback = self.start()
        self.clock.now += 301
        with self.assertRaises(BrowserSessionError):
            self.finish(cookie, callback)
        self.assertEqual(self.invocations, 0)

    def test_authenticated_session_has_hard_expiry(self):
        _, cookie, callback = self.start()
        completed = self.finish(cookie, callback)
        fresh = completed.set_cookie.split(";", 1)[0]
        self.clock.now += 1801
        self.assertIsNone(self.manager.get_identity(fresh))
        self.assertFalse(self.manager.verify_csrf(fresh, completed.csrf_token))

    def test_logout_removes_auth_and_expires_cookie(self):
        _, cookie, callback = self.start()
        completed = self.finish(cookie, callback)
        fresh = completed.set_cookie.split(";", 1)[0]
        cleared = self.manager.logout(fresh)
        self.assertIn("Max-Age=0", cleared)
        self.assertIn("Secure", cleared)
        self.assertIn("HttpOnly", cleared)
        self.assertIsNone(self.manager.get_identity(fresh))
        self.assertFalse(self.manager.verify_csrf(fresh, completed.csrf_token))

    def test_duplicate_and_malformed_cookies_fail_closed(self):
        _, cookie, callback = self.start()
        duplicate = cookie + "; " + cookie
        with self.assertRaises(BrowserSessionError):
            self.finish(duplicate, callback)
        self.assertIsNone(self.manager.get_identity(duplicate))
        self.assertIsNone(self.manager.get_identity(COOKIE_NAME + "=%0a"))
        self.assertIsNone(self.manager.get_identity(""))
        self.assertIsNone(self.manager.get_identity("x" * 5000))

    def test_unauthorized_session_capacity_denied(self):
        limited = BrowserSessionManager(
            self.config, self.metadata, StandInTransport(self.config),
            clock=self.clock, max_sessions=1,
        )
        limited.start_login()
        with self.assertRaises(BrowserSessionError):
            limited.start_login()
        self.clock.now += 301
        limited.start_login()

    def test_mismatched_transport_rejected(self):
        invalid = StandInTransport(ClientConfig(
            self.config.issuer, "another-client", self.config.redirect_uri
        ))
        with self.assertRaises(ValueError):
            BrowserSessionManager(self.config, self.metadata, invalid)

    def test_invalid_csrf_type_and_unicode_rejected(self):
        _, cookie, callback = self.start()
        completed = self.finish(cookie, callback)
        fresh = completed.set_cookie.split(";", 1)[0]
        self.assertFalse(self.manager.verify_csrf(fresh, "\ud800"))
        self.assertFalse(self.manager.verify_csrf(fresh, ""))
        self.assertFalse(self.manager.verify_csrf(fresh, "x" * 300))

    def test_logout_without_session_also_clears_browser_cookie(self):
        result = self.manager.logout("invalid-cookie")
        self.assertIn("Max-Age=0", result)


if __name__ == "__main__":
    unittest.main()
