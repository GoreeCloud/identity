"""Offline safeguards for disposable browser-based OIDC CI smoke tests."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_ci_login_fixture import build_fixture, CLIENT_ID, CALLBACK_URI
from smoke_login import LoginForm, assert_local_url
from goreecloud_identity.oidc import OIDCError


class SyntheticLoginFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realm = json.loads((ROOT / "realm/goreecloud-realm.json").read_text(encoding="utf-8"))

    def test_fixture_creates_one_public_pkce_client_and_one_synthetic_user(self):
        fixture = build_fixture(self.realm, "gc-ci-test-1234", "CI9!" + "x" * 40)
        self.assertEqual(len(fixture["clients"]), 1)
        client = fixture["clients"][0]
        self.assertEqual(client["clientId"], CLIENT_ID)
        self.assertTrue(client["publicClient"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertFalse(client["implicitFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertEqual(client["redirectUris"], [CALLBACK_URI])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertEqual(len(fixture["users"]), 1)
        self.assertEqual(fixture["users"][0]["username"], "gc-ci-test-1234")
        self.assertTrue(fixture["users"][0]["credentials"])
        self.assertEqual(self.realm["users"], [])
        self.assertEqual(self.realm["clients"], [])

    def test_rejects_existing_user_or_client(self):
        current = {**self.realm, "users": [{"username": "not-a-test-account"}]}
        with self.assertRaises(ValueError):
            build_fixture(current, "gc-ci-test-1234", "CI9!" + "x" * 40)

    def test_rejects_wrong_realm(self):
        current = {**self.realm, "realm": "production"}
        with self.assertRaises(ValueError):
            build_fixture(current, "gc-ci-test-1234", "CI9!" + "x" * 40)

    def test_rejects_weak_or_unmarked_identity(self):
        with self.assertRaises(ValueError):
            build_fixture(self.realm, "admin", "CI9!" + "x" * 40)
        with self.assertRaises(ValueError):
            build_fixture(self.realm, "gc-ci-test-1234", "short")


class BrowserNavigationTests(unittest.TestCase):
    def test_accepts_only_local_realm(self):
        assert_local_url("http://localhost:8080/realms/goreecloud/protocol/openid-connect/auth?client_id=x")

    def test_allows_only_exact_dummy_callback(self):
        assert_local_url(CALLBACK_URI + "?code=foo&state=bar", allow_callback=True)
        with self.assertRaises(OIDCError):
            assert_local_url(CALLBACK_URI + "?code=foo", allow_callback=False)

    def test_refuses_external_identity_redirect(self):
        for value in (
            "https://accounts.example.com/auth",
            "http://127.0.0.1:8080/realms/goreecloud/login-actions/authenticate",
            "http://localhost:8080/admin/master/console/",
            "http://localhost:8080/realms/production/login-actions/authenticate",
            "http://localhost:8080/realms/goreecloud/../../admin",
            "file:///etc/passwd",
        ):
            with self.subTest(value=value), self.assertRaises(OIDCError):
                assert_local_url(value)

    def test_refuses_external_callback(self):
        for value in (
            "http://127.0.0.1:8766/oidc/callback?code=x",
            "http://localhost:8765/oidc/callback?code=x",
            "http://127.0.0.1:8765/oidc/callback#token",
        ):
            with self.subTest(value=value), self.assertRaises(OIDCError):
                assert_local_url(value, allow_callback=True)

    def test_extracts_keycloak_form_action(self):
        parser = LoginForm()
        parser.feed('<form id="kc-form-login" action="http://localhost:8080/realms/goreecloud/login-actions/authenticate?x=1&amp;y=2"></form>')
        self.assertEqual(parser.action, "http://localhost:8080/realms/goreecloud/login-actions/authenticate?x=1&y=2")


if __name__ == "__main__":
    unittest.main()
