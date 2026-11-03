"""Offline security tests for issuer-pinned JWKS acquisition and key rotation."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric import rsa

from goreecloud_identity.jwks_trust import (
    JWKSUnavailable, PinnedIssuerKeys, _validate_issuer, validate_public_jwks,
)


def b64(x):
    return base64.urlsafe_b64encode(x.to_bytes((x.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def jwk(kid="test-key", bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig",
            "alg": "RS256", "n": b64(pub.n), "e": b64(pub.e)}


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeHTTPResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, a, b, c):
        return False

    def read(self, limit):
        return self.payload[:limit]


class FakeOpener:
    def __init__(self, datasets):
        self.datasets = list(datasets)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request.full_url, request.get_method(), timeout))
        if not self.datasets:
            raise OSError("simulated issuer outage")
        next_data = self.datasets.pop(0)
        if isinstance(next_data, Exception):
            raise next_data
        return FakeHTTPResponse(json.dumps(next_data).encode())


class JWKSCacheTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.issuer = "https://identity.example.test/realms/goreecloud"
        self.first = jwk()
        self.second = jwk("rotated-key")
        self.keys = PinnedIssuerKeys(self.issuer, ttl_seconds=60,
                                     unknown_kid_refresh_seconds=10, clock=self.clock)

    def install(self, *data):
        self.opener = FakeOpener(data)
        self.keys._opener = self.opener
        return self.opener

    def test_fixed_url_and_first_fetch_then_cache(self):
        opener = self.install({"keys": [self.first]})
        self.assertEqual(self.keys.for_key("test-key")["keys"][0]["kid"], "test-key")
        self.keys.for_key("test-key")
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(opener.calls[0], (self.issuer + "/protocol/openid-connect/certs", "GET", 5))

    def test_unknown_kid_fails_closed_and_is_rate_limited(self):
        op = self.install({"keys": [self.first]})
        self.keys.for_key("test-key")
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("not-there")
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("not-there")
        self.assertEqual(len(op.calls), 1)

    def test_key_rotation_after_cooldown(self):
        self.install({"keys": [self.first]}, {"keys": [self.second]})
        self.keys.for_key("test-key")
        self.clock.now += 11
        self.assertEqual(self.keys.for_key("rotated-key")["keys"][0]["kid"], "rotated-key")
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("test-key")

    def test_expired_cache_fails_closed_during_outage(self):
        op = self.install({"keys": [self.first]}, OSError("backend unavailable"))
        self.keys.for_key("test-key")
        self.clock.now += 61
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("test-key")
        self.assertEqual(len(op.calls), 2)

    def test_explicit_cache_clear_fetches_again(self):
        op = self.install({"keys": [self.first]}, {"keys": [self.second]})
        self.keys.for_key("test-key")
        self.keys.clear()
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("test-key")
        self.assertEqual(len(op.calls), 2)

    def test_rejects_issuer_override_and_http(self):
        for issuer in (
            "http://id.example.test/realms/goreecloud",
            "https://user:pass@id.example.test/realms/goreecloud",
            "https://id.example.test/realms/goreecloud?next=evil",
            "https://id.example.test/realms/",
            "https://id.example.test/realms/goreecloud/extra",
            "https://id.example.test/%2e%2e/realms/goreecloud",
            "file:///etc/hosts",
        ):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                _validate_issuer(issuer)
        _validate_issuer("http://localhost:8080/realms/goreecloud")

    def test_rejects_unsafe_key_metadata(self):
        for candidate in (
            {**self.first, "d": "private"},
            {**self.first, "k": "private"},
            {**self.first, "kid": ""},
            {**self.first, "kid": "bad/kid"},
            {**self.first, "n": ""},
        ):
            with self.subTest(candidate=str(candidate.get("kid"))), self.assertRaises(JWKSUnavailable):
                validate_public_jwks({"keys": [candidate]})

    def test_rejects_duplicate_kid(self):
        with self.assertRaises(JWKSUnavailable):
            validate_public_jwks({"keys": [self.first, self.first]})

    def test_rejects_weak_rsa_key(self):
        weak = jwk("weak", bits=1024)
        with self.assertRaises(JWKSUnavailable):
            validate_public_jwks({"keys": [weak]})

    def test_skips_other_valid_key_types_but_requires_rs256(self):
        values = validate_public_jwks({"keys": [
            {"kty": "EC", "alg": "ES256", "kid": "other", "crv": "P-256", "x": "a", "y": "b"},
            self.first,
        ]})
        self.assertEqual(len(values["keys"]), 1)
        with self.assertRaises(JWKSUnavailable):
            validate_public_jwks({"keys": [{"kty": "EC", "alg": "ES256", "kid": "other"}]})

    def test_invalid_json_response_denied(self):
        self.keys._opener = FakeOpener([])
        with self.assertRaises(JWKSUnavailable):
            self.keys.for_key("test-key")


if __name__ == "__main__":
    unittest.main()
