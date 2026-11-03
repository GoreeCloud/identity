import base64
from dataclasses import replace
import hashlib
import sys
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from goreecloud_identity.oidc import (
    ClientConfig, Metadata, OIDCError, PendingFlow, StrictTransport,
    begin_authorization, complete_authorization, parse_callback,
    validate_id_token, validate_metadata,
)


def b64int(value):
    return base64.urlsafe_b64encode(
        value.to_bytes((value.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("ascii")


class StubTransport(StrictTransport):
    def __init__(self, config, jwks, response):
        self.config = config
        self.keys = jwks
        self.response = response
        self.invocations = 0

    def jwks(self):
        return self.keys

    def exchange(self, metadata, code, verifier):
        self.invocations += 1
        return self.response


class OIDCLoginFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.key.public_key().public_numbers()
        cls.keys = {"keys": [{
            "kid": "key-1", "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": b64int(public.n), "e": b64int(public.e),
        }]}
        cls.config = ClientConfig(
            "https://identity.example.test/realms/goreecloud",
            "goreecloud-demo",
            "https://demo.example.test/oidc/callback",
        )
        cls.meta = Metadata(
            cls.config.issuer + "/protocol/openid-connect/auth",
            cls.config.issuer + "/protocol/openid-connect/token",
            cls.config.issuer + "/protocol/openid-connect/certs",
        )

    def setUp(self):
        self.url, self.flow = begin_authorization(self.config, self.meta)
        self.access = "sample-access-token"
        self.response = {
            "token_type": "Bearer",
            "access_token": self.access,
            "id_token": self.signed_id(),
        }
        self.transport = StubTransport(self.config, self.keys, self.response)

    def claims(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": self.config.issuer, "aud": self.config.client_id,
            "sub": "verified-person-1", "nonce": self.flow.nonce,
            "iat": now - 1, "exp": now + 300,
        }
        claims.update(overrides)
        return claims

    def signed_id(self, **overrides):
        return jwt.encode(
            self.claims(**overrides), self.key, algorithm="RS256",
            headers={"kid": "key-1"},
        )

    def callback(self, state=None, code="short-code"):
        state = self.flow.state if state is None else state
        return self.config.redirect_uri + "?state=" + state + "&code=" + code

    def finish(self, url=None, **kwargs):
        return complete_authorization(
            self.config, self.meta, self.flow,
            self.callback() if url is None else url, self.transport, **kwargs,
        )

    def test_authorization_request_contains_s256_and_nonce(self):
        parsed = urlsplit(self.url)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "identity.example.test")
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["scope"], ["openid profile"])
        self.assertEqual(query["nonce"], [self.flow.nonce])
        self.assertEqual(query["state"], [self.flow.state])
        self.assertEqual(query["redirect_uri"], [self.config.redirect_uri])
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(self.flow.verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(query["code_challenge"], [expected])
        self.assertNotIn(self.flow.verifier, self.url)

    def test_valid_complete_flow(self):
        identity = self.finish()
        self.assertEqual(identity.sub, "verified-person-1")
        self.assertEqual(identity.issuer, self.config.issuer)
        self.assertEqual(self.transport.invocations, 1)

    def test_approval_is_single_use(self):
        self.finish()
        with self.assertRaises(OIDCError):
            self.finish()
        self.assertEqual(self.transport.invocations, 1)

    def test_wrong_state_fails_before_exchange(self):
        with self.assertRaises(OIDCError):
            self.finish(self.callback(state="attacker-state"))
        self.assertEqual(self.transport.invocations, 0)

    def test_expired_authorization_rejected(self):
        with self.assertRaises(OIDCError):
            self.finish(now=self.flow.issued_at + 301)

    def test_provider_error_rejected(self):
        with self.assertRaises(OIDCError):
            self.finish(self.config.redirect_uri + "?state=" + self.flow.state + "&error=access_denied")

    def test_redirect_host_mismatch(self):
        with self.assertRaises(OIDCError):
            self.finish(self.callback().replace("demo.example.test", "attacker.example.test"))

    def test_repeated_code_rejected(self):
        with self.assertRaises(OIDCError):
            self.finish(self.callback() + "&code=attacker")

    def test_fragment_callback_rejected(self):
        with self.assertRaises(OIDCError):
            self.finish(self.callback() + "#fragment")

    def test_nonce_mismatch_rejected(self):
        self.response["id_token"] = self.signed_id(nonce="wrong")
        with self.assertRaises(OIDCError):
            self.finish()

    def test_wrong_id_token_audience_rejected(self):
        self.response["id_token"] = self.signed_id(aud="another-app")
        with self.assertRaises(OIDCError):
            self.finish()

    def test_wrong_issuer_rejected(self):
        self.response["id_token"] = self.signed_id(iss="https://attacker.example.test/realms/goreecloud")
        with self.assertRaises(OIDCError):
            self.finish()

    def test_expired_id_token_rejected(self):
        self.response["id_token"] = self.signed_id(exp=int(time.time()) - 200)
        with self.assertRaises(OIDCError):
            self.finish()

    def test_id_token_at_hash_verified(self):
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(self.access.encode("ascii")).digest()[:16]
        ).rstrip(b"=").decode("ascii")
        self.response["id_token"] = self.signed_id(at_hash=expected)
        self.assertEqual(self.finish().sub, "verified-person-1")

    def test_at_hash_mismatch_rejected(self):
        self.response["id_token"] = self.signed_id(at_hash="untrusted-value")
        with self.assertRaises(OIDCError):
            self.finish()

    def test_unsigned_token_rejected(self):
        self.response["id_token"] = jwt.encode(self.claims(), "not-an-actual-key", algorithm="HS256", headers={"kid":"key-1"})
        with self.assertRaises(OIDCError):
            self.finish()

    def test_tampered_signature_rejected(self):
        parts = self.response["id_token"].split(".")
        parts[2] = ("B" if parts[2][0] != "B" else "C") + parts[2][1:]
        self.response["id_token"] = ".".join(parts)
        with self.assertRaises(OIDCError):
            self.finish()

    def test_duplicate_kid_rejected(self):
        self.transport.keys = {"keys": self.keys["keys"] * 2}
        with self.assertRaises(OIDCError):
            self.finish()

    def test_private_jwk_rejected(self):
        self.transport.keys = {"keys": [{**self.keys["keys"][0], "d": "secret"}]}
        with self.assertRaises(OIDCError):
            self.finish()

    def test_wrong_token_type_rejected(self):
        self.response["token_type"] = "Basic"
        with self.assertRaises(OIDCError):
            self.finish()

    def test_untrusted_transport_rejected_before_exchange(self):
        self.transport.config = replace(self.config, client_id="attacker")
        with self.assertRaises(OIDCError):
            self.finish()
        self.assertEqual(self.transport.invocations, 0)

    def test_discovery_issuer_mismatch(self):
        doc = self.sample_metadata()
        doc["issuer"] = "https://attacker.test"
        with self.assertRaises(OIDCError):
            validate_metadata(doc, self.config)

    def sample_metadata(self):
        return {
            "issuer": self.config.issuer,
            "authorization_endpoint": self.meta.authorization_endpoint,
            "token_endpoint": self.meta.token_endpoint,
            "jwks_uri": self.meta.jwks_uri,
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["plain", "S256"],
        }

    def test_discovery_rejects_unadvertised_pkce(self):
        doc = self.sample_metadata()
        doc["code_challenge_methods_supported"] = ["plain"]
        with self.assertRaises(OIDCError):
            validate_metadata(doc, self.config)

    def test_discovery_rejects_other_token_endpoint(self):
        doc = self.sample_metadata()
        doc["token_endpoint"] = "https://attacker.test/exchange"
        with self.assertRaises(OIDCError):
            validate_metadata(doc, self.config)

    def test_valid_discovery(self):
        self.assertEqual(validate_metadata(self.sample_metadata(), self.config), self.meta)

    def test_http_issuer_rejected_outside_local_dev(self):
        with self.assertRaises(OIDCError):
            ClientConfig("http://identity.example.test/realms/goreecloud",
                         "client", "https://client.example.test/callback")

    def test_explicit_local_dev_only(self):
        dev = ClientConfig(
            "http://localhost:8080/realms/goreecloud", "local-dev",
            "http://127.0.0.1:8765/oidc/callback", allow_local_dev=True,
        )
        self.assertTrue(dev.allow_local_dev)
        with self.assertRaises(OIDCError):
            ClientConfig(dev.issuer, dev.client_id,
                         "http://0.0.0.0:8765/oidc/callback", allow_local_dev=True)

    def test_duplicate_state_parameter_rejected(self):
        with self.assertRaises(OIDCError):
            parse_callback(self.callback() + "&state=other", self.config)

    def test_unapproved_network_endpoint_rejected(self):
        with self.assertRaises(OIDCError):
            self.transport._json("https://attacker.test/jwks")

    def test_issuer_parameter_must_match_if_present(self):
        uri = self.callback() + "&iss=https%3A%2F%2Fattacker.test"
        with self.assertRaises(OIDCError):
            parse_callback(uri, self.config)


if __name__ == "__main__":
    unittest.main()
