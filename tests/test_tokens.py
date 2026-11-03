import base64
import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from goreecloud_identity.tokens import VerificationError, verify_access_token


def b64int(value):
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


class TokenVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.key.public_key().public_numbers()
        cls.jwks = {"keys": [{"kty": "RSA", "kid": "development-test",
                               "alg": "RS256", "use": "sig",
                               "n": b64int(numbers.n), "e": b64int(numbers.e)}]}
        cls.issuer = "https://identity.example.test/realms/goreecloud"
        cls.audience = "goreecloud-api"
        cls.client = "goreecloud-app"

    def payload(self, **changes):
        now = int(time.time())
        claims = {
            "iss": self.issuer, "sub": "verified-user-1",
            "aud": self.audience, "azp": self.client,
            "goreecloud_tenant": "household",
            "iat": now - 30, "nbf": now - 30, "exp": now + 300,
            "typ": "Bearer", "scope": "openid profile identity:read",
            "realm_access": {"roles": ["member"]},
            "groups": ["household"],
        }
        claims.update(changes)
        return claims

    def token(self, **changes):
        return jwt.encode(self.payload(**changes), self.key,
                          algorithm="RS256", headers={"kid": "development-test"})

    def verify(self, token=None, **kwargs):
        opts = dict(issuer=self.issuer, audience=self.audience,
                    authorized_party=self.client, tenant_id="household",
                    jwks=self.jwks, required_scopes={"identity:read"})
        opts.update(kwargs)
        return verify_access_token(token or self.token(), **opts)

    def test_verifies_signature_claims_scope_and_subject(self):
        result = self.verify()
        self.assertTrue(result.subject.authenticated)
        self.assertEqual(result.subject.tenant_id, "household")
        self.assertEqual(result.subject.roles, frozenset({"member"}))
        self.assertEqual(result.subject.groups, frozenset({"household"}))
        self.assertIn("identity:read", result.scopes)

    def test_wrong_issuer_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(iss="https://imposter.example.test/realms/goreecloud"))

    def test_wrong_audience_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(aud="another-api"))

    def test_wrong_oauth_client_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(azp="unknown-client"))

    def test_expired_token_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(exp=int(time.time())-120))

    def test_future_token_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(nbf=int(time.time())+120))

    def test_id_token_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(typ="ID"))

    def test_scope_missing_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(scope="openid"))

    def test_overlong_token_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(exp=int(time.time())+7200))

    def test_unsigned_or_symmetric_token_denied(self):
        bad = jwt.encode(self.payload(), "unused-development-only-test-secret-32bytes", algorithm="HS256",
                         headers={"kid": "development-test"})
        with self.assertRaises(VerificationError):
            self.verify(bad)

    def test_unknown_kid_denied(self):
        keys = {"keys": [{**self.jwks["keys"][0], "kid": "other-key"}]}
        with self.assertRaises(VerificationError):
            self.verify(jwks=keys)

    def test_duplicate_kid_denied(self):
        keys = {"keys": self.jwks["keys"] * 2}
        with self.assertRaises(VerificationError):
            self.verify(jwks=keys)

    def test_private_signing_material_rejected(self):
        keys = {"keys": [{**self.jwks["keys"][0], "d": "private"}]}
        with self.assertRaises(VerificationError):
            self.verify(jwks=keys)

    def test_tampered_signature_denied(self):
        token = self.token()
        parts = token.split(".")
        parts[-1] = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
        with self.assertRaises(VerificationError):
            self.verify(".".join(parts))

    def test_missing_subject_denied(self):
        with self.assertRaises(VerificationError):
            self.verify(self.token(sub=""))

    def test_non_https_issuer_not_allowed(self):
        with self.assertRaises(VerificationError):
            self.verify(issuer="http://identity.example.test/realms/goreecloud")


if __name__ == "__main__":
    unittest.main()
