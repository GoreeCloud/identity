"""Require the signed access token to match the trusted resource tenant.

All tokens, signing keys and tenant labels are synthetic; no network or production
data is needed. These negative tests reproduce the previous authorization defect.
"""
import base64
import sys
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from goreecloud_identity.tokens import VerificationError, verify_access_token


def b64_integer(value):
    return base64.urlsafe_b64encode(
        value.to_bytes((value.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("ascii")


class SignedTenantClaimRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.key.public_key().public_numbers()
        cls.jwks = {"keys": [{
            "kty": "RSA", "kid": "synthetic-test-key", "use": "sig", "alg": "RS256",
            "n": b64_integer(numbers.n), "e": b64_integer(numbers.e),
        }]}
        cls.issuer = "https://identity.example.test/realms/goreecloud"

    def signed(self, *, tenant="family", omit_tenant=False):
        now = int(time.time())
        claims = {
            "iss": self.issuer, "sub": "synthetic-subject",
            "aud": "goreecloud-gateway-console", "azp": "synthetic-client",
            "iat": now - 5, "nbf": now - 5, "exp": now + 300,
            "typ": "Bearer", "scope": "openid gateway:read",
            "realm_access": {"roles": ["gateway-reader"]},
        }
        if not omit_tenant:
            claims["goreecloud_tenant"] = tenant
        return jwt.encode(claims, self.key, algorithm="RS256",
                          headers={"kid": "synthetic-test-key"})

    def check(self, token, *, tenant="family"):
        return verify_access_token(
            token, issuer=self.issuer, audience="goreecloud-gateway-console",
            authorized_party="synthetic-client", tenant_id=tenant,
            jwks=self.jwks, required_scopes={"gateway:read"},
        )

    def test_matching_signed_tenant_passes(self):
        verified = self.check(self.signed())
        self.assertEqual(verified.subject.tenant_id, "family")

    def test_omitted_signed_tenant_denied(self):
        with self.assertRaises(VerificationError):
            self.check(self.signed(omit_tenant=True))

    def test_other_signed_tenant_denied(self):
        with self.assertRaises(VerificationError):
            self.check(self.signed(tenant="business"))

    def test_malformed_signed_tenant_denied(self):
        for claim in (None, "", 0, True, ["family"], {"id": "family"}):
            with self.subTest(type=type(claim).__name__):
                with self.assertRaises(VerificationError):
                    self.check(self.signed(tenant=claim))

    def test_untrusted_requested_tenant_cannot_override_signed_tenant(self):
        with self.assertRaises(VerificationError):
            self.check(self.signed(tenant="family"), tenant="business")


if __name__ == "__main__":
    unittest.main()
