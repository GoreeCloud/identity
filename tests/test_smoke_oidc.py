import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from smoke_oidc import ISSUER, REQUIRED, validate_discovery, validate_jwks, is_local_endpoint, read_json


def sample():
    return {
        "issuer": ISSUER,
        "response_types_supported": ["code"],
        **{key: ISSUER + suffix for key, suffix in REQUIRED.items()},
    }


class OIDCDiscoverySafetyTests(unittest.TestCase):
    def test_valid_local_metadata(self):
        self.assertEqual(validate_discovery(sample()), ISSUER + REQUIRED["jwks_uri"])

    def test_wrong_issuer_denied(self):
        d = sample()
        d["issuer"] = "https://attacker.example/realms/goreecloud"
        with self.assertRaises(ValueError):
            validate_discovery(d)

    def test_redirected_authorization_rejected(self):
        d = sample()
        d["authorization_endpoint"] = "https://attacker.example/login"
        with self.assertRaises(ValueError):
            validate_discovery(d)

    def test_password_flow_only_rejected(self):
        d = sample()
        d["response_types_supported"] = ["token"]
        with self.assertRaises(ValueError):
            validate_discovery(d)

    def test_endpoint_query_injection_rejected(self):
        d = sample()
        d["jwks_uri"] += "?redirect=https://attacker.example"
        with self.assertRaises(ValueError):
            validate_discovery(d)

    def test_malformed_url_rejected(self):
        self.assertFalse(is_local_endpoint("http://localhost:bad/realms/goreecloud/protocol/openid-connect/certs"))

    def test_private_key_leak_rejected(self):
        with self.assertRaises(ValueError):
            validate_jwks({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB", "d": "secret"}]})

    def test_public_jwks_accepted(self):
        validate_jwks({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]})

    def test_untrusted_fetch_url_denied_before_network(self):
        with self.assertRaises(ValueError):
            read_json("http://localhost:8080/realms/other/protocol/openid-connect/certs")


if __name__ == "__main__":
    unittest.main()
