"""Offline end-to-end resource authorization using signed Keycloak-shaped access JWTs."""
import base64
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from goreecloud_identity.jwks_trust import PinnedIssuerKeys, JWKSUnavailable
from goreecloud_identity.policy import AccessRequest, PolicyRule
from goreecloud_identity.resource_server import ResourceAuthorizer, ResourceIdentityConfig


def b64int(x):
    return base64.urlsafe_b64encode(
        x.to_bytes((x.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()


class FakeIssuerKeys:
    def __init__(self, issuer, jwks):
        self.issuer = issuer
        self.jwks = jwks
        self.calls = 0

    def for_key(self, kid):
        self.calls += 1
        if kid != "res-test":
            raise JWKSUnavailable("unknown signer")
        return self.jwks


class ResourceAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = cls.key.public_key().public_numbers()
        cls.public = {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "res-test",
            "n": b64int(pub.n), "e": b64int(pub.e),
        }]}
        cls.issuer = "https://identity.example.test/realms/goreecloud"

    def setUp(self):
        self.config = ResourceIdentityConfig(
            self.issuer, "goreecloud-gateway-api", "goreecloud-ci-app", "family",
            frozenset({"gateway:read"}),
        )
        self.keys = FakeIssuerKeys(self.issuer, self.public)
        self.rule = PolicyRule(
            "family", "gateway-console", "read", "allow", frozenset({"gateway-reader"})
        )
        self.req = AccessRequest("family", "gateway-console", "read", "10.0.0.2")
        self.authorizer = ResourceAuthorizer(self.config, self.keys, [self.rule])

    def claims(self, **changes):
        t = int(time.time())
        out = {
            "iss": self.issuer, "sub": "synthetic-user",
            "aud": self.config.audience, "azp": self.config.authorized_party,
            "goreecloud_tenant": "family",
            "iat": t - 10, "exp": t + 300, "nbf": t - 10,
            "typ": "Bearer", "scope": "openid gateway:read",
            "realm_access": {"roles": ["gateway-reader"]},
            "groups": ["family-members"],
        }
        out.update(changes)
        return out

    def signed(self, **claims):
        return jwt.encode(self.claims(**claims), self.key, algorithm="RS256",
                          headers={"kid": "res-test"})

    def test_valid_signature_scope_role_and_tenant_allows(self):
        result = self.authorizer.authorize(self.signed(), self.req)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "explicit_allow")

    def test_missing_policy_denied(self):
        authorizer = ResourceAuthorizer(self.config, self.keys, [])
        self.assertFalse(authorizer.authorize(self.signed(), self.req).allowed)

    def test_deny_overrides_allow_independent_of_order(self):
        deny = PolicyRule("family","gateway-console","read","deny",
                          frozenset({"gateway-reader"}))
        for policies in ([self.rule,deny],[deny,self.rule]):
            authorizer = ResourceAuthorizer(self.config, self.keys, policies)
            self.assertEqual(authorizer.authorize(self.signed(),self.req).reason,"explicit_deny")

    def test_wrong_tenant_resource_denied(self):
        other = AccessRequest("business","gateway-console","read","10.0.0.2")
        self.assertEqual(self.authorizer.authorize(self.signed(),other).reason,"tenant_mismatch")

    def test_wrong_resource_denied(self):
        other = AccessRequest("family","vpn-management","read","10.0.0.2")
        self.assertFalse(self.authorizer.authorize(self.signed(),other).allowed)

    def test_wrong_action_denied(self):
        other = AccessRequest("family","gateway-console","delete","10.0.0.2")
        self.assertFalse(self.authorizer.authorize(self.signed(),other).allowed)

    def test_invalid_direct_ip_denied(self):
        other = AccessRequest("family","gateway-console","read","X-Forwarded-For: 1.1.1.1")
        self.assertFalse(self.authorizer.authorize(self.signed(),other).allowed)

    def test_missing_scope_rejected_before_policy(self):
        self.assertEqual(self.authorizer.authorize(self.signed(scope="openid"),self.req).reason,
                         "authentication_failed")

    def test_wrong_issuer_denied(self):
        self.assertFalse(self.authorizer.authorize(
            self.signed(iss="https://attacker.test/realms/goreecloud"),self.req
        ).allowed)

    def test_wrong_audience_denied(self):
        self.assertFalse(self.authorizer.authorize(self.signed(aud="other-api"),self.req).allowed)

    def test_wrong_oauth_client_denied(self):
        self.assertFalse(self.authorizer.authorize(self.signed(azp="other-client"),self.req).allowed)

    def test_expired_token_denied(self):
        self.assertFalse(self.authorizer.authorize(
            self.signed(exp=int(time.time())-120),self.req
        ).allowed)

    def test_wrong_token_class_denied(self):
        self.assertFalse(self.authorizer.authorize(self.signed(typ="ID"),self.req).allowed)

    def test_untrusted_roles_never_accepted(self):
        self.assertFalse(self.authorizer.authorize(
            self.signed(realm_access={"roles":["ordinary-user"]}),self.req
        ).allowed)

    def test_invalid_signature_denied(self):
        raw=self.signed()
        parts=raw.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        self.assertFalse(self.authorizer.authorize(".".join(parts),self.req).allowed)

    def test_unsupported_jwt_algorithm_rejected_before_key_fetch(self):
        keys=FakeIssuerKeys(self.issuer,self.public)
        auth=ResourceAuthorizer(self.config,keys,[self.rule])
        bad=jwt.encode(self.claims(),"development-test-not-an-actual-secret",
                       algorithm="HS256",headers={"kid":"res-test"})
        self.assertFalse(auth.authorize(bad,self.req).allowed)
        self.assertEqual(keys.calls,0)

    def test_unknown_key_denied(self):
        raw=jwt.encode(self.claims(),self.key,algorithm="RS256",headers={"kid":"unexpected"})
        self.assertEqual(self.authorizer.authorize(raw,self.req).reason,"authentication_failed")

    def test_malformed_token_denied(self):
        for token in ("","not-a-jwt","x"*20000):
            with self.subTest(token=token[:12]):
                self.assertFalse(self.authorizer.authorize(token,self.req).allowed)

    def test_mismatched_trust_issuer_rejected_early(self):
        keys=FakeIssuerKeys("https://attacker.test/realms/goreecloud",self.public)
        with self.assertRaises(ValueError):
            ResourceAuthorizer(self.config,keys,[self.rule])

    def test_unscoped_config_invalid(self):
        with self.assertRaises(ValueError):
            ResourceIdentityConfig("", "api", "client", "family", frozenset())
        with self.assertRaises(ValueError):
            ResourceIdentityConfig(self.issuer, "api", "client", "family", frozenset())


if __name__ == "__main__":
    unittest.main()
