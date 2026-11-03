"""Offline contract tests for disposable Gateway/OIDC Keycloak claims."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_ci_login_fixture import build_fixture
from smoke_gateway_claims import check_gateway_claims, classify_verified_gateway_claims


class GatewayClaimContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = json.loads((ROOT / "realm/goreecloud-realm.json").read_text(encoding="utf-8"))

    def test_synthetic_keycloak_fixture_does_not_change_committed_realm(self):
        original = json.dumps(self.base, sort_keys=True)
        ci = build_fixture(self.base, "gc-ci-gateway-123", "Test9!" + "x" * 40)
        self.assertEqual(json.dumps(self.base, sort_keys=True), original)
        self.assertEqual(self.base["users"], [])
        self.assertEqual(self.base["clients"], [])
        self.assertEqual(len(ci["users"]), 1)
        self.assertEqual(ci["users"][0]["realmRoles"], ["gateway-reader"])
        self.assertEqual(ci["roles"]["realm"][0]["name"], "gateway-reader")
        self.assertFalse(ci["clients"][0]["fullScopeAllowed"])
        self.assertNotIn("scopeMappings", ci["clients"][0])
        self.assertEqual(ci["scopeMappings"], [{"client": "goreecloud-ci-public", "roles": ["gateway-reader"]}])
        self.assertEqual(ci["clients"][0]["defaultClientScopes"], ["basic", "profile", "gateway:read"])

    def test_synthetic_client_scope_only_adds_gateway_access_claims(self):
        ci = build_fixture(self.base, "gc-ci-gateway-123", "Test9!" + "x" * 40)
        scopes = {item["name"]: item for item in ci["clientScopes"]}
        self.assertEqual(set(scopes), {"basic", "profile", "gateway:read"})
        basic = scopes["basic"]
        self.assertEqual(basic["attributes"]["include.in.token.scope"], "false")
        self.assertEqual(len(basic["protocolMappers"]), 1)
        sub_mapper = basic["protocolMappers"][0]
        self.assertEqual(sub_mapper["protocolMapper"], "oidc-sub-mapper")
        self.assertEqual(sub_mapper["config"]["access.token.claim"], "true")
        self.assertEqual(scopes["profile"]["protocolMappers"], [])
        scope = scopes["gateway:read"]
        self.assertEqual(scope["attributes"]["include.in.token.scope"], "true")
        by_type = {x["protocolMapper"]: x for x in scope["protocolMappers"]}
        role = by_type["oidc-usermodel-realm-role-mapper"]["config"]
        self.assertEqual(role["claim.name"], "realm_access.roles")
        self.assertEqual(role["multivalued"], "true")
        self.assertEqual(role["access.token.claim"], "true")
        self.assertEqual(role["id.token.claim"], "false")
        audience = by_type["oidc-audience-mapper"]["config"]
        self.assertEqual(audience["included.custom.audience"], "goreecloud-gateway-console")
        self.assertEqual(audience["access.token.claim"], "true")
        self.assertEqual(audience["id.token.claim"], "false")
        tenant = by_type["oidc-hardcoded-claim-mapper"]["config"]
        self.assertEqual(tenant["claim.name"], "goreecloud_tenant")
        self.assertEqual(tenant["claim.value"], "family")
        self.assertEqual(tenant["id.token.claim"], "false")

    def example(self):
        return {
            "iss": "http://localhost:8080/realms/goreecloud",
            "aud": ["account", "goreecloud-gateway-console"],
            "sub": "synthetic",
            "typ": "Bearer",
            "azp": "goreecloud-ci-public",
            "scope": "openid gateway:read",
            "goreecloud_tenant": "family",
            "realm_access": {"roles": ["gateway-reader"]},
        }

    def test_verified_claim_diagnostic_is_static_and_never_prints_values(self):
        self.assertEqual(
            classify_verified_gateway_claims(self.example(), "goreecloud-ci-public"),
            "none",
        )
        claims = self.example()
        secret = "private-credential-marker"
        claims.update({
            "aud": [secret], "azp": secret, "goreecloud_tenant": secret,
            "scope": secret, "realm_access": {"roles": [secret]}, "typ": secret,
        })
        categories = classify_verified_gateway_claims(claims, "goreecloud-ci-public")
        self.assertEqual(categories, "audience,client,tenant,scope,role,type")
        self.assertNotIn(secret, categories)

    def test_accepts_gateway_contract_after_token_verification(self):
        check_gateway_claims(self.example(), "goreecloud-ci-public")

    def test_rejects_wrong_resource(self):
        claims = self.example()
        claims["aud"] = ["other-resource"]
        with self.assertRaises(ValueError):
            check_gateway_claims(claims, "goreecloud-ci-public")

    def test_rejects_wrong_client(self):
        claims = self.example()
        claims["azp"] = "untrusted-client"
        with self.assertRaises(ValueError):
            check_gateway_claims(claims, "goreecloud-ci-public")

    def test_rejects_missing_role_or_scope(self):
        for path in ("role", "scope"):
            with self.subTest(path=path):
                claims = self.example()
                if path == "role":
                    claims["realm_access"]["roles"] = ["guest"]
                else:
                    claims["scope"] = "openid gateway:writer"
                with self.assertRaises(ValueError):
                    check_gateway_claims(claims, "goreecloud-ci-public")

    def test_rejects_tenant_or_token_class(self):
        for path in ("tenant", "typ"):
            with self.subTest(path=path):
                claims = self.example()
                if path == "tenant":
                    claims["goreecloud_tenant"] = "different"
                else:
                    claims["typ"] = "ID"
                with self.assertRaises(ValueError):
                    check_gateway_claims(claims, "goreecloud-ci-public")

    def test_unregistered_or_unscoped_fixture_is_not_accepted(self):
        with self.assertRaises(ValueError):
            build_fixture({**self.base, "users": [{"username": "operator"}]},
                          "gc-ci-gateway-123", "Test9!" + "x" * 40)


if __name__ == "__main__":
    unittest.main()
