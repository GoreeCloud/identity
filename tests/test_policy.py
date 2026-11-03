import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from goreecloud_identity.policy import Subject, AccessRequest, PolicyRule, evaluate


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.user = Subject("u1", "family", True, frozenset({"member"}), frozenset({"household"}))
        self.req = AccessRequest("family", "photos", "view", "192.168.0.10")
        self.allow = PolicyRule("family", "photos", "view", "allow", frozenset({"member"}))

    def test_no_policy_denies(self):
        self.assertFalse(evaluate(self.user, self.req, []).allowed)

    def test_explicit_allow(self):
        self.assertEqual(evaluate(self.user, self.req, [self.allow]).reason, "explicit_allow")

    def test_deny_overrides_allow_regardless_of_order(self):
        deny = PolicyRule("family", "photos", "view", "deny", frozenset({"member"}))
        for rules in ([deny, self.allow], [self.allow, deny]):
            self.assertEqual(evaluate(self.user, self.req, rules).reason, "explicit_deny")

    def test_unauthenticated_subject_denied(self):
        anon = Subject("u1", "family", False, frozenset({"member"}))
        self.assertFalse(evaluate(anon, self.req, [self.allow]).allowed)

    def test_empty_subject_denied(self):
        anon = Subject("", "family", True, frozenset({"member"}))
        self.assertFalse(evaluate(anon, self.req, [self.allow]).allowed)

    def test_cross_tenant_denied_even_with_role(self):
        request = AccessRequest("work", "photos", "view", "192.168.0.10")
        self.assertEqual(evaluate(self.user, request, [self.allow]).reason, "tenant_mismatch")

    def test_resource_and_action_must_match(self):
        request = AccessRequest("family", "photos", "delete", "192.168.0.10")
        self.assertFalse(evaluate(self.user, request, [self.allow]).allowed)

    def test_group_matching(self):
        group_rule = PolicyRule("family", "photos", "view", "allow", groups=frozenset({"household"}))
        self.assertTrue(evaluate(self.user, self.req, [group_rule]).allowed)

    def test_ip_scope(self):
        rule = PolicyRule("family", "photos", "view", "allow", roles=frozenset({"member"}), cidrs=("10.0.0.0/8",))
        self.assertFalse(evaluate(self.user, self.req, [rule]).allowed)
        inside = AccessRequest("family", "photos", "view", "10.10.0.10")
        self.assertTrue(evaluate(self.user, inside, [rule]).allowed)

    def test_invalid_ip_denied(self):
        request = AccessRequest("family", "photos", "view", "not-an-ip")
        self.assertEqual(evaluate(self.user, request, [self.allow]).reason, "invalid_client_ip")

    def test_cannot_define_unscoped_allow(self):
        with self.assertRaises(ValueError):
            PolicyRule("family", "photos", "view", "allow")

    def test_invalid_network_rejected(self):
        with self.assertRaises(ValueError):
            PolicyRule("family", "photos", "view", "allow", roles=frozenset({"member"}), cidrs=("no",))


if __name__ == "__main__":
    unittest.main()
