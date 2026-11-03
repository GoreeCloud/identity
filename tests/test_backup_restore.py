import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from smoke_backup_restore import assert_ci_environment, assert_isolated_compose


class BackupRestoreSafetyTests(unittest.TestCase):
    def test_refuses_non_ci(self):
        with self.assertRaises(RuntimeError):
            assert_ci_environment({})

    def test_refuses_wrong_repository(self):
        with self.assertRaises(RuntimeError):
            assert_ci_environment({"GITHUB_ACTIONS": "true", "CI": "true",
                                   "GITHUB_REPOSITORY": "another/identity"})

    def test_accepts_authorized_ephemeral_ci_environment(self):
        assert_ci_environment({"GITHUB_ACTIONS": "true", "CI": "true",
                               "GITHUB_REPOSITORY": "GoreeCloud/identity"})

    def test_requires_loopback_only_compose_and_known_services(self):
        cfg = {
            "services": {
                "identity": {"ports": [{"host_ip": "127.0.0.1", "published": "8080"}],
                             "command": ["start-dev", "--import-realm"],
                             "environment": {"KC_HOSTNAME": "http://localhost:8080"}},
                "db": {"environment": {"POSTGRES_DB": "goreecloud_identity"}},
            }
        }
        assert_isolated_compose(cfg)
        cfg["services"]["identity"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaises(RuntimeError):
            assert_isolated_compose(cfg)

    def test_refuses_exposed_database_port(self):
        cfg = {
            "services": {
                "identity": {"ports": [{"host_ip": "127.0.0.1", "published": "8080"}],
                             "command": ["start-dev", "--import-realm"],
                             "environment": {"KC_HOSTNAME": "http://localhost:8080"}},
                "db": {"environment": {"POSTGRES_DB": "goreecloud_identity"},
                       "ports": [{"published": "5432"}]},
            }
        }
        with self.assertRaises(RuntimeError):
            assert_isolated_compose(cfg)


if __name__ == "__main__":
    unittest.main()
