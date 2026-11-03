import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from init_env import create_env
from check_config import check


class BootstrapTests(unittest.TestCase):
    def test_creates_private_secrets_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            self.assertTrue(create_env(path))
            raw = path.read_text(encoding="utf-8")
            self.assertIn("KC_BOOTSTRAP_ADMIN_PASSWORD=", raw)
            self.assertIn("POSTGRES_PASSWORD=", raw)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertFalse(create_env(path))
            self.assertEqual(path.read_text(encoding="utf-8"), raw)

    def test_preflight_without_local_secrets(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(check(root), [])


if __name__ == "__main__":
    unittest.main()
