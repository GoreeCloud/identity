"""Development packaging manifest is narrow and does not claim a license."""
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DevelopmentPackagingTests(unittest.TestCase):
    def test_only_authored_src_modules_are_in_package_scope(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            metadata = tomllib.load(handle)
        project = metadata["project"]
        self.assertEqual(project["name"], "goreecloud-identity-resource-dev")
        self.assertEqual(project["version"], "0.0.0")
        if (ROOT / "LICENSE").exists():
            self.assertIn("license", project)
        else:
            self.assertNotIn("license", project)
        self.assertEqual(project["dependencies"], ["PyJWT[crypto]==2.15.1"])
        self.assertEqual(
            metadata["tool"]["setuptools"]["packages"]["find"]["where"], ["src"])
        self.assertEqual(
            metadata["tool"]["setuptools"]["packages"]["find"]["include"],
            ["goreecloud_identity", "goreecloud_identity.*"])
        self.assertFalse(metadata["tool"]["setuptools"]["include-package-data"])

    def test_rights_review_is_not_misrepresented_as_done(self):
        if not (ROOT / "LICENSE").exists():
            self.assertIn("license for these authored files must be selected",
                          (ROOT / "THIRD_PARTY.md").read_text())
