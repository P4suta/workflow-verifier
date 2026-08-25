import tempfile
import unittest
from pathlib import Path

from scripts.verify_release_version import validate


class VerifyReleaseVersionTests(unittest.TestCase):
    def fixture(self, root: Path, version: str) -> None:
        (root / "helpers").mkdir()
        (root / "lib" / "application").mkdir(parents=True)
        (root / "dune-project").write_text(f"(version {version})\n", encoding="utf-8")
        (root / "workflow-verifier.opam").write_text(f'version: "{version}"\n', encoding="utf-8")
        (root / "helpers" / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\n', encoding="utf-8"
        )
        (root / "lib" / "application" / "cli.ml").write_text(
            f'let version = "workflow-verifier {version}\\n"\n', encoding="utf-8"
        )
        (root / "CHANGELOG.md").write_text(f"## {version}\n", encoding="utf-8")

    def test_exact_tag_and_all_surfaces_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "1.2.3-rc.1")
            self.assertEqual(validate(root, "v1.2.3-rc.1"), "1.2.3-rc.1")
            with self.assertRaisesRegex(ValueError, "tag"):
                validate(root, "v1.2.3")
            (root / "helpers" / "Cargo.toml").write_text('version = "9.9.9"\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Cargo"):
                validate(root, "v1.2.3-rc.1")

    def test_development_versions_are_not_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "1.2.3-dev")
            with self.assertRaisesRegex(ValueError, "development"):
                validate(root, "v1.2.3-dev")
            self.assertEqual(validate(root, None, allow_development=True), "1.2.3-dev")


if __name__ == "__main__":
    unittest.main()
