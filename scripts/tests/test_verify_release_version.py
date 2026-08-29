import tempfile
import unittest
from pathlib import Path

from scripts.verify_release_version import validate


class VerifyReleaseVersionTests(unittest.TestCase):
    def fixture(self, root: Path, version: str, *, heading: bool = True) -> None:
        (root / "lib" / "foundation").mkdir(parents=True)
        (root / "man").mkdir()
        (root / "Cargo.toml").write_text(
            "\n".join(
                [
                    "[package]",
                    'name = "workflow-verifier"',
                    "version.workspace = true",
                    'repository = "https://github.com/P4suta/workflow-verifier"',
                    "",
                    "[workspace]",
                    'members = ["."]',
                    "",
                    "[workspace.package]",
                    f'version = "{version}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "Cargo.lock").write_text(
            "\n".join(
                [
                    "version = 4",
                    "",
                    "[[package]]",
                    'name = "workflow-verifier"',
                    f'version = "{version}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "dune-project").write_text(f"(version {version})\n", encoding="utf-8")
        for relative in (
            "workflow-verifier.opam",
            "workflow-verifier.opam.locked",
            "workflow-verifier.opam.locked-ocaml54",
        ):
            (root / relative).write_text(f'version: "{version}"\n', encoding="utf-8")
        (root / "pyproject.toml").write_text(
            f'[project]\nname = "release-tools"\nversion = "{version}"\n',
            encoding="utf-8",
        )
        (root / "lib" / "foundation" / "product_version.ml").write_text(
            f'let version = "{version}"\n', encoding="utf-8"
        )
        (root / "man" / "workflow-verifier.1").write_text(
            f'.TH WORKFLOW-VERIFIER 1 "August 2026" "workflow-verifier {version}"\n',
            encoding="utf-8",
        )
        release_heading = (
            f"\n## [{version}](https://github.com/P4suta/workflow-verifier/"
            f"releases/tag/v{version}) - 2026-08-29\n"
            if heading
            else ""
        )
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n" + release_heading,
            encoding="utf-8",
        )

    def test_exact_tag_linked_heading_and_all_surfaces_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "1.2.3-rc.1")
            self.assertEqual(validate(root, "v1.2.3-rc.1"), "1.2.3-rc.1")
            with self.assertRaisesRegex(ValueError, "tag"):
                validate(root, "v1.2.3")
            (root / "dune-project").write_text("(version 9.9.9)\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mismatch.*out of sync"):
                validate(root, "v1.2.3-rc.1")

    def test_bootstrap_unreleased_heading_is_valid_only_for_development(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "0.1.0", heading=False)
            self.assertEqual(validate(root, None, allow_development=True), "0.1.0")
            with self.assertRaisesRegex(ValueError, "release-plz release heading"):
                validate(root, None)
            with self.assertRaisesRegex(ValueError, "release-plz release heading"):
                validate(root, "v0.1.0")

    def test_release_heading_must_be_linked_unique_and_date_valid(self) -> None:
        replacements = [
            (
                "https://github.com/P4suta/workflow-verifier/releases/tag/v1.2.3",
                "https://example.invalid/releases/tag/v1.2.3",
                "release link",
            ),
            (" - 2026-08-29", " - 2026-02-30", "date"),
            (
                "## [1.2.3](https://github.com/P4suta/workflow-verifier/"
                "releases/tag/v1.2.3) - 2026-08-29",
                "## 1.2.3 - 2026-08-29",
                "linked format",
            ),
        ]
        for old, new, message in replacements:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, "1.2.3")
                changelog = root / "CHANGELOG.md"
                changelog.write_text(
                    changelog.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
                )
                with self.assertRaisesRegex(ValueError, message):
                    validate(root, "v1.2.3")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "1.2.3")
            changelog = root / "CHANGELOG.md"
            heading = changelog.read_text(encoding="utf-8").splitlines()[-1]
            changelog.write_text(
                changelog.read_text(encoding="utf-8") + heading + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "duplicated"):
                validate(root, "v1.2.3")

    def test_development_versions_are_not_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "1.2.3-dev", heading=False)
            with self.assertRaisesRegex(ValueError, "development"):
                validate(root, "v1.2.3-dev")
            self.assertEqual(validate(root, None, allow_development=True), "1.2.3-dev")


if __name__ == "__main__":
    unittest.main()
