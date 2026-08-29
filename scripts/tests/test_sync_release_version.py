from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.sync_release_version import cargo_version, synchronize


class SyncReleaseVersionTests(unittest.TestCase):
    def fixture(self, root: Path, authority: str = "0.2.0", derived: str = "0.1.0") -> None:
        (root / "lib" / "foundation").mkdir(parents=True)
        (root / "man").mkdir()
        (root / "member").mkdir()
        (root / "Cargo.toml").write_text(
            "\n".join(
                [
                    "[package]",
                    'name = "workflow-verifier"',
                    "version.workspace = true",
                    "",
                    "[workspace]",
                    'members = [".", "member"]',
                    "",
                    "[workspace.package]",
                    f'version = "{authority}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "member" / "Cargo.toml").write_text(
            "\n".join(
                [
                    "[package]",
                    'name = "workflow-verifier-helper"',
                    "version.workspace = true",
                    "",
                    "[dependencies]",
                    'workflow-verifier-internal = { package = "workflow-verifier", '
                    f'path = "..", version = "={derived}" }}',
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
                    f'version = "{derived}"',
                    "",
                    "[[package]]",
                    'name = "workflow-verifier-helper"',
                    f'version = "{derived}"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "dune-project").write_text(f"(version {derived})\n", encoding="utf-8")
        for relative in (
            "workflow-verifier.opam",
            "workflow-verifier.opam.locked",
            "workflow-verifier.opam.locked-ocaml54",
        ):
            (root / relative).write_text(f'version: "{derived}"\n', encoding="utf-8")
        (root / "pyproject.toml").write_text(
            f'[project]\nname = "release-tools"\nversion = "{derived}"\n',
            encoding="utf-8",
        )
        (root / "lib" / "foundation" / "product_version.ml").write_text(
            f'let version = "{derived}"\n', encoding="utf-8"
        )
        (root / "man" / "workflow-verifier.1").write_text(
            f'.TH WORKFLOW-VERIFIER 1 "August 2026" "workflow-verifier {derived}"\n',
            encoding="utf-8",
        )

    def test_update_check_and_idempotence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            member = root / "member" / "Cargo.toml"
            before = member.read_text(encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "out of sync"):
                synchronize(root, check=True)
            self.assertEqual(member.read_text(encoding="utf-8"), before)

            version, changed = synchronize(root)
            self.assertEqual(version, "0.2.0")
            self.assertIn("member/Cargo.toml", changed)
            self.assertIn("Cargo.lock", changed)
            self.assertIn('version = "=0.2.0"', member.read_text(encoding="utf-8"))
            self.assertEqual(synchronize(root, check=True), ("0.2.0", ()))
            self.assertEqual(synchronize(root), ("0.2.0", ()))

    def test_semver_validation_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, authority="1.2.3-alpha.1+build.007")
            self.assertEqual(cargo_version(root), "1.2.3-alpha.1+build.007")

        for invalid in ("01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2", "1.2.3+"):
            with self.subTest(version=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, authority=invalid)
                with self.assertRaisesRegex(ValueError, "not SemVer"):
                    cargo_version(root)

    def test_missing_and_duplicate_surfaces_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "lib" / "foundation" / "product_version.ml").unlink()
            with self.assertRaisesRegex(ValueError, "cannot read.*product_version"):
                synchronize(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            product = root / "lib" / "foundation" / "product_version.ml"
            product.write_text('let version = "0.1.0"\nlet version = "0.1.0"\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicated"):
                synchronize(root)

    def test_workspace_path_dependency_requires_an_exact_constraint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            member = root / "member" / "Cargo.toml"
            member.write_text(
                member.read_text(encoding="utf-8").replace(', version = "=0.1.0"', ""),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must have an exact version"):
                synchronize(root)


if __name__ == "__main__":
    unittest.main()
