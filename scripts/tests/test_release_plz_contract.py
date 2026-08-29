from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleasePlzContractTests(unittest.TestCase):
    def workspace_config(self) -> dict[str, object]:
        document = tomllib.loads((ROOT / "release-plz.toml").read_text(encoding="utf-8"))
        workspace = document.get("workspace")
        self.assertIsInstance(workspace, dict)
        return workspace  # type: ignore[return-value]

    def test_release_pr_is_draft_only_and_publication_is_disabled(self) -> None:
        config = self.workspace_config()
        self.assertIs(config["publish"], False)
        self.assertIs(config["git_tag_enable"], False)
        self.assertIs(config["git_release_enable"], False)
        self.assertIs(config["release_always"], False)
        self.assertIs(config["pr_draft"], True)
        self.assertEqual(config["pr_name"], "chore: release v{{ version }}")
        self.assertEqual(config["git_tag_name"], "v{{ version }}")
        self.assertIs(config["features_always_increment_minor"], False)
        self.assertIs(config["semver_check"], True)

    def test_only_user_impact_or_explicit_breaking_commits_trigger_a_release(self) -> None:
        pattern = re.compile(str(self.workspace_config()["release_commits"]))
        qualifying = [
            "feat: add a rule",
            "fix: derive product versions from Cargo metadata",
            "fix(parser): retain a span",
            "perf: avoid a graph scan",
            "refactor(core): centralize comparison",
            "revert: restore the stable behavior",
            "docs!: remove a compatibility promise",
            "chore(build)!: replace the public wire contract",
        ]
        ignored = [
            "docs: clarify the release procedure",
            "ci: pin an action",
            "test: cover a boundary",
            "deps(rust): bump dependencies",
            "chore: release v0.1.0",
            "style: apply formatting",
        ]
        for subject in qualifying:
            with self.subTest(subject=subject):
                self.assertIsNotNone(pattern.match(subject))
        for subject in ignored:
            with self.subTest(subject=subject):
                self.assertIsNone(pattern.match(subject))

    def test_unpublished_bootstrap_keeps_cargo_0_1_0_and_starts_unreleased(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(cargo["workspace"]["package"]["version"], "0.1.0")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]\n", changelog)
        self.assertNotRegex(changelog, r"(?m)^## \[0\.1\.0\]")


if __name__ == "__main__":
    unittest.main()
