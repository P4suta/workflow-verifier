from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleasePlzContractTests(unittest.TestCase):
    def assert_changelog_state(self, changelog: str, version: str) -> None:
        self.assertEqual(changelog.count("## [Unreleased]\n"), 1)

        prefix = f"## [{version}]"
        release_headings = [line for line in changelog.splitlines() if line.startswith(prefix)]
        self.assertLessEqual(len(release_headings), 1)
        if release_headings:
            escaped = re.escape(version)
            self.assertRegex(
                release_headings[0],
                rf"^## \[{escaped}\]\(https://github\.com/P4suta/"
                rf"workflow-verifier/releases/tag/v{escaped}\) - \d{{4}}-\d{{2}}-\d{{2}}$",
            )

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

    def test_development_and_generated_release_pr_keep_cargo_authoritative(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        version = str(cargo["workspace"]["package"]["version"])
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assert_changelog_state(changelog, version)

    def test_linked_release_plz_heading_is_an_allowed_contract_state(self) -> None:
        self.assert_changelog_state(
            "## [Unreleased]\n\n"
            "## [0.1.0](https://github.com/P4suta/"
            "workflow-verifier/releases/tag/v0.1.0) - 2026-08-29\n",
            "0.1.0",
        )


if __name__ == "__main__":
    unittest.main()
