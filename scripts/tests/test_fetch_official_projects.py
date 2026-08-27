from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.fetch_official_projects import (
    _git,
    _safe_path,
    _snapshot_digest,
    _tree_entries,
    load_manifest,
)


class OfficialProjectAcquisitionTests(unittest.TestCase):
    @mock.patch("scripts.fetch_official_projects.subprocess.run")
    def test_git_acquisition_ignores_ambient_git_configuration(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.dict(
            "scripts.fetch_official_projects.os.environ",
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "url.git@example.invalid:.insteadOf",
                "GIT_CONFIG_VALUE_0": "https://github.com/",
            },
            clear=False,
        ):
            _git(["status", "--porcelain"], cwd=Path("."), deadline=time.monotonic() + 1)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertNotIn("GIT_CONFIG_KEY_0", environment)
        self.assertNotIn("GIT_CONFIG_VALUE_0", environment)

    def test_repository_manifest_is_exactly_pinned_and_balanced(self) -> None:
        document, digest = load_manifest(Path("official/official-projects-v1.json"))
        self.assertEqual(document["schema"], "official-projects-v1")
        self.assertEqual(len(document["projects"]), 8)
        self.assertTrue(digest.startswith("sha256:"))

    def test_paths_and_selected_tree_links_fail_closed(self) -> None:
        for invalid in ("", "../ci.yml", "/ci.yml", "ci\\config.yml", "a/./b"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "safe relative"):
                    _safe_path(invalid, "fixture")
        raw = b"120000 blob 0123456789abcdef0123456789abcdef01234567\t.github/workflows/ci.yml\0"
        with self.assertRaisesRegex(ValueError, "symlink"):
            _tree_entries(raw, [".github/workflows"])

    def test_snapshot_digest_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / "ci.yml"
            workflow.write_text("jobs: {}\n", encoding="utf-8")
            digest, files = _snapshot_digest(root)
            self.assertTrue(digest.startswith("sha256:"))
            self.assertEqual(files, 1)
            link = root / "linked.yml"
            try:
                link.symlink_to(workflow)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                _snapshot_digest(root)


if __name__ == "__main__":
    unittest.main()
