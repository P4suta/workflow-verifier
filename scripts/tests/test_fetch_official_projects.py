from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.fetch_official_projects import (
    _safe_path,
    _snapshot_digest,
    _tree_entries,
    load_manifest,
)


class OfficialProjectAcquisitionTests(unittest.TestCase):
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
