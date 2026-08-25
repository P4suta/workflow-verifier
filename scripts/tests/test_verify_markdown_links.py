from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_markdown_links import verify


class MarkdownLinkTests(unittest.TestCase):
    def test_local_and_https_links_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.md").write_text("# Target\n", encoding="utf-8")
            (root / "README.md").write_text(
                "[local](target.md) [remote](https://example.test/path)\n",
                encoding="utf-8",
            )
            self.assertEqual(verify(root), 2)

    def test_missing_escaping_and_insecure_links_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            readme = root / "README.md"
            for link in ("missing.md", "../outside.md", "http://example.test"):
                readme.write_text(f"[bad]({link})\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify(root)


if __name__ == "__main__":
    unittest.main()
