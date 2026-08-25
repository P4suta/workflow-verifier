from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_release_index import generate


class ReleaseIndexTests(unittest.TestCase):
    def test_index_is_canonical_complete_and_excludes_its_own_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifacts").mkdir()
            (root / "artifacts" / "product.tar.gz").write_bytes(b"product")
            (root / "artifacts" / "product.tar.gz.sigstore.json").write_bytes(b"product signature")
            (root / "evidence.json").write_bytes(b"evidence\n")
            index = root / "release-index-v1.json"
            sums = root / "SHA256SUMS"
            Path(str(index) + ".sigstore.json").write_bytes(b"old index signature")
            Path(str(sums) + ".sigstore.json").write_bytes(b"old sums signature")
            self.assertEqual(generate(root, index, sums, "v0.1.0"), 3)
            document = json.loads(index.read_text(encoding="utf-8"))
            self.assertEqual(document["schema"], "release-index-v1")
            self.assertEqual(
                [item["path"] for item in document["files"]],
                [
                    "artifacts/product.tar.gz",
                    "artifacts/product.tar.gz.sigstore.json",
                    "evidence.json",
                ],
            )
            lines = sums.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 4)
            self.assertTrue(any(line.endswith("  release-index-v1.json") for line in lines))
            self.assertFalse(any(line.endswith("  SHA256SUMS") for line in lines))
            self.assertEqual(
                index.read_bytes(),
                (
                    json.dumps(
                        document,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            expected = hashlib.sha256(index.read_bytes()).hexdigest()
            self.assertIn(f"{expected}  release-index-v1.json", lines)

    def test_symlink_and_bad_tag_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            payload.write_bytes(b"payload")
            with self.assertRaisesRegex(ValueError, "planned tag"):
                generate(root, root / "index.json", root / "sums", "latest")
            linked = root / "linked"
            try:
                linked.symlink_to(payload)
            except OSError:
                return
            with self.assertRaisesRegex(ValueError, "symlink"):
                generate(root, root / "index.json", root / "sums", "v0.1.0")

    def test_outputs_must_be_confined_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "release"
            root.mkdir()
            (root / "payload").write_bytes(b"payload")
            escaped_index = parent / "escaped-index.json"
            escaped_sums = parent / "escaped-sums"
            with self.assertRaisesRegex(ValueError, "must stay within"):
                generate(root, escaped_index, escaped_sums, "v0.1.0")
            self.assertFalse(escaped_index.exists())
            self.assertFalse(escaped_sums.exists())


if __name__ == "__main__":
    unittest.main()
