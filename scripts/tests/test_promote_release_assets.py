from __future__ import annotations

import gzip
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.promote_release_assets import promote


def canonical(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


class PromoteReleaseAssetsTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        staged = root / "staged"
        (staged / "artifacts").mkdir(parents=True)
        payload = staged / "artifacts" / "product.tar.gz"
        payload.write_bytes(b"product")
        signature = staged / "artifacts" / "product.sigstore.json"
        signature.write_bytes(b"signature")
        canonical(
            staged / "release-evidence-v3.json",
            {
                "artifacts": [
                    {
                        "digest": "sha256:" + "0" * 64,
                        "kind": "product",
                        "name": "product.tar.gz",
                        "path": "artifacts/product.tar.gz",
                        "platform": "linux-x86_64",
                        "signature": {
                            "digest": "sha256:" + "1" * 64,
                            "kind": "sigstore",
                            "path": "artifacts/product.sigstore.json",
                        },
                    }
                ],
                "schema": "release-evidence-v3",
            },
        )
        return staged

    def test_public_assets_and_deterministic_evidence_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = self.fixture(root)
            first = root / "first"
            second = root / "second"
            outputs = promote(staged, first, "0.1.0")
            promote(staged, second, "0.1.0")
            self.assertEqual(
                sorted(path.name for path in outputs),
                [
                    "product.sigstore.json",
                    "product.tar.gz",
                    "workflow-verifier-0.1.0-release-evidence.tar.gz",
                ],
            )
            bundle = first / "workflow-verifier-0.1.0-release-evidence.tar.gz"
            self.assertEqual(
                bundle.read_bytes(),
                (second / bundle.name).read_bytes(),
            )
            with gzip.open(bundle, "rb") as stream:
                with tarfile.open(fileobj=stream) as archive:
                    self.assertIn(
                        "workflow-verifier-release-evidence/release-evidence-v3.json",
                        archive.getnames(),
                    )

    def test_nonempty_output_and_unsafe_version_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = self.fixture(root)
            output = root / "public"
            output.mkdir()
            (output / "existing").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "empty"):
                promote(staged, output, "0.1.0")
            with self.assertRaisesRegex(ValueError, "version"):
                promote(staged, root / "other", "../bad")


if __name__ == "__main__":
    unittest.main()
