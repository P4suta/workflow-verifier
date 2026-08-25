from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_conformance_manifest import verify


class ConformanceManifestTests(unittest.TestCase):
    def test_repository_manifest_binds_every_exact_vector(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self.assertGreaterEqual(
            verify(root / "conformance" / "manifest-v1.json", root),
            6,
        )

    def test_tampered_vector_and_noncanonical_manifest_fail(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = root / "conformance" / "manifest-v1.json"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            document = json.loads(source.read_text(encoding="utf-8"))
            vector = document["vectors"][0]
            path = destination / vector["path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(b"changed\n")
            manifest = destination / "manifest.json"
            manifest.write_text(
                json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                verify(manifest, destination)

            manifest.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(ValueError, "canonical"):
                verify(manifest, destination)


if __name__ == "__main__":
    unittest.main()
