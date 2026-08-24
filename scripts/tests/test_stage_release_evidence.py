from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.stage_release_evidence import stage
from scripts.tests.test_verify_release_evidence import fixture


class StageReleaseEvidenceTests(unittest.TestCase):
    def test_stages_every_v2_evidence_file_under_canonical_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            destination = root / "dist"
            outputs = stage(manifest, destination)
            self.assertEqual(len(outputs), 10)
            self.assertEqual(
                sorted(path.name for path in outputs),
                sorted(
                    [
                        "release-evidence-v2.json",
                        "corpus-report-v1.json",
                        "official-compat-v1.json",
                        "maintainer-security-attestation-v1.json",
                        "maintainer-security-attestation-v1.json.sig",
                        "maintainer-allowed-signers",
                        *[f"performance-{platform}.json" for platform in ("linux-x86_64", "windows-x86_64", "macos-arm64", "macos-x86_64")],
                    ]
                ),
            )

    def test_tampered_or_duplicate_platform_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["performance"][1]["platform"] = document["performance"][0]["platform"]
            manifest.write_text(json.dumps(document) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicated"):
                stage(manifest, root / "dist")


if __name__ == "__main__":
    unittest.main()
