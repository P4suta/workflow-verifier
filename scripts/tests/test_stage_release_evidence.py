from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.stage_release_evidence import stage
from scripts.tests.test_verify_release_evidence import fixture


class StageReleaseEvidenceTests(unittest.TestCase):
    def test_direct_script_entrypoint_resolves_its_sibling_module(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "scripts/stage_release_evidence.py",
                "--help",
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--manifest", completed.stdout)

    def test_stages_every_v4_reference_without_flattening_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            destination = root / "dist"
            outputs = stage(manifest, destination)
            self.assertIn(destination / "release-evidence-v4.json", outputs)
            self.assertTrue((destination / "gates" / "unit.json").is_file())
            self.assertTrue((destination / "sbom" / "workflow-verifier.cdx.json").is_file())
            self.assertTrue((destination / "maintainer-allowed-signers").is_file())
            self.assertGreater(len(outputs), 40)

    def test_tampered_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            artifact = root / value["artifacts"][0]["path"]
            artifact.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "digest.*mismatch"):
                stage(manifest, root / "dist")

    def test_symlink_destination_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            target = root / "target"
            target.mkdir()
            destination = root / "dist"
            try:
                destination.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                stage(manifest, destination)


if __name__ == "__main__":
    unittest.main()
