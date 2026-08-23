import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.compare_determinism import compare
from scripts.determinism_probe import artifact_manifest


class CompareDeterminismTests(unittest.TestCase):
    def platform(self, root: Path, name: str, changed: bool = False) -> Path:
        directory = root / name
        directory.mkdir()
        (directory / "report-v1.json").write_bytes(b"different\n" if changed else b"report\n")
        (directory / "workflow-verifier.lock").write_bytes(b"lock\n")
        (directory / "fix.diff").write_bytes(b"diff\n")
        manifest = artifact_manifest(
            directory, ["report-v1.json", "workflow-verifier.lock", "fix.diff"]
        )
        (directory / "determinism-v1.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        return directory

    def test_identical_platform_artifacts_pass_independent_of_argument_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows = self.platform(root, "windows-x86_64")
            linux = self.platform(root, "linux-x86_64")
            macos = self.platform(root, "macos-arm64")
            result = compare([windows, macos, linux])
            self.assertTrue(result["passed"])
            self.assertEqual(
                result["platforms"], ["linux-x86_64", "macos-arm64", "windows-x86_64"]
            )

    def test_any_byte_difference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.platform(root, "linux-x86_64")
            changed = self.platform(root, "windows-x86_64", changed=True)
            result = compare([changed, baseline])
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["failures"],
                ["report-v1.json differs between linux-x86_64 and windows-x86_64"],
            )

    def test_tampered_manifest_fails_before_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platform = self.platform(root, "linux-x86_64")
            (platform / "fix.diff").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "manifest does not match"):
                compare([platform, self.platform(root, "macos-arm64")])

    def test_direct_script_entrypoint_resolves_its_sibling_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linux = self.platform(root, "linux-x86_64")
            windows = self.platform(root, "windows-x86_64")
            output = root / "comparison.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "scripts/compare_determinism.py",
                    "--output",
                    str(output),
                    str(linux),
                    str(windows),
                ],
                cwd=Path(__file__).resolve().parents[2],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["passed"])


if __name__ == "__main__":
    unittest.main()
