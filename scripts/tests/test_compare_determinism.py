import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.compare_determinism import compare
from scripts.determinism_probe import artifact_manifest, canonical_json


def report_bytes(
    *, binary: str = "a", source_commit: str | None = None, persona: str = "audit"
) -> bytes:
    document = {
        "digest": None,
        "persona": persona,
        "schema": "report-v2",
        "tool": {
            "binary_digest": "sha256:" + binary * 64,
            "build": {"source_commit": source_commit},
        },
    }
    document["digest"] = (
        "sha256:" + hashlib.sha256(canonical_json(document, trailing_newline=False)).hexdigest()
    )
    return canonical_json(document)


class CompareDeterminismTests(unittest.TestCase):
    def platform(
        self,
        root: Path,
        name: str,
        *,
        binary: str = "a",
        source_commit: str | None = None,
        persona: str = "audit",
        changed_fix: bool = False,
    ) -> Path:
        directory = root / name
        directory.mkdir()
        (directory / "report-v2.json").write_bytes(
            report_bytes(binary=binary, source_commit=source_commit, persona=persona)
        )
        (directory / "workflow-verifier.lock").write_bytes(b"lock\n")
        (directory / "fix.diff").write_bytes(b"changed\n" if changed_fix else b"diff\n")
        manifest = artifact_manifest(
            directory, ["report-v2.json", "workflow-verifier.lock", "fix.diff"]
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
            self.assertEqual(result["platforms"], ["linux-x86_64", "macos-arm64", "windows-x86_64"])

    def test_platform_bound_report_provenance_is_recorded_but_not_compared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.platform(root, "linux-x86_64", binary="a")
            changed = self.platform(root, "windows-x86_64", binary="b", source_commit="c" * 40)
            result = compare([changed, baseline])
            self.assertTrue(result["passed"])
            reports = result["report_projection"]["reports"]
            self.assertNotEqual(reports[0]["raw_digest"], reports[1]["raw_digest"])
            self.assertEqual(reports[0]["semantic_digest"], reports[1]["semantic_digest"])

    def test_semantic_report_difference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.platform(root, "linux-x86_64")
            changed = self.platform(root, "windows-x86_64", persona="paranoid")
            result = compare([changed, baseline])
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["failures"],
                ["report-v2 semantic content differs between linux-x86_64 and windows-x86_64"],
            )

    def test_portable_artifact_byte_difference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.platform(root, "linux-x86_64")
            changed = self.platform(root, "windows-x86_64", changed_fix=True)
            result = compare([changed, baseline])
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["failures"],
                ["fix.diff differs between linux-x86_64 and windows-x86_64"],
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
