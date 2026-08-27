import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.compare_determinism import RELEASE_PLATFORMS, compare
from scripts.determinism_probe import artifact_manifest, canonical_json


def report_bytes(
    *, binary: str = "a", source_commit: str | None = None, persona: str = "audit"
) -> bytes:
    document = {
        "digest": None,
        "persona": persona,
        "schema": "report-v3",
        "semantic_digest": None,
        "tool": {
            "build": {
                "binary_digest": "sha256:" + binary * 64,
                "compiler": "rustc test",
                "implementation": "rust",
                "source_commit": source_commit,
                "target": "test-target",
            },
            "name": "workflow-verifier",
            "version": "0.1.0",
        },
    }
    semantic = copy.deepcopy(document)
    semantic.pop("digest")
    semantic.pop("semantic_digest")
    semantic["tool"].pop("build")
    document["semantic_digest"] = (
        "sha256:" + hashlib.sha256(canonical_json(semantic, trailing_newline=False)).hexdigest()
    )
    authenticated = copy.deepcopy(document)
    authenticated.pop("digest")
    document["digest"] = (
        "sha256:"
        + hashlib.sha256(canonical_json(authenticated, trailing_newline=False)).hexdigest()
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
        (directory / "report-v3.json").write_bytes(
            report_bytes(binary=binary, source_commit=source_commit, persona=persona)
        )
        (directory / "workflow-verifier.lock").write_bytes(b"lock\n")
        (directory / "fix.diff").write_bytes(b"changed\n" if changed_fix else b"diff\n")
        manifest = artifact_manifest(
            directory, ["report-v3.json", "workflow-verifier.lock", "fix.diff"]
        )
        (directory / "determinism-v2.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        return directory

    def release_set(
        self,
        root: Path,
        overrides: dict[str, dict[str, object]] | None = None,
    ) -> dict[str, Path]:
        overrides = {} if overrides is None else overrides
        return {
            platform: self.platform(root, platform, **overrides.get(platform, {}))
            for platform in sorted(RELEASE_PLATFORMS)
        }

    def test_identical_platform_artifacts_pass_independent_of_argument_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(root)
            result = compare(list(reversed(platforms.values())))
            self.assertTrue(result["passed"])
            self.assertEqual(
                result["platforms"],
                [
                    "linux-arm64",
                    "linux-x86_64",
                    "macos-arm64",
                    "macos-x86_64",
                    "windows-x86_64",
                ],
            )
            self.assertEqual(result["schema"], "determinism-comparison-v2")

    def test_platform_bound_report_provenance_is_recorded_but_not_compared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(
                root,
                {"windows-x86_64": {"binary": "b", "source_commit": "c" * 40}},
            )
            result = compare(list(platforms.values()))
            self.assertTrue(result["passed"])
            reports = result["report_projection"]["reports"]
            self.assertEqual(len({report["raw_digest"] for report in reports}), 2)
            self.assertEqual(len({report["semantic_digest"] for report in reports}), 1)

    def test_semantic_report_difference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(root, {"windows-x86_64": {"persona": "paranoid"}})
            result = compare(list(platforms.values()))
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["failures"],
                ["report-v3 semantic content differs between linux-arm64 and windows-x86_64"],
            )

    def test_portable_artifact_byte_difference_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(root, {"windows-x86_64": {"changed_fix": True}})
            result = compare(list(platforms.values()))
            self.assertFalse(result["passed"])
            self.assertEqual(
                result["failures"],
                ["fix.diff differs between linux-arm64 and windows-x86_64"],
            )

    def test_tampered_manifest_fails_before_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(root)
            platform = platforms["linux-x86_64"]
            (platform / "fix.diff").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "manifest does not match"):
                compare(list(platforms.values()))

    def test_missing_release_platform_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            platforms = self.release_set(Path(temporary))
            platforms.pop("linux-arm64")
            with self.assertRaisesRegex(ValueError, "exactly five"):
                compare(list(platforms.values()))

    def test_direct_script_entrypoint_resolves_its_sibling_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            platforms = self.release_set(root)
            output = root / "comparison.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "scripts/compare_determinism.py",
                    "--output",
                    str(output),
                    *(str(path) for path in platforms.values()),
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
