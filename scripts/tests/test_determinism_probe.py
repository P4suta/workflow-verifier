import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.determinism_probe import artifact_manifest, build_commands, canonical_json


def report_bytes(binary: str = "a") -> bytes:
    document = {
        "digest": None,
        "persona": "audit",
        "schema": "report-v2",
        "tool": {
            "binary_digest": "sha256:" + binary * 64,
            "build": {"source_commit": None},
        },
    }
    document["digest"] = (
        "sha256:" + hashlib.sha256(canonical_json(document, trailing_newline=False)).hexdigest()
    )
    return canonical_json(document)


class DeterminismProbeTests(unittest.TestCase):
    def test_commands_use_the_same_relative_fixture_and_never_enable_network(self) -> None:
        commands = build_commands(Path("bin/workflow-verifier"), "test/fixtures/determinism")
        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[0][1], "check")
        self.assertIn("--trust-repository-config", commands[0])
        self.assertEqual(commands[0][commands[0].index("--cache-mode") + 1], "off")
        self.assertTrue(all("--trust-repository-config" in command for command in commands))
        self.assertEqual(commands[0][-1], "test/fixtures/determinism")
        self.assertEqual(commands[1][1], "resolve")
        self.assertEqual(commands[2][1], "fix")
        self.assertTrue(all("--allow-network" not in command for command in commands))

    def test_manifest_is_order_independent_and_hashes_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "report-v2.json").write_bytes(report_bytes())
            (root / "workflow-verifier.lock").write_bytes(b"lock\n")
            (root / "fix.diff").write_bytes(b"diff\n")
            first = artifact_manifest(
                root, ["fix.diff", "report-v2.json", "workflow-verifier.lock"]
            )
            second = artifact_manifest(
                root, ["workflow-verifier.lock", "fix.diff", "report-v2.json"]
            )
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "determinism-v1")
            self.assertEqual(first["local_repetitions"], 2)
            self.assertRegex(first["report_semantic_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                [item["name"] for item in first["artifacts"]],
                ["fix.diff", "report-v2.json", "workflow-verifier.lock"],
            )

    def test_unsafe_fixture_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "safe relative"):
            build_commands(Path("workflow-verifier"), "../fixture")
        with self.assertRaisesRegex(ValueError, "safe relative"):
            build_commands(Path("workflow-verifier"), "C:\\fixture")


if __name__ == "__main__":
    unittest.main()
