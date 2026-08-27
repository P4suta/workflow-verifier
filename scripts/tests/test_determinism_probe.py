import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.determinism_probe import artifact_manifest, build_commands, canonical_json


def report_bytes(binary: str = "a") -> bytes:
    document = {
        "digest": None,
        "persona": "audit",
        "schema": "report-v3",
        "semantic_digest": None,
        "tool": {
            "build": {
                "binary_digest": "sha256:" + binary * 64,
                "compiler": "rustc test",
                "implementation": "rust",
                "source_commit": None,
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


class DeterminismProbeTests(unittest.TestCase):
    def test_ci_and_local_tasks_probe_the_rust_cli_on_all_five_platforms(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        ci = (repository / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        justfile = (repository / "justfile").read_text(encoding="utf-8")
        mise = (repository / "mise.toml").read_text(encoding="utf-8")
        determinism_job = ci.split("  determinism-probe:", 1)[1].split("  determinism-compare:", 1)[
            0
        ]

        self.assertIn("platform: linux-arm64", determinism_job)
        self.assertIn("cargo build --locked -p workflow-verifier-cli", determinism_job)
        self.assertIn("_determinism/determinism-linux-arm64", ci)
        self.assertIn("cargo build --locked -p workflow-verifier-cli", justfile)
        self.assertIn("{{linux_arm64}}", justfile)
        self.assertIn("_build/determinism/linux-arm64", mise)

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
            (root / "report-v3.json").write_bytes(report_bytes())
            (root / "workflow-verifier.lock").write_bytes(b"lock\n")
            (root / "fix.diff").write_bytes(b"diff\n")
            first = artifact_manifest(
                root, ["fix.diff", "report-v3.json", "workflow-verifier.lock"]
            )
            second = artifact_manifest(
                root, ["workflow-verifier.lock", "fix.diff", "report-v3.json"]
            )
            self.assertEqual(first, second)
            self.assertEqual(first["schema"], "determinism-v2")
            self.assertEqual(first["local_repetitions"], 2)
            self.assertRegex(first["report_semantic_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                [item["name"] for item in first["artifacts"]],
                ["fix.diff", "report-v3.json", "workflow-verifier.lock"],
            )

    def test_unsafe_fixture_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "safe relative"):
            build_commands(Path("workflow-verifier"), "../fixture")
        with self.assertRaisesRegex(ValueError, "safe relative"):
            build_commands(Path("workflow-verifier"), "C:\\fixture")


if __name__ == "__main__":
    unittest.main()
