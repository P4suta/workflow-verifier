import json
import tempfile
import unittest
from pathlib import Path

from scripts.dogfood_gate import extract_evidence, prepare_image, verify


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


class DogfoodGateTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        documents = {
            "report.json": {"diagnostics": [], "properties": [{"state": "Proved"}], "schema": "report-v1"},
            "report.sarif.json": {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [], "version": "2.1.0"},
            "graph.json": {"edges": [], "entrypoints": ["entry"], "nodes": [{"id": "entry"}]},
            "diff.json": {"base_digest": "sha256:" + "0" * 64, "changes": [], "head_digest": "sha256:" + "1" * 64, "schema": "semantic-diff-v1"},
            "policy.json": {"cases": [{"passed": True}], "passed": True, "schema": "policy-test-v1"},
            "lock.json": {"entries": [], "integrity": "sha256:" + "2" * 64, "schema": "lock-v2"},
            "doctor.json": {"backends": [{"id": "oci:docker", "available": True}], "frontends": [], "resolver_network": False, "sandbox_executor": True, "schema": "doctor-v1"},
            "plan.json": {"backend": "oci:docker", "digest": "sha256:" + "3" * 64, "schema": "runner-v1", "status": {"state": "complete"}, "steps": [{"id": "build"}]},
            "run.json": {"evidence": {"events": [{"kind": "backend_attested"}, {"kind": "process_started"}, {"kind": "artifact_recorded"}], "plan_digest": "sha256:" + "3" * 64, "schema": "evidence-v1"}, "outcome": {"state": "completed"}, "schema": "sandbox-run-v1"},
            "replay.json": {"events": [{"kind": "backend_attested"}, {"kind": "process_started"}, {"kind": "artifact_recorded"}], "plan_digest": "sha256:" + "3" * 64, "schema": "evidence-v1"},
            "audit.json": {"event_count": 3, "plan_digest": "sha256:" + "3" * 64, "schema": "sandbox-audit-v1", "status": {"state": "verified"}},
        }
        for name, document in documents.items():
            (root / name).write_text(canonical(document), encoding="utf-8", newline="\n")
        (root / "explain.txt").write_text("WV-SEC-001\ntrace:\n  - source\ncapabilities: network\n", encoding="utf-8", newline="\n")
        (root / "graph.dot").write_text("digraph workflow {\n}\n", encoding="utf-8", newline="\n")
        (root / "fix.patch").write_text("--- a/workflow.yml\n+++ b/workflow.yml\n", encoding="utf-8", newline="\n")

    def test_complete_live_cli_evidence_passes_and_is_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            result = verify(root)
            self.assertTrue(result["passed"])
            self.assertEqual(result["schema"], "dogfood-v1")
            self.assertEqual(len(result["artifacts"]), 14)
            self.assertTrue(all(item["digest"].startswith("sha256:") for item in result["artifacts"]))

    def test_missing_or_semantically_incomplete_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "audit.json").unlink()
            with self.assertRaisesRegex(ValueError, "audit.json"):
                verify(root)
            self.fixture(root)
            run = json.loads((root / "run.json").read_text(encoding="utf-8"))
            run["outcome"]["state"] = "step_failed"
            (root / "run.json").write_text(canonical(run), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "completed"):
                verify(root)

    def test_extracts_canonical_evidence_and_rejects_non_run_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            output = root / "evidence.json"
            extract_evidence(root / "run.json", output)
            self.assertEqual(output.read_text(encoding="utf-8"), (root / "replay.json").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "sandbox-run-v1"):
                extract_evidence(root / "report.json", output)

    def test_prepares_only_a_content_addressed_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / ".workflow-verifier.toml"
            config.write_text('[sandbox]\nimage = "sha256:' + "0" * 64 + '"\n', encoding="utf-8", newline="\n")
            image = "sha256:" + "a" * 64
            prepare_image(config, image)
            self.assertIn(image, config.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "content digest"):
                prepare_image(config, "alpine:latest")


if __name__ == "__main__":
    unittest.main()
