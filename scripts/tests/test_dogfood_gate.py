import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.dogfood_gate import extract_evidence, prepare_image, verify


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def evidence(plan_digest: str) -> dict[str, object]:
    bodies = [
        {"kind": "backend_attested"},
        {"kind": "process_started"},
        {"kind": "artifact_recorded"},
    ]
    events: list[dict[str, object]] = []
    previous = plan_digest
    for sequence, body in enumerate(bodies):
        unsigned = {"body": body, "previous_digest": previous, "sequence": sequence}
        digest = "sha256:" + hashlib.sha256(canonical(unsigned)[:-1].encode("utf-8")).hexdigest()
        events.append({**unsigned, "digest": digest})
        previous = digest
    return {"events": events, "plan_digest": plan_digest, "schema": "evidence-v2"}


class DogfoodGateTests(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        plan_digest = "sha256:" + "3" * 64
        runtime_evidence = evidence(plan_digest)
        documents = {
            "report.json": {
                "diagnostics": [],
                "inputs": [
                    {"path": ".github/workflows/ci.yml"},
                    {"path": ".gitlab-ci.yml"},
                    {"path": "azure-pipelines.yml"},
                    {"path": ".circleci/config.yml"},
                ],
                "persona": "audit",
                "properties": [{"state": "Proved"}],
                "schema": "report-v3",
            },
            "report.sarif.json": {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [],
                "version": "2.1.0",
            },
            "graph.json": {"edges": [], "entrypoints": ["entry"], "nodes": [{"id": "entry"}]},
            "diff.json": {
                "base_digest": "sha256:" + "0" * 64,
                "changes": [],
                "head_digest": "sha256:" + "1" * 64,
                "schema": "semantic-diff-v1",
            },
            "policy.json": {
                "cases": [{"passed": True}],
                "passed": True,
                "schema": "policy-test-v1",
            },
            "lock.json": {"entries": [], "integrity": "sha256:" + "2" * 64, "schema": "lock-v2"},
            "doctor.json": {
                "backends": [{"id": "oci:docker", "available": True}],
                "frontends": ["github", "gitlab", "azure", "circleci"],
                "resolver_network": False,
                "sandbox_executor": True,
                "schema": "doctor-v2",
            },
            "plan.json": {
                "backend": "oci:docker",
                "digest": plan_digest,
                "schema": "runner-v2",
                "status": {"state": "complete"},
                "steps": [{"id": "build"}],
            },
            "run.json": {
                "evidence": runtime_evidence,
                "outcome": {"state": "completed"},
                "schema": "sandbox-run-v2",
            },
            "replay.json": runtime_evidence,
            "audit.json": {
                "event_count": 3,
                "evidence_tail": runtime_evidence["events"][-1]["digest"],
                "plan_digest": plan_digest,
                "reconciliation": {"state": "Proved"},
                "schema": "sandbox-audit-v1",
                "status": {"state": "verified"},
            },
        }
        for name, document in documents.items():
            (root / name).write_text(canonical(document), encoding="utf-8", newline="\n")
        (root / "explain.txt").write_text(
            "WV-SEC-001\ntrace:\n  - source\ncapabilities: network\n",
            encoding="utf-8",
            newline="\n",
        )
        (root / "graph.dot").write_text("digraph workflow {\n}\n", encoding="utf-8", newline="\n")
        (root / "fix.patch").write_text(
            "--- a/workflow.yml\n+++ b/workflow.yml\n", encoding="utf-8", newline="\n"
        )

    def test_complete_live_cli_evidence_passes_and_is_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            result = verify(root)
            self.assertTrue(result["passed"])
            self.assertEqual(result["schema"], "dogfood-v1")
            self.assertEqual(len(result["artifacts"]), 14)
            self.assertTrue(
                all(item["digest"].startswith("sha256:") for item in result["artifacts"])
            )

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

    def test_all_four_frontends_and_zero_diagnostics_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["inputs"] = report["inputs"][:-1]
            (root / "report.json").write_text(canonical(report), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "four provider"):
                verify(root)
            self.fixture(root)
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["diagnostics"] = [{"rule_id": "WV-TEST"}]
            (root / "report.json").write_text(canonical(report), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "diagnostics"):
                verify(root)
            self.fixture(root)
            doctor = json.loads((root / "doctor.json").read_text(encoding="utf-8"))
            doctor["frontends"].remove("azure")
            (root / "doctor.json").write_text(canonical(doctor), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "exactly four frontends"):
                verify(root)

    def test_legacy_reference_report_is_not_product_dogfood_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            report["schema"] = "report-v2"
            (root / "report.json").write_text(canonical(report), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "report-v3"):
                verify(root)

    def test_runtime_hash_chain_and_audit_tail_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            run = json.loads((root / "run.json").read_text(encoding="utf-8"))
            run["evidence"]["events"][0]["body"]["kind"] = "backend_error"
            (root / "run.json").write_text(canonical(run), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "digest"):
                verify(root)
            self.fixture(root)
            audit = json.loads((root / "audit.json").read_text(encoding="utf-8"))
            audit["evidence_tail"] = "sha256:" + "9" * 64
            (root / "audit.json").write_text(canonical(audit), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "tail"):
                verify(root)
            self.fixture(root)
            audit = json.loads((root / "audit.json").read_text(encoding="utf-8"))
            audit["reconciliation"]["state"] = "Unknown"
            (root / "audit.json").write_text(canonical(audit), encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "Proved"):
                verify(root)

    def test_extracts_canonical_evidence_and_rejects_non_run_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            output = root / "evidence.json"
            extract_evidence(root / "run.json", output)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                (root / "replay.json").read_text(encoding="utf-8"),
            )
            with self.assertRaisesRegex(ValueError, "sandbox-run-v2"):
                extract_evidence(root / "report.json", output)

    def test_prepares_only_a_content_addressed_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / ".workflow-verifier.toml"
            config.write_text(
                '[sandbox]\ncapsule_digest = "sha256:' + "0" * 64 + '"\n',
                encoding="utf-8",
                newline="\n",
            )
            image = "sha256:" + "a" * 64
            prepare_image(config, image)
            self.assertIn(image, config.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ValueError, "content digest"):
                prepare_image(config, "alpine:latest")


if __name__ == "__main__":
    unittest.main()
