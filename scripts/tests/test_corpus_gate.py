import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.corpus_gate import evaluate, tree_digest


SHA = "a" * 40
DIGEST = "sha256:" + ("b" * 64)
LICENSE_DIGEST = "sha256:" + hashlib.sha256(b"MIT\n").hexdigest()


def diagnostic(identifier: str, rule_id: str) -> dict[str, object]:
    return {
        "id": identifier,
        "rule_id": rule_id,
        "severity": "warning",
        "confidence": "high",
        "message": "reviewed fixture",
        "span": {
            "file": ".github/workflows/ci.yml",
            "start": {"byte": 0, "line": 1, "column": 1},
            "stop": {"byte": 1, "line": 1, "column": 2},
        },
        "trace": [],
        "capabilities": [],
        "evidence": [],
        "fix": None,
    }


def report(diagnostics: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": "report-v1",
        "digest": DIGEST,
        "tool": {"name": "workflow-verifier", "version": "0.1.0"},
        "persona": "audit",
        "inputs": [],
        "graphs": [],
        "properties": [],
        "diagnostics": diagnostics,
        "summary": {},
    }


class CorpusGateTests(unittest.TestCase):
    def repository(
        self,
        root: Path,
        identifier: str,
        provider: str,
        expected: list[dict[str, str]],
        allowed: list[dict[str, str]],
        actual: list[dict[str, object]],
    ) -> dict[str, object]:
        checkout = root / "corpus" / identifier
        checkout.mkdir(parents=True)
        (checkout / "LICENSE").write_bytes(b"MIT\n")
        workflow = checkout / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(b"name: fixture\n")
        report_path = root / "reports" / f"{identifier.replace('/', '-')}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report(actual), ensure_ascii=False), encoding="utf-8"
        )
        return {
            "id": identifier,
            "provider": provider,
            "url": f"https://example.invalid/{identifier}.git",
            "revision": SHA,
            "checkout": identifier,
            "source_digest": tree_digest(checkout),
            "license": "MIT",
            "license_path": "LICENSE",
            "license_digest": LICENSE_DIGEST,
            "report": report_path.relative_to(root / "reports").as_posix(),
            "expected_diagnostics": expected,
            "allowed_diagnostics": allowed,
        }

    def test_metrics_are_deterministic_and_allowed_findings_are_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {"id": "diag_" + "1" * 20, "rule_id": "WV-SEC-001"}
            allowed = {"id": "diag_" + "2" * 20, "rule_id": "WV-PERM-001"}
            unexpected = diagnostic("diag_" + "3" * 20, "WV-NEW-001")
            repositories = [
                self.repository(
                    root,
                    "gitlab/acme/unsafe",
                    "gitlab",
                    [expected],
                    [allowed],
                    [
                        diagnostic(expected["id"], expected["rule_id"]),
                        diagnostic(allowed["id"], allowed["rule_id"]),
                        unexpected,
                    ],
                ),
                self.repository(root, "github/acme/clean", "github", [], [], []),
            ]
            manifest = root / "corpus.json"
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": repositories}),
                encoding="utf-8",
            )

            first = evaluate(manifest, root / "corpus", root / "reports")
            manifest.write_text(
                json.dumps(
                    {"schema": "corpus-v1", "repositories": list(reversed(repositories))}
                ),
                encoding="utf-8",
            )
            second = evaluate(manifest, root / "corpus", root / "reports")

            self.assertEqual(first, second)
            self.assertEqual(first["metrics"]["true_positive"], 1)
            self.assertEqual(first["metrics"]["false_positive"], 1)
            self.assertEqual(first["metrics"]["false_negative"], 0)
            self.assertEqual(first["metrics"]["allowed"], 1)
            self.assertEqual(first["metrics"]["precision"], "0.500000")
            self.assertEqual(first["metrics"]["recall"], "1.000000")
            self.assertFalse(first["passed"])
            self.assertEqual(first["failures"], ["precision 0.500000 is below 0.950000"])

    def test_missing_known_vulnerability_fails_recall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {"id": "diag_" + "4" * 20, "rule_id": "WV-AUTH-001"}
            repository = self.repository(
                root, "azure/acme/missing", "azure", [expected], [], []
            )
            manifest = root / "corpus.json"
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": [repository]}),
                encoding="utf-8",
            )
            result = evaluate(manifest, root / "corpus", root / "reports")
            self.assertEqual(result["metrics"]["recall"], "0.000000")
            self.assertIn("recall 0.000000 is below 1.000000", result["failures"])

    def test_source_license_and_strict_manifest_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.repository(
                root, "circleci/acme/strict", "circleci", [], [], []
            )
            manifest = root / "corpus.json"
            repository["revision"] = "main"
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": [repository]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "immutable 40-character"):
                evaluate(manifest, root / "corpus", root / "reports")

            repository["revision"] = SHA
            repository["unknown"] = True
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": [repository]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                evaluate(manifest, root / "corpus", root / "reports")

            repository.pop("unknown")
            (root / "corpus" / repository["checkout"] / "LICENSE").write_text(
                "changed\n", encoding="utf-8"
            )
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": [repository]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "source digest"):
                evaluate(manifest, root / "corpus", root / "reports")

    def test_release_gate_requires_one_hundred_unique_repositories_per_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self.repository(root, "github/acme/one", "github", [], [], [])
            manifest = root / "corpus.json"
            manifest.write_text(
                json.dumps({"schema": "corpus-v1", "repositories": [repository]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "100 repositories for github"):
                evaluate(
                    manifest,
                    root / "corpus",
                    root / "reports",
                    release=True,
                )


if __name__ == "__main__":
    unittest.main()
