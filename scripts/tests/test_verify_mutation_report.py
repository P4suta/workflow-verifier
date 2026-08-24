import json
from pathlib import Path
import tempfile
import unittest

from scripts.verify_mutation_report import verify


def mutant(identifier: str, path: str, outcome: str, expected: bool = False) -> dict[str, object]:
    full_id = identifier * 64
    return {
        "mutant": {
            "id": full_id[:20],
            "full_id": full_id,
            "path": path,
            "range": {
                "start_byte": 1,
                "end_byte": 2,
                "start_line": 1,
                "start_column": 0,
                "end_line": 1,
                "end_column": 1,
            },
            "family": "boolean",
            "rule": "boolean-literal@1",
            "original": "true",
            "replacement": "false",
            "source_digest": "a" * 64,
        },
        "outcome": outcome,
        "error": None,
        "duration_seconds": 0.1,
        "cached": False,
        "stages": [],
        "timeout_confirmed": False,
        "timeout_retry": None,
        "expected_survivor": expected,
        "expectation": (
            {
                "reason": "Semantically equivalent under this proved invariant.",
                "status": "fulfilled",
                "detail": None,
            }
            if expected
            else None
        ),
        "stdout": {"contents": "", "truncated": False, "total_bytes": 0},
        "stderr": {"contents": "", "truncated": False, "total_bytes": 0},
    }


def report(mutants: list[dict[str, object]]) -> dict[str, object]:
    killed = sum(item["outcome"] == "killed" for item in mutants)
    survived = sum(item["outcome"] == "survived" for item in mutants)
    expected = sum(item["expected_survivor"] for item in mutants)
    total = len(mutants)
    return {
        "document_type": "ocaml-mutants.run-report-v1",
        "schema_version": 1,
        "run_id": "test-run",
        "status": "completed",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "workspace": {"digest": "b" * 64, "toolchain": "OCaml 5.5.0"},
        "profile": "balanced",
        "selection": {"description": "full"},
        "test": {
            "command": ["dune", "runtest", "--force"],
            "baseline_duration_seconds": 1.0,
            "timeout_seconds": 10.0,
            "stages": [],
        },
        "cache": {"mode": "off", "key": "unavailable"},
        "summary": {
            "kind": "complete",
            "total": total,
            "executed": total,
            "not_run": 0,
            "killed": killed,
            "survived": survived,
            "timeout": 0,
            "unconfirmed_timeouts": 0,
            "inconclusive": 0,
            "error": 0,
            "expected_survivors": expected,
            "unexpected_survivors": survived - expected,
            "unfulfilled_expectations": 0,
            "detected": killed,
            "score": 100.0 if killed else None,
        },
        "mutants": mutants,
        "not_run": [],
        "expectations": [],
        "failure": None,
        "skips": [],
        "warnings": [],
    }


class VerifyMutationReportTests(unittest.TestCase):
    def write(self, root: Path, document: dict[str, object]) -> Path:
        path = root / "mutation.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_complete_kills_and_documented_equivalents_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = report(
                [
                    mutant("1", "lib/domain/abstract_value.ml", "killed"),
                    mutant("2", "lib/verifier/verifier.ml", "killed"),
                    mutant("3", "lib/syntax/yaml_cst.ml", "survived", expected=True),
                ]
            )
            result = verify(
                self.write(root, document),
                ["lib/domain/", "lib/verifier/", "lib/syntax/"],
            )
            self.assertTrue(result["passed"])
            self.assertEqual(result["mutants"], 3)
            self.assertEqual(result["detected"], 2)
            self.assertEqual(result["expected_survivors"], 1)

    def test_unexpected_survivor_is_a_gate_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = report([mutant("4", "lib/domain/condition.ml", "survived")])
            result = verify(self.write(root, document), ["lib/domain/"])
            self.assertFalse(result["passed"])
            self.assertEqual(result["failures"], ["one unexpected mutant survived"])

    def test_infrastructure_failure_cannot_count_as_a_kill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            killed = mutant("6", "lib/domain/condition.ml", "killed")
            killed["stderr"]["contents"] = (
                "Error: Another Dune instance is currently running "
                "in the same build directory."
            )
            killed["stderr"]["total_bytes"] = len(killed["stderr"]["contents"])
            with self.assertRaisesRegex(ValueError, "infrastructure failure"):
                verify(self.write(root, report([killed])), ["lib/domain/"])

    def test_partial_inconsistent_or_vacuous_reports_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = report([mutant("5", "lib/domain/condition.ml", "killed")])
            document["summary"]["kind"] = "partial"
            with self.assertRaisesRegex(ValueError, "complete mutation run"):
                verify(self.write(root, document), ["lib/domain/"])

            document = report([mutant("5", "lib/domain/condition.ml", "killed")])
            document["summary"]["executed"] = 2
            with self.assertRaisesRegex(ValueError, "summary counters"):
                verify(self.write(root, document), ["lib/domain/"])

            document = report([mutant("5", "lib/domain/condition.ml", "killed")])
            with self.assertRaisesRegex(ValueError, "no executed mutant under lib/verifier"):
                verify(self.write(root, document), ["lib/domain/", "lib/verifier/"])


if __name__ == "__main__":
    unittest.main()
