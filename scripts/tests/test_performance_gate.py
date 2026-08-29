import json
import tempfile
import unittest
from pathlib import Path

from scripts.performance_gate import compare


def ledger(
    revision: str,
    samples: list[int],
    explanations: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "environment": {"executor": "release-runner-v2"},
        "regression_explanations": explanations or [],
        "revision": revision,
        "scenarios": [{"id": "cold-check", "samples_ns": samples}],
        "schema": "performance-v2",
    }


class PerformanceGateTests(unittest.TestCase):
    def write(self, root: Path, name: str, document: dict[str, object]) -> Path:
        path = root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_median_threshold_and_review_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.write(root, "baseline.json", ledger("a" * 40, [90, 100, 110]))
            current = self.write(root, "current.json", ledger("b" * 40, [100, 110, 120]))
            result = compare(baseline, current)
            self.assertTrue(result["passed"])
            self.assertEqual(result["comparisons"][0]["change_percent"], "10.000")

            current = self.write(root, "current.json", ledger("b" * 40, [111]))
            self.assertFalse(compare(baseline, current)["passed"])
            explained = ledger(
                "b" * 40,
                [111],
                [
                    {
                        "reason": "Intentional additional whole-program proof pass.",
                        "review": "https://github.com/example/workflow-verifier/issues/123",
                        "scenario": "cold-check",
                    }
                ],
            )
            current = self.write(root, "current.json", explained)
            self.assertTrue(compare(baseline, current)["passed"])

    def test_schema_and_scenario_shape_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.write(root, "baseline.json", ledger("a" * 40, [1]))
            invalid = ledger("b" * 40, [1])
            invalid["scenarios"][0]["mode"] = "warm"
            current = self.write(root, "current.json", invalid)
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                compare(baseline, current)


if __name__ == "__main__":
    unittest.main()
