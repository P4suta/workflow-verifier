import json
from pathlib import Path
import tempfile
import unittest

from scripts.performance_gate import compare


def measurement(
    revision: str,
    cold: list[int],
    warm: list[int],
    incremental: list[int],
    explanations: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "schema": "performance-v1",
        "revision": revision,
        "environment": {
            "corpus_digest": "sha256:" + "a" * 64,
            "machine": "release-runner-v1",
        },
        "scenarios": [
            {
                "id": "four-provider-corpus",
                "modes": {
                    "cold": {"samples_ns": cold},
                    "incremental": {"samples_ns": incremental},
                    "warm": {"samples_ns": warm},
                },
            }
        ],
        "regression_explanations": explanations or [],
    }


class PerformanceGateTests(unittest.TestCase):
    def write(self, root: Path, name: str, document: dict[str, object]) -> Path:
        path = root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_medians_and_threshold_are_exact_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.write(
                root, "baseline.json", measurement("a" * 40, [90, 100, 110], [50, 60, 70], [70, 80, 90])
            )
            current = self.write(
                root, "current.json", measurement("b" * 40, [100, 110, 120], [55, 66, 77], [77, 88, 99])
            )
            result = compare(baseline, current)
            self.assertTrue(result["passed"])
            rows = result["comparisons"]
            self.assertEqual([row["mode"] for row in rows], ["cold", "incremental", "warm"])
            self.assertEqual(rows[0]["change_percent"], "10.000")
            self.assertEqual(rows[0]["status"], "within-limit")

    def test_more_than_ten_percent_requires_a_reviewed_explanation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self.write(
                root, "baseline.json", measurement("a" * 40, [100], [100], [100])
            )
            current = self.write(
                root, "current.json", measurement("b" * 40, [111], [100], [100])
            )
            failed = compare(baseline, current)
            self.assertFalse(failed["passed"])
            self.assertEqual(failed["comparisons"][0]["status"], "regression")

            explained = measurement(
                "b" * 40,
                [111],
                [100],
                [100],
                [
                    {
                        "scenario": "four-provider-corpus",
                        "mode": "cold",
                        "reason": "Intentional additional whole-program proof pass.",
                        "review": "https://github.com/example/workflow-verifier/issues/123",
                    }
                ],
            )
            current = self.write(root, "current.json", explained)
            accepted = compare(baseline, current)
            self.assertTrue(accepted["passed"])
            self.assertEqual(accepted["comparisons"][0]["status"], "explained-regression")

    def test_schema_is_strict_and_all_modes_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = measurement("a" * 40, [1], [1], [1])
            baseline = self.write(root, "baseline.json", good)
            missing = measurement("b" * 40, [1], [1], [1])
            del missing["scenarios"][0]["modes"]["warm"]
            current = self.write(root, "current.json", missing)
            with self.assertRaisesRegex(ValueError, "exactly cold, incremental, and warm"):
                compare(baseline, current)

            extra = measurement("b" * 40, [1], [1], [1])
            extra["surprise"] = 1
            current = self.write(root, "current.json", extra)
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                compare(baseline, current)

    def test_environment_and_scenario_sets_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_document = measurement("a" * 40, [1], [1], [1])
            current_document = measurement("b" * 40, [1], [1], [1])
            current_document["environment"]["machine"] = "different"
            baseline = self.write(root, "baseline.json", baseline_document)
            current = self.write(root, "current.json", current_document)
            with self.assertRaisesRegex(ValueError, "environment"):
                compare(baseline, current)


if __name__ == "__main__":
    unittest.main()
