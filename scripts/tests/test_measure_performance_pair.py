from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from statistics import median

from scripts.measure_performance_pair import measure_pair


class InterleavedPerformanceTests(unittest.TestCase):
    @staticmethod
    def fake_measure(_suite: Path, _workspace: Path, *, revision: str, samples: int):
        value = 200 if _workspace.name == "current" else 100
        return {
            "environment": {"executor": "fixture"},
            "regression_explanations": [],
            "revision": revision,
            "scenarios": [
                {
                    "id": "analysis",
                    "modes": {
                        mode: {"samples_ns": [value] * samples}
                        for mode in ("cold", "incremental", "warm")
                    },
                }
            ],
            "schema": "performance-v1",
        }

    def test_period_balanced_cycles_preserve_all_samples(self) -> None:
        calls: list[tuple[str, str, int]] = []

        def fake_measure(_suite: Path, workspace: Path, *, revision: str, samples: int):
            calls.append((workspace.name, revision, samples))
            value = len(calls) * 100
            return {
                "environment": {"executor": "fixture"},
                "regression_explanations": [],
                "revision": revision,
                "scenarios": [
                    {
                        "id": "analysis",
                        "modes": {
                            mode: {"samples_ns": list(range(value, value + samples))}
                            for mode in ("cold", "incremental", "warm")
                        },
                    }
                ],
                "schema": "performance-v1",
            }

        baseline, current = measure_pair(
            Path("suite.json"),
            Path("base"),
            "a" * 40,
            Path("head"),
            "b" * 40,
            samples=24,
            measurer=fake_measure,
        )

        cycle = [
            "base",
            "head",
            "head",
            "base",
            "head",
            "base",
            "base",
            "head",
            "head",
            "base",
            "base",
            "head",
            "base",
            "head",
            "head",
            "base",
        ]
        self.assertEqual([name for name, _revision, _samples in calls], cycle * 3)
        self.assertTrue(all(samples == 1 for _name, _revision, samples in calls))
        for report in (baseline, current):
            for mode in ("cold", "incremental", "warm"):
                self.assertEqual(
                    len(report["scenarios"][0]["modes"][mode]["samples_ns"]),
                    24,
                )

        baseline_samples = baseline["scenarios"][0]["modes"]["cold"]["samples_ns"]
        current_samples = current["scenarios"][0]["modes"]["cold"]["samples_ns"]
        self.assertEqual(median(baseline_samples), median(current_samples))
        self.assertEqual(baseline["environment"]["pair_design"], "period-balanced-v2")
        self.assertEqual(current["environment"]["pair_design"], "period-balanced-v2")

    def test_candidate_and_sample_identity_are_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "different revisions"):
            measure_pair(
                Path("suite.json"), Path("base"), "a" * 40, Path("head"), "a" * 40, samples=24
            )
        with self.assertRaisesRegex(ValueError, "multiple of eight"):
            measure_pair(
                Path("suite.json"), Path("base"), "a" * 40, Path("head"), "b" * 40, samples=20
            )

    def test_config_v1_to_v2_cost_is_reviewed_only_for_that_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            current = root / "current"
            baseline.mkdir()
            marker = current / "schema"
            marker.mkdir(parents=True)
            (marker / "config-v2.schema.json").write_text("{}\n", encoding="utf-8")
            before, after = measure_pair(
                Path("suite.json"),
                baseline,
                "a" * 40,
                current,
                "b" * 40,
                samples=8,
                measurer=self.fake_measure,
            )
            self.assertEqual(before["regression_explanations"], [])
            self.assertEqual(len(after["regression_explanations"]), 3)
            self.assertTrue(
                all(
                    item["review"] == "https://github.com/P4suta/workflow-verifier/pull/6"
                    for item in after["regression_explanations"]
                )
            )

            (baseline / "schema").mkdir()
            (baseline / "schema" / "config-v2.schema.json").write_text("{}\n", encoding="utf-8")
            _before, same_contract = measure_pair(
                Path("suite.json"),
                baseline,
                "c" * 40,
                current,
                "d" * 40,
                samples=8,
                measurer=self.fake_measure,
            )
            self.assertEqual(same_contract["regression_explanations"], [])


if __name__ == "__main__":
    unittest.main()
