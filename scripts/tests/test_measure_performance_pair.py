from __future__ import annotations

import unittest
from pathlib import Path
from statistics import median

from scripts.measure_performance_pair import measure_pair


class InterleavedPerformanceTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
