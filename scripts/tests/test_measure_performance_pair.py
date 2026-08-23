from __future__ import annotations

from pathlib import Path
import unittest

from scripts.measure_performance_pair import measure_pair


class InterleavedPerformanceTests(unittest.TestCase):
    def test_counterbalanced_batches_preserve_all_samples(self) -> None:
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
            samples=21,
            measurer=fake_measure,
        )

        self.assertEqual([name for name, _revision, _samples in calls], ["base", "head", "head", "base", "base", "head"])
        self.assertTrue(all(samples == 7 for _name, _revision, samples in calls))
        for report in (baseline, current):
            for mode in ("cold", "incremental", "warm"):
                self.assertEqual(len(report["scenarios"][0]["modes"][mode]["samples_ns"]), 21)

    def test_candidate_and_sample_identity_are_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "different revisions"):
            measure_pair(
                Path("suite.json"), Path("base"), "a" * 40, Path("head"), "a" * 40, samples=21
            )
        with self.assertRaisesRegex(ValueError, "multiple of three"):
            measure_pair(
                Path("suite.json"), Path("base"), "a" * 40, Path("head"), "b" * 40, samples=20
            )


if __name__ == "__main__":
    unittest.main()
