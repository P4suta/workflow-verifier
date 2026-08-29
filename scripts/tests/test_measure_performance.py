import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.measure_performance as measurement
from scripts.measure_performance import measure


class MeasurePerformanceTests(unittest.TestCase):
    def suite(self, root: Path, command: list[str]) -> Path:
        document = {
            "environment": {"executor": "fixture", "implementation": "rust"},
            "scenarios": [
                {
                    "before_each": [],
                    "command": command,
                    "cwd": "work",
                    "id": "fixture",
                    "setup": [],
                    "timeout_seconds": 5,
                }
            ],
            "schema": "performance-suite-v2",
        }
        path = root / "suite.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_relative_executable_is_made_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary) / "test"
            cwd.mkdir()
            resolved = measurement._native_argv(["../target/release/verifier", "check"], cwd)
            self.assertEqual(
                resolved, [str((cwd / "../target/release/verifier").resolve()), "check"]
            )

    def test_committed_suite_has_distinct_product_scenarios(self) -> None:
        root = Path(__file__).resolve().parents[2]
        suite = root / "performance" / "rust-suite-v2.json"
        document = json.loads(suite.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "performance-suite-v2")
        identifiers = {scenario["id"] for scenario in document["scenarios"]}
        self.assertEqual(
            identifiers,
            {
                "cold-check",
                "graph-json",
                "lsp-edit",
                "lsp-initial",
                "lsp-noop",
                "mixed-workspace",
                "self-dogfood",
            },
        )
        self.assertNotIn("cache-mode", suite.read_text(encoding="utf-8"))
        with mock.patch.object(measurement, "_run") as invoked:
            result = measure(suite, root, revision="a" * 40, samples=1)
        self.assertEqual(result["schema"], "performance-v2")
        self.assertEqual(len(result["scenarios"]), 7)
        self.assertGreaterEqual(invoked.call_count, 8)

    def test_one_scenario_is_measured_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            marker = root / "work" / "marker.txt"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('marker.txt').write_bytes(b'ok')",
            ]
            result = measure(self.suite(root, command), root, revision="b" * 40, samples=2)
            self.assertEqual(result["schema"], "performance-v2")
            self.assertEqual(len(result["scenarios"][0]["samples_ns"]), 2)
            self.assertTrue(all(value > 0 for value in result["scenarios"][0]["samples_ns"]))
            self.assertEqual(marker.read_bytes(), b"ok")

    def test_suite_is_strict_and_cwd_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            suite = self.suite(root, [sys.executable, "-c", "pass"])
            document = json.loads(suite.read_text(encoding="utf-8"))
            document["scenarios"][0]["cwd"] = "../outside"
            suite.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "safe relative"):
                measure(suite, root, revision="b" * 40, samples=1)


if __name__ == "__main__":
    unittest.main()
