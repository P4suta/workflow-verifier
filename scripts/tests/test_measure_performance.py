import json
from pathlib import Path
import sys
import tempfile
import unittest

from scripts.measure_performance import measure


class MeasurePerformanceTests(unittest.TestCase):
    def suite(self, root: Path, command: list[str]) -> Path:
        document = {
            "schema": "performance-suite-v1",
            "environment": {
                "corpus_digest": "sha256:" + "a" * 64,
                "machine": "test-runner",
            },
            "scenarios": [
                {
                    "id": "fixture",
                    "cwd": "work",
                    "modes": {
                        mode: {
                            "before_each": [],
                            "command": command,
                            "setup": [],
                            "timeout_seconds": 5,
                        }
                        for mode in ("cold", "incremental", "warm")
                    },
                }
            ],
        }
        path = root / "suite.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_all_modes_are_measured_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            marker = root / "work" / "marker.txt"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('marker.txt').write_bytes(b'ok')",
            ]
            result = measure(
                self.suite(root, command),
                root,
                revision="b" * 40,
                samples=2,
            )
            self.assertEqual(result["schema"], "performance-v1")
            self.assertEqual(result["revision"], "b" * 40)
            self.assertEqual(result["regression_explanations"], [])
            modes = result["scenarios"][0]["modes"]
            self.assertEqual(set(modes), {"cold", "incremental", "warm"})
            self.assertTrue(all(len(value["samples_ns"]) == 2 for value in modes.values()))
            self.assertTrue(all(sample > 0 for value in modes.values() for sample in value["samples_ns"]))
            self.assertEqual(marker.read_bytes(), b"ok")

    def test_setup_and_before_each_are_observable_and_failures_stop_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            suite = self.suite(root, [sys.executable, "-c", "raise SystemExit(7)"])
            with self.assertRaisesRegex(RuntimeError, "exit 7"):
                measure(suite, root, revision="b" * 40, samples=1)

    def test_suite_is_strict_and_cwd_cannot_escape_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            suite = self.suite(root, [sys.executable, "-c", "pass"])
            document = json.loads(suite.read_text(encoding="utf-8"))
            document["scenarios"][0]["cwd"] = "../outside"
            suite.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "safe relative"):
                measure(suite, root, revision="b" * 40, samples=1)

            document["scenarios"][0]["cwd"] = "work"
            document["extra"] = True
            suite.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                measure(suite, root, revision="b" * 40, samples=1)


if __name__ == "__main__":
    unittest.main()
