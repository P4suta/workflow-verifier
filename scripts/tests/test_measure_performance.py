import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.measure_performance as measurement
from scripts.measure_performance import measure


class MeasurePerformanceTests(unittest.TestCase):
    def test_relative_executable_is_made_absolute_for_native_windows_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary) / "test"
            cwd.mkdir()
            resolved = measurement._native_argv(["../_build/default/bin/main.exe", "check"], cwd)
            self.assertEqual(
                resolved,
                [str((cwd / "../_build/default/bin/main.exe").resolve()), "check"],
            )

    def test_extensionless_rust_executable_resolves_to_windows_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary) / "test"
            executable = Path(temporary) / "target" / "release" / "workflow-verifier.exe"
            cwd.mkdir()
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            with mock.patch.object(measurement.sys, "platform", "win32"):
                resolved = measurement._native_argv(
                    ["../target/release/workflow-verifier", "check"], cwd
                )
            self.assertEqual(resolved, [str(executable.resolve()), "check"])

    def test_current_cache_contract_is_lowered_to_fresh_legacy_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            command = ["analyzer", "check", "--cache-mode", "user", "."]
            lowered = measurement._contract_argv(command, workspace)
            self.assertEqual(
                lowered[:5], ["analyzer", "check", "--no-cache", "--write-cache", "--cache"]
            )
            self.assertTrue(lowered[5].endswith("performance-user-cache-v1.json"))
            self.assertEqual(lowered[6:], ["."])

            schema = workspace / "schema"
            schema.mkdir()
            (schema / "config-v2.schema.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(measurement._contract_argv(command, workspace), command)

    def test_committed_suite_is_strict_and_exercises_every_mode(self) -> None:
        root = Path(__file__).resolve().parents[2]
        with mock.patch.object(measurement, "_run") as invoked:
            result = measure(
                root / "performance" / "suite-v1.json",
                root,
                revision="a" * 40,
                samples=1,
            )
        self.assertEqual(
            [item["id"] for item in result["scenarios"]],
            ["arcade-scale-analysis", "four-provider-analysis"],
        )
        self.assertTrue(
            all(
                set(scenario["modes"]) == {"cold", "incremental", "warm"}
                for scenario in result["scenarios"]
            )
        )
        self.assertGreaterEqual(invoked.call_count, 16)

    def test_committed_rust_suite_measures_fresh_distinct_mode_workloads(self) -> None:
        root = Path(__file__).resolve().parents[2]
        suite = root / "performance" / "rust-suite-v1.json"
        document = json.loads(suite.read_text(encoding="utf-8"))
        self.assertEqual(document["environment"]["suite"], "rust-suite-v1")
        self.assertEqual(document["environment"]["implementation"], "rust")
        self.assertEqual(document["environment"]["cache_semantics"], "fresh-process-analysis")
        for scenario in document["scenarios"]:
            modes = scenario["modes"]
            for specification in modes.values():
                self.assertIn("../target/release/workflow-verifier", specification["command"])
                self.assertIn(
                    ["--cache-mode", "off"],
                    [
                        specification["command"][index : index + 2]
                        for index in range(len(specification["command"]) - 1)
                    ],
                )
            self.assertEqual(modes["cold"]["before_each"], [])
            self.assertNotIn(modes["cold"]["command"], modes["cold"]["setup"])
            self.assertEqual(modes["warm"]["before_each"], [])
            self.assertEqual(modes["warm"]["setup"][-1], modes["warm"]["command"])
            self.assertEqual(modes["incremental"]["setup"][-1], modes["incremental"]["command"])
            self.assertEqual(len(modes["incremental"]["before_each"]), 1)
            self.assertIn("toggle", modes["incremental"]["before_each"][0])

        with mock.patch.object(measurement, "_run") as invoked:
            result = measure(suite, root, revision="c" * 40, samples=1)
        self.assertEqual(result["environment"]["suite"], "rust-suite-v1")
        self.assertEqual(result["environment"]["cache_semantics"], "fresh-process-analysis")
        self.assertEqual(len(result["scenarios"]), 2)
        self.assertGreaterEqual(invoked.call_count, 18)

    def test_ci_period_balances_and_separates_ocaml_and_rust_evidence(self) -> None:
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("performance-regression:", workflow)
        self.assertIn("rust-performance-regression:", workflow)
        self.assertIn("--suite performance/suite-v1.json", workflow)
        self.assertIn("--suite performance/rust-suite-v1.json", workflow)
        self.assertIn("performance-ocaml-${{ matrix.platform }}", workflow)
        self.assertIn("performance-rust-${{ matrix.platform }}", workflow)
        self.assertIn("_performance-evidence/ocaml/${PERFORMANCE_PLATFORM}", workflow)
        self.assertIn("_performance-evidence/rust/${PERFORMANCE_PLATFORM}", workflow)
        self.assertGreaterEqual(workflow.count("--samples 24"), 2)
        self.assertGreaterEqual(workflow.count("scripts/performance_gate.py"), 2)

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
            self.assertEqual(
                result["environment"]["cache_semantics"],
                "fresh-analysis-with-isolated-write",
            )
            modes = result["scenarios"][0]["modes"]
            self.assertEqual(set(modes), {"cold", "incremental", "warm"})
            self.assertTrue(all(len(value["samples_ns"]) == 2 for value in modes.values()))
            self.assertTrue(
                all(sample > 0 for value in modes.values() for sample in value["samples_ns"])
            )
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
