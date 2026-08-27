from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


class GitHubActionTests(unittest.TestCase):
    def test_action_uses_an_environment_credential_name_and_never_the_value_in_argv(self) -> None:
        runner = ROOT / "action" / "run.py"
        metadata = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("github-token:", metadata)
        self.assertIn("action/run.py", metadata)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            github_output = root / "github-output"
            environment = {
                **os.environ,
                "GITHUB_OUTPUT": str(github_output),
                "RUNNER_TEMP": str(root),
                "WV_ACTION_BINARY": "workflow-verifier-test-double",
                "WV_ACTION_CONFIG": "",
                "WV_ACTION_FORMAT": "json",
                "WV_ACTION_GITHUB_HOST": "github.com",
                "WV_ACTION_GITHUB_TOKEN": "top-secret-value",
                "WV_ACTION_NETWORK_PROFILE": "",
                "WV_ACTION_OUTPUT": str(report),
                "WV_ACTION_PATH": ".",
                "WV_ACTION_PERSONA": "gate",
                "WV_ACTION_RESOLVE": "true",
            }
            specification = importlib.util.spec_from_file_location(
                "workflow_verifier_action_run", runner
            )
            self.assertIsNotNone(specification)
            self.assertIsNotNone(specification.loader)
            action_run = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(action_run)

            records: list[dict[str, object]] = []

            def run_test_double(
                arguments: list[str],
                *,
                env: dict[str, str],
                stdin: int,
                stdout: int | None,
                stderr: int | None,
                check: bool,
            ) -> subprocess.CompletedProcess[list[str]]:
                records.append(
                    {
                        "argv": arguments[1:],
                        "credential_present": env.get(
                            "WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN"
                        )
                        == "top-secret-value",
                        "quiet": stdout is subprocess.DEVNULL
                        and stderr is subprocess.DEVNULL,
                        "stdin_closed": stdin is subprocess.DEVNULL,
                    }
                )
                operation = arguments[1]
                if operation == "resolve":
                    lock = Path(arguments[arguments.index("--lockfile") + 1])
                    lock.write_text("{}\n", encoding="utf-8")
                else:
                    output = Path(arguments[arguments.index("--output") + 1])
                    output.write_text("{}\n", encoding="utf-8")
                return subprocess.CompletedProcess(arguments, 0)

            captured_stdout = io.StringIO()
            captured_stderr = io.StringIO()
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(action_run.subprocess, "run", side_effect=run_test_double),
                redirect_stdout(captured_stdout),
                redirect_stderr(captured_stderr),
            ):
                status = action_run.main()

            self.assertEqual(status, 0, captured_stderr.getvalue())
            self.assertNotIn(
                "top-secret-value",
                captured_stdout.getvalue() + captured_stderr.getvalue(),
            )
            self.assertEqual(len(records), 2)
            self.assertTrue(records[0]["credential_present"])
            self.assertFalse(records[1]["credential_present"])
            self.assertTrue(records[0]["quiet"])
            self.assertFalse(records[1]["quiet"])
            self.assertTrue(all(record["stdin_closed"] for record in records))
            self.assertIn(
                "github@github.com=WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN",
                records[0]["argv"],
            )
            self.assertNotIn("top-secret-value", json.dumps(records))
            self.assertTrue(report.is_file())

    def test_release_publication_and_action_publication_are_source_disabled(self) -> None:
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        trigger = release.split("permissions:", 1)[0]
        self.assertNotIn("push:\n    tags:", trigger)
        self.assertNotIn("  publish:\n", release)
        self.assertNotIn("gh release create", release)
        self.assertNotIn("actions/attest@", release)
        self.assertNotIn("contents: write", release)
        self.assertFalse((ROOT / ".github" / "workflows" / "publish-action.yml").exists())


if __name__ == "__main__":
    unittest.main()
