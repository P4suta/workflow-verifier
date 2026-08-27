from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GitHubActionTests(unittest.TestCase):
    def test_action_uses_an_environment_credential_name_and_never_the_value_in_argv(self) -> None:
        runner = ROOT / "action" / "run.py"
        metadata = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("github-token:", metadata)
        self.assertIn("action/run.py", metadata)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            report = root / "report.json"
            analyzer = root / "fake-analyzer"
            analyzer.write_text(
                """#!/usr/bin/env python3
import json, os, pathlib, sys
record = {
    "argv": sys.argv[1:],
    "credential_present": os.environ.get("WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN") == "top-secret-value",
}
with pathlib.Path(os.environ["WV_ACTION_TEST_TRACE"]).open("a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\\n")
if sys.argv[1] == "resolve":
    print(os.environ.get("WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN", ""))
    print(os.environ.get("WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN", ""), file=sys.stderr)
    lock = pathlib.Path(sys.argv[sys.argv.index("--lockfile") + 1])
    lock.write_text("{}\\n", encoding="utf-8")
else:
    report = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    report.write_text("{}\\n", encoding="utf-8")
""",
                encoding="utf-8",
            )
            analyzer.chmod(analyzer.stat().st_mode | stat.S_IXUSR)
            github_output = root / "github-output"
            environment = {
                **os.environ,
                "GITHUB_OUTPUT": str(github_output),
                "RUNNER_TEMP": str(root),
                "WV_ACTION_BINARY": str(analyzer),
                "WV_ACTION_CONFIG": "",
                "WV_ACTION_FORMAT": "json",
                "WV_ACTION_GITHUB_HOST": "github.com",
                "WV_ACTION_GITHUB_TOKEN": "top-secret-value",
                "WV_ACTION_NETWORK_PROFILE": "",
                "WV_ACTION_OUTPUT": str(report),
                "WV_ACTION_PATH": ".",
                "WV_ACTION_PERSONA": "gate",
                "WV_ACTION_RESOLVE": "true",
                "WV_ACTION_TEST_TRACE": str(trace),
            }
            completed = subprocess.run(
                [sys.executable, "-B", str(runner)],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn("top-secret-value", completed.stdout + completed.stderr)
            records = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 2)
            self.assertTrue(records[0]["credential_present"])
            self.assertFalse(records[1]["credential_present"])
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
