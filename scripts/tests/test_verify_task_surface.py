from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.verify_task_surface import PINNED_JUST, REVISION_FIXTURE, verify


class TaskSurfaceTests(unittest.TestCase):
    def test_real_parser_contract_and_aligned_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mise.toml").write_text(
                '[tasks.build]\nrun = "true"\n[tasks.performance-measure]\nrun = "true"\n'
                '[tasks.determinism-compare]\nrun = "true"\n',
                encoding="utf-8",
            )
            completed = [
                mock.Mock(returncode=0, stdout=f"just {PINNED_JUST}\n", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="build determinism-compare performance-measure\n",
                    stderr="",
                ),
                mock.Mock(
                    returncode=0,
                    stdout=f"python measure.py --revision {REVISION_FIXTURE}\n",
                    stderr="",
                ),
                mock.Mock(
                    returncode=0,
                    stdout="",
                    stderr="python -B scripts/compare_determinism.py "
                    "--output _build/determinism/comparison.json "
                    "linux-x86_64 linux-arm64 windows-x86_64 macos-arm64 macos-x86_64\n",
                ),
            ]
            with mock.patch("scripts.verify_task_surface._run", side_effect=completed) as run:
                self.assertEqual(
                    verify(root), ["build", "determinism-compare", "performance-measure"]
                )
                run.assert_any_call(
                    [
                        "just",
                        "--dry-run",
                        "determinism-compare",
                        "linux-x86_64",
                        "linux-arm64",
                        "windows-x86_64",
                        "macos-arm64",
                        "macos-x86_64",
                    ],
                    root,
                )

    def test_determinism_comparison_rejects_missing_inputs_and_command_failure(self) -> None:
        command = (
            "python -B scripts/compare_determinism.py "
            "--output _build/determinism/comparison.json "
            "linux-x86_64 linux-arm64 windows-x86_64 macos-arm64 macos-x86_64"
        )
        failures = [(1, command)] + [
            (0, command.replace(platform, ""))
            for platform in [
                "linux-x86_64",
                "linux-arm64",
                "windows-x86_64",
                "macos-arm64",
                "macos-x86_64",
            ]
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mise.toml").write_text('[tasks.build]\nrun = "true"\n', encoding="utf-8")
            for status, output in failures:
                with self.subTest(status=status, output=output):
                    completed = [
                        mock.Mock(returncode=0, stdout=f"just {PINNED_JUST}\n", stderr=""),
                        mock.Mock(returncode=0, stdout="build\n", stderr=""),
                        mock.Mock(returncode=0, stdout=REVISION_FIXTURE, stderr=""),
                        mock.Mock(returncode=status, stdout=output, stderr=""),
                    ]
                    with mock.patch("scripts.verify_task_surface._run", side_effect=completed):
                        with self.assertRaisesRegex(ValueError, "determinism-compare dry-run"):
                            verify(root)

    def test_version_and_name_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mise.toml").write_text('[tasks.build]\nrun = "true"\n', encoding="utf-8")
            with mock.patch(
                "scripts.verify_task_surface._run",
                return_value=mock.Mock(returncode=0, stdout="just 1.56.0\n", stderr=""),
            ):
                with self.assertRaisesRegex(ValueError, PINNED_JUST):
                    verify(root)

            completed = [
                mock.Mock(returncode=0, stdout=f"just {PINNED_JUST}\n", stderr=""),
                mock.Mock(returncode=0, stdout="build extra\n", stderr=""),
            ]
            with mock.patch("scripts.verify_task_surface._run", side_effect=completed):
                with self.assertRaisesRegex(ValueError, "task names differ"):
                    verify(root)


if __name__ == "__main__":
    unittest.main()
