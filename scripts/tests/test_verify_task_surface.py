from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.verify_task_surface import PINNED_JUST, REVISION_FIXTURE, verify


class TaskSurfaceTests(unittest.TestCase):
    def test_real_parser_contract_and_aligned_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mise.toml").write_text(
                '[tasks.build]\nrun = "true"\n[tasks.performance-measure]\nrun = "true"\n',
                encoding="utf-8",
            )
            completed = [
                mock.Mock(returncode=0, stdout=f"just {PINNED_JUST}\n", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="build performance-measure\n",
                    stderr="",
                ),
                mock.Mock(
                    returncode=0,
                    stdout=f"python measure.py --revision {REVISION_FIXTURE}\n",
                    stderr="",
                ),
            ]
            with mock.patch("scripts.verify_task_surface._run", side_effect=completed):
                self.assertEqual(verify(root), ["build", "performance-measure"])

    def test_version_and_name_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "mise.toml").write_text(
                '[tasks.build]\nrun = "true"\n', encoding="utf-8"
            )
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
