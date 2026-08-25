from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from scripts.materialize_release_input import materialize
from scripts.package_release import build_package


class MaterializeReleaseInputTests(unittest.TestCase):
    def test_regular_input_becomes_a_new_packageable_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "built-tool"
            source.write_bytes(b"native-binary")
            destination = root / "release" / "workflow-verifier"

            self.assertEqual(materialize(source, destination), destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertFalse(destination.is_symlink())
            self.assertTrue(stat.S_ISREG(destination.lstat().st_mode))
            build_package(
                "linux-x86_64",
                "1.0.0",
                [("bin/workflow-verifier", destination)],
                root / "release.tar.gz",
            )

    def test_symlink_input_is_dereferenced_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "main.exe"
            target.write_bytes(b"native-binary")
            source = root / "workflow-verifier"
            try:
                source.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            destination = root / "release" / "workflow-verifier"

            with self.assertRaisesRegex(ValueError, "non-symlink"):
                build_package(
                    "linux-x86_64",
                    "1.0.0",
                    [("bin/workflow-verifier", source)],
                    root / "direct.tar.gz",
                )
            materialize(source, destination)
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_bytes(), target.read_bytes())
            build_package(
                "linux-x86_64",
                "1.0.0",
                [("bin/workflow-verifier", destination)],
                root / "materialized.tar.gz",
            )

    def test_empty_non_file_and_existing_destinations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.touch()
            with self.assertRaisesRegex(ValueError, "nonempty regular file"):
                materialize(empty, root / "empty-output")
            with self.assertRaisesRegex(ValueError, "regular file or symlink"):
                materialize(root, root / "directory-output")

            source = root / "source"
            source.write_bytes(b"artifact")
            destination = root / "destination"
            destination.write_bytes(b"do-not-replace")
            with self.assertRaisesRegex(ValueError, "already exists"):
                materialize(source, destination)
            self.assertEqual(destination.read_bytes(), b"do-not-replace")


if __name__ == "__main__":
    unittest.main()
