import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from scripts.package_release import build_package


class PackageReleaseTests(unittest.TestCase):
    def test_tarball_is_deterministic_rooted_and_permissioned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "workflow-verifier"
            readme = root / "README.md"
            binary.write_bytes(b"native-binary")
            readme.write_text("documentation\n", encoding="utf-8")
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            files = [("bin/workflow-verifier", binary), ("README.md", readme)]

            build_package("linux-x86_64", "1.2.3", files, first)
            build_package("linux-x86_64", "1.2.3", files, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                members = {member.name: member for member in archive.getmembers()}
                prefix = "workflow-verifier-1.2.3-linux-x86_64"
                self.assertEqual(
                    sorted(members),
                    [f"{prefix}/README.md", f"{prefix}/bin/workflow-verifier"],
                )
                self.assertEqual(members[f"{prefix}/bin/workflow-verifier"].mode, 0o755)
                self.assertEqual(members[f"{prefix}/README.md"].mode, 0o644)
                self.assertTrue(all(member.mtime == 0 for member in members.values()))

    def test_windows_zip_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "workflow-verifier.exe"
            binary.write_bytes(b"portable-executable")
            first = root / "first.zip"
            second = root / "second.zip"
            files = [("bin/workflow-verifier.exe", binary)]

            build_package("windows-x86_64", "1.2.3-rc.1", files, first)
            build_package("windows-x86_64", "1.2.3-rc.1", files, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(io.BytesIO(first.read_bytes())) as archive:
                self.assertEqual(
                    archive.namelist(),
                    ["workflow-verifier-1.2.3-rc.1-windows-x86_64/bin/workflow-verifier.exe"],
                )

    def test_paths_symlinks_duplicates_and_wrong_suffix_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            artifact.write_bytes(b"artifact")
            with self.assertRaises(ValueError):
                build_package("linux-x86_64", "1.0.0", [("../escape", artifact)], root / "a.tar.gz")
            with self.assertRaises(ValueError):
                build_package(
                    "linux-x86_64",
                    "1.0.0",
                    [("bin/tool", artifact), ("bin/tool", artifact)],
                    root / "b.tar.gz",
                )
            with self.assertRaises(ValueError):
                build_package("windows-x86_64", "1.0.0", [("bin/tool", artifact)], root / "c.tar.gz")
            linked = root / "linked"
            try:
                linked.symlink_to(artifact)
            except OSError:
                return
            with self.assertRaises(ValueError):
                build_package("linux-x86_64", "1.0.0", [("bin/tool", linked)], root / "d.tar.gz")


if __name__ == "__main__":
    unittest.main()
