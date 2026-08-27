from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_linux_compat import verify

HEADER = """  Class:                             ELF64
  Machine:                           Advanced Micro Devices X86-64
"""
ARM64_HEADER = """  Class:                             ELF64
  Machine:                           AArch64
"""


class LinuxCompatibilityTests(unittest.TestCase):
    def test_glibc_floor_and_needed_allowlist_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "workflow-verifier"
            binary.write_bytes(b"ELF fixture")
            with patch(
                "scripts.verify_linux_compat._run",
                side_effect=[
                    HEADER,
                    "Name: GLIBC_2.28\nName: GLIBC_2.17\n",
                    "(NEEDED) Shared library: [libc.so.6]\n",
                ],
            ):
                result = verify(binary)
            self.assertEqual(result["glibc_floor"], "2.28")
            self.assertEqual(result["needed"], ["libc.so.6"])
            self.assertEqual(result["architecture"], "x86_64")

    def test_aarch64_uses_the_same_floor_with_its_native_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "workflow-verifier"
            binary.write_bytes(b"ELF fixture")
            with patch(
                "scripts.verify_linux_compat._run",
                side_effect=[
                    ARM64_HEADER,
                    "Name: GLIBC_2.28\nName: GLIBC_2.17\n",
                    "(NEEDED) Shared library: [ld-linux-aarch64.so.1]\n"
                    "(NEEDED) Shared library: [libc.so.6]\n",
                ],
            ):
                result = verify(binary)
            self.assertEqual(result["architecture"], "aarch64")
            self.assertEqual(result["needed"], ["ld-linux-aarch64.so.1", "libc.so.6"])

    def test_new_glibc_cxx_or_unexpected_library_fail(self) -> None:
        cases = [
            ("Name: GLIBC_2.29\n", "(NEEDED) Shared library: [libc.so.6]\n", "above 2.28"),
            (
                "Name: GLIBC_2.28\nName: GLIBCXX_3.4\n",
                "(NEEDED) Shared library: [libc.so.6]\n",
                r"C\+\+",
            ),
            (
                "Name: GLIBC_2.28\n",
                "(NEEDED) Shared library: [libcrypto.so.3]\n",
                "unexpected DT_NEEDED",
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "workflow-verifier"
            binary.write_bytes(b"ELF fixture")
            for versions, dynamic, message in cases:
                with (
                    self.subTest(message=message),
                    patch(
                        "scripts.verify_linux_compat._run",
                        side_effect=[HEADER, versions, dynamic],
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        verify(binary)


if __name__ == "__main__":
    unittest.main()
