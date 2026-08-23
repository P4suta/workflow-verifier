import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.generate_sbom import generate


class GenerateSbomTests(unittest.TestCase):
    def test_spdx_and_checksums_are_deterministic_complete_and_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alpha = root / "workflow-verifier-linux.tar.gz"
            beta = root / "workflow-verifier-windows.zip"
            alpha.write_bytes(b"linux")
            beta.write_bytes(b"windows")
            first_sbom = root / "first.spdx.json"
            first_sums = root / "first.SHA256SUMS"
            second_sbom = root / "second.spdx.json"
            second_sums = root / "second.SHA256SUMS"

            generate([beta, alpha], first_sbom, first_sums, "1.2.3")
            generate([alpha, beta], second_sbom, second_sums, "1.2.3")

            self.assertEqual(first_sbom.read_bytes(), second_sbom.read_bytes())
            self.assertEqual(first_sums.read_bytes(), second_sums.read_bytes())
            document = json.loads(first_sbom.read_text(encoding="utf-8"))
            self.assertEqual(document["documentDescribes"], ["SPDXRef-Package-workflow-verifier"])
            self.assertEqual(document["packages"][0]["versionInfo"], "1.2.3")
            self.assertEqual(len(document["files"]), 2)
            self.assertEqual(len(document["relationships"]), 3)
            self.assertNotIn(str(root), first_sbom.read_text(encoding="utf-8"))
            expected = "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in (alpha, beta)
            )
            self.assertEqual(first_sums.read_text(encoding="utf-8"), expected)

    def test_empty_duplicate_names_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "sbom.json"
            sums = root / "SHA256SUMS"
            with self.assertRaises(ValueError):
                generate([], output, sums, "1.0.0")
            left = root / "left" / "same.bin"
            right = root / "right" / "same.bin"
            left.parent.mkdir()
            right.parent.mkdir()
            left.write_bytes(b"left")
            right.write_bytes(b"right")
            with self.assertRaises(ValueError):
                generate([left, right], output, sums, "1.0.0")
            linked = root / "linked"
            try:
                linked.symlink_to(left)
            except OSError:
                return
            with self.assertRaises(ValueError):
                generate([linked], output, sums, "1.0.0")


if __name__ == "__main__":
    unittest.main()
