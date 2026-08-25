import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_sbom import generate, generate_release


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

    def test_release_mode_emits_one_spdx_per_payload_and_aggregate_cyclonedx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / "workflow-verifier-linux.tar.gz"
            helper = root / "workflow-verifier-helper-linux.tar.gz"
            product.write_bytes(b"product")
            helper.write_bytes(b"helper")
            components = {
                "components": [
                    {
                        "applies_to": ["product"],
                        "id": "cmdliner",
                        "license": "ISC",
                        "name": "cmdliner",
                        "purl": "pkg:opam/cmdliner@2.1.1",
                        "relationship": "runtime",
                        "version": "2.1.1",
                    },
                    {
                        "applies_to": ["all"],
                        "id": "rust",
                        "license": "Apache-2.0 OR MIT",
                        "name": "Rust",
                        "purl": "pkg:generic/rust@1.98.0",
                        "relationship": "build",
                        "version": "1.98.0",
                    },
                ],
                "schema": "sbom-components-v1",
            }
            manifest = root / "components.json"
            manifest.write_text(
                json.dumps(components, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            output = root / "spdx"
            cyclonedx = root / "workflow-verifier.cdx.json"
            checksums = root / "SBOM-SHA256SUMS"

            generated = generate_release(
                [("product", product), ("helper", helper)],
                dependency_manifest=manifest,
                output_dir=output,
                cyclonedx=cyclonedx,
                checksums=checksums,
                version="0.1.0",
            )

            self.assertEqual(len(generated), 3)
            product_spdx = json.loads(
                (output / f"{product.name}.spdx.json").read_text(encoding="utf-8")
            )
            self.assertEqual(product_spdx["name"], product.name)
            self.assertEqual(product_spdx["spdxVersion"], "SPDX-2.3")
            self.assertTrue(
                any(
                    relation["relationshipType"] == "BUILD_DEPENDENCY_OF"
                    for relation in product_spdx["relationships"]
                )
            )
            aggregate = json.loads(cyclonedx.read_text(encoding="utf-8"))
            self.assertEqual(aggregate["bomFormat"], "CycloneDX")
            self.assertEqual(aggregate["specVersion"], "1.6")
            self.assertIn(product.name, checksums.read_text(encoding="utf-8"))
            self.assertNotIn(str(root), cyclonedx.read_text(encoding="utf-8"))

            components["components"][1]["version"] = "latest"
            manifest.write_text(
                json.dumps(components, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaisesRegex(ValueError, "must be exact"):
                generate_release(
                    [("product", product)],
                    dependency_manifest=manifest,
                    output_dir=output,
                    cyclonedx=cyclonedx,
                    checksums=checksums,
                    version="0.1.0",
                )


if __name__ == "__main__":
    unittest.main()
