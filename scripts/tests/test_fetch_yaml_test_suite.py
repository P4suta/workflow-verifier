from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from scripts.fetch_yaml_test_suite import (
    PIN_PATH,
    TreeEntry,
    build_export,
    canonical_case_entries,
    load_pin,
    validate_checkout_identity,
    validate_export,
)

COMMIT = "6e6c296ae9c9d2d5c4134b4b64d01b29ac19ff6f"


def entry(path: str, *, mode: str = "100644", object_id: str = "a" * 40):
    return TreeEntry(mode=mode, kind="blob", object_id=object_id, path=PurePosixPath(path))


class YamlSuiteExportTests(unittest.TestCase):
    def test_repository_pin_is_the_single_typed_export_authority(self) -> None:
        pin = load_pin(PIN_PATH)
        self.assertEqual(pin.release, "data-2022-01-17")
        self.assertEqual(pin.commit, COMMIT)
        self.assertEqual(pin.cases, 402)
        self.assertEqual(pin.export_schema, 1)
        self.assertEqual(pin.export_files, 1887)
        self.assertEqual(
            pin.export_tree_sha256,
            "7d4d407d90a557f337770260d31f7e518551921e73aa56681b4516d947587158",
        )

    def test_checkout_identity_binds_annotated_tag_object_and_commit(self) -> None:
        pin = load_pin(PIN_PATH)
        validate_checkout_identity(
            pin,
            tag_object="5f49729577242103ae23838ac2ad4d9145aec126",
            commit=COMMIT,
        )
        with self.assertRaisesRegex(RuntimeError, "tag object mismatch"):
            validate_checkout_identity(pin, tag_object="0" * 40, commit=COMMIT)
        with self.assertRaisesRegex(RuntimeError, "commit mismatch"):
            validate_checkout_identity(
                pin,
                tag_object="5f49729577242103ae23838ac2ad4d9145aec126",
                commit="0" * 40,
            )

    def fixture(self) -> tuple[list[TreeEntry], dict[PurePosixPath, bytes]]:
        entries = [
            entry("A001/in.yaml", object_id="1" * 40),
            entry("A001/test.event", object_id="2" * 40),
            entry("B002/00/error", object_id="3" * 40),
            entry("B002/00/in.yaml", object_id="4" * 40),
            entry("name/alias-to-a001", mode="120000", object_id="5" * 40),
            entry("tags/mapping-alias", mode="120000", object_id="6" * 40),
            entry("README.md", object_id="7" * 40),
        ]
        blobs = {
            PurePosixPath("A001/in.yaml"): b"key: value\n",
            PurePosixPath("A001/test.event"): b"+STR\n+DOC\n-DOC\n-STR\n",
            PurePosixPath("B002/00/error"): b"",
            PurePosixPath("B002/00/in.yaml"): b"bad: [\n",
        }
        return entries, blobs

    def test_symlink_aliases_and_non_case_files_are_excluded(self) -> None:
        entries, _ = self.fixture()
        selected = canonical_case_entries(entries, expected_cases=2)
        self.assertEqual(
            [item.path.as_posix() for item in selected],
            [
                "A001/in.yaml",
                "A001/test.event",
                "B002/00/error",
                "B002/00/in.yaml",
            ],
        )

    def test_export_is_deterministic_and_self_validating(self) -> None:
        entries, blobs = self.fixture()
        selected = canonical_case_entries(entries, expected_cases=2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first_manifest = build_export(
                first,
                commit=COMMIT,
                entries=selected,
                blobs=blobs,
                expected_cases=2,
            )
            second_manifest = build_export(
                second,
                commit=COMMIT,
                entries=selected,
                blobs=blobs,
                expected_cases=2,
            )
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(
                (first / ".workflow-verifier-yaml-suite-v1.json").read_bytes(),
                (second / ".workflow-verifier-yaml-suite-v1.json").read_bytes(),
            )
            self.assertEqual(
                validate_export(first, commit=COMMIT, expected_cases=2), first_manifest
            )
            self.assertEqual(
                sorted(
                    path.parent.relative_to(first).as_posix() for path in first.rglob("in.yaml")
                ),
                ["A001", "B002/00"],
            )
            self.assertFalse((first / "name").exists())
            self.assertFalse((first / "tags").exists())

    def test_existing_or_tampered_exports_fail_closed(self) -> None:
        entries, blobs = self.fixture()
        selected = canonical_case_entries(entries, expected_cases=2)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "suite"
            manifest = build_export(
                destination,
                commit=COMMIT,
                entries=selected,
                blobs=blobs,
                expected_cases=2,
            )
            self.assertEqual(
                build_export(
                    destination,
                    commit=COMMIT,
                    entries=selected,
                    blobs=blobs,
                    expected_cases=2,
                ),
                manifest,
            )
            (destination / "A001" / "in.yaml").write_bytes(b"bad: value\n")
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                validate_export(destination, commit=COMMIT, expected_cases=2)
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                build_export(
                    destination,
                    commit=COMMIT,
                    entries=selected,
                    blobs=blobs,
                    expected_cases=2,
                )

    def test_manifest_and_filesystem_extras_are_rejected(self) -> None:
        entries, blobs = self.fixture()
        selected = canonical_case_entries(entries, expected_cases=2)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "suite"
            build_export(
                destination,
                commit=COMMIT,
                entries=selected,
                blobs=blobs,
                expected_cases=2,
            )
            (destination / "unexpected.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected export entry"):
                validate_export(destination, commit=COMMIT, expected_cases=2)
            (destination / "unexpected.txt").unlink()
            manifest_path = destination / ".workflow-verifier-yaml-suite-v1.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["unexpected"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "manifest fields"):
                validate_export(destination, commit=COMMIT, expected_cases=2)

    def test_export_must_match_independently_pinned_file_and_tree_evidence(self) -> None:
        entries, blobs = self.fixture()
        selected = canonical_case_entries(entries, expected_cases=2)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "suite"
            with self.assertRaisesRegex(RuntimeError, "file count mismatch"):
                build_export(
                    destination,
                    commit=COMMIT,
                    entries=selected,
                    blobs=blobs,
                    expected_cases=2,
                    expected_files=5,
                )
            with self.assertRaisesRegex(RuntimeError, "pinned tree digest mismatch"):
                build_export(
                    destination,
                    commit=COMMIT,
                    entries=selected,
                    blobs=blobs,
                    expected_cases=2,
                    expected_files=4,
                    expected_tree_sha256="0" * 64,
                )


if __name__ == "__main__":
    unittest.main()
