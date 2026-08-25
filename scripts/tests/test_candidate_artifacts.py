import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.candidate_artifacts import (
    aggregate_fragments,
    build_path_prefix_map,
    build_source_assets,
    package_install,
    repackage_windows,
    write_fragment,
)
from scripts.package_release import build_package

SUBJECT = "a" * 40


def write(path: Path, contents: bytes = b"fixture\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    return path


def artifact_pair(root: Path, name: str, contents: bytes) -> tuple[Path, Path]:
    first = write(root / "first" / name, contents)
    second = write(root / "second" / name, contents)
    return first, second


class CandidateArtifactsTests(unittest.TestCase):
    def test_ocaml_build_path_prefix_map_uses_the_specified_escape_alphabet(self) -> None:
        self.assertEqual(
            build_path_prefix_map(r"C:\source=one%two"),
            r".=C%.\source%+one%#two",
        )
        with self.assertRaises(ValueError):
            build_path_prefix_map("")

    def test_install_package_is_deterministic_complete_and_helper_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "_build" / "install" / "default"
            write(install / "bin" / "workflow-verifier.exe", b"analyzer")
            write(install / "doc" / "workflow-verifier" / "README.md", b"docs")
            write(install / "share" / "workflow-verifier" / "schema.json", b"{}\n")
            write(install / "man" / "man1" / "workflow-verifier.1", b"manual")
            windows = write(root / "target" / "workflow-verifier-windows-helper.exe", b"win")
            agent = write(root / "target" / "workflow-verifier-vm-agent.exe", b"agent")
            helpers = [
                ("bin/workflow-verifier-windows-helper.exe", windows),
                ("bin/workflow-verifier-vm-agent.exe", agent),
            ]
            first = root / "first.zip"
            first_helpers = root / "first-helpers.zip"
            second = root / "second.zip"
            second_helpers = root / "second-helpers.zip"

            package_install(
                install_root=install,
                workspace_root=root,
                platform="windows-x86_64",
                version="0.1.0",
                helpers=helpers,
                output=first,
                helpers_output=first_helpers,
            )
            package_install(
                install_root=install,
                workspace_root=root,
                platform="windows-x86_64",
                version="0.1.0",
                helpers=list(reversed(helpers)),
                output=second,
                helpers_output=second_helpers,
            )

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_helpers.read_bytes(), second_helpers.read_bytes())
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertTrue(any(name.endswith("/bin/workflow-verifier.exe") for name in names))
                self.assertTrue(
                    any(name.endswith("/doc/workflow-verifier/README.md") for name in names)
                )
                self.assertEqual(sum(name.endswith(".exe") for name in names), 3)
            with zipfile.ZipFile(first_helpers) as archive:
                self.assertEqual(len(archive.namelist()), 2)
                self.assertFalse(
                    any(name.endswith("/bin/workflow-verifier.exe") for name in archive.namelist())
                )

            with self.assertRaisesRegex(ValueError, "helper inventory"):
                package_install(
                    install_root=install,
                    workspace_root=root,
                    platform="windows-x86_64",
                    version="0.1.0",
                    helpers=helpers[:1],
                    output=root / "bad.zip",
                    helpers_output=root / "bad-helpers.zip",
                )

    def test_reproducibility_fragments_aggregate_only_with_exact_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fragments: list[Path] = []
            platforms = (
                "linux-x86_64",
                "windows-x86_64",
                "macos-arm64",
                "macos-x86_64",
            )
            for platform in platforms:
                product = artifact_pair(
                    root / platform, f"product-{platform}.bin", platform.encode()
                )
                helper = artifact_pair(root / platform, f"helper-{platform}.bin", b"helper")
                fragment = root / f"{platform}.json"
                write_fragment(
                    platform=platform,
                    subject_commit=SUBJECT,
                    source_date_epoch=123,
                    artifacts=[("product", *product), ("helper", *helper)],
                    output=fragment,
                )
                fragments.append(fragment)
            source = artifact_pair(root / "source", "source.tar.gz", b"source")
            corresponding = artifact_pair(root / "source", "corresponding-source.tar.gz", b"source")
            schemas = artifact_pair(root / "source", "schemas.tar.gz", b"schemas")
            source_fragment = root / "source.json"
            write_fragment(
                platform="source",
                subject_commit=SUBJECT,
                source_date_epoch=123,
                artifacts=[
                    ("source", *source),
                    ("corresponding-source", *corresponding),
                    ("schema-bundle", *schemas),
                ],
                output=source_fragment,
            )
            fragments.append(source_fragment)
            gate = root / "reproducible-build.json"

            aggregate_fragments(fragments=fragments, subject_commit=SUBJECT, output=gate)

            document = json.loads(gate.read_text(encoding="utf-8"))
            self.assertEqual(document["schema"], "release-gate-v1")
            self.assertEqual(document["gate"], "reproducible-build")
            self.assertEqual(document["status"], "pass")
            self.assertEqual(document["details"]["builds_per_artifact"], 2)
            self.assertEqual(len(document["details"]["artifacts"]), 11)
            self.assertEqual(
                gate.read_bytes(),
                json.dumps(
                    document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                ).encode()
                + b"\n",
            )

            with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                aggregate_fragments(
                    fragments=fragments[:-1],
                    subject_commit=SUBJECT,
                    output=root / "incomplete.json",
                )
            different = write(root / "different.bin", b"different")
            with self.assertRaisesRegex(ValueError, "clean builds differ"):
                write_fragment(
                    platform="linux-x86_64",
                    subject_commit=SUBJECT,
                    source_date_epoch=123,
                    artifacts=[("product", product[0], different), ("helper", *helper)],
                    output=root / "different.json",
                )

    def test_windows_repackage_replaces_exact_executables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsigned_files = [
                ("bin/workflow-verifier.exe", write(root / "input" / "analyzer.exe", b"a")),
                (
                    "bin/workflow-verifier-windows-helper.exe",
                    write(root / "input" / "windows.exe", b"w"),
                ),
                (
                    "bin/workflow-verifier-vm-agent.exe",
                    write(root / "input" / "agent.exe", b"v"),
                ),
                ("doc/workflow-verifier/README.md", write(root / "input" / "README.md", b"d")),
            ]
            unsigned = root / "windows-unsigned-payload.zip"
            build_package("windows-x86_64", "0.1.0", unsigned_files, unsigned)
            signed = root / "signed"
            write(signed / "workflow-verifier.exe", b"signed-a")
            write(signed / "workflow-verifier-windows-helper.exe", b"signed-w")
            write(signed / "workflow-verifier-vm-agent.exe", b"signed-v")
            output = root / "workflow-verifier-0.1.0-windows-x86_64.zip"
            helpers = root / "workflow-verifier-helpers-0.1.0-windows-x86_64.zip"

            repackage_windows(
                unsigned_archive=unsigned,
                signed_directory=signed,
                version="0.1.0",
                output=output,
                helpers_output=helpers,
            )

            with zipfile.ZipFile(output) as archive:
                executable = next(
                    name
                    for name in archive.namelist()
                    if name.endswith("/bin/workflow-verifier.exe")
                )
                self.assertEqual(archive.read(executable), b"signed-a")
                readme = next(name for name in archive.namelist() if name.endswith("/README.md"))
                self.assertEqual(archive.read(readme), b"d")
            with zipfile.ZipFile(helpers) as archive:
                self.assertEqual(len(archive.namelist()), 2)

            (signed / "workflow-verifier.exe").write_bytes(b"a")
            with self.assertRaisesRegex(ValueError, "did not transform"):
                repackage_windows(
                    unsigned_archive=unsigned,
                    signed_directory=signed,
                    version="0.1.0",
                    output=root / "unchanged.zip",
                    helpers_output=root / "unchanged-helpers.zip",
                )

    def test_source_assets_are_commit_bound_static_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            write(root / "README.md", b"source\n")
            write(root / "schema" / "one.schema.json", b"{}\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Release Test",
                    "-c",
                    "user.email=release@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            output = Path(temporary) / "output"
            fragment = Path(temporary) / "source-fragment.json"

            build_source_assets(
                repository=root,
                subject_commit=revision,
                version="0.1.0",
                output_dir=output,
                fragment=fragment,
            )

            source = output / "workflow-verifier-0.1.0-source.tar.gz"
            corresponding = output / "workflow-verifier-0.1.0-corresponding-source.tar.gz"
            schemas = output / "workflow-verifier-0.1.0-schemas.tar.gz"
            self.assertEqual(source.read_bytes(), corresponding.read_bytes())
            with tarfile.open(source, "r:gz") as archive:
                self.assertIn("workflow-verifier-0.1.0/README.md", archive.getnames())
            with tarfile.open(schemas, "r:gz") as archive:
                self.assertTrue(
                    any(name.endswith("/schema/one.schema.json") for name in archive.getnames())
                )
            record = json.loads(fragment.read_text(encoding="utf-8"))
            self.assertEqual(record["subject_commit"], revision)
            self.assertEqual(
                {artifact["role"] for artifact in record["artifacts"]},
                {"source", "corresponding-source", "schema-bundle"},
            )


if __name__ == "__main__":
    unittest.main()
