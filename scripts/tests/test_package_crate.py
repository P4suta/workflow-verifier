from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.package_crate import REQUIRED_FILES, inspect_crate

SUBJECT = "a" * 40
VERSION = "0.1.0"


def crate_fixture(path: Path, *, extra: dict[str, bytes] | None = None) -> None:
    root = f"workflow-verifier-{VERSION}"
    contents = {name: f"fixture:{name}\n".encode() for name in REQUIRED_FILES}
    contents[".cargo_vcs_info.json"] = json.dumps(
        {"git": {"dirty": False, "sha1": SUBJECT}, "path_in_vcs": ""}
    ).encode()
    contents["Cargo.toml"] = (
        b'[package]\nname = "workflow-verifier"\nversion = "0.1.0"\n'
        b'[[bin]]\nname = "workflow-verifier"\npath = "src/main.rs"\n'
        b"[dependencies]\n"
    )
    if extra:
        contents.update(extra)
    with tarfile.open(path, mode="w:gz") as archive:
        for name, payload in sorted(contents.items()):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.mode = 0o644
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


class PackageCrateTests(unittest.TestCase):
    def test_inventory_and_candidate_commit_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"workflow-verifier-{VERSION}.crate"
            crate_fixture(path)
            files = inspect_crate(path, version=VERSION, subject_commit=SUBJECT)
            self.assertEqual(set(files), REQUIRED_FILES)

    def test_private_helpers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"workflow-verifier-{VERSION}.crate"
            crate_fixture(path, extra={"helpers/linux/Cargo.toml": b"[package]\n"})
            with self.assertRaisesRegex(ValueError, "forbidden first-party content"):
                inspect_crate(path, version=VERSION, subject_commit=SUBJECT)

    def test_stale_candidate_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"workflow-verifier-{VERSION}.crate"
            crate_fixture(path)
            with self.assertRaisesRegex(ValueError, "candidate commit C"):
                inspect_crate(path, version=VERSION, subject_commit="b" * 40)

    def test_candidate_and_release_workflows_enforce_digest_reproduction(self) -> None:
        root = Path(__file__).resolve().parents[2]
        candidate = (root / ".github" / "workflows" / "candidate.yml").read_text(encoding="utf-8")
        release = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        smoke_fixture = (
            root
            / "test"
            / "fixtures"
            / "crate-install-smoke"
            / ".github"
            / "workflows"
            / "smoke.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("scripts/package_crate.py", candidate)
        self.assertIn("scripts/package_crate.py", release)
        self.assertIn("environment: crate-publication", release)
        self.assertIn("cargo publish --locked -p workflow-verifier", release)
        self.assertIn("needs.release_evidence.outputs.subject_commit", release)
        self.assertIn("needs.release_evidence.outputs.crate_digest", release)
        self.assertIn("version_url=", release)
        self.assertIn("workflow-verifier/$VERSION/download", release)
        self.assertIn(
            'cp -R test/fixtures/crate-install-smoke "$RUNNER_TEMP/crate-smoke"',
            release,
        )
        self.assertNotIn("$RUNNER_TEMP/crate-smoke/.github/workflows", release)
        self.assertIn("permissions: {}", smoke_fixture)


if __name__ == "__main__":
    unittest.main()
