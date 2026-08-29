#!/usr/bin/env python3
"""Build the public crate twice and emit commit-bound digest evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

CRATE = "workflow-verifier"
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
FORBIDDEN_PREFIXES = (
    ".github/",
    "corpus/",
    "crates/",
    "evaluation/",
    "helpers/",
    "release-evidence/",
)
REQUIRED_FILES = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "build.rs",
    "CHANGELOG.md",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "src/lib.rs",
    "src/main.rs",
}


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return "sha256:" + result.hexdigest()


def _run(arguments: list[str], *, cwd: Path) -> bytes:
    try:
        completed = subprocess.run(arguments, cwd=cwd, capture_output=True, check=False)
    except OSError as error:
        raise ValueError(f"cannot execute {arguments[0]}: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{' '.join(arguments)} failed: {stderr}")
    return completed.stdout


def _git(repository: Path, *arguments: str) -> str:
    return (
        _run(
            ["git", "-c", f"safe.directory={repository.resolve()}", *arguments],
            cwd=repository,
        )
        .decode("ascii", errors="strict")
        .strip()
    )


def _member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    member = archive.getmember(name)
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"crate member {name} is not a regular file")
    return stream.read()


def inspect_crate(
    path: Path,
    *,
    version: str,
    subject_commit: str,
    require_clean: bool = True,
) -> list[str]:
    """Validate crate inventory, package identity, and Cargo VCS provenance."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect crate: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError("crate must be a nonempty regular non-symlink file")
    expected_root = f"{CRATE}-{version}"
    files: list[str] = []
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError("crate archive is empty")
        for member in members:
            logical = PurePosixPath(member.name)
            if logical.is_absolute() or any(part in {"", ".", ".."} for part in logical.parts):
                raise ValueError(f"crate contains unsafe path {member.name}")
            if not logical.parts or logical.parts[0] != expected_root:
                raise ValueError(f"crate entry is outside {expected_root}")
            if member.isdir():
                continue
            if not member.isfile() or member.size <= 0:
                raise ValueError(
                    f"crate contains a link, special file, or empty file: {member.name}"
                )
            relative = PurePosixPath(*logical.parts[1:]).as_posix()
            if any(
                relative == prefix[:-1] or relative.startswith(prefix)
                for prefix in FORBIDDEN_PREFIXES
            ):
                raise ValueError(f"crate contains forbidden first-party content: {relative}")
            files.append(relative)
        if len(files) != len(set(files)):
            raise ValueError("crate contains duplicate files")
        missing = REQUIRED_FILES - set(files)
        if missing:
            raise ValueError(f"crate is missing required files: {sorted(missing)}")

        vcs_path = f"{expected_root}/.cargo_vcs_info.json"
        try:
            vcs = json.loads(_member_bytes(archive, vcs_path))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"crate VCS metadata is invalid: {error}") from error
        git = vcs.get("git") if isinstance(vcs, dict) else None
        if not isinstance(git, dict) or git.get("sha1") != subject_commit:
            raise ValueError("crate VCS metadata is not bound to candidate commit C")
        if require_clean and git.get("dirty") not in {None, False}:
            raise ValueError("candidate crate was built from a dirty tracked tree")

        manifest_path = f"{expected_root}/Cargo.toml"
        try:
            manifest = tomllib.loads(_member_bytes(archive, manifest_path).decode("utf-8"))
        except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f"packaged Cargo.toml is invalid: {error}") from error
        package = manifest.get("package", {})
        if (
            not isinstance(package, dict)
            or package.get("name") != CRATE
            or package.get("version") != version
        ):
            raise ValueError("packaged Cargo identity does not match the release")
        binaries = manifest.get("bin", [])
        if (
            not isinstance(binaries, list)
            or len(binaries) != 1
            or not isinstance(binaries[0], dict)
            or binaries[0].get("name") != CRATE
        ):
            raise ValueError("crate must install exactly the workflow-verifier binary")
        dependencies = manifest.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ValueError("packaged dependencies must be a table")
        for name, dependency in dependencies.items():
            if isinstance(dependency, dict) and "path" in dependency:
                raise ValueError(f"public crate retains path dependency {name}")
    return sorted(files, key=lambda item: item.encode("utf-8"))


def package_twice(
    *,
    repository: Path,
    subject_commit: str,
    version: str,
    output: Path,
    evidence: Path,
    allow_dirty: bool = False,
    offline: bool = False,
) -> dict[str, Any]:
    if not REVISION.fullmatch(subject_commit):
        raise ValueError("subject commit must be exact lowercase 40-hex")
    if not VERSION.fullmatch(version):
        raise ValueError("version must be an exact release SemVer")
    repository = repository.resolve(strict=True)
    if _git(repository, "rev-parse", "HEAD") != subject_commit:
        raise ValueError("checked-out repository is not candidate commit C")
    if not allow_dirty and _git(repository, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("candidate tracked tree is dirty")

    expected_name = f"{CRATE}-{version}.crate"
    with tempfile.TemporaryDirectory(prefix="workflow-verifier-crate-") as temporary:
        temporary_root = Path(temporary)
        built: list[Path] = []
        inventories: list[list[str]] = []
        for repetition in ("first", "second"):
            target = temporary_root / repetition
            arguments = [
                "cargo",
                "package",
                "--locked",
                "--package",
                CRATE,
                "--target-dir",
                str(target),
            ]
            if allow_dirty:
                arguments.append("--allow-dirty")
            if offline:
                arguments.append("--offline")
            _run(arguments, cwd=repository)
            crate = target / "package" / expected_name
            inventories.append(
                inspect_crate(
                    crate,
                    version=version,
                    subject_commit=subject_commit,
                    require_clean=not allow_dirty,
                )
            )
            built.append(crate)
        first = built[0].read_bytes()
        second = built[1].read_bytes()
        if first != second:
            raise ValueError("two candidate crate packages are not byte-identical")
        if inventories[0] != inventories[1]:
            raise ValueError("two candidate crate inventories differ")

        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        temporary_output = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(first)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_output, output)
        except BaseException:
            temporary_output.unlink(missing_ok=True)
            raise

    result: dict[str, Any] = {
        "artifact": {
            "digest": _digest(output),
            "name": expected_name,
            "role": "crate-package",
            "size": output.stat().st_size,
        },
        "file_count": len(inventories[0]),
        "schema": "crate-package-v1",
        "subject_commit": subject_commit,
        "version": version,
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(_canonical(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--subject-commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--offline", action="store_true")
    arguments = parser.parse_args()
    try:
        result = package_twice(
            repository=arguments.repository,
            subject_commit=arguments.subject_commit,
            version=arguments.version,
            output=arguments.output,
            evidence=arguments.evidence,
            allow_dirty=arguments.allow_dirty,
            offline=arguments.offline,
        )
    except (OSError, ValueError) as error:
        print(f"crate package gate: {error}", file=sys.stderr)
        return 1
    print(result["artifact"]["digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
