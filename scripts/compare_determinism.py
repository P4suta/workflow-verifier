#!/usr/bin/env python3
"""Byte-compare determinism probe artifacts from two or more platforms."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

if __package__:
    from .determinism_probe import ARTIFACTS, artifact_manifest
else:
    from determinism_probe import ARTIFACTS, artifact_manifest


PLATFORM = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _manifest(directory: Path) -> dict[str, Any]:
    path = directory / "determinism-v1.json"
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect determinism manifest {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"determinism manifest must be a nonempty regular file: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse determinism manifest {path}: {error}") from error
    expected = artifact_manifest(directory, list(ARTIFACTS))
    if document != expected:
        raise ValueError(f"determinism manifest does not match artifacts in {directory}")
    return expected


def compare(directories: list[Path]) -> dict[str, Any]:
    if len(directories) < 2:
        raise ValueError("at least two platform artifact directories are required")
    platforms: dict[str, Path] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for directory in directories:
        platform = directory.name
        if not PLATFORM.fullmatch(platform):
            raise ValueError(f"invalid platform directory name: {platform}")
        if platform in platforms:
            raise ValueError(f"duplicate platform directory: {platform}")
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"platform artifact path must be a directory: {directory}")
        platforms[platform] = directory
        manifests[platform] = _manifest(directory)
    ordered = sorted(platforms, key=lambda value: value.encode("utf-8"))
    baseline = ordered[0]
    failures: list[str] = []
    for name in ARTIFACTS:
        expected = (platforms[baseline] / name).read_bytes()
        for platform in ordered[1:]:
            if (platforms[platform] / name).read_bytes() != expected:
                failures.append(f"{name} differs between {baseline} and {platform}")
    common = manifests[baseline]["artifacts"]
    return {
        "artifacts": common if not failures else [],
        "failures": failures,
        "passed": not failures,
        "platforms": ordered,
        "schema": "determinism-comparison-v1",
    }


def _atomic_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("platforms", nargs="+", type=Path)
    arguments = parser.parse_args()
    try:
        result = compare(arguments.platforms)
        _atomic_json(arguments.output, result)
    except ValueError as error:
        print(f"determinism comparison: {error}", file=sys.stderr)
        return 2
    if not result["passed"]:
        for failure in result["failures"]:
            print(f"determinism comparison: {failure}", file=sys.stderr)
        return 1
    print(
        f"determinism comparison: {len(result['artifacts'])} artifacts are byte-identical "
        f"across {len(result['platforms'])} platforms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
