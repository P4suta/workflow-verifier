#!/usr/bin/env python3
"""Compare portable bytes and report semantics from two or more platforms."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

if __package__:
    from .determinism_probe import (
        ARTIFACTS,
        REPORT_PROJECTION_EXCLUSIONS,
        artifact_manifest,
        parse_json,
        report_semantic_bytes,
    )
else:
    from determinism_probe import (
        ARTIFACTS,
        REPORT_PROJECTION_EXCLUSIONS,
        artifact_manifest,
        parse_json,
        report_semantic_bytes,
    )


PLATFORM = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PORTABLE_ARTIFACTS = ("fix.diff", "workflow-verifier.lock")
RELEASE_PLATFORMS = {
    "linux-arm64",
    "linux-x86_64",
    "macos-arm64",
    "macos-x86_64",
    "windows-x86_64",
}
# GitHub Actions downloads each named artifact into a directory with this
# documented upload name, while local probes use the bare platform name.
GITHUB_ARTIFACT_PREFIX = "determinism-"


def _platform_name(directory: Path) -> str:
    name = directory.name
    if name in RELEASE_PLATFORMS:
        return name
    if name.startswith(GITHUB_ARTIFACT_PREFIX):
        projected = name.removeprefix(GITHUB_ARTIFACT_PREFIX)
        if projected in RELEASE_PLATFORMS:
            return projected
    return name


def _manifest(directory: Path) -> dict[str, Any]:
    path = directory / "determinism-v2.json"
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect determinism manifest {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"determinism manifest must be a nonempty regular file: {path}")
    try:
        document = parse_json(path.read_bytes(), "determinism-v2 JSON")
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot parse determinism manifest {path}: {error}") from error
    expected = artifact_manifest(directory, list(ARTIFACTS))
    if document != expected:
        raise ValueError(f"determinism manifest does not match artifacts in {directory}")
    return expected


def compare(directories: list[Path]) -> dict[str, Any]:
    if len(directories) != len(RELEASE_PLATFORMS):
        raise ValueError("exactly five platform artifact directories are required")
    platforms: dict[str, Path] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for directory in directories:
        platform = _platform_name(directory)
        if not PLATFORM.fullmatch(platform):
            raise ValueError(f"invalid platform directory name: {platform}")
        if platform in platforms:
            raise ValueError(f"duplicate platform directory: {platform}")
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"platform artifact path must be a directory: {directory}")
        platforms[platform] = directory
        manifests[platform] = _manifest(directory)
    if set(platforms) != RELEASE_PLATFORMS:
        raise ValueError(
            "determinism platform coverage mismatch; "
            f"missing={sorted(RELEASE_PLATFORMS - set(platforms))}, "
            f"unknown={sorted(set(platforms) - RELEASE_PLATFORMS)}"
        )
    ordered = sorted(platforms, key=lambda value: value.encode("utf-8"))
    baseline = ordered[0]
    failures: list[str] = []
    for name in PORTABLE_ARTIFACTS:
        expected = (platforms[baseline] / name).read_bytes()
        for platform in ordered[1:]:
            if (platforms[platform] / name).read_bytes() != expected:
                failures.append(f"{name} differs between {baseline} and {platform}")
    report_semantics = {
        platform: report_semantic_bytes((directory / "report-v3.json").read_bytes())
        for platform, directory in platforms.items()
    }
    for platform in ordered[1:]:
        if report_semantics[platform] != report_semantics[baseline]:
            failures.append(f"report-v3 semantic content differs between {baseline} and {platform}")
    common = [
        artifact
        for artifact in manifests[baseline]["artifacts"]
        if artifact["name"] in PORTABLE_ARTIFACTS
    ]
    reports = []
    for platform in ordered:
        raw = next(
            artifact
            for artifact in manifests[platform]["artifacts"]
            if artifact["name"] == "report-v3.json"
        )
        reports.append(
            {
                "platform": platform,
                "raw_digest": raw["digest"],
                "raw_size": raw["size"],
                "semantic_digest": manifests[platform]["report_semantic_digest"],
                "semantic_size": len(report_semantics[platform]),
            }
        )
    return {
        "artifacts": common if not failures else [],
        "failures": failures,
        "passed": not failures,
        "platforms": ordered,
        "report_projection": {
            "excluded_fields": list(REPORT_PROJECTION_EXCLUSIONS),
            "reports": reports,
        },
        "schema": "determinism-comparison-v2",
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
        f"determinism comparison: {len(result['artifacts'])} portable artifacts are "
        f"byte-identical and report semantics match across {len(result['platforms'])} platforms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
