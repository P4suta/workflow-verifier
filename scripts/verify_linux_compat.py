#!/usr/bin/env python3
"""Enforce the Linux x86_64 glibc 2.28 floor and DT_NEEDED allowlist."""

from __future__ import annotations

import argparse
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

GLIBC = re.compile(r"\bGLIBC_(\d+)\.(\d+)\b")
NEEDED = re.compile(r"\(NEEDED\).*\[([^\]]+)\]")
DEFAULT_NEEDED = {
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libdl.so.2",
    "libgcc_s.so.1",
    "libm.so.6",
    "libpthread.so.0",
    "librt.so.1",
}


class CompatibilityResult(TypedDict):
    glibc_floor: str
    needed: list[str]
    path: str


def _run(readelf: str, arguments: list[str], path: Path) -> str:
    completed = subprocess.run(
        [readelf, *arguments, str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"readelf failed for {path}: {detail}")
    return completed.stdout.decode("utf-8", errors="strict")


def verify(
    path: Path, readelf: str = "readelf", allowed: set[str] | None = None
) -> CompatibilityResult:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"ELF input must be a nonempty regular non-symlink file: {path}")
    header = _run(readelf, ["--file-header"], path)
    if (
        "Class:" not in header
        or "ELF64" not in header
        or "Advanced Micro Devices X86-64" not in header
    ):
        raise ValueError(f"{path} is not an ELF64 x86_64 executable")
    versions = _run(readelf, ["--version-info"], path)
    required = {(int(major), int(minor)) for major, minor in GLIBC.findall(versions)}
    if not required:
        raise ValueError(f"{path} has no measurable GLIBC symbol floor")
    maximum = max(required)
    if maximum > (2, 28):
        raise ValueError(f"{path} requires GLIBC_{maximum[0]}.{maximum[1]}, above 2.28")
    if "GLIBCXX_" in versions or "CXXABI_" in versions:
        raise ValueError(f"{path} unexpectedly depends on a C++ runtime")
    dynamic = _run(readelf, ["--dynamic"], path)
    needed = set(NEEDED.findall(dynamic))
    allowed = DEFAULT_NEEDED if allowed is None else allowed
    unexpected = needed - allowed
    if unexpected:
        raise ValueError(f"{path} has unexpected DT_NEEDED entries: {sorted(unexpected)}")
    return {
        "glibc_floor": f"{maximum[0]}.{maximum[1]}",
        "needed": sorted(needed),
        "path": path.name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("executables", nargs="+", type=Path)
    arguments = parser.parse_args()
    try:
        results = [verify(path, arguments.readelf) for path in arguments.executables]
    except (OSError, UnicodeError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"linux compatibility: {error}", file=sys.stderr)
        return 2
    for result in results:
        print(
            f"linux compatibility: {result['path']} "
            f"GLIBC_{result['glibc_floor']} needed={','.join(result['needed'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
