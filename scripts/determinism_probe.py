#!/usr/bin/env python3
"""Generate byte-comparable report, lockfile, and fix artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


ARTIFACTS = ("fix.diff", "report-v1.json", "workflow-verifier.lock")


def _safe_relative(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
        or re.match(r"^[A-Za-z]:", value)
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return path.as_posix()


def build_commands(analyzer: Path, fixture: str) -> list[list[str]]:
    fixture = _safe_relative(fixture, "fixture")
    executable = analyzer.as_posix()
    lockfile = f"{fixture}/workflow-verifier.lock"
    return [
        [executable, "check", "--persona", "audit", "--format", "json", fixture],
        [executable, "resolve", "--lockfile", lockfile, fixture],
        [executable, "fix", "--lockfile", lockfile, fixture],
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def artifact_manifest(root: Path, names: list[str]) -> dict[str, Any]:
    if set(names) != set(ARTIFACTS) or len(names) != len(ARTIFACTS):
        raise ValueError("determinism manifest requires exactly report, lockfile, and fix artifacts")
    artifacts: list[dict[str, Any]] = []
    for name in sorted(names, key=lambda value: value.encode("utf-8")):
        if name != PurePosixPath(name).name or "\\" in name:
            raise ValueError(f"unsafe determinism artifact name: {name}")
        path = root / name
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError(f"cannot inspect determinism artifact {path}: {error}") from error
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
            raise ValueError(f"determinism artifact must be a nonempty regular file: {path}")
        artifacts.append({"digest": _sha256(path), "name": name, "size": metadata.st_size})
    return {"artifacts": artifacts, "schema": "determinism-v1"}


def _atomic_bytes(path: Path, contents: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _execute(command: list[str], root: Path, label: str) -> bytes:
    environment = dict(os.environ)
    environment.update({"LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{label} exceeded 180 seconds") from error
    except OSError as error:
        raise RuntimeError(f"cannot execute {label}: {error}") from error
    if len(completed.stdout) > 64 * 1024 * 1024 or len(completed.stderr) > 4 * 1024 * 1024:
        raise RuntimeError(f"{label} exceeded the output bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"{label} returned exit {completed.returncode}: {detail}")
    return completed.stdout


def probe(analyzer: Path, fixture: str, output: Path, root: Path) -> dict[str, Any]:
    root = root.resolve()
    fixture_argument = _safe_relative(fixture, "fixture")
    fixture_path = root.joinpath(*PurePosixPath(fixture_argument).parts)
    try:
        fixture_path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError("fixture escapes or does not exist under the workspace") from error
    if not fixture_path.is_dir() or fixture_path.is_symlink():
        raise ValueError("fixture must be a directory, not a symlink")
    executable = analyzer if analyzer.is_absolute() else root / analyzer
    if not executable.is_file():
        raise ValueError(f"analyzer executable does not exist: {executable}")
    commands = build_commands(executable.resolve(), fixture_argument)
    report = _execute(commands[0], root, "check determinism probe")
    lockfile = _execute(commands[1], root, "resolve determinism probe")
    fix = _execute(commands[2], root, "fix determinism probe")
    try:
        report_json = json.loads(report.decode("utf-8"))
        lock_json = json.loads(lockfile.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"determinism probe emitted invalid UTF-8 JSON: {error}") from error
    if report_json.get("schema") != "report-v1":
        raise RuntimeError("check determinism probe did not emit report-v1")
    if lock_json.get("schema") != "lock-v2":
        raise RuntimeError("resolve determinism probe did not emit lock-v2")
    expected_lock = (fixture_path / "workflow-verifier.lock").read_bytes()
    if lockfile != expected_lock:
        raise RuntimeError("offline resolve did not reproduce the canonical fixture lockfile")
    if not fix.startswith(b"--- ") or b"\r" in fix:
        raise RuntimeError("fix determinism probe did not emit a canonical LF-only unified diff")
    outputs = {
        "fix.diff": fix,
        "report-v1.json": report,
        "workflow-verifier.lock": lockfile,
    }
    for name, contents in outputs.items():
        _atomic_bytes(output / name, contents)
    manifest = artifact_manifest(output, list(outputs))
    _atomic_bytes(
        output / "determinism-v1.json",
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workspace", type=Path, default=Path("."))
    arguments = parser.parse_args()
    try:
        result = probe(
            arguments.analyzer,
            arguments.fixture,
            arguments.output,
            arguments.workspace,
        )
    except (ValueError, RuntimeError, OSError) as error:
        print(f"determinism probe: {error}", file=sys.stderr)
        return 2
    print(f"determinism probe: {len(result['artifacts'])} canonical artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
