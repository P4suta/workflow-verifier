#!/usr/bin/env python3
"""Generate locally repeatable check-report, lockfile, and fix artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ARTIFACTS = ("fix.diff", "report.json", "workflow-verifier.lock")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPORT_PROJECTION_EXCLUSIONS = (
    "analysis_digest",
    "digest",
    "tool",
)


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
        [
            executable,
            "check",
            "--trust-repository-config",
            "--persona",
            "audit",
            "--format",
            "json",
            fixture,
        ],
        [
            executable,
            "resolve",
            "--trust-repository-config",
            "--lockfile",
            lockfile,
            fixture,
        ],
        [
            executable,
            "fix",
            "--trust-repository-config",
            "--lockfile",
            lockfile,
            fixture,
        ],
    ]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_bytes(contents: bytes) -> str:
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def _domain_digest(domain: bytes, contents: bytes) -> str:
    digest = hashlib.sha256()
    for field in (domain, contents):
        digest.update(len(field).to_bytes(8, byteorder="big"))
        digest.update(field)
    return "sha256:" + digest.hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON number {value}")


def canonical_json(value: Any, *, trailing_newline: bool = True) -> bytes:
    suffix = "\n" if trailing_newline else ""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + suffix
    ).encode("utf-8")


def parse_json(contents: bytes, label: str) -> Any:
    try:
        return json.loads(
            contents.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {label}: {error}") from error


def report_semantic_bytes(contents: bytes) -> bytes:
    """Validate report provenance and return its platform-neutral projection."""

    document = parse_json(contents, "workflow-verifier-report/1 JSON")
    if not isinstance(document, dict) or document.get("schema") != "workflow-verifier-report/1":
        raise ValueError("determinism report must be a workflow-verifier-report/1 object")
    if contents != canonical_json(document):
        raise ValueError("determinism report must be canonical JSON")
    report_digest = document.get("digest")
    if not isinstance(report_digest, str) or not DIGEST.fullmatch(report_digest):
        raise ValueError("determinism report digest is invalid")
    authenticated = copy.deepcopy(document)
    authenticated.pop("digest")
    if (
        _domain_digest(
            b"workflow-verifier-report/1/document",
            canonical_json(authenticated, trailing_newline=False),
        )
        != report_digest
    ):
        raise ValueError("determinism report digest does not authenticate its body")
    semantic_digest = document.get("analysis_digest")
    if not isinstance(semantic_digest, str) or not DIGEST.fullmatch(semantic_digest):
        raise ValueError("determinism report analysis digest is invalid")
    tool = document.get("tool")
    if not isinstance(tool, dict) or set(tool) != {
        "commit",
        "compiler",
        "name",
        "target",
        "version",
    }:
        raise ValueError("determinism report tool fields are invalid")
    if not isinstance(tool["commit"], (str, type(None))) or not all(
        isinstance(tool[field], str) and tool[field]
        for field in ("compiler", "name", "target", "version")
    ):
        raise ValueError("determinism report tool provenance is invalid")

    projection = copy.deepcopy(document)
    projection.pop("digest")
    projection.pop("analysis_digest")
    projection.pop("tool")
    semantic_bytes = canonical_json(projection)
    if (
        _domain_digest(
            b"workflow-verifier-report/1/analysis",
            canonical_json(projection, trailing_newline=False),
        )
        != semantic_digest
    ):
        raise ValueError("determinism report analysis digest does not authenticate projection")
    return semantic_bytes


def artifact_manifest(root: Path, names: list[str]) -> dict[str, Any]:
    if set(names) != set(ARTIFACTS) or len(names) != len(ARTIFACTS):
        raise ValueError(
            "determinism manifest requires exactly report, lockfile, and fix artifacts"
        )
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
    report_semantic = report_semantic_bytes((root / "report.json").read_bytes())
    return {
        "artifacts": artifacts,
        "local_repetitions": 2,
        "report_semantic_digest": _sha256_bytes(report_semantic),
        "schema": "determinism-v2",
    }


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
            capture_output=True,
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
    labels = ("check determinism probe", "resolve determinism probe", "fix determinism probe")
    first = [
        _execute(command, root, label) for command, label in zip(commands, labels, strict=True)
    ]
    second = [
        _execute(command, root, f"{label} repetition")
        for command, label in zip(commands, labels, strict=True)
    ]
    for label, initial, repeated in zip(labels, first, second, strict=True):
        if initial != repeated:
            raise RuntimeError(f"{label} is not byte-repeatable on this platform")
    report, lockfile, fix = first
    try:
        report_json = parse_json(report, "workflow-verifier-report/1 JSON")
        report_semantic_bytes(report)
        lock_json = parse_json(lockfile, "lock-v2 JSON")
    except ValueError as error:
        raise RuntimeError(f"determinism probe emitted invalid canonical JSON: {error}") from error
    if report_json.get("schema") != "workflow-verifier-report/1":
        raise RuntimeError("check determinism probe did not emit workflow-verifier-report/1")
    if lock_json.get("schema") != "lock-v2":
        raise RuntimeError("resolve determinism probe did not emit lock-v2")
    expected_lock = (fixture_path / "workflow-verifier.lock").read_bytes()
    if lockfile != expected_lock:
        raise RuntimeError("offline resolve did not reproduce the canonical fixture lockfile")
    if not fix.startswith(b"--- ") or b"\r" in fix:
        raise RuntimeError("fix determinism probe did not emit a canonical LF-only unified diff")
    outputs = {
        "fix.diff": fix,
        "report.json": report,
        "workflow-verifier.lock": lockfile,
    }
    for name, contents in outputs.items():
        _atomic_bytes(output / name, contents)
    manifest = artifact_manifest(output, list(outputs))
    _atomic_bytes(
        output / "determinism-v2.json",
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
    print(
        f"determinism probe: {len(result['artifacts'])} canonical artifacts "
        "are locally byte-repeatable"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
