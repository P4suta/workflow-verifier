#!/usr/bin/env python3
"""Fetch and canonically export the immutable, MIT yaml-test-suite release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "test" / "upstream" / "yaml-test-suite.toml"
MANIFEST_NAME = ".workflow-verifier-yaml-suite-v1.json"
DOCUMENT_TYPE = "workflow-verifier.yaml-test-suite-export-v1"
REGULAR_MODES = frozenset({"100644", "100755"})
CASE_ID = re.compile(r"[0-9A-Z]{4}\Z")
HEX_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class YamlSuitePin:
    repository: str
    release: str
    tag_object: str
    commit: str
    cases: int
    license: str
    export_schema: int
    export_files: int
    export_tree_sha256: str


def load_pin(path: Path) -> YamlSuitePin:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"cannot decode yaml-test-suite pin: {error}") from error
    expected_fields = {
        "schema",
        "repository",
        "release",
        "tag_object",
        "commit",
        "cases",
        "license",
        "export_schema",
        "export_files",
        "export_tree_sha256",
    }
    if set(raw) != expected_fields:
        raise RuntimeError("yaml-test-suite pin fields are not exact")

    def positive_integer(field: str) -> int:
        value = raw[field]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise RuntimeError(f"yaml-test-suite pin {field} is not a positive integer")
        return value

    schema = positive_integer("schema")
    export_schema = positive_integer("export_schema")
    repository = raw["repository"]
    release = raw["release"]
    tag_object = raw["tag_object"]
    commit = raw["commit"]
    license_name = raw["license"]
    export_tree_sha256 = raw["export_tree_sha256"]
    if schema != 1 or export_schema != 1:
        raise RuntimeError("yaml-test-suite pin schema is unsupported")
    if (
        not isinstance(repository, str)
        or not repository.startswith("https://github.com/")
        or not repository.endswith(".git")
        or not isinstance(release, str)
        or not release
        or not isinstance(tag_object, str)
        or re.fullmatch(r"[0-9a-f]{40}", tag_object) is None
        or not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or license_name != "MIT"
        or not isinstance(export_tree_sha256, str)
        or HEX_SHA256.fullmatch(export_tree_sha256) is None
    ):
        raise RuntimeError("yaml-test-suite pin contains invalid immutable evidence")
    return YamlSuitePin(
        repository=repository,
        release=release,
        tag_object=tag_object,
        commit=commit,
        cases=positive_integer("cases"),
        license=license_name,
        export_schema=export_schema,
        export_files=positive_integer("export_files"),
        export_tree_sha256=export_tree_sha256,
    )


PIN = load_pin(PIN_PATH)
REPOSITORY = PIN.repository
RELEASE = PIN.release
COMMIT = PIN.commit
EXPECTED_CASES = PIN.cases
DEFAULT_DESTINATION = ROOT / "_build" / "upstream" / f"yaml-test-suite-{RELEASE}"
DEFAULT_EXPORT_DESTINATION = ROOT / "_build" / "upstream" / f"yaml-test-suite-canonical-{RELEASE}"


@dataclass(frozen=True, order=True)
class TreeEntry:
    path: PurePosixPath
    mode: str
    kind: str
    object_id: str


def git(*arguments: str, cwd: Path | None = None) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def git_bytes(*arguments: str, cwd: Path, input_bytes: bytes | None = None) -> bytes:
    process = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        input=input_bytes,
        capture_output=True,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def safe_path(raw: str) -> PurePosixPath:
    if "\\" in raw:
        raise RuntimeError(f"non-canonical upstream path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeError(f"unsafe upstream path: {raw!r}")
    if path.as_posix() != raw:
        raise RuntimeError(f"non-canonical upstream path: {raw!r}")
    return path


def tree_entries(checkout: Path) -> tuple[TreeEntry, ...]:
    raw = git_bytes("ls-tree", "-r", "-z", "--full-tree", "HEAD", cwd=checkout)
    entries: list[TreeEntry] = []
    seen: set[PurePosixPath] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split(" ", 2)
            path = safe_path(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise RuntimeError("malformed git tree record") from error
        if path in seen:
            raise RuntimeError(f"duplicate upstream tree path: {path.as_posix()}")
        seen.add(path)
        entries.append(TreeEntry(path=path, mode=mode, kind=kind, object_id=object_id))
    return tuple(sorted(entries))


def canonical_case_entries(
    entries: Iterable[TreeEntry], *, expected_cases: int = EXPECTED_CASES
) -> tuple[TreeEntry, ...]:
    ordered = tuple(sorted(entries))
    case_directories = {
        entry.path.parent
        for entry in ordered
        if entry.mode in REGULAR_MODES
        and entry.kind == "blob"
        and len(entry.path.parts) >= 2
        and entry.path.name == "in.yaml"
        and CASE_ID.fullmatch(entry.path.parts[0]) is not None
    }
    if len(case_directories) != expected_cases:
        raise RuntimeError(
            f"suite case count mismatch: expected {expected_cases}, found {len(case_directories)}"
        )
    selected: list[TreeEntry] = []
    for entry in ordered:
        if entry.path.parent not in case_directories:
            continue
        if entry.mode not in REGULAR_MODES or entry.kind != "blob":
            raise RuntimeError(f"non-regular entry inside case {entry.path.as_posix()}")
        selected.append(entry)
    selected_cases = {entry.path.parent for entry in selected if entry.path.name == "in.yaml"}
    if selected_cases != case_directories:
        raise RuntimeError("canonical case selection lost an in.yaml input")
    return tuple(selected)


def read_blobs(checkout: Path, entries: Iterable[TreeEntry]) -> dict[PurePosixPath, bytes]:
    ordered = tuple(entries)
    request = b"".join(entry.object_id.encode("ascii") + b"\n" for entry in ordered)
    response = git_bytes("cat-file", "--batch", cwd=checkout, input_bytes=request)
    cursor = 0
    blobs: dict[PurePosixPath, bytes] = {}
    for entry in ordered:
        newline = response.find(b"\n", cursor)
        if newline < 0:
            raise RuntimeError("git cat-file omitted a blob header")
        try:
            object_id, kind, raw_size = response[cursor:newline].decode("ascii").split()
            size = int(raw_size)
        except (UnicodeError, ValueError) as error:
            raise RuntimeError("malformed git cat-file header") from error
        cursor = newline + 1
        stop = cursor + size
        if (
            object_id != entry.object_id
            or kind != "blob"
            or size < 0
            or stop >= len(response)
            or response[stop] != 0x0A
        ):
            raise RuntimeError(f"git blob evidence mismatch for {entry.path.as_posix()}")
        blobs[entry.path] = response[cursor:stop]
        cursor = stop + 1
    if cursor != len(response):
        raise RuntimeError("git cat-file returned trailing data")
    return blobs


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def manifest_for(
    *,
    commit: str,
    entries: Iterable[TreeEntry],
    blobs: Mapping[PurePosixPath, bytes],
    expected_cases: int,
) -> dict[str, object]:
    ordered = tuple(sorted(entries))
    paths = {entry.path for entry in ordered}
    if set(blobs) != paths:
        missing = sorted(path.as_posix() for path in paths - set(blobs))
        extra = sorted(path.as_posix() for path in set(blobs) - paths)
        raise RuntimeError(f"blob set mismatch: missing={missing}, extra={extra}")
    cases = sorted(
        entry.path.parent.as_posix() for entry in ordered if entry.path.name == "in.yaml"
    )
    if len(cases) != expected_cases or len(set(cases)) != expected_cases:
        raise RuntimeError("export entries do not contain the expected unique cases")
    files = []
    for entry in ordered:
        contents = blobs[entry.path]
        files.append(
            {
                "bytes": len(contents),
                "mode": entry.mode,
                "object_id": entry.object_id,
                "path": entry.path.as_posix(),
                "sha256": hashlib.sha256(contents).hexdigest(),
            }
        )
    payload: dict[str, object] = {
        "case_count": expected_cases,
        "cases": cases,
        "document_type": DOCUMENT_TYPE,
        "files": files,
        "schema_version": 1,
        "upstream_commit": commit,
    }
    return {
        **payload,
        "tree_sha256": hashlib.sha256(canonical_json(payload)).hexdigest(),
    }


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"duplicate manifest key: {key!r}")
        result[key] = value
    return result


def filesystem_entries(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack = [(root, PurePosixPath())]
    while stack:
        directory, relative = stack.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            child_relative = relative / child.name
            child_path = child_relative.as_posix()
            metadata = child.stat(follow_symlinks=False)
            if child.is_symlink():
                raise RuntimeError(f"symlink in canonical export: {child_path}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(child_path)
                stack.append((Path(child.path), child_relative))
            elif stat.S_ISREG(metadata.st_mode):
                files.add(child_path)
            else:
                raise RuntimeError(f"special file in canonical export: {child_path}")
    return files, directories


def validate_pinned_export_evidence(
    manifest: Mapping[str, object],
    *,
    expected_files: int | None,
    expected_tree_sha256: str | None,
) -> None:
    raw_files = manifest.get("files")
    if expected_files is not None and (
        not isinstance(raw_files, list) or len(raw_files) != expected_files
    ):
        actual = len(raw_files) if isinstance(raw_files, list) else "invalid"
        raise RuntimeError(
            f"canonical export file count mismatch: expected {expected_files}, found {actual}"
        )
    if expected_tree_sha256 is not None and manifest.get("tree_sha256") != expected_tree_sha256:
        raise RuntimeError("canonical export pinned tree digest mismatch")


def validate_export(
    destination: Path,
    *,
    commit: str = COMMIT,
    expected_cases: int = EXPECTED_CASES,
    expected_files: int | None = None,
    expected_tree_sha256: str | None = None,
) -> dict[str, object]:
    try:
        metadata = destination.lstat()
    except FileNotFoundError as error:
        raise RuntimeError(f"canonical export is absent: {destination}") from error
    if not stat.S_ISDIR(metadata.st_mode) or destination.is_symlink():
        raise RuntimeError(f"canonical export is not a real directory: {destination}")
    manifest_path = destination / MANIFEST_NAME
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot decode canonical export manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise RuntimeError("canonical export manifest root is not an object")
    expected_root_fields = {
        "case_count",
        "cases",
        "document_type",
        "files",
        "schema_version",
        "tree_sha256",
        "upstream_commit",
    }
    if set(manifest) != expected_root_fields:
        raise RuntimeError("canonical export manifest fields are not exact")
    if manifest["document_type"] != DOCUMENT_TYPE or manifest["schema_version"] != 1:
        raise RuntimeError("canonical export manifest discriminator mismatch")
    if manifest["upstream_commit"] != commit:
        raise RuntimeError(
            "canonical export commit mismatch: "
            f"expected {commit}, found {manifest['upstream_commit']}"
        )
    if manifest["case_count"] != expected_cases:
        raise RuntimeError("canonical export case count mismatch")
    cases = manifest["cases"]
    raw_files = manifest["files"]
    if (
        not isinstance(cases, list)
        or not all(isinstance(case, str) for case in cases)
        or cases != sorted(set(cases))
        or len(cases) != expected_cases
        or not all(CASE_ID.fullmatch(safe_path(case).parts[0]) is not None for case in cases)
    ):
        raise RuntimeError("canonical export case ledger is invalid")
    if not isinstance(raw_files, list):
        raise RuntimeError("canonical export file ledger is not an array")
    expected_file_fields = {"bytes", "mode", "object_id", "path", "sha256"}
    ledger: list[tuple[PurePosixPath, dict[str, Any]]] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict) or set(raw_file) != expected_file_fields:
            raise RuntimeError("canonical export file fields are not exact")
        raw_path = raw_file["path"]
        if not isinstance(raw_path, str):
            raise RuntimeError("canonical export file path is not a string")
        path = safe_path(raw_path)
        if path.parent.as_posix() not in cases:
            raise RuntimeError(f"file is outside canonical cases: {raw_path}")
        if raw_file["mode"] not in REGULAR_MODES:
            raise RuntimeError(f"non-regular mode in manifest: {raw_path}")
        if (
            not isinstance(raw_file["object_id"], str)
            or HEX_OBJECT_ID.fullmatch(raw_file["object_id"]) is None
            or not isinstance(raw_file["bytes"], int)
            or isinstance(raw_file["bytes"], bool)
            or raw_file["bytes"] < 0
            or not isinstance(raw_file["sha256"], str)
            or HEX_SHA256.fullmatch(raw_file["sha256"]) is None
        ):
            raise RuntimeError(f"invalid file evidence in manifest: {raw_path}")
        ledger.append((path, raw_file))
    ledger_paths = [path.as_posix() for path, _ in ledger]
    if ledger_paths != sorted(set(ledger_paths)):
        raise RuntimeError("canonical export file ledger is not sorted and unique")
    input_cases = sorted(path.parent.as_posix() for path, _ in ledger if path.name == "in.yaml")
    if input_cases != cases:
        raise RuntimeError("canonical export inputs contradict the case ledger")
    payload = {key: value for key, value in manifest.items() if key != "tree_sha256"}
    expected_tree = hashlib.sha256(canonical_json(payload)).hexdigest()
    if manifest["tree_sha256"] != expected_tree:
        raise RuntimeError("canonical export tree digest mismatch")
    validate_pinned_export_evidence(
        manifest,
        expected_files=expected_files,
        expected_tree_sha256=expected_tree_sha256,
    )
    actual_files, actual_directories = filesystem_entries(destination)
    expected_files = {MANIFEST_NAME, *ledger_paths}
    unexpected_files = sorted(actual_files - expected_files)
    missing_files = sorted(expected_files - actual_files)
    if unexpected_files or missing_files:
        detail = unexpected_files[0] if unexpected_files else missing_files[0]
        kind = "unexpected" if unexpected_files else "missing"
        raise RuntimeError(f"{kind} export entry: {detail}")
    expected_directories = {
        PurePosixPath(*path.parts[:index]).as_posix()
        for path, _ in ledger
        for index in range(1, len(path.parts))
    }
    if actual_directories != expected_directories:
        extras = sorted(actual_directories - expected_directories)
        missing = sorted(expected_directories - actual_directories)
        detail = extras[0] if extras else missing[0]
        kind = "unexpected" if extras else "missing"
        raise RuntimeError(f"{kind} export directory: {detail}")
    for path, evidence in ledger:
        contents = (destination / Path(*path.parts)).read_bytes()
        if len(contents) != evidence["bytes"]:
            raise RuntimeError(f"size mismatch for export file {path.as_posix()}")
        if hashlib.sha256(contents).hexdigest() != evidence["sha256"]:
            raise RuntimeError(f"digest mismatch for export file {path.as_posix()}")
    return manifest


def build_export(
    destination: Path,
    *,
    commit: str,
    entries: Iterable[TreeEntry],
    blobs: Mapping[PurePosixPath, bytes],
    expected_cases: int = EXPECTED_CASES,
    expected_files: int | None = None,
    expected_tree_sha256: str | None = None,
) -> dict[str, object]:
    destination = destination.resolve()
    if destination.exists():
        return validate_export(
            destination,
            commit=commit,
            expected_cases=expected_cases,
            expected_files=expected_files,
            expected_tree_sha256=expected_tree_sha256,
        )
    manifest = manifest_for(
        commit=commit,
        entries=entries,
        blobs=blobs,
        expected_cases=expected_cases,
    )
    validate_pinned_export_evidence(
        manifest,
        expected_files=expected_files,
        expected_tree_sha256=expected_tree_sha256,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent))
    try:
        raw_files = manifest["files"]
        assert isinstance(raw_files, list)
        for raw_file in raw_files:
            assert isinstance(raw_file, dict)
            path = safe_path(str(raw_file["path"]))
            target = staging / Path(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blobs[path])
        (staging / MANIFEST_NAME).write_bytes(canonical_json(manifest))
        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return validate_export(
        destination,
        commit=commit,
        expected_cases=expected_cases,
        expected_files=expected_files,
        expected_tree_sha256=expected_tree_sha256,
    )


def validate_checkout_identity(pin: YamlSuitePin, *, tag_object: str, commit: str) -> None:
    if tag_object != pin.tag_object:
        raise RuntimeError(
            f"suite annotated tag object mismatch: expected {pin.tag_object}, found {tag_object}"
        )
    if commit != pin.commit:
        raise RuntimeError(f"suite release commit mismatch: expected {pin.commit}, found {commit}")


def validate_checkout(destination: Path) -> bool:
    if not (destination / ".git").exists():
        return False
    tag_reference = f"refs/tags/{PIN.release}"
    validate_checkout_identity(
        PIN,
        tag_object=git("rev-parse", f"{tag_reference}^{{tag}}", cwd=destination),
        commit=git("rev-parse", f"{tag_reference}^{{commit}}", cwd=destination),
    )
    actual_head = git("rev-parse", "HEAD^{commit}", cwd=destination)
    if actual_head != PIN.commit:
        raise RuntimeError(
            f"suite checkout HEAD mismatch: expected {PIN.commit}, found {actual_head}"
        )
    canonical_case_entries(tree_entries(destination))
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--verify-export-only", action="store_true")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--export-destination", type=Path, default=DEFAULT_EXPORT_DESTINATION)
    arguments = parser.parse_args()
    destination = arguments.destination.resolve()
    export_destination = arguments.export_destination.resolve()
    if arguments.verify_export_only:
        validate_export(
            export_destination,
            expected_files=PIN.export_files,
            expected_tree_sha256=PIN.export_tree_sha256,
        )
        print(export_destination)
        return
    if (
        export_destination == destination
        or export_destination.is_relative_to(destination)
        or destination.is_relative_to(export_destination)
    ):
        raise RuntimeError("checkout and canonical export paths must not overlap")
    if not validate_checkout(destination):
        if destination.exists():
            raise RuntimeError(f"refusing to replace non-suite path: {destination}")
        if not arguments.allow_network:
            raise RuntimeError("suite is absent; pass --allow-network to fetch the pinned release")
        destination.parent.mkdir(parents=True, exist_ok=True)
        git(
            "clone",
            "--branch",
            RELEASE,
            "--depth",
            "1",
            "--config",
            "advice.detachedHead=false",
            REPOSITORY,
            str(destination),
        )
        if not validate_checkout(destination):
            shutil.rmtree(destination, ignore_errors=True)
            raise RuntimeError("fetched suite could not be validated")
    entries = canonical_case_entries(tree_entries(destination))
    blobs = read_blobs(destination, entries)
    build_export(
        export_destination,
        commit=COMMIT,
        entries=entries,
        blobs=blobs,
        expected_cases=EXPECTED_CASES,
        expected_files=PIN.export_files,
        expected_tree_sha256=PIN.export_tree_sha256,
    )
    print(export_destination)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"yaml-test-suite: {error}", file=sys.stderr)
        raise SystemExit(1) from error
