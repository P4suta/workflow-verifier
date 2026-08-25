#!/usr/bin/env python3
"""Create the final canonical release index and checksum layer without digest cycles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink output {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _confined_output(root: Path, path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"refusing symlink {label} output {path}")
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} output must stay within the release root") from error
    if not relative.parts:
        raise ValueError(f"{label} output must be a file below the release root")
    return resolved


def generate(root: Path, index_path: Path, checksums_path: Path, tag: str) -> int:
    if not TAG.fullmatch(tag):
        raise ValueError("planned tag is invalid")
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("release root must be a non-symlink directory")
    root = root.resolve(strict=True)
    index_path = _confined_output(root, index_path, "release index")
    checksums_path = _confined_output(root, checksums_path, "checksums")
    if index_path == checksums_path:
        raise ValueError("release index and checksums must be distinct")
    excluded = {
        index_path,
        checksums_path,
        Path(str(index_path) + ".sigstore.json").resolve(),
        Path(str(checksums_path) + ".sigstore.json").resolve(),
    }
    files: list[tuple[str, Path, int, str]] = []
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"release tree contains symlink {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise ValueError(f"release tree contains invalid file {path}")
        resolved = path.resolve(strict=True)
        if resolved in excluded:
            continue
        relative = resolved.relative_to(root).as_posix()
        files.append((relative, path, metadata.st_size, _digest(path)))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    if not files:
        raise ValueError("release index has no payload files")
    if len({name for name, _path, _size, _digest_value in files}) != len(files):
        raise ValueError("release index has duplicate paths")
    index = {
        "files": [
            {
                "digest": f"sha256:{digest}",
                "path": name,
                "size": size,
            }
            for name, _path, size, digest in files
        ],
        "planned_tag": tag,
        "schema": "release-index-v1",
    }
    index_bytes = (
        json.dumps(index, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    _atomic(index_path, index_bytes)

    checksum_files = files + [
        (
            index_path.relative_to(root).as_posix(),
            index_path,
            len(index_bytes),
            hashlib.sha256(index_bytes).hexdigest(),
        )
    ]
    checksum_files.sort(key=lambda item: item[0].encode("utf-8"))
    checksums = "".join(
        f"{digest}  {name}\n" for name, _path, _size, digest in checksum_files
    ).encode("utf-8")
    _atomic(checksums_path, checksums)
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    arguments = parser.parse_args()
    try:
        count = generate(
            arguments.root,
            arguments.index,
            arguments.checksums,
            arguments.tag,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"release index: {count} payload files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
