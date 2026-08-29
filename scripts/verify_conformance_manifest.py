#!/usr/bin/env python3
"""Verify the content-addressed cross-language conformance manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PROTOCOLS = {
    "canonical-json",
    "source-manifest-v2",
    "scenario-v1",
    "runner-v2",
    "sandbox-run-v2",
    "evidence-v2",
}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field {key}")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _load(path: Path, label: str) -> tuple[Any, bytes]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"{label} must be a nonempty regular non-symlink file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {label}: {error}") from error
    return value, raw


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError("vector path must be a string")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe vector path {value!r}")
    return path


def verify(manifest_path: Path, root: Path) -> int:
    manifest, raw = _load(manifest_path, "conformance manifest")
    if raw != _canonical(manifest):
        raise ValueError("conformance manifest must be canonical JSON")
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "vectors"}:
        raise ValueError("conformance manifest fields are not exact")
    if manifest["schema"] != "conformance-manifest-v2":
        raise ValueError("unsupported conformance manifest schema")
    vectors = manifest["vectors"]
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("conformance manifest needs vectors")
    paths: list[str] = []
    root = root.resolve(strict=True)
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict) or set(vector) != {
            "digest",
            "expected",
            "path",
            "protocol",
            "size",
        }:
            raise ValueError(f"vector {index} fields are not exact")
        relative = _relative(vector["path"])
        path = root.joinpath(*relative.parts)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"vector {relative} must be a regular non-symlink file")
        digest = vector["digest"]
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError(f"vector {relative} digest is invalid")
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"vector {relative} digest mismatch")
        if vector["size"] != metadata.st_size:
            raise ValueError(f"vector {relative} size mismatch")
        if vector["expected"] not in {"accept", "reject"}:
            raise ValueError(f"vector {relative} expected result is invalid")
        if vector["protocol"] not in PROTOCOLS:
            raise ValueError(f"vector {relative} protocol is unknown")
        if vector["expected"] == "accept":
            value, vector_raw = _load(path, f"accepted vector {relative}")
            if vector_raw != _canonical(value):
                raise ValueError(f"accepted vector {relative} is not canonical JSON")
        paths.append(relative.as_posix())
    if paths != sorted(paths, key=lambda value: value.encode("utf-8")):
        raise ValueError("conformance vectors must be sorted by UTF-8 path bytes")
    if len(paths) != len(set(paths)):
        raise ValueError("conformance vector paths must be unique")
    return len(vectors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("conformance/manifest-v2.json"))
    parser.add_argument("--root", type=Path, default=Path("."))
    arguments = parser.parse_args()
    try:
        count = verify(arguments.manifest, arguments.root)
    except (OSError, ValueError) as error:
        print(f"conformance manifest: {error}", file=sys.stderr)
        return 2
    print(f"conformance manifest: {count} content-addressed vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
