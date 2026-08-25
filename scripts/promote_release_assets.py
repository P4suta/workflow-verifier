#!/usr/bin/env python3
"""Promote verified staged evidence into unique public assets plus one evidence bundle."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.verify_release_evidence import _exact, _load_json, _object
except ModuleNotFoundError:
    from verify_release_evidence import _exact, _load_json, _object  # type: ignore[no-redef]


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a path")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} is unsafe")
    return path


def _regular(path: Path, label: str) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"{label} must be a nonempty regular non-symlink file")


def _atomic_copy(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(input_stream, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _bundle(staged: Path, output: Path) -> None:
    entries: list[tuple[str, Path, int]] = []
    for path in staged.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"staged evidence contains symlink {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise ValueError(f"staged evidence contains invalid file {path}")
        entries.append((path.relative_to(staged).as_posix(), path, metadata.st_size))
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, path, size in entries:
            info = tarfile.TarInfo(f"workflow-verifier-release-evidence/{name}")
            info.size = size
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(path.read_bytes()))
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0
            ) as compressed:
                compressed.write(archive_bytes.getvalue())
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def promote(staged: Path, output: Path, version: str) -> list[Path]:
    if not VERSION.fullmatch(version):
        raise ValueError("release version is invalid")
    staged = staged.resolve(strict=True)
    manifest_path = staged / "release-evidence-v3.json"
    manifest, _ = _load_json(manifest_path, "staged release evidence", canonical=True)
    if not isinstance(manifest, dict) or manifest.get("schema") != "release-evidence-v3":
        raise ValueError("staged evidence manifest is not release-evidence-v3")
    try:
        metadata = output.lstat()
    except FileNotFoundError:
        output.mkdir(parents=True)
    else:
        if output.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("public release destination must be a directory")
        if any(output.iterdir()):
            raise ValueError("public release destination must be empty")

    sources: list[tuple[str, Path]] = []
    names: set[str] = set()
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("release evidence artifacts must be an array")
    for index, raw in enumerate(artifacts):
        item = _object(
            raw,
            required={"digest", "kind", "name", "path", "platform"},
            allowed={"digest", "kind", "name", "path", "platform", "signature", "subject"},
            label=f"artifact[{index}]",
        )
        name = item["name"]
        if not isinstance(name, str) or PurePosixPath(name).name != name:
            raise ValueError(f"artifact[{index}].name is unsafe")
        relative = _relative(item["path"], f"artifact[{index}].path")
        source = staged.joinpath(*relative.parts)
        _regular(source, f"artifact[{index}]")
        if name in names:
            raise ValueError(f"duplicate public asset name {name}")
        names.add(name)
        sources.append((name, source))
        signature = item.get("signature")
        if signature is not None:
            signature = _exact(
                signature, {"digest", "kind", "path"}, f"artifact[{index}].signature"
            )
            signature_relative = _relative(signature["path"], f"artifact[{index}].signature.path")
            signature_source = staged.joinpath(*signature_relative.parts)
            _regular(signature_source, f"artifact[{index}].signature")
            signature_name = signature_relative.name
            if signature_name in names:
                raise ValueError(f"duplicate public asset name {signature_name}")
            names.add(signature_name)
            sources.append((signature_name, signature_source))

    outputs: list[Path] = []
    for name, source in sorted(sources, key=lambda item: item[0].encode("utf-8")):
        destination = output / name
        _atomic_copy(source, destination)
        outputs.append(destination)
    bundle = output / f"workflow-verifier-{version}-release-evidence.tar.gz"
    if bundle.name in names:
        raise ValueError("release evidence bundle name collides with an artifact")
    _bundle(staged, bundle)
    outputs.append(bundle)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    try:
        outputs = promote(arguments.staged, arguments.output, arguments.version)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"release promotion: {len(outputs)} public assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
