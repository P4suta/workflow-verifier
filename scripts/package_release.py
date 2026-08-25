#!/usr/bin/env python3
"""Create a deterministic, rooted workflow-verifier release archive."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

IDENTIFIER = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")


def _regular(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect release input {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"release input must be a nonempty regular non-symlink file: {path}")


def _logical_name(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise ValueError(f"unsafe release archive path: {value!r}")
    return path.as_posix()


def _inputs(files: list[tuple[str, Path]]) -> list[tuple[str, Path, int]]:
    normalized: list[tuple[str, Path, int]] = []
    names: set[str] = set()
    for logical, source in files:
        name = _logical_name(logical)
        if name in names:
            raise ValueError(f"duplicate release archive path: {name}")
        names.add(name)
        _regular(source)
        mode = 0o755 if name.startswith("bin/") else 0o644
        normalized.append((name, source, mode))
    if not normalized:
        raise ValueError("release package must contain at least one file")
    return sorted(normalized, key=lambda item: item[0].encode("utf-8"))


def _tar_gz(prefix: str, files: list[tuple[str, Path, int]]) -> bytes:
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, source, mode in files:
            contents = source.read_bytes()
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(contents)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(contents))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=output, mtime=0) as stream:
        stream.write(tar_bytes.getvalue())
    return output.getvalue()


def _zip(prefix: str, files: list[tuple[str, Path, int]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, source, mode in files:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(
                info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
            )
    return output.getvalue()


def _atomic_write(path: Path, contents: bytes) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValueError(f"cannot inspect release output {path}: {error}") from error
    else:
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"release output must not replace a link or special file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("release output parent must be a non-symlink directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def build_package(
    platform: str,
    version: str,
    files: list[tuple[str, Path]],
    output: Path,
) -> None:
    if not IDENTIFIER.fullmatch(platform):
        raise ValueError("platform must be a simple stable identifier")
    if not IDENTIFIER.fullmatch(version):
        raise ValueError("version must be a simple SemVer-compatible identifier")
    windows = platform.startswith("windows-")
    expected_suffix = ".zip" if windows else ".tar.gz"
    if not output.name.endswith(expected_suffix):
        raise ValueError(f"{platform} release output must end in {expected_suffix}")
    normalized = _inputs(files)
    prefix = f"workflow-verifier-{version}-{platform}"
    contents = _zip(prefix, normalized) if windows else _tar_gz(prefix, normalized)
    _atomic_write(output, contents)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        metavar="ARCHIVE_PATH=SOURCE_PATH",
    )
    arguments = parser.parse_args()
    files: list[tuple[str, Path]] = []
    for specification in arguments.file:
        if "=" not in specification:
            parser.error(f"--file needs ARCHIVE_PATH=SOURCE_PATH: {specification}")
        logical, source = specification.split("=", 1)
        files.append((logical, Path(source)))
    build_package(arguments.platform, arguments.version, files, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
