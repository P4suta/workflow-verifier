#!/usr/bin/env python3
"""Build a deterministic, content-addressed macOS Linux VM bundle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _regular(path: Path, name: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect {name}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"{name} must be a nonempty regular non-symlink file")


def _validate_ext4(path: Path) -> None:
    with path.open("rb") as source:
        source.seek(1024 + 56)
        magic = source.read(2)
    if magic != b"\x53\xef":
        raise ValueError("rootfs must contain an ext4 superblock")


def _validate_static_agent(path: Path, architecture: str) -> None:
    expected_machine = {"x86_64": 62, "arm64": 183}[architecture]
    with path.open("rb") as source:
        header = source.read(64)
        if (
            len(header) != 64
            or header[:4] != b"\x7fELF"
            or header[4] != 2
            or header[5] != 1
            or header[6] != 1
        ):
            raise ValueError("agent must be a little-endian ELF64 executable")
        (
            file_type,
            machine,
            elf_version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _string_section,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", header, 16)
        if file_type not in {2, 3} or elf_version != 1 or header_size != 64:
            raise ValueError("agent must be a valid ELF64 executable")
        if machine != expected_machine:
            raise ValueError(
                f"agent architecture does not match bundle architecture {architecture}"
            )
        if program_count == 0 or program_entry_size < 56:
            raise ValueError("agent must contain ELF program headers")
        source.seek(0, os.SEEK_END)
        file_size = source.tell()
        table_size = program_entry_size * program_count
        if program_offset > file_size or table_size > file_size - program_offset:
            raise ValueError("agent ELF program header table is truncated")
        has_load = False
        for index in range(program_count):
            source.seek(program_offset + index * program_entry_size)
            program_header = source.read(56)
            if len(program_header) != 56:
                raise ValueError("agent ELF program header is truncated")
            program_type = struct.unpack_from("<I", program_header)[0]
            if program_type == 1:
                has_load = True
            if program_type == 3:
                raise ValueError("agent must be statically linked without PT_INTERP")
        if not has_load:
            raise ValueError("agent must contain a loadable ELF segment")


def _padding(length: int) -> bytes:
    return b"\0" * ((-length) % 4)


@dataclass(frozen=True)
class _CpioEntry:
    name: str
    mode: int
    contents: bytes = b""


def _newc(entries: list[_CpioEntry]) -> bytes:
    output = bytearray()
    for inode, entry in enumerate(entries + [_CpioEntry("TRAILER!!!", 0)], start=1):
        name = entry.name.encode("utf-8") + b"\0"
        fields = (
            inode,
            entry.mode,
            0,
            0,
            2 if stat.S_ISDIR(entry.mode) else 1,
            0,
            len(entry.contents),
            0,
            0,
            0,
            0,
            len(name),
            0,
        )
        header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
        output.extend(header)
        output.extend(name)
        output.extend(_padding(len(header) + len(name)))
        output.extend(entry.contents)
        output.extend(_padding(len(entry.contents)))
    return bytes(output)


def read_newc(archive: bytes) -> dict[str, bytes]:
    """Read the deterministic newc subset emitted by this builder."""
    offset = 0
    entries: dict[str, bytes] = {}
    while offset + 110 <= len(archive):
        header = archive[offset : offset + 110]
        if header[:6] != b"070701":
            raise ValueError(f"invalid newc magic at byte {offset}")
        values = [int(header[index : index + 8], 16) for index in range(6, 110, 8)]
        size = values[6]
        name_size = values[11]
        offset += 110
        name = archive[offset : offset + name_size - 1].decode("utf-8")
        offset += name_size
        offset += (-offset) % 4
        contents = archive[offset : offset + size]
        offset += size
        offset += (-offset) % 4
        if name == "TRAILER!!!":
            return entries
        entries[name] = bytes(contents)
    raise ValueError("newc archive has no trailer")


def _initrd(agent: bytes) -> bytes:
    directories = [
        "dev",
        "proc",
        "sys",
        "source",
        "workspace",
        "control",
        "sysroot",
    ]
    archive = _newc(
        [_CpioEntry(name, stat.S_IFDIR | 0o755) for name in directories]
        + [_CpioEntry("workflow-verifier-vm-agent", stat.S_IFREG | 0o755, agent)]
    )
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=compressed,
        mtime=0,
    ) as target:
        target.write(archive)
    return compressed.getvalue()


def _copy(source: Path, destination: Path, mode: int) -> None:
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    os.utime(destination, (0, 0))


def build_bundle(
    kernel: Path,
    rootfs: Path,
    agent: Path,
    output: Path,
    architecture: str,
    version: str,
) -> str:
    if architecture not in {"arm64", "x86_64"}:
        raise ValueError("architecture must be arm64 or x86_64")
    if not version or "\0" in version:
        raise ValueError("version must be nonempty and NUL-free")
    for path, name in ((kernel, "kernel"), (rootfs, "rootfs"), (agent, "agent")):
        _regular(path, name)
    _validate_ext4(rootfs)
    _validate_static_agent(agent, architecture)
    if output.exists() or output.is_symlink():
        raise ValueError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent))
    try:
        _copy(kernel, temporary / "vmlinuz", 0o644)
        _copy(rootfs, temporary / "rootfs.raw", 0o644)
        _copy(agent, temporary / "workflow-verifier-vm-agent", 0o755)
        (temporary / "initrd.img").write_bytes(_initrd(agent.read_bytes()))
        (temporary / "initrd.img").chmod(0o644)
        os.utime(temporary / "initrd.img", (0, 0))
        manifest = {
            "agent_digest": _sha256(temporary / "workflow-verifier-vm-agent"),
            "architecture": architecture,
            "initrd_digest": _sha256(temporary / "initrd.img"),
            "kernel_digest": _sha256(temporary / "vmlinuz"),
            "rootfs_digest": _sha256(temporary / "rootfs.raw"),
            "schema": "vm-image-v1",
            "version": version,
        }
        encoded = (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        (temporary / "manifest.json").write_bytes(encoded)
        manifest_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        (temporary / "manifest.sha256").write_text(manifest_digest + "\n", encoding="ascii")
        os.replace(temporary, output)
        return manifest_digest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    digest = build_bundle(
        arguments.kernel,
        arguments.rootfs,
        arguments.agent,
        arguments.output,
        arguments.architecture,
        arguments.version,
    )
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
