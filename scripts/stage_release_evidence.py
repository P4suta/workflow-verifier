#!/usr/bin/env python3
"""Stage the digest-verified v2 evidence bundle with canonical public names."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Any

try:
    from scripts.verify_release_evidence import (
        PLATFORMS,
        ROOT_FIELDS,
        _exact,
        _load_json,
        _resolve_file,
        _verify_digest,
    )
except ModuleNotFoundError:  # Direct script execution from the repository root.
    from verify_release_evidence import (  # type: ignore[no-redef]
        PLATFORMS,
        ROOT_FIELDS,
        _exact,
        _load_json,
        _resolve_file,
        _verify_digest,
    )


def _record(root: Path, value: Any, label: str) -> Path:
    record = _exact(value, {"digest", "path"}, label)
    _, path = _resolve_file(root, record["path"], f"{label}.path")
    _verify_digest(path, record["digest"], f"{label}.digest")
    return path


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError(f"refusing to replace symlink destination {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def stage(manifest_path: Path, destination: Path) -> list[Path]:
    manifest, _ = _load_json(manifest_path, "release evidence manifest", limit=1024 * 1024)
    _exact(manifest, ROOT_FIELDS, "release evidence manifest")
    if manifest["schema"] != "release-evidence-v2":
        raise ValueError("release evidence schema must be release-evidence-v2")
    root = manifest_path.parent
    sources: list[tuple[str, Path]] = [
        ("release-evidence-v2.json", manifest_path),
        ("corpus-report-v1.json", _record(root, manifest["corpus"], "corpus evidence")),
        (
            "official-compat-v1.json",
            _record(root, manifest["official_compat"], "official compatibility evidence"),
        ),
    ]
    performance = manifest["performance"]
    if not isinstance(performance, list) or len(performance) != len(PLATFORMS):
        raise ValueError("release evidence must contain exactly four performance reports")
    seen: set[str] = set()
    for index, raw in enumerate(performance):
        label = f"performance evidence[{index}]"
        record = _exact(raw, {"digest", "path", "platform"}, label)
        platform = record["platform"]
        if platform not in PLATFORMS or platform in seen:
            raise ValueError(f"{label}.platform is unsupported or duplicated")
        seen.add(platform)
        _, source = _resolve_file(root, record["path"], f"{label}.path")
        _verify_digest(source, record["digest"], f"{label}.digest")
        sources.append((f"performance-{platform}.json", source))
    security = _exact(
        manifest["security_attestation"],
        {"digest", "path", "signature_digest", "signature_path"},
        "security attestation evidence",
    )
    _, attestation = _resolve_file(root, security["path"], "security attestation path")
    _, signature = _resolve_file(root, security["signature_path"], "security signature path")
    _verify_digest(attestation, security["digest"], "security attestation digest")
    _verify_digest(signature, security["signature_digest"], "security signature digest")
    sources.extend(
        [
            ("maintainer-security-attestation-v1.json", attestation),
            ("maintainer-security-attestation-v1.json.sig", signature),
            ("maintainer-allowed-signers", root / "maintainer-allowed-signers"),
        ]
    )
    try:
        destination_metadata = destination.lstat()
    except FileNotFoundError:
        destination.mkdir(parents=True)
    except OSError as error:
        raise ValueError(f"cannot inspect staging destination: {error}") from error
    else:
        if destination.is_symlink() or not stat.S_ISDIR(destination_metadata.st_mode):
            raise ValueError("staging destination must be a directory, not a symlink")
    outputs: list[Path] = []
    for name, source in sources:
        try:
            metadata = source.lstat()
        except OSError as error:
            raise ValueError(f"cannot inspect evidence source {source}: {error}") from error
        if source.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
            raise ValueError(f"evidence source must be a nonempty regular non-symlink file: {source}")
        output = destination / name
        _atomic_copy(source, output)
        outputs.append(output)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        outputs = stage(arguments.manifest, arguments.destination)
    except (OSError, ValueError) as error:
        print(f"release evidence staging: {error}", file=os.sys.stderr)
        return 1
    print(f"release evidence staging: {len(outputs)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
