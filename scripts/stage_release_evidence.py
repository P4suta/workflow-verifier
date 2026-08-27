#!/usr/bin/env python3
"""Stage every digest-checked release-evidence-v4 input without renaming it."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from scripts.verify_release_evidence import (
        ROOT_FIELDS,
        _exact,
        _load_json,
        _object,
        _resolve_file,
        _verify_digest,
    )
except ModuleNotFoundError:  # Direct execution from the repository root.
    from verify_release_evidence import (  # type: ignore[no-redef]
        ROOT_FIELDS,
        _exact,
        _load_json,
        _object,
        _resolve_file,
        _verify_digest,
    )


def _reference(root: Path, value: Any, label: str) -> tuple[str, Path]:
    record = _exact(value, {"digest", "path"}, label)
    relative, path = _resolve_file(root, record["path"], f"{label}.path")
    _verify_digest(path, record["digest"], f"{label}.digest")
    return relative, path


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
    manifest, _ = _load_json(manifest_path, "release evidence manifest", canonical=True)
    manifest = _exact(manifest, ROOT_FIELDS, "release evidence manifest")
    if manifest["schema"] != "release-evidence-v4":
        raise ValueError("release evidence schema must be release-evidence-v4")
    root = manifest_path.parent
    sources: dict[str, Path] = {"release-evidence-v4.json": manifest_path}

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        raise ValueError("release evidence artifacts must be an array")
    for index, raw in enumerate(artifacts):
        item = _object(
            raw,
            required={"digest", "kind", "name", "path", "platform"},
            allowed={
                "digest",
                "kind",
                "name",
                "path",
                "platform",
                "signature",
                "subject",
            },
            label=f"artifact[{index}]",
        )
        relative, source = _resolve_file(root, item["path"], f"artifact[{index}].path")
        _verify_digest(source, item["digest"], f"artifact[{index}].digest")
        sources[relative] = source
        if "signature" in item:
            signature = _exact(
                item["signature"],
                {"digest", "kind", "path"},
                f"artifact[{index}].signature",
            )
            relative, source = _resolve_file(
                root,
                signature["path"],
                f"artifact[{index}].signature.path",
            )
            _verify_digest(
                source,
                signature["digest"],
                f"artifact[{index}].signature.digest",
            )
            sources[relative] = source

    gates = manifest["gates"]
    if not isinstance(gates, list):
        raise ValueError("release evidence gates must be an array")
    for index, raw in enumerate(gates):
        gate = _exact(
            raw,
            {"evidence", "id", "status", "subject_commit"},
            f"gate[{index}]",
        )
        relative, source = _reference(root, gate["evidence"], f"gate[{index}].evidence")
        sources[relative] = source

    audit = _exact(
        manifest["self_audit"],
        {
            "digest",
            "independent",
            "path",
            "signature_digest",
            "signature_path",
            "sole_maintainer",
        },
        "self_audit",
    )
    for path_field, digest_field in (
        ("path", "digest"),
        ("signature_path", "signature_digest"),
    ):
        relative, source = _resolve_file(root, audit[path_field], f"self_audit.{path_field}")
        _verify_digest(source, audit[digest_field], f"self_audit.{digest_field}")
        sources[relative] = source
    allowed = root / "maintainer-allowed-signers"
    try:
        metadata = allowed.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect maintainer allowed signers: {error}") from error
    if allowed.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("maintainer allowed signers must be a regular non-symlink file")
    sources["maintainer-allowed-signers"] = allowed

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
    for relative, source in sorted(sources.items()):
        output = destination.joinpath(*relative.split("/"))
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
        print(f"release evidence staging: {error}", file=sys.stderr)
        return 1
    print(f"release evidence staging: {len(outputs)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
