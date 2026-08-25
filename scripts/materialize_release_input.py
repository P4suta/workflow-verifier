#!/usr/bin/env python3
"""Dereference one built artifact into a new regular release input file."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import tempfile
from pathlib import Path


def materialize(source: Path, destination: Path) -> Path:
    if source.absolute() == destination.absolute():
        raise ValueError("release source and destination must differ")
    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect release source {source}: {error}") from error
    if not (stat.S_ISREG(source_metadata.st_mode) or stat.S_ISLNK(source_metadata.st_mode)):
        raise ValueError(f"release source must be a regular file or symlink: {source}")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValueError(f"cannot inspect release destination {destination}: {error}") from error
    else:
        raise ValueError(f"release destination already exists: {destination}")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        parent_metadata = destination.parent.lstat()
    except OSError as error:
        raise ValueError(f"cannot prepare release destination {destination}: {error}") from error
    if destination.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("release destination parent must be a directory, not a symlink")

    try:
        input_stream = source.open("rb")
    except OSError as error:
        raise ValueError(f"cannot open release source {source}: {error}") from error
    try:
        opened_metadata = os.fstat(input_stream.fileno())
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size == 0:
            raise ValueError(f"release source target must be a nonempty regular file: {source}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    finally:
        input_stream.close()

    output_metadata = destination.lstat()
    if (
        destination.is_symlink()
        or not stat.S_ISREG(output_metadata.st_mode)
        or output_metadata.st_size == 0
    ):
        raise ValueError(
            f"materialized release input is not a nonempty regular file: {destination}"
        )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        output = materialize(arguments.source, arguments.destination)
    except (OSError, ValueError) as error:
        print(f"release input materialization: {error}", file=os.sys.stderr)
        return 1
    print(f"release input materialization: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
