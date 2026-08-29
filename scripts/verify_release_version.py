#!/usr/bin/env python3
"""Verify Cargo-authoritative metadata and an exact release-plz release identity."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

try:
    from scripts.sync_release_version import cargo_version, synchronize
except ModuleNotFoundError:  # Direct execution sets scripts/ as sys.path[0].
    from sync_release_version import cargo_version, synchronize  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]


def _read(root: Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {relative}: {error}") from error


def _repository(root: Path) -> str:
    try:
        document = tomllib.loads(_read(root, "Cargo.toml"))
        repository = document["package"]["repository"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"Cargo package repository is missing: {error}") from error
    if not isinstance(repository, str) or not repository.startswith("https://"):
        raise ValueError("Cargo package repository must be an HTTPS URL")
    return repository.rstrip("/")


def _validate_changelog(
    root: Path,
    version: str,
    *,
    require_release_heading: bool,
) -> None:
    changelog = _read(root, "CHANGELOG.md")
    candidate = re.compile(
        rf"^## (?:\[{re.escape(version)}\](?:\([^)]*\))?|{re.escape(version)})(?:\s.*)?$"
    )
    version_headings = [line for line in changelog.splitlines() if candidate.fullmatch(line)]
    if not version_headings:
        if require_release_heading:
            raise ValueError("CHANGELOG has no exact release-plz release heading")
        return
    if len(version_headings) != 1:
        raise ValueError("CHANGELOG release heading is duplicated")

    heading = re.fullmatch(
        rf"## \[{re.escape(version)}\]\((https://[^\s()]+)\) - "
        r"([0-9]{4}-[0-9]{2}-[0-9]{2})",
        version_headings[0],
    )
    if heading is None:
        raise ValueError("CHANGELOG release heading is not in release-plz linked format")
    expected_link = f"{_repository(root)}/releases/tag/v{version}"
    if heading.group(1) != expected_link:
        raise ValueError(f"CHANGELOG release link must be {expected_link}")
    try:
        dt.date.fromisoformat(heading.group(2))
    except ValueError as error:
        raise ValueError("CHANGELOG release date is invalid") from error


def validate(
    root: Path,
    tag: str | None,
    *,
    allow_development: bool = False,
) -> str:
    root = root.resolve()
    version = cargo_version(root)
    try:
        synchronize(root, check=True)
    except ValueError as error:
        raise ValueError(f"derived release version mismatch: {error}") from error
    if not allow_development and version.endswith("-dev"):
        raise ValueError("development versions are not publishable")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"release tag {tag} does not match v{version}")
    _validate_changelog(
        root,
        version,
        require_release_heading=tag is not None or not allow_development,
    )
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag")
    parser.add_argument("--allow-development", action="store_true")
    arguments = parser.parse_args()
    try:
        version = validate(
            arguments.root,
            arguments.tag,
            allow_development=arguments.allow_development,
        )
    except ValueError as error:
        print(f"release version gate: {error}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
