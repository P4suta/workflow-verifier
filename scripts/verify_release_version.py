#!/usr/bin/env python3
"""Verify that every public version surface matches an exact release tag."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _read(root: Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read {relative}: {error}") from error


def _match(label: str, pattern: str, source: str) -> str:
    match = re.search(pattern, source, re.MULTILINE)
    if match is None:
        raise ValueError(f"{label} version is missing")
    return match.group(1)


def validate(
    root: Path,
    tag: str | None,
    *,
    allow_development: bool = False,
) -> str:
    version = _match(
        "dune-project",
        r"(?m)^\(version\s+([^\s)]+)\)\s*$",
        _read(root, "dune-project"),
    )
    if not SEMVER.fullmatch(version):
        raise ValueError(f"dune-project version is not SemVer: {version}")
    surfaces = [
        (
            "opam",
            _match(
                "opam",
                r'^version:\s*"([^"]+)"\s*$',
                _read(root, "workflow-verifier.opam"),
            ),
        ),
        (
            "Cargo workspace",
            _match(
                "Cargo workspace",
                r'(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"([^"]+)"\s*$',
                _read(root, "Cargo.toml"),
            ),
        ),
    ]
    for label, actual in surfaces:
        if actual != version:
            raise ValueError(f"{label} version {actual} does not match {version}")
    cli = _read(root, "lib/application/cli.ml")
    if f"workflow-verifier {version}\\n" not in cli:
        raise ValueError("CLI version does not match dune-project")
    changelog = _read(root, "CHANGELOG.md")
    if (
        re.search(
            rf"(?m)^##\s+{re.escape(version)}(?:\s+-\s+[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})?\s*$",
            changelog,
        )
        is None
    ):
        raise ValueError("CHANGELOG has no exact release heading")
    curl_path = root / "lib" / "application" / "curl_transport.ml"
    if curl_path.is_file():
        curl = curl_path.read_text(encoding="utf-8")
        if f"workflow-verifier/{version}" not in curl:
            raise ValueError("resolver User-Agent version does not match dune-project")
    if not allow_development and version.endswith("-dev"):
        raise ValueError("development versions are not publishable")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"release tag {tag} does not match v{version}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag")
    parser.add_argument("--allow-development", action="store_true")
    arguments = parser.parse_args()
    version = validate(
        arguments.root,
        arguments.tag,
        allow_development=arguments.allow_development,
    )
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
