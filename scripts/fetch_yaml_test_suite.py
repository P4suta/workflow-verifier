#!/usr/bin/env python3
"""Fetch the immutable, MIT-licensed yaml-test-suite release on explicit opt-in."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/yaml/yaml-test-suite.git"
RELEASE = "data-2022-01-17"
COMMIT = "6e6c296ae9c9d2d5c4134b4b64d01b29ac19ff6f"
DEFAULT_DESTINATION = ROOT / "_build" / "upstream" / "yaml-test-suite-data-2022-01-17"


def git(*arguments: str, cwd: pathlib.Path | None = None) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def validate(destination: pathlib.Path) -> bool:
    if not (destination / ".git").exists():
        return False
    actual = git("rev-parse", "HEAD^{commit}", cwd=destination)
    if actual != COMMIT:
        raise RuntimeError(
            f"suite checkout digest mismatch: expected {COMMIT}, found {actual}"
        )
    count = sum(1 for _ in destination.rglob("in.yaml"))
    if count != 402:
        raise RuntimeError(f"suite case count mismatch: expected 402, found {count}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--destination", type=pathlib.Path, default=DEFAULT_DESTINATION)
    arguments = parser.parse_args()
    destination = arguments.destination.resolve()
    if validate(destination):
        print(destination)
        return
    if destination.exists():
        raise RuntimeError(f"refusing to replace non-suite path: {destination}")
    if not arguments.allow_network:
        raise RuntimeError("suite is absent; pass --allow-network to fetch the pinned release")
    destination.parent.mkdir(parents=True, exist_ok=True)
    git(
        "clone",
        "--branch",
        RELEASE,
        "--depth",
        "1",
        "--config",
        "advice.detachedHead=false",
        REPOSITORY,
        str(destination),
    )
    if not validate(destination):
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError("fetched suite could not be validated")
    print(destination)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"yaml-test-suite: {error}", file=sys.stderr)
        raise SystemExit(1) from error
