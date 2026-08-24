#!/usr/bin/env python3
"""Verify the real Just parser and keep the Just/mise task surfaces aligned."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PINNED_JUST = "1.57.0"
REVISION_FIXTURE = "0123456789abcdef0123456789abcdef01234567"


def _run(argv: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot run {' '.join(argv)}: {error}") from error


def verify(root: Path = ROOT, *, just: str = "just") -> list[str]:
    version = _run([just, "--version"], root)
    if version.returncode != 0:
        raise ValueError(f"just --version failed: {version.stderr.strip()}")
    if version.stdout.strip() != f"just {PINNED_JUST}":
        raise ValueError(
            f"Just {PINNED_JUST} is required, got {version.stdout.strip() or '<empty>'}"
        )

    summary = _run([just, "--summary"], root)
    if summary.returncode != 0:
        raise ValueError(f"just --summary failed: {summary.stderr.strip()}")
    just_tasks = set(summary.stdout.split())
    if not just_tasks:
        raise ValueError("just --summary returned no recipes")

    try:
        mise = tomllib.loads((root / "mise.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"cannot parse mise.toml: {error}") from error
    raw_tasks = mise.get("tasks")
    if not isinstance(raw_tasks, dict):
        raise ValueError("mise.toml has no [tasks] table")
    mise_tasks = set(raw_tasks)
    if just_tasks != mise_tasks:
        missing_in_just = sorted(mise_tasks - just_tasks)
        missing_in_mise = sorted(just_tasks - mise_tasks)
        details = []
        if missing_in_just:
            details.append("missing in Just: " + ", ".join(missing_in_just))
        if missing_in_mise:
            details.append("missing in mise: " + ", ".join(missing_in_mise))
        raise ValueError("task names differ (" + "; ".join(details) + ")")

    dry_run = _run(
        [just, "--dry-run", "performance-measure", REVISION_FIXTURE], root
    )
    if dry_run.returncode != 0:
        raise ValueError(
            "just --dry-run performance-measure failed: "
            + (dry_run.stderr.strip() or dry_run.stdout.strip())
        )
    if REVISION_FIXTURE not in dry_run.stdout + dry_run.stderr:
        raise ValueError("performance-measure dry-run did not bind the revision argument")
    return sorted(just_tasks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--just", default="just")
    arguments = parser.parse_args()
    try:
        tasks = verify(arguments.root, just=arguments.just)
    except ValueError as error:
        print(f"task-surface gate: {error}", file=sys.stderr)
        return 1
    print(
        f"task-surface gate: Just {PINNED_JUST}; "
        f"{len(tasks)} aligned Just/mise tasks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
