#!/usr/bin/env python3
"""Validate the squash-commit subject carried by a pull request title."""

from __future__ import annotations

import argparse
import re
import sys

TYPES = (
    "feat",
    "fix",
    "perf",
    "refactor",
    "docs",
    "test",
    "build",
    "ci",
    "chore",
    "deps",
    "revert",
    "style",
)
TYPE_PATTERN = "(?:" + "|".join(TYPES) + ")"
TITLE = re.compile(
    rf"^{TYPE_PATTERN}(?:\([A-Za-z0-9][A-Za-z0-9._/-]*\))?!?: "
    r"\S(?:[^\r\n]*\S)?$"
)


def validate_title(title: str) -> str:
    if TITLE.fullmatch(title) is None:
        allowed = "|".join(TYPES)
        raise ValueError(
            f"PR title must match {allowed}(optional-scope)(optional-!): non-empty summary"
        )
    return title


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("title")
    arguments = parser.parse_args()
    try:
        validate_title(arguments.title)
    except ValueError as error:
        print(f"PR title gate: {error}", file=sys.stderr)
        return 1
    print("PR title gate: valid Conventional Commit title")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
