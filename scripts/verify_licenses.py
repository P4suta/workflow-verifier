#!/usr/bin/env python3
"""Verify the complete dual-license texts and every public SPDX surface."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPDX_EXPRESSION = "MIT OR Apache-2.0"
APACHE_MARKERS = (
    "Apache License\n                           Version 2.0, January 2004",
    "1. Definitions.",
    "2. Grant of Copyright License.",
    "3. Grant of Patent License.",
    "4. Redistribution.",
    "5. Submission of Contributions.",
    "6. Trademarks.",
    "7. Disclaimer of Warranty.",
    "8. Limitation of Liability.",
    "9. Accepting Warranty or Additional Liability.",
    "END OF TERMS AND CONDITIONS",
    "APPENDIX: How to apply the Apache License to your work.",
)
MIT_MARKERS = (
    "MIT License",
    "Permission is hereby granted, free of charge",
    "The above copyright notice and this permission notice shall be included",
    'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND',
    "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE",
)


def has_exact_spdx(source: str) -> bool:
    quoted = re.escape(f'"{SPDX_EXPRESSION}"')
    return re.search(rf"(?:\(license\s+|license\s*:\s*){quoted}", source) is not None


def validate_apache(source: str) -> list[str]:
    failures: list[str] = []
    normalized = source.replace("\r\n", "\n")
    if len(normalized) < 10_000:
        failures.append("Apache-2.0 text is truncated")
    for marker in APACHE_MARKERS:
        if marker not in normalized:
            prefix = marker.split(".", 1)[0]
            label = f"section {prefix}" if prefix.isdigit() else prefix.lower()
            failures.append(f"Apache-2.0 text is missing {label}")
    return failures


def validate_mit(source: str) -> list[str]:
    failures: list[str] = []
    normalized = source.replace("\r\n", "\n")
    if len(normalized) < 900:
        failures.append("MIT text is truncated")
    for marker in MIT_MARKERS:
        if marker not in normalized:
            failures.append(f"MIT text is missing {marker!r}")
    return failures


def read(root: pathlib.Path, relative: str, failures: list[str]) -> str:
    path = root / relative
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("must be a regular non-symlink file")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as error:
        failures.append(f"{relative}: {error}")
        return ""


def validate(root: pathlib.Path) -> list[str]:
    failures: list[str] = []
    apache = read(root, "LICENSE-APACHE", failures)
    mit = read(root, "LICENSE-MIT", failures)
    dune_project = read(root, "dune-project", failures)
    opam = read(root, "workflow-verifier.opam", failures)
    readme = read(root, "README.md", failures)

    failures.extend(validate_apache(apache))
    failures.extend(validate_mit(mit))
    if not has_exact_spdx(dune_project):
        failures.append(f"dune-project must declare {SPDX_EXPRESSION!r}")
    if not has_exact_spdx(opam):
        failures.append(f"workflow-verifier.opam must declare {SPDX_EXPRESSION!r}")
    if f"License: {SPDX_EXPRESSION}" not in readme:
        failures.append("README license badge must state the dual-license expression")
    return failures


def run() -> None:
    failures = validate(ROOT)
    if failures:
        for failure in failures:
            print(f"license gate: {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("license gate: complete MIT and Apache-2.0 texts; SPDX surfaces agree")


if __name__ == "__main__":
    run()
