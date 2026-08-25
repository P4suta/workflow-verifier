#!/usr/bin/env python3
"""Verify local Markdown links offline and reject unsafe or insecure targets."""

from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+['\"][^)]*['\"])?\)")
SCHEMES = {"https", "mailto"}
SKIPPED = {".git", "_build", "_opam", "evaluation"}


def _markdown_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.md"):
        relative = path.relative_to(root)
        if any(part in SKIPPED for part in relative.parts):
            continue
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Markdown input must be a regular non-symlink file: {relative}")
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))


def verify(root: Path) -> int:
    root = root.resolve(strict=True)
    files = _markdown_files(root)
    checked = 0
    for source in files:
        try:
            text = source.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError) as error:
            raise ValueError(f"cannot read {source.relative_to(root)}: {error}") from error
        for match in LINK.finditer(text):
            raw = match.group(1)
            target = urlsplit(raw)
            if target.scheme:
                if target.scheme.lower() not in SCHEMES:
                    raise ValueError(
                        f"{source.relative_to(root)} uses unsupported link scheme {target.scheme}"
                    )
                if target.scheme.lower() == "https" and not target.netloc:
                    raise ValueError(f"{source.relative_to(root)} has malformed HTTPS link {raw}")
                checked += 1
                continue
            decoded = unquote(target.path)
            if not decoded:
                checked += 1
                continue
            if "\\" in decoded or decoded.startswith(("/", "~")):
                raise ValueError(f"{source.relative_to(root)} has unsafe local link {raw}")
            candidate = source.parent / decoded
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                metadata = candidate.lstat()
            except (OSError, ValueError) as error:
                raise ValueError(
                    f"{source.relative_to(root)} has missing or escaping local link {raw}: {error}"
                ) from error
            if candidate.is_symlink() or not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                raise ValueError(
                    f"{source.relative_to(root)} local link is not a regular file/directory: {raw}"
                )
            checked += 1
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    arguments = parser.parse_args()
    try:
        checked = verify(arguments.root)
    except (OSError, ValueError) as error:
        print(f"Markdown link gate: {error}", file=sys.stderr)
        return 1
    print(f"Markdown link gate: {checked} links verified offline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
