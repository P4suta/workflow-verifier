#!/usr/bin/env python3
"""Verify the public package installs one CLI and the versioned schemas only."""

from __future__ import annotations

import pathlib
import sys


def fail(message: str) -> None:
    print(f"install-layout gate: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: verify_install_layout.py INSTALL_ROOT")

root = pathlib.Path(sys.argv[1]).resolve()
if not root.is_dir():
    fail(f"install root does not exist: {root}")

files = sorted(path for path in root.rglob("*") if path.is_file())
relative = [path.relative_to(root).as_posix() for path in files]
executables = [path for path in relative if path in {"bin/workflow-verifier", "bin/workflow-verifier.exe"}]
if len(executables) != 1:
    fail(f"expected one workflow-verifier executable, found {executables}")

schemas = {
    "share/workflow-verifier/report-v1.schema.json",
    "share/workflow-verifier/config-v1.schema.json",
}
missing = schemas - set(relative)
if missing:
    fail(f"missing schemas: {', '.join(sorted(missing))}")

installed_schemas = {
    path
    for path in relative
    if path.startswith("share/workflow-verifier/") and path.endswith(".schema.json")
}
unexpected_schemas = installed_schemas - schemas
if unexpected_schemas:
    fail(f"non-public schemas leaked into analyzer install: {', '.join(sorted(unexpected_schemas))}")

for path in relative:
    if pathlib.PurePosixPath(path).suffix in {".cmi", ".cma", ".cmxa", ".cmx", ".a"}:
        fail(f"private analyzer library leaked into install: {path}")

print(f"install-layout gate: {len(executables)} executable, {len(schemas)} schemas")
