#!/usr/bin/env python3
"""Validate SARIF output against the digest-pinned OASIS 2.1.0 schema."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft4Validator, FormatChecker

OASIS_SCHEMA_ID = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
DRAFT4_SCHEMA_ID = "http://json-schema.org/draft-04/schema#"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field {key}")
        value[key] = item
    return value


def _load(path: Path, label: str) -> tuple[Any, bytes]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"{label} must be a nonempty regular non-symlink file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {label}: {error}") from error
    return value, raw


def verify(schema_path: Path, schema_digest: str, documents: list[Path]) -> int:
    if not DIGEST.fullmatch(schema_digest):
        raise ValueError("OASIS schema digest must be lowercase sha256")
    schema, raw_schema = _load(schema_path, "OASIS SARIF schema")
    actual_digest = "sha256:" + hashlib.sha256(raw_schema).hexdigest()
    if actual_digest != schema_digest:
        raise ValueError("OASIS SARIF schema digest mismatch")
    if not isinstance(schema, dict):
        raise ValueError("OASIS SARIF schema root must be an object")
    if schema.get("id") != OASIS_SCHEMA_ID or schema.get("$schema") != DRAFT4_SCHEMA_ID:
        raise ValueError("unexpected OASIS SARIF schema identity")
    Draft4Validator.check_schema(schema)
    validator = Draft4Validator(schema, format_checker=FormatChecker())
    if not documents:
        raise ValueError("at least one SARIF document is required")
    for path in documents:
        document, _raw = _load(path, f"SARIF document {path}")
        if not isinstance(document, dict) or document.get("$schema") != OASIS_SCHEMA_ID:
            raise ValueError(f"SARIF document {path} does not name the OASIS schema")
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            error = errors[0]
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            raise ValueError(f"SARIF document {path} at {location}: {error.message}")
    return len(documents)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--schema-digest", required=True)
    parser.add_argument("documents", nargs="+", type=Path)
    arguments = parser.parse_args()
    try:
        count = verify(arguments.schema, arguments.schema_digest, arguments.documents)
    except (OSError, ValueError) as error:
        print(f"SARIF schema gate: {error}", file=sys.stderr)
        return 2
    print(f"SARIF schema gate: {count} document(s) valid against OASIS SARIF 2.1.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
