#!/usr/bin/env python3
"""Validate the immutable evaluation corpus and enforce precision/recall gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

PROVIDERS = ("github", "gitlab", "azure", "circleci")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?$")
DIAGNOSTIC_ID = re.compile(r"^diag_[0-9a-f]{20}$")
RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
SPDX_EXPRESSION = re.compile(r"^[A-Za-z0-9.+() -]+$")

ROOT_FIELDS = {"schema", "repositories"}
REPOSITORY_FIELDS = {
    "id",
    "provider",
    "url",
    "revision",
    "checkout",
    "source_digest",
    "license",
    "license_path",
    "license_digest",
    "report",
    "expected_diagnostics",
    "allowed_diagnostics",
}
EXPECTATION_FIELDS = {"id", "rule_id"}
REPORT_FIELDS = {
    "completeness",
    "configuration",
    "diagnostics",
    "digest",
    "gate",
    "graphs",
    "inputs",
    "lock",
    "persona",
    "provider_profiles",
    "properties",
    "schema",
    "snapshot",
    "summary",
    "tool",
}
DIAGNOSTIC_FIELDS = {
    "capabilities",
    "confidence",
    "evidence",
    "fix",
    "id",
    "message",
    "rule_id",
    "severity",
    "span",
    "trace",
}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect JSON input {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"JSON input must be a regular non-symlink file: {path}")
    if metadata.st_size == 0 or metadata.st_size > 64 * 1024 * 1024:
        raise ValueError(f"JSON input has an invalid size: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse JSON input {path}: {error}") from error


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return path


def _inside(root: Path, relative: PurePosixPath, label: str) -> Path:
    root_resolved = root.resolve()
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} escapes or does not exist under {root}") from error
    return candidate


def _sha256_bytes(contents: bytes) -> str:
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def tree_digest(root: Path) -> str:
    """Hash a source snapshot by canonical path, size, and file digest."""
    try:
        metadata = root.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect corpus checkout {root}: {error}") from error
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"corpus checkout must be a directory, not a symlink: {root}")
    records: list[dict[str, Any]] = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")
    ):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            raise ValueError(f"corpus checkout contains forbidden VCS metadata: {path}")
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError(f"corpus checkout contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"corpus checkout contains a non-regular file: {path}")
        records.append(
            {
                "digest": _sha256_file(path),
                "path": relative.as_posix(),
                "size": metadata.st_size,
            }
        )
    if not records:
        raise ValueError(f"corpus checkout is empty: {root}")
    return _sha256_bytes(_canonical({"files": records, "schema": "source-tree-v1"}))


def _url(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free immutable HTTPS origin")
    return value


def _expectations(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    result: dict[str, str] = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{label}[{index}] must be an object")
        _exact_fields(item, EXPECTATION_FIELDS, f"{label}[{index}]")
        identifier = item["id"]
        rule_id = item["rule_id"]
        if not isinstance(identifier, str) or not DIAGNOSTIC_ID.fullmatch(identifier):
            raise ValueError(f"{label}[{index}].id is not a canonical diagnostic ID")
        if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
            raise ValueError(f"{label}[{index}].rule_id is invalid")
        if identifier in result:
            raise ValueError(f"{label} contains duplicate diagnostic {identifier}")
        result[identifier] = rule_id
    return result


def _report_diagnostics(path: Path) -> dict[str, str]:
    document = _load_json(path)
    if not isinstance(document, dict) or document.get("schema") != "report-v2":
        raise ValueError(f"{path} is not a report-v2 document")
    _exact_fields(document, REPORT_FIELDS, f"{path} report")
    tool = document.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "workflow-verifier":
        raise ValueError(f"{path} was not produced by workflow-verifier")
    if document.get("persona") != "audit":
        raise ValueError(f"{path} is not an audit report")
    claimed_digest = document.get("digest")
    if not isinstance(claimed_digest, str) or not DIGEST.fullmatch(claimed_digest):
        raise ValueError(f"{path} has an invalid report digest")
    provisional = dict(document)
    provisional["digest"] = None
    if claimed_digest != _sha256_bytes(_canonical(provisional)):
        raise ValueError(f"{path} report digest does not authenticate canonical content")
    diagnostics = document.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise ValueError(f"{path} diagnostics must be an array")
    result: dict[str, str] = {}
    for index, item in enumerate(diagnostics):
        if not isinstance(item, dict):
            raise ValueError(f"{path} diagnostic {index} must be an object")
        _exact_fields(item, DIAGNOSTIC_FIELDS, f"{path} diagnostic {index}")
        identifier = item.get("id")
        rule_id = item.get("rule_id")
        if not isinstance(identifier, str) or not DIAGNOSTIC_ID.fullmatch(identifier):
            raise ValueError(f"{path} diagnostic {index} has an invalid ID")
        if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
            raise ValueError(f"{path} diagnostic {index} has an invalid rule ID")
        if identifier in result:
            raise ValueError(f"{path} contains duplicate diagnostic {identifier}")
        result[identifier] = rule_id
    return result


def _ratio(numerator: int, denominator: int) -> str:
    value = Decimal(1) if denominator == 0 else Decimal(numerator) / Decimal(denominator)
    return f"{value.quantize(Decimal('0.000001')):.6f}"


def _repository(
    value: Any,
    index: int,
    corpus_root: Path,
    reports_root: Path,
) -> tuple[dict[str, Any], dict[str, int]]:
    label = f"repositories[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    _exact_fields(value, REPOSITORY_FIELDS, label)
    identifier = value["id"]
    if (
        not isinstance(identifier, str)
        or not IDENTIFIER.fullmatch(identifier)
        or ".." in PurePosixPath(identifier).parts
    ):
        raise ValueError(f"{label}.id is invalid")
    provider = value["provider"]
    if provider not in PROVIDERS:
        raise ValueError(f"{label}.provider is unsupported")
    url = _url(value["url"], f"{label}.url")
    revision = value["revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError(f"{label}.revision must be an immutable 40-character lowercase commit")
    checkout_relative = _safe_relative(value["checkout"], f"{label}.checkout")
    checkout = _inside(corpus_root, checkout_relative, f"{label}.checkout")
    actual_source_digest = tree_digest(checkout)
    source_digest = value["source_digest"]
    if not isinstance(source_digest, str) or not DIGEST.fullmatch(source_digest):
        raise ValueError(f"{label}.source_digest is invalid")
    if source_digest != actual_source_digest:
        raise ValueError(f"{label} source digest does not match checkout")

    license_expression = value["license"]
    if (
        not isinstance(license_expression, str)
        or not SPDX_EXPRESSION.fullmatch(license_expression)
        or license_expression.upper() in {"", "NOASSERTION", "NONE"}
    ):
        raise ValueError(f"{label}.license must be a reviewed SPDX expression")
    license_relative = _safe_relative(value["license_path"], f"{label}.license_path")
    license_path = _inside(checkout, license_relative, f"{label}.license_path")
    license_metadata = license_path.lstat()
    if license_path.is_symlink() or not stat.S_ISREG(license_metadata.st_mode):
        raise ValueError(f"{label}.license_path must be a regular non-symlink file")
    license_digest = value["license_digest"]
    if not isinstance(license_digest, str) or not DIGEST.fullmatch(license_digest):
        raise ValueError(f"{label}.license_digest is invalid")
    if _sha256_file(license_path) != license_digest:
        raise ValueError(f"{label} license digest does not match license evidence")

    report_relative = _safe_relative(value["report"], f"{label}.report")
    report_path = _inside(reports_root, report_relative, f"{label}.report")
    actual = _report_diagnostics(report_path)
    expected = _expectations(value["expected_diagnostics"], f"{label}.expected_diagnostics")
    allowed = _expectations(value["allowed_diagnostics"], f"{label}.allowed_diagnostics")
    overlap = sorted(set(expected) & set(allowed))
    if overlap:
        raise ValueError(f"{label} diagnostics cannot be both expected and allowed: {overlap[0]}")
    for diagnostic_id in sorted(set(actual) & set(expected)):
        if actual[diagnostic_id] != expected[diagnostic_id]:
            raise ValueError(f"{label} expected rule mismatch for {diagnostic_id}")
    for diagnostic_id in sorted(set(actual) & set(allowed)):
        if actual[diagnostic_id] != allowed[diagnostic_id]:
            raise ValueError(f"{label} allowed rule mismatch for {diagnostic_id}")

    actual_ids = set(actual)
    expected_ids = set(expected)
    allowed_ids = set(allowed)
    matched = actual_ids & expected_ids
    missing = expected_ids - actual_ids
    accepted = actual_ids & allowed_ids
    unexpected = actual_ids - expected_ids - allowed_ids
    result = {
        "allowed": sorted(accepted),
        "expected": sorted(expected_ids),
        "id": identifier,
        "missing": sorted(missing),
        "provider": provider,
        "report_digest": _sha256_file(report_path),
        "revision": revision,
        "source_digest": source_digest,
        "unexpected": sorted(unexpected),
        "url": url,
    }
    counts = {
        "allowed": len(accepted),
        "false_negative": len(missing),
        "false_positive": len(unexpected),
        "true_positive": len(matched),
    }
    return result, counts


def evaluate(
    manifest_path: Path,
    corpus_root: Path,
    reports_root: Path,
    *,
    release: bool = False,
) -> dict[str, Any]:
    document = _load_json(manifest_path)
    if not isinstance(document, dict):
        raise ValueError("corpus manifest must be an object")
    _exact_fields(document, ROOT_FIELDS, "corpus manifest")
    if document["schema"] != "corpus-v1":
        raise ValueError("corpus manifest schema must be corpus-v1")
    repositories = document["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("corpus manifest repositories must be a nonempty array")

    evaluated: list[dict[str, Any]] = []
    totals = {"allowed": 0, "false_negative": 0, "false_positive": 0, "true_positive": 0}
    identifiers: set[str] = set()
    origins: set[tuple[str, str]] = set()
    provider_counts = {provider: 0 for provider in PROVIDERS}
    provider_expected = {provider: 0 for provider in PROVIDERS}
    for index, repository in enumerate(repositories):
        result, counts = _repository(repository, index, corpus_root, reports_root)
        if result["id"] in identifiers:
            raise ValueError(f"duplicate corpus repository id: {result['id']}")
        identity = (result["url"], result["revision"])
        if identity in origins:
            raise ValueError(
                f"duplicate corpus repository origin: {result['url']}@{result['revision']}"
            )
        identifiers.add(result["id"])
        origins.add(identity)
        provider_counts[result["provider"]] += 1
        provider_expected[result["provider"]] += len(result["expected"])
        for key, count in counts.items():
            totals[key] += count
        evaluated.append(result)

    if release:
        for provider in PROVIDERS:
            if provider_counts[provider] < 100:
                raise ValueError(
                    f"release corpus requires at least 100 repositories for {provider}; "
                    f"found {provider_counts[provider]}"
                )
        for provider in PROVIDERS:
            if provider_expected[provider] == 0:
                raise ValueError(
                    f"release corpus has no known-vulnerability expectation for {provider}"
                )

    normalized_repositories = []
    for repository in repositories:
        normalized = dict(repository)
        normalized["expected_diagnostics"] = sorted(
            repository["expected_diagnostics"], key=lambda item: item["id"].encode("utf-8")
        )
        normalized["allowed_diagnostics"] = sorted(
            repository["allowed_diagnostics"], key=lambda item: item["id"].encode("utf-8")
        )
        normalized_repositories.append(normalized)
    normalized_manifest = {
        "repositories": sorted(
            normalized_repositories, key=lambda item: item["id"].encode("utf-8")
        ),
        "schema": "corpus-v1",
    }

    precision = _ratio(totals["true_positive"], totals["true_positive"] + totals["false_positive"])
    recall = _ratio(totals["true_positive"], totals["true_positive"] + totals["false_negative"])
    failures: list[str] = []
    if Decimal(precision) < Decimal("0.950000"):
        failures.append(f"precision {precision} is below 0.950000")
    if Decimal(recall) < Decimal("1.000000"):
        failures.append(f"recall {recall} is below 1.000000")
    metrics: dict[str, Any] = dict(totals)
    metrics["precision"] = precision
    metrics["recall"] = recall
    return {
        "failures": failures,
        "manifest_digest": _sha256_bytes(_canonical(normalized_manifest)),
        "metrics": metrics,
        "passed": not failures,
        "providers": provider_counts,
        "repositories": sorted(evaluated, key=lambda item: item["id"].encode("utf-8")),
        "schema": "corpus-report-v1",
    }


def _atomic_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--corpus-root", required=True, type=Path)
    parser.add_argument("--reports-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release", action="store_true")
    arguments = parser.parse_args()
    try:
        result = evaluate(
            arguments.manifest,
            arguments.corpus_root,
            arguments.reports_root,
            release=arguments.release,
        )
        _atomic_json(arguments.output, result)
    except ValueError as error:
        print(f"corpus gate: {error}", file=sys.stderr)
        return 2
    if not result["passed"]:
        for failure in result["failures"]:
            print(f"corpus gate: {failure}", file=sys.stderr)
        return 1
    print(
        "corpus gate: "
        f"precision={result['metrics']['precision']} "
        f"recall={result['metrics']['recall']} repositories={len(result['repositories'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
