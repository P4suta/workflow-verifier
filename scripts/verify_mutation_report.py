#!/usr/bin/env python3
"""Verify a non-vacuous, complete ocaml-mutants run report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any


TOP_FIELDS = {
    "document_type",
    "schema_version",
    "run_id",
    "status",
    "started_at",
    "finished_at",
    "workspace",
    "profile",
    "selection",
    "test",
    "cache",
    "summary",
    "mutants",
    "not_run",
    "expectations",
    "failure",
    "skips",
    "warnings",
}
SUMMARY_FIELDS = {
    "kind",
    "total",
    "executed",
    "not_run",
    "killed",
    "survived",
    "timeout",
    "unconfirmed_timeouts",
    "inconclusive",
    "error",
    "expected_survivors",
    "unexpected_survivors",
    "unfulfilled_expectations",
    "detected",
    "score",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX20 = re.compile(r"^[0-9a-f]{20}$")
INFRASTRUCTURE_FAILURE_MARKERS = (
    "another dune instance is currently running",
    "waiting for build directory lock",
    "failed to acquire dune build lock",
    "runner failed during spawnchild",
    "createprocessasuserw failed",
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")


def _load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect mutation report {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"mutation report must be a nonempty regular non-symlink file: {path}")
    if metadata.st_size > 256 * 1024 * 1024:
        raise ValueError(f"mutation report exceeds 256 MiB: {path}")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse mutation report {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("mutation report must be an object")
    return document, "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise ValueError(f"{label} must be a safe relative path")
    return path.as_posix()


def _required_prefix(value: str) -> str:
    normalized = _safe_path(value.rstrip("/"), "required prefix")
    return normalized + "/"


def _counter(summary: dict[str, Any], name: str) -> int:
    value = summary[name]
    if type(value) is not int or value < 0:
        raise ValueError(f"mutation summary {name} must be a nonnegative integer")
    return value


def _result_evidence_text(result: dict[str, Any], label: str) -> str:
    chunks: list[str] = []
    error = result.get("error")
    if error is not None:
        chunks.append(json.dumps(error, ensure_ascii=False, sort_keys=True))
    for stream_name in ("stdout", "stderr"):
        stream = result.get(stream_name)
        if not isinstance(stream, dict) or not isinstance(stream.get("contents"), str):
            raise ValueError(f"{label}.{stream_name} is malformed")
        chunks.append(stream["contents"])
    return "\n".join(chunks).casefold()


def verify(report_path: Path, required_prefixes: list[str]) -> dict[str, Any]:
    if not required_prefixes:
        raise ValueError("at least one required mutation path prefix is required")
    prefixes = sorted({_required_prefix(prefix) for prefix in required_prefixes})
    document, report_digest = _load(report_path)
    _exact_fields(document, TOP_FIELDS, "mutation report")
    if document["document_type"] != "ocaml-mutants.run-report-v1" or document["schema_version"] != 1:
        raise ValueError("mutation report is not ocaml-mutants.run-report-v1 schema version 1")
    if document["status"] != "completed" or document["failure"] is not None:
        raise ValueError("mutation gate requires a successfully completed run")
    if document["profile"] not in {"balanced", "strong", "all"}:
        raise ValueError("mutation report has an unknown profile")
    workspace = document["workspace"]
    if not isinstance(workspace, dict) or not HEX64.fullmatch(str(workspace.get("digest", ""))):
        raise ValueError("mutation report has an invalid workspace digest")
    summary = document["summary"]
    if not isinstance(summary, dict):
        raise ValueError("mutation report summary must be an object")
    _exact_fields(summary, SUMMARY_FIELDS, "mutation summary")
    if summary["kind"] != "complete":
        raise ValueError("mutation gate requires a complete mutation run")
    counters = {
        name: _counter(summary, name)
        for name in SUMMARY_FIELDS
        if name not in {"kind", "score"}
    }
    mutants = document["mutants"]
    not_run = document["not_run"]
    if not isinstance(mutants, list) or not isinstance(not_run, list):
        raise ValueError("mutation report mutant collections must be arrays")
    if not_run or counters["not_run"] != 0:
        raise ValueError("complete mutation report cannot contain not-run mutants")
    if not mutants:
        raise ValueError("mutation report is vacuous: no mutants were executed")

    actual = {"killed": 0, "survived": 0, "timeout": 0, "inconclusive": 0, "error": 0}
    expected_survivors = 0
    unexpected_survivors = 0
    unconfirmed_timeouts = 0
    full_ids: set[str] = set()
    prefix_counts = {prefix: 0 for prefix in prefixes}
    for index, result in enumerate(mutants):
        label = f"mutation result {index}"
        if not isinstance(result, dict) or not isinstance(result.get("mutant"), dict):
            raise ValueError(f"{label} is malformed")
        mutant = result["mutant"]
        identifier = mutant.get("id")
        full_id = mutant.get("full_id")
        if (
            not isinstance(identifier, str)
            or not HEX20.fullmatch(identifier)
            or not isinstance(full_id, str)
            or not HEX64.fullmatch(full_id)
            or identifier != full_id[:20]
        ):
            raise ValueError(f"{label} has an invalid identity")
        if full_id in full_ids:
            raise ValueError(f"mutation report contains duplicate mutant {full_id}")
        full_ids.add(full_id)
        path = _safe_path(mutant.get("path"), f"{label}.path")
        for prefix in prefixes:
            if path.startswith(prefix):
                prefix_counts[prefix] += 1
        outcome = result.get("outcome")
        if outcome not in actual:
            raise ValueError(f"{label} has an invalid outcome")
        evidence_text = _result_evidence_text(result, label)
        for marker in INFRASTRUCTURE_FAILURE_MARKERS:
            if marker in evidence_text:
                raise ValueError(
                    f"{label} records an infrastructure failure marker: {marker}"
                )
        actual[outcome] += 1
        expected = result.get("expected_survivor")
        if type(expected) is not bool:
            raise ValueError(f"{label}.expected_survivor must be boolean")
        expectation = result.get("expectation")
        if expected:
            if (
                outcome != "survived"
                or not isinstance(expectation, dict)
                or expectation.get("status") != "fulfilled"
                or not isinstance(expectation.get("reason"), str)
                or not expectation["reason"].strip()
            ):
                raise ValueError(f"{label} has an invalid equivalent-mutant expectation")
            expected_survivors += 1
        elif outcome == "survived":
            unexpected_survivors += 1
        if outcome == "timeout" and result.get("timeout_confirmed") is not True:
            unconfirmed_timeouts += 1

    for prefix, count in prefix_counts.items():
        if count == 0:
            raise ValueError(f"mutation report has no executed mutant under {prefix.rstrip('/')}")
    if counters["total"] != len(mutants) or counters["executed"] != len(mutants):
        raise ValueError("mutation summary counters do not match executed mutants")
    for outcome, count in actual.items():
        if counters[outcome] != count:
            raise ValueError(f"mutation summary counters do not match {outcome} outcomes")
    if (
        counters["expected_survivors"] != expected_survivors
        or counters["unexpected_survivors"] != unexpected_survivors
        or counters["unconfirmed_timeouts"] != unconfirmed_timeouts
    ):
        raise ValueError("mutation summary counters do not match survivor/timeout evidence")
    detected = actual["killed"] + actual["timeout"] - unconfirmed_timeouts
    if counters["detected"] != detected:
        raise ValueError("mutation summary detected counter is inconsistent")
    failures: list[str] = []
    if unexpected_survivors:
        amount = "one" if unexpected_survivors == 1 else str(unexpected_survivors)
        failures.append(f"{amount} unexpected mutant{'s' if unexpected_survivors != 1 else ''} survived")
    if actual["inconclusive"]:
        failures.append(f"{actual['inconclusive']} mutation outcomes were inconclusive")
    if actual["error"]:
        failures.append(f"{actual['error']} mutation outcomes failed")
    if unconfirmed_timeouts:
        failures.append(f"{unconfirmed_timeouts} mutation timeouts were unconfirmed")
    if counters["unfulfilled_expectations"]:
        failures.append(f"{counters['unfulfilled_expectations']} mutation expectations were unfulfilled")
    if detected == 0 and unexpected_survivors == 0:
        failures.append("no mutant was detected")
    return {
        "detected": detected,
        "expected_survivors": expected_survivors,
        "failures": failures,
        "mutants": len(mutants),
        "passed": not failures,
        "profile": document["profile"],
        "report_digest": report_digest,
        "required_prefixes": prefixes,
        "schema": "mutation-gate-v1",
        "unexpected_survivors": unexpected_survivors,
        "workspace_digest": workspace["digest"],
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
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-prefix", action="append", default=[])
    arguments = parser.parse_args()
    try:
        result = verify(arguments.report, arguments.require_prefix)
        _atomic_json(arguments.output, result)
    except ValueError as error:
        print(f"mutation gate: {error}", file=sys.stderr)
        return 2
    if not result["passed"]:
        for failure in result["failures"]:
            print(f"mutation gate: {failure}", file=sys.stderr)
        return 1
    print(
        f"mutation gate: {result['detected']}/{result['mutants']} detected, "
        f"{result['expected_survivors']} reviewed equivalents"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
