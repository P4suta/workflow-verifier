#!/usr/bin/env python3
"""Validate end-to-end CLI and live OCI dogfood evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any


MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ARTIFACTS = (
    "report.json",
    "report.sarif.json",
    "explain.txt",
    "graph.json",
    "graph.dot",
    "diff.json",
    "fix.patch",
    "policy.json",
    "lock.json",
    "doctor.json",
    "plan.json",
    "run.json",
    "replay.json",
    "audit.json",
)
EXPECTED_FRONTENDS = {"github", "gitlab", "azure", "circleci"}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _bytes(path: pathlib.Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular dogfood artifact {path.name}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"dogfood artifact {path.name} has invalid size {size}")
    value = path.read_bytes()
    if b"\r" in value:
        raise ValueError(f"dogfood artifact {path.name} is not LF-canonical")
    return value


def _json(path: pathlib.Path) -> dict[str, Any]:
    raw = _bytes(path)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _schema(document: dict[str, Any], expected: str, name: str) -> None:
    if document.get("schema") != expected:
        raise ValueError(f"{name} must use {expected}")


def _state(document: dict[str, Any], field: str, expected: str, name: str) -> None:
    value = document.get(field)
    if not isinstance(value, dict) or value.get("state") != expected:
        raise ValueError(f"{name} {field} must be {expected}")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _canonical_without_newline(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _report_frontends(report: dict[str, Any]) -> set[str]:
    inputs = report.get("inputs")
    if not isinstance(inputs, list):
        raise ValueError("report.json lacks source inputs")
    frontends: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("report.json contains an invalid source input")
        path = item["path"].replace("\\", "/").lower()
        while path.startswith("./"):
            path = path[2:]
        if path.startswith(".github/workflows/"):
            frontends.add("github")
        elif path in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
            frontends.add("gitlab")
        elif path in {"azure-pipelines.yml", "azure-pipelines.yaml"}:
            frontends.add("azure")
        elif path in {".circleci/config.yml", ".circleci/config.yaml"}:
            frontends.add("circleci")
    return frontends


def _verify_evidence_chain(evidence: dict[str, Any], name: str) -> str:
    plan_digest = evidence.get("plan_digest")
    events = evidence.get("events")
    if not isinstance(plan_digest, str) or DIGEST.fullmatch(plan_digest) is None:
        raise ValueError(f"{name} has an invalid plan digest")
    if not isinstance(events, list) or not events:
        raise ValueError(f"{name} has no runtime events")
    previous = plan_digest
    for sequence, event in enumerate(events):
        if not isinstance(event, dict) or not isinstance(event.get("body"), dict):
            raise ValueError(f"{name} event {sequence} is invalid")
        if event.get("sequence") != sequence:
            raise ValueError(f"{name} event sequence is not contiguous")
        if event.get("previous_digest") != previous:
            raise ValueError(f"{name} event previous digest mismatch")
        unsigned = {
            "body": event["body"],
            "previous_digest": previous,
            "sequence": sequence,
        }
        expected = "sha256:" + hashlib.sha256(_canonical_without_newline(unsigned)).hexdigest()
        if event.get("digest") != expected:
            raise ValueError(f"{name} event digest mismatch")
        previous = expected
    return previous


def extract_evidence(run_path: pathlib.Path, output: pathlib.Path) -> None:
    run = _json(run_path)
    _schema(run, "sandbox-run-v1", run_path.name)
    evidence = run.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("schema") != "evidence-v1":
        raise ValueError("sandbox-run-v1 lacks evidence-v1")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical(evidence))


def prepare_image(config_path: pathlib.Path, image: str) -> None:
    if DIGEST.fullmatch(image) is None:
        raise ValueError("sandbox image must be a sha256 content digest")
    if config_path.is_symlink() or not config_path.is_file():
        raise ValueError("sandbox config must be a regular file")
    source = config_path.read_text(encoding="utf-8")
    pattern = re.compile(r'(?m)^image\s*=\s*"sha256:[0-9a-f]{64}"\s*$')
    updated, count = pattern.subn(f'image = "{image}"', source)
    if count != 1:
        raise ValueError("sandbox config must contain exactly one pinned image")
    config_path.write_text(updated, encoding="utf-8", newline="\n")


def verify(root: pathlib.Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("dogfood evidence root must be a regular directory")
    raw = {name: _bytes(root / name) for name in ARTIFACTS}

    report = _json(root / "report.json")
    _schema(report, "report-v1", "report.json")
    if not isinstance(report.get("properties"), list) or not report["properties"]:
        raise ValueError("report.json contains no proved properties")
    if report.get("diagnostics") != []:
        raise ValueError("report.json dogfood must contain zero diagnostics")
    if _report_frontends(report) != EXPECTED_FRONTENDS:
        raise ValueError("report.json must analyze all four provider entrypoints")

    sarif = _json(root / "report.sarif.json")
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list):
        raise ValueError("report.sarif.json is not SARIF 2.1.0")

    explain = raw["explain.txt"].decode("utf-8")
    if "trace:\n" not in explain or "capabilities:" not in explain:
        raise ValueError("explain.txt lacks a complete trace or capabilities")

    graph = _json(root / "graph.json")
    if not isinstance(graph.get("nodes"), list) or not graph["nodes"]:
        raise ValueError("graph.json contains no semantic nodes")
    if not isinstance(graph.get("edges"), list):
        raise ValueError("graph.json lacks semantic edges")
    if not raw["graph.dot"].startswith(b"digraph workflow {\n"):
        raise ValueError("graph.dot is not a workflow DOT graph")

    difference = _json(root / "diff.json")
    _schema(difference, "semantic-diff-v1", "diff.json")
    if not isinstance(difference.get("changes"), list):
        raise ValueError("diff.json lacks semantic changes")

    patch = raw["fix.patch"].decode("utf-8")
    if "--- " not in patch or "+++ " not in patch:
        raise ValueError("fix.patch contains no behavior-preserving source diff")

    policy = _json(root / "policy.json")
    _schema(policy, "policy-test-v1", "policy.json")
    cases = policy.get("cases")
    if policy.get("passed") is not True or not isinstance(cases, list) or not cases:
        raise ValueError("policy.json did not execute passing fixtures")
    if not all(isinstance(case, dict) and case.get("passed") is True for case in cases):
        raise ValueError("policy.json contains a failing fixture")

    lock = _json(root / "lock.json")
    if lock.get("schema") not in ("lock-v1", "lock-v2"):
        raise ValueError("lock.json is not a supported canonical lock")

    doctor = _json(root / "doctor.json")
    _schema(doctor, "doctor-v1", "doctor.json")
    backends = doctor.get("backends")
    frontends = doctor.get("frontends")
    if doctor.get("sandbox_executor") is not True or not isinstance(backends, list):
        raise ValueError("doctor.json reports no sandbox executor")
    if (
        not isinstance(frontends, list)
        or len(frontends) != len(EXPECTED_FRONTENDS)
        or set(frontends) != EXPECTED_FRONTENDS
    ):
        raise ValueError("doctor.json does not expose exactly four frontends")
    if not any(
        isinstance(backend, dict)
        and backend.get("id") == "oci:docker"
        and backend.get("available") is True
        for backend in backends
    ):
        raise ValueError("doctor.json reports no healthy oci:docker backend")

    plan = _json(root / "plan.json")
    _schema(plan, "runner-v1", "plan.json")
    _state(plan, "status", "complete", "plan.json")
    if plan.get("backend") != "oci:docker" or not plan.get("steps"):
        raise ValueError("plan.json is not a complete executable OCI plan")

    run = _json(root / "run.json")
    _schema(run, "sandbox-run-v1", "run.json")
    _state(run, "outcome", "completed", "run.json")
    evidence = run.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("schema") != "evidence-v1":
        raise ValueError("run.json lacks evidence-v1")
    if evidence.get("plan_digest") != plan.get("digest"):
        raise ValueError("run.json evidence does not bind plan.json")
    evidence_tail = _verify_evidence_chain(evidence, "run.json evidence")
    events = evidence.get("events")
    kinds = {
        body.get("kind")
        for event in events
        if isinstance(event, dict)
        for body in [event.get("body")]
        if isinstance(body, dict)
    }
    required_kinds = {"backend_attested", "process_started", "artifact_recorded"}
    if not required_kinds.issubset(kinds):
        raise ValueError("run.json lacks backend, process, or artifact evidence")

    replay = _json(root / "replay.json")
    if replay != evidence:
        raise ValueError("replay.json is not the exact run evidence")

    audit = _json(root / "audit.json")
    _schema(audit, "sandbox-audit-v1", "audit.json")
    _state(audit, "status", "verified", "audit.json")
    _state(audit, "reconciliation", "Proved", "audit.json")
    if audit.get("event_count") != len(events):
        raise ValueError("audit.json event count does not match evidence")
    if audit.get("evidence_tail") != evidence_tail:
        raise ValueError("audit.json evidence tail does not match evidence")
    if audit.get("plan_digest") != plan.get("digest"):
        raise ValueError("audit.json does not bind plan.json")

    artifacts = [
        {
            "digest": "sha256:" + hashlib.sha256(raw[name]).hexdigest(),
            "name": name,
            "size": len(raw[name]),
        }
        for name in ARTIFACTS
    ]
    return {"artifacts": artifacts, "passed": True, "schema": "dogfood-v1"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract-evidence")
    extract.add_argument("--run", required=True, type=pathlib.Path)
    extract.add_argument("--output", required=True, type=pathlib.Path)
    prepare = subparsers.add_parser("prepare-image")
    prepare.add_argument("--config", required=True, type=pathlib.Path)
    prepare.add_argument("--image", required=True)
    gate = subparsers.add_parser("verify")
    gate.add_argument("--root", required=True, type=pathlib.Path)
    gate.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "extract-evidence":
            extract_evidence(arguments.run, arguments.output)
        elif arguments.command == "prepare-image":
            prepare_image(arguments.config, arguments.image)
        else:
            result = verify(arguments.root)
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_bytes(_canonical(result))
            print(f"dogfood gate: {len(result['artifacts'])} artifacts passed")
    except (OSError, ValueError) as error:
        print(f"dogfood gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
