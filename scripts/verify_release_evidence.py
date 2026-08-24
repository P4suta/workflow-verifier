#!/usr/bin/env python3
"""Verify two-commit release evidence and signed maintainer attestation."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


PROVIDERS = ("github", "gitlab", "azure", "circleci")
PLATFORMS = ("linux-x86_64", "windows-x86_64", "macos-arm64", "macos-x86_64")
REQUIRED_PERFORMANCE_SCENARIOS = {
    "arcade-scale-analysis",
    "four-provider-analysis",
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
HTTPS = re.compile(r"^https://[^\s]+$")
REVIEW_URL = re.compile(
    r"^https://github\.com/P4suta/workflow-verifier/(?:issues|pull)/[1-9][0-9]*(?:#[^\s]+)?$"
)
ROOT_FIELDS = {
    "corpus",
    "maintainer",
    "official_compat",
    "performance",
    "planned_tag",
    "review",
    "schema",
    "security_attestation",
    "subject_commit",
}
FILE_FIELDS = {"digest", "path"}
PERFORMANCE_FIELDS = FILE_FIELDS | {"platform"}
SECURITY_FIELDS = FILE_FIELDS | {"signature_digest", "signature_path"}
MAINTAINER = "P4suta"
MAINTAINER_EMAIL = "42543015+P4suta@users.noreply.github.com"
SIGNATURE_NAMESPACE = "workflow-verifier-release"
MAINTAINER_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIIGLhVoqkzwA7KEiBKWh+6imgA8yphi5j+iD20y6zmg0"
)
REQUIRED_SECURITY_SCOPE = {
    "authorization-dominance",
    "canonical-protocols-and-evidence-hash-chains",
    "dependency-resolution-redirects-and-allowlists",
    "fix-proof-obligations",
    "native-containment-backends",
    "untrusted-and-secret-dataflow",
    "yaml-parser-and-expression-denial-of-service",
}
FINDING_FIELDS = {
    "due_date",
    "id",
    "owner",
    "severity",
    "status",
    "summary",
    "tracking_url",
}
RISK_FIELDS = {
    "description",
    "due_date",
    "id",
    "owner",
    "severity",
    "tracking_url",
}
ATTESTATION_FIELDS = {
    "completed_at",
    "decision",
    "findings",
    "maintainer",
    "planned_tag",
    "residual_risks",
    "review",
    "schema",
    "scope",
    "subject_commit",
}
OFFICIAL_FIELDS = {
    "acquisition_digest",
    "failures",
    "manifest_digest",
    "passed",
    "projects",
    "providers",
    "repositories",
    "schema",
    "tool_version",
}
OFFICIAL_PROJECT_FIELDS = {
    "diagnostics",
    "files",
    "graphs",
    "id",
    "inputs",
    "provider",
    "report_digest",
    "report_sha256",
    "revision",
    "snapshot_digest",
    "tree",
}
OFFICIAL_SEVERITIES = {"critical", "error", "note", "total", "warning"}
CORPUS_FIELDS = {
    "failures",
    "manifest_digest",
    "metrics",
    "passed",
    "providers",
    "repositories",
    "schema",
}
CORPUS_METRIC_FIELDS = {
    "allowed",
    "false_negative",
    "false_positive",
    "precision",
    "recall",
    "true_positive",
}
CORPUS_REPOSITORY_FIELDS = {
    "allowed",
    "expected",
    "id",
    "missing",
    "provider",
    "report_digest",
    "revision",
    "source_digest",
    "unexpected",
    "url",
}
PERFORMANCE_REPORT_FIELDS = {
    "baseline",
    "comparisons",
    "current",
    "environment",
    "failures",
    "passed",
    "schema",
    "threshold_percent",
}
COMPARISON_FIELDS = {
    "baseline_median_ns",
    "change_percent",
    "current_median_ns",
    "explanation",
    "mode",
    "scenario",
    "status",
}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    extra = sorted(set(value) - fields)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _load_json(path: Path, label: str, *, limit: int = 256 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect {label} {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"{label} must be a nonempty regular non-symlink file: {path}")
    if metadata.st_size > limit:
        raise ValueError(f"{label} exceeds {limit} bytes: {path}")
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {label} {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be an object")
    return document, raw


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or ":" in raw_parts[0]
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return path


def _resolve_file(root: Path, value: Any, label: str) -> tuple[str, Path]:
    relative = _safe_relative(value, label)
    root_resolved = root.resolve(strict=True)
    path = root.joinpath(*relative.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
        metadata = path.lstat()
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} escapes or does not exist") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"{label} must name a nonempty regular non-symlink file")
    return relative.as_posix(), path


def _expect_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _verify_digest(path: Path, expected: Any, label: str) -> None:
    digest = _expect_digest(expected, label)
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise ValueError(f"{label} does not match {path.name}")


def _expect_https(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HTTPS.fullmatch(value) or "\n" in value or "\r" in value:
        raise ValueError(f"{label} must be an HTTPS URL")
    return value


def _expect_review(value: Any, label: str) -> str:
    url = _expect_https(value, label)
    if not REVIEW_URL.fullmatch(url):
        raise ValueError(f"{label} must identify a workflow-verifier issue or pull request")
    return url


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label} must be an array of nonempty strings")
    return value


def _publication_file(root: Path, value: Any, label: str) -> tuple[str, Path, dict[str, Any]]:
    record = _exact(value, FILE_FIELDS, label)
    relative, path = _resolve_file(root, record["path"], f"{label}.path")
    _verify_digest(path, record["digest"], f"{label}.digest")
    return relative, path, record


def _verify_corpus(path: Path) -> None:
    document, _ = _load_json(path, "corpus report")
    _exact(document, CORPUS_FIELDS, "corpus report")
    if document["schema"] != "corpus-report-v1":
        raise ValueError("corpus report schema must be corpus-report-v1")
    if document["passed"] is not True or document["failures"] != []:
        raise ValueError("corpus report must pass with no failures")
    _expect_digest(document["manifest_digest"], "corpus report manifest_digest")

    metrics = _exact(document["metrics"], CORPUS_METRIC_FIELDS, "corpus metrics")
    try:
        precision = Decimal(metrics["precision"])
        recall = Decimal(metrics["recall"])
    except (InvalidOperation, TypeError) as error:
        raise ValueError("corpus precision and recall must be decimals") from error
    if precision < Decimal("0.950000") or recall != Decimal("1.000000"):
        raise ValueError("corpus report must prove at least 95% precision and 100% recall")
    for counter in CORPUS_METRIC_FIELDS - {"precision", "recall"}:
        if type(metrics[counter]) is not int or metrics[counter] < 0:
            raise ValueError(f"corpus metrics.{counter} must be a nonnegative integer")

    providers = _exact(document["providers"], set(PROVIDERS), "corpus providers")
    repositories = document["repositories"]
    if not isinstance(repositories, list) or len(repositories) < 400:
        raise ValueError("corpus report must contain at least 400 repositories")
    counts = {provider: 0 for provider in PROVIDERS}
    known = {provider: False for provider in PROVIDERS}
    identities: set[str] = set()
    origins: set[str] = set()
    for index, raw in enumerate(repositories):
        label = f"corpus repositories[{index}]"
        repository = _exact(raw, CORPUS_REPOSITORY_FIELDS, label)
        provider = repository["provider"]
        if provider not in counts:
            raise ValueError(f"{label}.provider is unsupported")
        identifier = repository["id"]
        revision = repository["revision"]
        url = repository["url"]
        if not isinstance(identifier, str) or not identifier or identifier in identities:
            raise ValueError(f"{label}.id is empty or duplicated")
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            raise ValueError(f"{label}.revision is invalid")
        _expect_https(url, f"{label}.url")
        origin = f"{url}@{revision}"
        if origin in origins:
            raise ValueError(f"{label} duplicates a repository origin")
        identities.add(identifier)
        origins.add(origin)
        _expect_digest(repository["report_digest"], f"{label}.report_digest")
        _expect_digest(repository["source_digest"], f"{label}.source_digest")
        expected = _strings(repository["expected"], f"{label}.expected")
        _strings(repository["allowed"], f"{label}.allowed")
        if _strings(repository["missing"], f"{label}.missing"):
            raise ValueError(f"{label} has missing expected findings")
        if _strings(repository["unexpected"], f"{label}.unexpected"):
            raise ValueError(f"{label} has unexpected findings")
        counts[provider] += 1
        known[provider] = known[provider] or bool(expected)
    for provider in PROVIDERS:
        if type(providers[provider]) is not int or providers[provider] != counts[provider]:
            raise ValueError(f"corpus provider count for {provider} is inconsistent")
        if counts[provider] < 100 or not known[provider]:
            raise ValueError(f"corpus provider {provider} lacks release coverage")


def _verify_performance(path: Path, revision: str, platform: str) -> None:
    document, _ = _load_json(path, f"{platform} performance report", limit=16 * 1024 * 1024)
    _exact(document, PERFORMANCE_REPORT_FIELDS, f"{platform} performance report")
    if document["schema"] != "performance-comparison-v1":
        raise ValueError(f"performance report for {platform} has the wrong schema")
    if document["passed"] is not True or document["failures"] != []:
        raise ValueError(f"performance report for {platform} must pass with no failures")
    if document["threshold_percent"] != "10.000":
        raise ValueError(f"performance report for {platform} must enforce 10 percent")
    baseline = _exact(document["baseline"], {"digest", "revision"}, f"{platform} baseline")
    current = _exact(document["current"], {"digest", "revision"}, f"{platform} current")
    for identity, label in ((baseline, "baseline"), (current, "current")):
        _expect_digest(identity["digest"], f"{platform} {label}.digest")
        if not isinstance(identity["revision"], str) or not REVISION.fullmatch(identity["revision"]):
            raise ValueError(f"{platform} {label}.revision is invalid")
    if current["revision"] != revision:
        raise ValueError(f"performance report for {platform} targets the wrong revision")
    if baseline["revision"] == current["revision"] or baseline["digest"] == current["digest"]:
        raise ValueError(f"performance report for {platform} must use an independent baseline")
    environment = document["environment"]
    if not isinstance(environment, dict) or not environment or any(
        not isinstance(key, str) or not key or not isinstance(value, str) or not value
        for key, value in environment.items()
    ):
        raise ValueError(f"performance report for {platform} has an invalid environment")
    if environment.get("platform") != platform:
        raise ValueError(f"performance report for {platform} has the wrong platform identity")
    comparisons = document["comparisons"]
    if not isinstance(comparisons, list) or not comparisons:
        raise ValueError(f"performance report for {platform} has no comparisons")
    modes_by_scenario: dict[str, set[str]] = {}
    for index, raw in enumerate(comparisons):
        label = f"{platform} comparisons[{index}]"
        comparison = _exact(raw, COMPARISON_FIELDS, label)
        scenario = comparison["scenario"]
        mode = comparison["mode"]
        if not isinstance(scenario, str) or not scenario or mode not in {"cold", "incremental", "warm"}:
            raise ValueError(f"{label} has an invalid scenario or mode")
        if mode in modes_by_scenario.setdefault(scenario, set()):
            raise ValueError(f"{label} duplicates {scenario}/{mode}")
        modes_by_scenario[scenario].add(mode)
        status = comparison["status"]
        if status == "regression":
            raise ValueError(f"performance report for {platform} contains an unexplained regression")
        if status not in {"within-limit", "explained-regression"}:
            raise ValueError(f"{label}.status is invalid")
        explanation = comparison["explanation"]
        if status == "within-limit" and explanation is not None:
            raise ValueError(f"{label} has an unnecessary explanation")
        if status == "explained-regression":
            explanation = _exact(explanation, {"reason", "review"}, f"{label}.explanation")
            if not isinstance(explanation["reason"], str) or not explanation["reason"].strip():
                raise ValueError(f"{label}.explanation.reason is empty")
            _expect_https(explanation["review"], f"{label}.explanation.review")
    if set(modes_by_scenario) != REQUIRED_PERFORMANCE_SCENARIOS:
        raise ValueError(
            f"performance report for {platform} must contain the required scenarios"
        )
    if any(modes != {"cold", "incremental", "warm"} for modes in modes_by_scenario.values()):
        raise ValueError(f"performance report for {platform} omits a required mode")


def _verify_official(path: Path, tag: str) -> None:
    document, _ = _load_json(path, "official compatibility report", limit=8 * 1024 * 1024)
    _exact(document, OFFICIAL_FIELDS, "official compatibility report")
    if document["schema"] != "official-compat-v1":
        raise ValueError("official compatibility report schema must be official-compat-v1")
    if document["passed"] is not True or document["failures"] != []:
        raise ValueError("official compatibility report must pass with no failures")
    _expect_digest(document["acquisition_digest"], "official acquisition_digest")
    _expect_digest(document["manifest_digest"], "official manifest_digest")
    if document["tool_version"] != tag.removeprefix("v"):
        raise ValueError("official compatibility report targets the wrong tool version")
    if document["repositories"] != 8:
        raise ValueError("official compatibility report must contain exactly eight repositories")
    providers = _exact(document["providers"], set(PROVIDERS), "official providers")
    if any(providers[provider] != 2 for provider in PROVIDERS):
        raise ValueError("official compatibility report must contain two repositories per provider")
    projects = document["projects"]
    if not isinstance(projects, list) or len(projects) != 8:
        raise ValueError("official compatibility projects must contain exactly eight entries")
    identities: set[str] = set()
    counts = {provider: 0 for provider in PROVIDERS}
    for index, raw in enumerate(projects):
        label = f"official projects[{index}]"
        project = _exact(raw, OFFICIAL_PROJECT_FIELDS, label)
        identifier = project["id"]
        provider = project["provider"]
        if not isinstance(identifier, str) or not identifier or identifier in identities:
            raise ValueError(f"{label}.id is empty or duplicated")
        if provider not in counts:
            raise ValueError(f"{label}.provider is unsupported")
        identities.add(identifier)
        counts[provider] += 1
        for field in ("revision", "tree"):
            if not isinstance(project[field], str) or not REVISION.fullmatch(project[field]):
                raise ValueError(f"{label}.{field} is invalid")
        for field in ("report_digest", "report_sha256", "snapshot_digest"):
            _expect_digest(project[field], f"{label}.{field}")
        for field in ("files", "graphs", "inputs"):
            if type(project[field]) is not int or project[field] <= 0:
                raise ValueError(f"{label}.{field} must be a positive integer")
        diagnostics = _exact(project["diagnostics"], OFFICIAL_SEVERITIES, f"{label}.diagnostics")
        if any(type(diagnostics[key]) is not int or diagnostics[key] < 0 for key in diagnostics):
            raise ValueError(f"{label}.diagnostics must contain nonnegative integers")
        if diagnostics["total"] != sum(
            diagnostics[key] for key in ("critical", "error", "note", "warning")
        ):
            raise ValueError(f"{label}.diagnostics total is inconsistent")
    if counts != {provider: 2 for provider in PROVIDERS}:
        raise ValueError("official project provider counts are inconsistent")


def _expect_due_date(value: Any, label: str, completed: date) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO calendar date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO calendar date") from error
    if parsed < completed:
        raise ValueError(f"{label} is already overdue at attestation completion")


def _tracked(record: dict[str, Any], label: str, completed: date) -> None:
    _expect_https(record["tracking_url"], f"{label}.tracking_url")
    if not isinstance(record["owner"], str) or not record["owner"].strip():
        raise ValueError(f"{label}.owner must identify an accountable owner")
    _expect_due_date(record["due_date"], f"{label}.due_date", completed)


def _verify_attestation(
    path: Path,
    raw: bytes,
    *,
    subject_commit: str,
    tag: str,
    review: str,
) -> None:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    _exact(document, ATTESTATION_FIELDS, "maintainer security attestation")
    if document["schema"] != "maintainer-security-attestation-v1":
        raise ValueError("security attestation schema must be maintainer-security-attestation-v1")
    if document["subject_commit"] != subject_commit:
        raise ValueError("security attestation targets the wrong subject commit")
    if document["planned_tag"] != tag:
        raise ValueError("security attestation targets the wrong planned tag")
    if document["maintainer"] != MAINTAINER:
        raise ValueError("security attestation maintainer must be P4suta")
    if _expect_review(document["review"], "security attestation review") != review:
        raise ValueError("security attestation review does not match the manifest")
    completed_at = document["completed_at"]
    if not isinstance(completed_at, str):
        raise ValueError("security attestation completed_at must be an RFC 3339 timestamp")
    try:
        completed_timestamp = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("security attestation completed_at must be an RFC 3339 timestamp") from error
    if completed_timestamp.tzinfo is None:
        raise ValueError("security attestation completed_at must include a UTC offset")
    completed = completed_timestamp.date()
    scope = _strings(document["scope"], "security attestation scope")
    if len(scope) != len(set(scope)) or set(scope) != REQUIRED_SECURITY_SCOPE:
        raise ValueError("security attestation scope must exactly cover every required security area")
    findings = document["findings"]
    if not isinstance(findings, list):
        raise ValueError("security attestation findings must be an array")
    finding_ids: set[str] = set()
    for index, raw_finding in enumerate(findings):
        label = f"security attestation findings[{index}]"
        finding = _exact(raw_finding, FINDING_FIELDS, label)
        identifier = finding["id"]
        if not isinstance(identifier, str) or not identifier or identifier in finding_ids:
            raise ValueError(f"{label}.id is empty or duplicated")
        finding_ids.add(identifier)
        severity = finding["severity"]
        status = finding["status"]
        if severity not in {"critical", "high", "medium", "low", "note"}:
            raise ValueError(f"{label}.severity is invalid")
        if status not in {"resolved", "accepted", "open"}:
            raise ValueError(f"{label}.status is invalid")
        if not isinstance(finding["summary"], str) or len(finding["summary"].strip()) < 8:
            raise ValueError(f"{label}.summary is incomplete")
        if severity in {"critical", "high"} and status != "resolved":
            raise ValueError("critical and high security findings must be resolved")
        if status == "resolved":
            if any(finding[field] is not None for field in ("tracking_url", "owner", "due_date")):
                raise ValueError(f"{label} resolved tracking fields must be null")
        else:
            _tracked(finding, label, completed)
    risks = document["residual_risks"]
    if not isinstance(risks, list):
        raise ValueError("security attestation residual_risks must be an array")
    risk_ids: set[str] = set()
    for index, raw_risk in enumerate(risks):
        label = f"security attestation residual_risks[{index}]"
        risk = _exact(raw_risk, RISK_FIELDS, label)
        identifier = risk["id"]
        if not isinstance(identifier, str) or not identifier or identifier in risk_ids:
            raise ValueError(f"{label}.id is empty or duplicated")
        risk_ids.add(identifier)
        if risk["severity"] not in {"medium", "low", "note"}:
            raise ValueError("critical and high residual risks cannot be approved")
        if not isinstance(risk["description"], str) or len(risk["description"].strip()) < 8:
            raise ValueError(f"{label}.description is incomplete")
        _tracked(risk, label, completed)
    if document["decision"] != "approve":
        raise ValueError("maintainer security attestation decision must be approve")
    del path


def _run(command: list[str], *, cwd: Path, input_data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=input_data,
            stdin=subprocess.DEVNULL if input_data is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot execute {' '.join(command[:2])}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{' '.join(command[:2])} failed: {detail}")
    if len(completed.stdout) > 16 * 1024 * 1024:
        raise ValueError(f"{' '.join(command[:2])} output exceeded its bound")
    return completed.stdout


def _verify_signature(root: Path, attestation_path: Path, signature_path: Path, raw: bytes) -> None:
    allowed_signers = root / "maintainer-allowed-signers"
    expected = f"{MAINTAINER_EMAIL} {MAINTAINER_PUBLIC_KEY}\n".encode("ascii")
    try:
        actual = allowed_signers.read_bytes()
        metadata = allowed_signers.lstat()
    except OSError as error:
        raise ValueError(f"cannot read maintainer allowed signers: {error}") from error
    if allowed_signers.is_symlink() or not stat.S_ISREG(metadata.st_mode) or actual != expected:
        raise ValueError("maintainer allowed signers does not contain the pinned P4suta key")
    if signature_path.suffix != ".sig":
        raise ValueError("security attestation signature_path must end in .sig")
    try:
        root_resolved = root.resolve(strict=True)
        allowed_signers_resolved = allowed_signers.resolve(strict=True)
        signature_resolved = signature_path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"cannot resolve maintainer signature inputs: {error}") from error
    _run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed_signers_resolved),
            "-I",
            MAINTAINER_EMAIL,
            "-n",
            SIGNATURE_NAMESPACE,
            "-s",
            str(signature_resolved),
        ],
        cwd=root_resolved,
        input_data=raw,
    )
    del attestation_path


def _git(repository: Path, arguments: list[str]) -> bytes:
    return _run(
        ["git", "-c", f"safe.directory={repository.resolve()}", *arguments],
        cwd=repository,
    )


def _verify_repository_relation(
    repository: Path, manifest_path: Path, evidence_commit: str, subject_commit: str
) -> None:
    top = Path(_git(repository, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip()).resolve()
    try:
        manifest_relative = manifest_path.resolve(strict=True).relative_to(top).as_posix()
    except (OSError, ValueError) as error:
        raise ValueError("release evidence manifest must be inside the repository") from error
    if not manifest_relative.startswith("release-evidence/"):
        raise ValueError("release evidence manifest must be under release-evidence/")
    resolved_evidence = _git(repository, ["rev-parse", "--verify", f"{evidence_commit}^{{commit}}"])
    if resolved_evidence.decode("ascii").strip() != evidence_commit:
        raise ValueError("release evidence commit did not resolve exactly")
    parents = _git(repository, ["rev-list", "--parents", "-n", "1", evidence_commit])
    fields = parents.decode("ascii").strip().split()
    if fields != [evidence_commit, subject_commit]:
        raise ValueError("release evidence commit must have subject_commit as its only parent")
    names = _git(
        repository,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", subject_commit, evidence_commit],
    )
    changed = [name.decode("utf-8") for name in names.split(b"\0") if name]
    if not changed or any(
        not name.startswith("release-evidence/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        for name in changed
    ):
        raise ValueError("release evidence commit may change only release-evidence/**")
    commit = _git(repository, ["cat-file", "commit", evidence_commit])
    headers = commit.split(b"\n\n", 1)[0]
    if b"\ngpgsig " not in b"\n" + headers and b"\ngpgsig-sha256 " not in b"\n" + headers:
        raise ValueError("release evidence commit must carry a cryptographic signature")
    author = re.search(rb"(?m)^author [^\n<]+ <([^>]+)>", headers)
    if author is None or author.group(1).decode("utf-8", errors="replace") != MAINTAINER_EMAIL:
        raise ValueError("release evidence commit author must identify P4suta")


def verify(
    manifest_path: Path,
    *,
    revision: str,
    tag: str,
    repository: Path | None = Path("."),
) -> dict[str, str]:
    if not REVISION.fullmatch(revision):
        raise ValueError("release revision must be a lowercase 40-character commit")
    if not TAG.fullmatch(tag) or tag.endswith("-dev"):
        raise ValueError("release tag must be a stable or prerelease semantic version")
    manifest, _ = _load_json(manifest_path, "release evidence manifest", limit=1024 * 1024)
    _exact(manifest, ROOT_FIELDS, "release evidence manifest")
    if manifest["schema"] != "release-evidence-v2":
        raise ValueError("release evidence schema must be release-evidence-v2")
    subject_commit = manifest["subject_commit"]
    if not isinstance(subject_commit, str) or not REVISION.fullmatch(subject_commit):
        raise ValueError("release evidence subject_commit is invalid")
    if subject_commit == revision:
        raise ValueError("release evidence commit must be a child of subject_commit")
    if manifest["planned_tag"] != tag:
        raise ValueError("release evidence planned_tag does not match the release tag")
    if manifest["maintainer"] != MAINTAINER:
        raise ValueError("release evidence maintainer must be P4suta")
    review = _expect_review(manifest["review"], "release evidence review")
    root = manifest_path.parent
    if repository is not None:
        _verify_repository_relation(repository, manifest_path, revision, subject_commit)

    _, corpus_path, _ = _publication_file(root, manifest["corpus"], "corpus evidence")
    _verify_corpus(corpus_path)
    _, official_path, _ = _publication_file(
        root, manifest["official_compat"], "official compatibility evidence"
    )
    _verify_official(official_path, tag)

    performance = manifest["performance"]
    if not isinstance(performance, list) or len(performance) != len(PLATFORMS):
        raise ValueError("release evidence must contain exactly four performance reports")
    seen_platforms: set[str] = set()
    for index, raw in enumerate(performance):
        label = f"performance evidence[{index}]"
        record = _exact(raw, PERFORMANCE_FIELDS, label)
        platform = record["platform"]
        if platform not in PLATFORMS or platform in seen_platforms:
            raise ValueError(f"{label}.platform is unsupported or duplicated")
        seen_platforms.add(platform)
        _, path = _resolve_file(root, record["path"], f"{label}.path")
        _verify_digest(path, record["digest"], f"{label}.digest")
        _verify_performance(path, subject_commit, platform)
    if seen_platforms != set(PLATFORMS):
        raise ValueError("release evidence omits a required performance platform")

    security = _exact(
        manifest["security_attestation"], SECURITY_FIELDS, "security attestation evidence"
    )
    attestation_relative, attestation_path = _resolve_file(
        root, security["path"], "security attestation evidence.path"
    )
    signature_relative, signature_path = _resolve_file(
        root, security["signature_path"], "security attestation evidence.signature_path"
    )
    _verify_digest(attestation_path, security["digest"], "security attestation evidence.digest")
    _verify_digest(
        signature_path,
        security["signature_digest"],
        "security attestation evidence.signature_digest",
    )
    attestation, attestation_raw = _load_json(
        attestation_path, "maintainer security attestation", limit=4 * 1024 * 1024
    )
    del attestation
    _verify_attestation(
        attestation_path,
        attestation_raw,
        subject_commit=subject_commit,
        tag=tag,
        review=review,
    )
    _verify_signature(root, attestation_path, signature_path, attestation_raw)
    return {
        "attestation": attestation_relative,
        "signature": signature_relative,
        "subject_commit": subject_commit,
    }


def _append_github_output(path: Path, values: dict[str, str]) -> None:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("GitHub output must be a regular non-symlink file")
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key in ("attestation", "signature", "subject_commit"):
                stream.write(f"{key}={values[key]}\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ValueError(f"cannot write GitHub output {path}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()
    try:
        values = verify(
            arguments.manifest,
            revision=arguments.revision,
            tag=arguments.tag,
            repository=arguments.repository,
        )
        if arguments.github_output is not None:
            _append_github_output(arguments.github_output, values)
    except ValueError as error:
        print(f"release evidence gate: {error}", file=sys.stderr)
        return 1
    print(
        "release evidence gate: two-commit relation, corpus, official compatibility, "
        "four-platform performance, and signed maintainer attestation verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
