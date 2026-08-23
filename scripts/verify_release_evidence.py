#!/usr/bin/env python3
"""Fail closed unless externally reviewed publication evidence is complete."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any


PROVIDERS = ("github", "gitlab", "azure", "circleci")
PLATFORMS = ("linux-x86_64", "windows-x86_64", "macos-arm64", "macos-x86_64")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
HTTPS = re.compile(r"^https://[^\s]+$")
REVIEW_URL = re.compile(
    r"^https://github\.com/P4suta/workflow-verifier/(?:issues|pull)/[1-9][0-9]*(?:#[^\s]+)?$"
)
GITHUB_WORKFLOW_IDENTITY = re.compile(
    r"^https://github\.com/[^/]+/[^/]+/\.github/workflows/[^@]+@refs/tags/[^\s]+$"
)
ROOT_FIELDS = {"corpus", "performance", "revision", "schema", "security_review", "tag"}
FILE_FIELDS = {"digest", "path", "review"}
PERFORMANCE_FIELDS = FILE_FIELDS | {"platform"}
SECURITY_FIELDS = {
    "bundle_digest",
    "bundle_path",
    "certificate_identity",
    "certificate_oidc_issuer",
    "decision",
    "independence",
    "report_digest",
    "report_path",
    "review",
    "reviewer",
}
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
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
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
    _expect_review(record["review"], f"{label}.review")
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
    if any(modes != {"cold", "incremental", "warm"} for modes in modes_by_scenario.values()):
        raise ValueError(f"performance report for {platform} omits a required mode")


def verify(manifest_path: Path, *, revision: str, tag: str) -> dict[str, str]:
    if not REVISION.fullmatch(revision):
        raise ValueError("release revision must be a lowercase 40-character commit")
    if not TAG.fullmatch(tag) or tag.endswith("-dev"):
        raise ValueError("release tag must be a stable or prerelease semantic version")
    manifest, _ = _load_json(manifest_path, "release evidence manifest", limit=1024 * 1024)
    _exact(manifest, ROOT_FIELDS, "release evidence manifest")
    if manifest["schema"] != "release-evidence-v1":
        raise ValueError("release evidence schema must be release-evidence-v1")
    if manifest["revision"] != revision:
        raise ValueError("release evidence revision does not match the tagged commit")
    if manifest["tag"] != tag:
        raise ValueError("release evidence tag does not match the release tag")
    root = manifest_path.parent

    _, corpus_path, _ = _publication_file(root, manifest["corpus"], "corpus evidence")
    _verify_corpus(corpus_path)

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
        relative, path = _resolve_file(root, record["path"], f"{label}.path")
        del relative
        _verify_digest(path, record["digest"], f"{label}.digest")
        _expect_review(record["review"], f"{label}.review")
        _verify_performance(path, revision, platform)
    if seen_platforms != set(PLATFORMS):
        raise ValueError("release evidence omits a required performance platform")

    security = _exact(manifest["security_review"], SECURITY_FIELDS, "security review evidence")
    if security["decision"] != "approved":
        raise ValueError("independent security review decision must be approved")
    reviewer = security["reviewer"]
    independence = security["independence"]
    if not isinstance(reviewer, str) or len(reviewer.strip()) < 3:
        raise ValueError("security review reviewer identity is missing")
    if not isinstance(independence, str) or len(independence.strip()) < 32:
        raise ValueError("security review independence statement is incomplete")
    _expect_review(security["review"], "security review evidence.review")
    identity = _expect_https(security["certificate_identity"], "security review certificate_identity")
    issuer = _expect_https(security["certificate_oidc_issuer"], "security review certificate_oidc_issuer")
    if issuer != "https://token.actions.githubusercontent.com":
        raise ValueError("security review certificate must use the GitHub Actions OIDC issuer")
    if not GITHUB_WORKFLOW_IDENTITY.fullmatch(identity):
        raise ValueError("security review certificate identity must be a tagged GitHub Actions workflow")
    if identity.startswith("https://github.com/P4suta/workflow-verifier/"):
        raise ValueError("security review signature must originate outside the implementation repository")

    report_relative, report_path = _resolve_file(root, security["report_path"], "security review report_path")
    bundle_relative, bundle_path = _resolve_file(root, security["bundle_path"], "security review bundle_path")
    if not report_relative.endswith(".pdf"):
        raise ValueError("security review report_path must end in .pdf")
    if not bundle_relative.endswith(".sigstore.json"):
        raise ValueError("security review bundle_path must end in .sigstore.json")
    _verify_digest(report_path, security["report_digest"], "security review report_digest")
    _verify_digest(bundle_path, security["bundle_digest"], "security review bundle_digest")
    bundle, _ = _load_json(bundle_path, "security review Sigstore bundle", limit=16 * 1024 * 1024)
    media_type = bundle.get("mediaType")
    if not isinstance(media_type, str) or "sigstore.bundle" not in media_type:
        raise ValueError("security review bundle is not a Sigstore bundle")
    return {
        "bundle": bundle_relative,
        "identity": identity,
        "issuer": issuer,
        "report": report_relative,
    }


def _append_github_output(path: Path, values: dict[str, str]) -> None:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("GitHub output must be a regular non-symlink file")
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key in ("report", "bundle", "identity", "issuer"):
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
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()
    try:
        values = verify(arguments.manifest, revision=arguments.revision, tag=arguments.tag)
        if arguments.github_output is not None:
            _append_github_output(arguments.github_output, values)
    except ValueError as error:
        print(f"release evidence gate: {error}", file=sys.stderr)
        return 1
    print("release evidence gate: corpus, four-platform performance, and independent review verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
