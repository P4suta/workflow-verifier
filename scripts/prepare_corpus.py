#!/usr/bin/env python3
"""Acquire immutable licensed CI snapshots and apply exhaustive diagnostic review."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

try:
    from scripts.corpus_gate import tree_digest
except ModuleNotFoundError:  # Direct script execution from the repository root.
    from corpus_gate import tree_digest  # type: ignore[no-redef]


PROVIDERS = ("github", "gitlab", "azure", "circleci")
PROVIDER_QUERIES = {
    "github": "path:.github/workflows extension:yml language:YAML",
    "gitlab": "filename:.gitlab-ci.yml language:YAML",
    "azure": "filename:azure-pipelines.yml language:YAML",
    "circleci": "path:.circleci filename:config.yml language:YAML",
}
PERMISSIVE_LICENSES = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
}
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIAGNOSTIC_ID = re.compile(r"^diag_[0-9a-f]{20}$")
RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
SPDX_EXPRESSION = re.compile(r"^[A-Za-z0-9.+() -]+$")
MAX_SOURCE_BYTES = 4 * 1024 * 1024
REPORT_V2_FIELDS = {
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
LEGACY_REPORT_V1_FIELDS = {
    "diagnostics",
    "digest",
    "graphs",
    "inputs",
    "persona",
    "properties",
    "schema",
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
CORPUS_REPOSITORY_FIELDS = {
    "allowed_diagnostics",
    "checkout",
    "expected_diagnostics",
    "id",
    "license",
    "license_digest",
    "license_path",
    "provider",
    "report",
    "revision",
    "source_digest",
    "url",
}


@dataclass(frozen=True)
class Candidate:
    provider: str
    full_name: str
    workflow_path: str


@dataclass(frozen=True)
class Snapshot:
    url: str
    revision: str
    workflow_path: str
    workflow_bytes: bytes
    license_expression: str
    license_path: str
    license_bytes: bytes


class Source(Protocol):
    def candidates(self, provider: str) -> Iterable[Candidate]: ...

    def fetch(self, candidate: Candidate) -> Snapshot: ...


Analyzer = Callable[[Path], dict[str, Any]]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read JSON input {path}: {error}") from error
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse JSON input {path}: {error}") from error


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_content(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _verify_document_digest(document: dict[str, Any], label: str) -> None:
    claimed = document.get("digest")
    if not isinstance(claimed, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", claimed):
        raise ValueError(f"{label}.digest is invalid")
    provisional = dict(document)
    provisional["digest"] = None
    actual = "sha256:" + hashlib.sha256(_canonical_content(provisional)).hexdigest()
    if claimed != actual:
        raise ValueError(f"{label}.digest does not authenticate its canonical content")


def _atomic_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    extra = sorted(set(value) - fields)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")
    return value


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} must be a safe relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return path


def _provider_path(provider: str, value: str) -> PurePosixPath:
    path = _relative(value, f"{provider} workflow path")
    normalized = path.as_posix()
    valid = {
        "github": normalized.startswith(".github/workflows/")
        and path.suffix.lower() in {".yml", ".yaml"},
        "gitlab": normalized == ".gitlab-ci.yml",
        "azure": path.name.lower() in {"azure-pipelines.yml", "azure-pipelines.yaml"},
        "circleci": normalized == ".circleci/config.yml",
    }
    if provider not in valid or not valid[provider]:
        raise ValueError(f"search result is not a canonical {provider} entrypoint: {value}")
    return path


def _repository_id(candidate: Candidate) -> str:
    if candidate.provider not in PROVIDERS:
        raise ValueError(f"unsupported corpus provider: {candidate.provider}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", candidate.full_name):
        raise ValueError(f"invalid GitHub repository name: {candidate.full_name}")
    identifier = f"{candidate.provider}/{candidate.full_name.lower()}"
    return _relative(identifier, "repository id").as_posix()


def _validate_snapshot(
    candidate: Candidate, snapshot: Snapshot
) -> tuple[PurePosixPath, PurePosixPath]:
    if not snapshot.url.startswith("https://") or "?" in snapshot.url or "#" in snapshot.url:
        raise ValueError("snapshot URL must be credential-free HTTPS")
    if not REVISION.fullmatch(snapshot.revision):
        raise ValueError("snapshot revision must be an immutable 40-character commit")
    workflow = _provider_path(candidate.provider, snapshot.workflow_path)
    if (
        workflow.as_posix()
        != _provider_path(candidate.provider, candidate.workflow_path).as_posix()
    ):
        raise ValueError("fetched workflow path differs from the search result")
    license_path = _relative(snapshot.license_path, "license path")
    if workflow == license_path:
        raise ValueError("workflow and license paths collide")
    if (
        not SPDX_EXPRESSION.fullmatch(snapshot.license_expression)
        or snapshot.license_expression not in PERMISSIVE_LICENSES
    ):
        raise ValueError(
            f"license is not in the reviewed permissive set: {snapshot.license_expression}"
        )
    for label, payload in (
        ("workflow", snapshot.workflow_bytes),
        ("license", snapshot.license_bytes),
    ):
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SOURCE_BYTES:
            raise ValueError(f"{label} bytes must be nonempty and at most 4 MiB")
    return workflow, license_path


def _validated_diagnostics(
    report: Any,
    label: str,
    *,
    schema: str,
    fields: set[str],
) -> list[dict[str, Any]]:
    report = _exact_fields(report, fields, label)
    if report["schema"] != schema or report["persona"] != "audit":
        raise ValueError(f"{label} must be an audit {schema} document")
    tool = report["tool"]
    if not isinstance(tool, dict) or tool.get("name") != "workflow-verifier":
        raise ValueError(f"{label} was not produced by workflow-verifier")
    _verify_document_digest(report, label)
    diagnostics = report["diagnostics"]
    if not isinstance(diagnostics, list):
        raise ValueError(f"{label}.diagnostics must be an array")
    seen: set[str] = set()
    for index, diagnostic in enumerate(diagnostics):
        diagnostic = _exact_fields(
            diagnostic,
            DIAGNOSTIC_FIELDS,
            f"{label}.diagnostics[{index}]",
        )
        identifier = diagnostic.get("id")
        rule_id = diagnostic.get("rule_id")
        if not isinstance(identifier, str) or not DIAGNOSTIC_ID.fullmatch(identifier):
            raise ValueError(f"{label}.diagnostics[{index}].id is invalid")
        if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
            raise ValueError(f"{label}.diagnostics[{index}].rule_id is invalid")
        if identifier in seen:
            raise ValueError(f"{label} contains duplicate diagnostic {identifier}")
        seen.add(identifier)
    return diagnostics


def _diagnostics(report: Any, label: str) -> list[dict[str, Any]]:
    return _validated_diagnostics(
        report,
        label,
        schema="report-v2",
        fields=REPORT_V2_FIELDS,
    )


def _legacy_diagnostics(report: Any, label: str) -> list[dict[str, Any]]:
    """Decode report-v1 only for an explicit, fail-closed review rebase."""
    return _validated_diagnostics(
        report,
        label,
        schema="report-v1",
        fields=LEGACY_REPORT_V1_FIELDS,
    )


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _write_source(root: Path, relative: PurePosixPath, payload: bytes) -> None:
    path = root.joinpath(*relative.parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _attempt_fetch(source: Source, candidate: Candidate) -> tuple[Snapshot | None, str | None]:
    try:
        return source.fetch(candidate), None
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        return None, str(error)


def acquire(
    source: Source,
    analyzer: Analyzer,
    output: Path,
    *,
    per_provider: int = 100,
    workers: int = 8,
) -> dict[str, Any]:
    if type(per_provider) is not int or not 1 <= per_provider <= 1000:
        raise ValueError("per_provider must be between 1 and 1000")
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError("workers must be between 1 and 32")
    if output.exists() or output.is_symlink():
        raise ValueError(f"refusing to replace existing corpus output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    corpus_root = staging / "corpus"
    reports_root = staging / "reports"
    repositories: list[dict[str, Any]] = []
    draft: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    origins: set[tuple[str, str]] = set()
    try:
        for provider in PROVIDERS:
            selected = 0
            candidates = iter(source.candidates(provider))
            failures: list[str] = []
            with ThreadPoolExecutor(max_workers=workers) as executor:
                while selected < per_provider:
                    batch: list[Candidate] = []
                    for _ in range(workers * 2):
                        try:
                            candidate = next(candidates)
                        except StopIteration:
                            break
                        if candidate.provider != provider:
                            raise ValueError(
                                "candidate provider differs from acquisition partition"
                            )
                        batch.append(candidate)
                    if not batch:
                        detail = failures[-1] if failures else "candidate search was exhausted"
                        raise ValueError(
                            f"could not acquire {per_provider} licensed {provider} repositories; "
                            f"selected {selected}: {detail}"
                        )
                    fetched = list(executor.map(lambda item: _attempt_fetch(source, item), batch))
                    for candidate, (snapshot, error) in zip(batch, fetched, strict=True):
                        if selected >= per_provider:
                            break
                        if snapshot is None:
                            failures.append(f"{candidate.full_name}: {error}")
                            continue
                        checkout: Path | None = None
                        try:
                            identifier = _repository_id(candidate)
                            workflow_path, license_path = _validate_snapshot(candidate, snapshot)
                            origin = (snapshot.url, snapshot.revision)
                            if identifier in identifiers or origin in origins:
                                raise ValueError(
                                    "duplicate repository identity or immutable origin"
                                )
                            checkout = corpus_root.joinpath(*PurePosixPath(identifier).parts)
                            _write_source(checkout, workflow_path, snapshot.workflow_bytes)
                            _write_source(checkout, license_path, snapshot.license_bytes)
                            report = analyzer(checkout)
                            diagnostics = _diagnostics(report, f"report for {identifier}")
                            report_relative = f"{identifier.replace('/', '--')}.json"
                            _atomic_json(reports_root / report_relative, report)
                            repository = {
                                "allowed_diagnostics": [],
                                "checkout": identifier,
                                "expected_diagnostics": [],
                                "id": identifier,
                                "license": snapshot.license_expression,
                                "license_digest": _sha256(snapshot.license_bytes),
                                "license_path": license_path.as_posix(),
                                "provider": provider,
                                "report": report_relative,
                                "revision": snapshot.revision,
                                "source_digest": tree_digest(checkout),
                                "url": snapshot.url,
                            }
                            repositories.append(repository)
                            if diagnostics:
                                draft.append(
                                    {
                                        "diagnostics": [
                                            {
                                                key: diagnostic.get(key)
                                                for key in (
                                                    "confidence",
                                                    "id",
                                                    "message",
                                                    "rule_id",
                                                    "severity",
                                                    "span",
                                                )
                                            }
                                            for diagnostic in diagnostics
                                        ],
                                        "id": identifier,
                                        "provider": provider,
                                        "url": snapshot.url,
                                    }
                                )
                            identifiers.add(identifier)
                            origins.add(origin)
                            selected += 1
                        except (
                            KeyError,
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ) as candidate_error:
                            if checkout is not None and checkout.exists():
                                shutil.rmtree(checkout)
                            failures.append(f"{candidate.full_name}: {candidate_error}")
        manifest = {"repositories": repositories, "schema": "corpus-v1"}
        _atomic_json(staging / "corpus-v1.json", manifest)
        _atomic_json(
            staging / "review-draft-v1.json",
            {"repositories": draft, "schema": "corpus-review-draft-v1"},
        )
        os.replace(staging, output)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def refresh(
    evaluation: Path,
    analyzer: Analyzer,
    output: Path,
    *,
    workers: int = 8,
) -> dict[str, Any]:
    """Re-run analysis over a verified immutable corpus into a new transaction."""
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError("workers must be between 1 and 32")
    if evaluation.is_symlink() or not evaluation.is_dir():
        raise ValueError(f"evaluation input must be a directory: {evaluation}")
    if output.exists() or output.is_symlink():
        raise ValueError(f"refusing to replace existing corpus output: {output}")
    manifest = _load_json(evaluation / "corpus-v1.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != "corpus-v1":
        raise ValueError("evaluation manifest must be a corpus-v1 document")
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("evaluation manifest repositories must be nonempty")
    source_corpus = evaluation / "corpus"
    if source_corpus.is_symlink() or not source_corpus.is_dir():
        raise ValueError("evaluation corpus must be a directory")

    validated: list[tuple[dict[str, Any], PurePosixPath, PurePosixPath]] = []
    report_paths: set[str] = set()
    for index, value in enumerate(repositories):
        if not isinstance(value, dict):
            raise ValueError(f"manifest.repositories[{index}] must be an object")
        identifier = value.get("id")
        provider = value.get("provider")
        checkout_relative = _relative(value.get("checkout"), "checkout path")
        report_relative = _relative(value.get("report"), "report path")
        if (
            not isinstance(identifier, str)
            or checkout_relative.as_posix() != identifier
            or provider not in PROVIDERS
            or not identifier.startswith(f"{provider}/")
        ):
            raise ValueError(f"manifest.repositories[{index}] has invalid identity")
        if report_relative.as_posix() in report_paths:
            raise ValueError("evaluation manifest contains duplicate report paths")
        report_paths.add(report_relative.as_posix())
        checkout = source_corpus.joinpath(*checkout_relative.parts)
        expected_digest = value.get("source_digest")
        if not isinstance(expected_digest, str) or tree_digest(checkout) != expected_digest:
            raise ValueError(f"source digest does not match immutable snapshot: {identifier}")
        validated.append((value, checkout_relative, report_relative))

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        corpus_root = staging / "corpus"
        reports_root = staging / "reports"
        shutil.copytree(source_corpus, corpus_root)

        def analyze_repository(
            item: tuple[dict[str, Any], PurePosixPath, PurePosixPath],
        ) -> tuple[dict[str, Any], PurePosixPath, dict[str, Any], list[dict[str, Any]]]:
            repository, checkout_relative, report_relative = item
            identifier = repository["id"]
            checkout = corpus_root.joinpath(*checkout_relative.parts)
            if tree_digest(checkout) != repository["source_digest"]:
                raise ValueError(f"copied source digest changed for {identifier}")
            report = analyzer(checkout)
            diagnostics = _diagnostics(report, f"report for {identifier}")
            refreshed = dict(repository)
            refreshed["allowed_diagnostics"] = []
            refreshed["expected_diagnostics"] = []
            return refreshed, report_relative, report, diagnostics

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(analyze_repository, validated))

        refreshed_repositories: list[dict[str, Any]] = []
        draft: list[dict[str, Any]] = []
        for repository, report_relative, report, diagnostics in results:
            _atomic_json(reports_root.joinpath(*report_relative.parts), report)
            refreshed_repositories.append(repository)
            if diagnostics:
                draft.append(
                    {
                        "diagnostics": [
                            {
                                key: diagnostic.get(key)
                                for key in (
                                    "confidence",
                                    "id",
                                    "message",
                                    "rule_id",
                                    "severity",
                                    "span",
                                )
                            }
                            for diagnostic in diagnostics
                        ],
                        "id": repository["id"],
                        "provider": repository["provider"],
                        "url": repository["url"],
                    }
                )
        refreshed_manifest = {
            "repositories": refreshed_repositories,
            "schema": "corpus-v1",
        }
        _atomic_json(staging / "corpus-v1.json", refreshed_manifest)
        _atomic_json(
            staging / "review-draft-v1.json",
            {"repositories": draft, "schema": "corpus-review-draft-v1"},
        )
        os.replace(staging, output)
        return refreshed_manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _report_map(manifest: dict[str, Any], reports_root: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    repositories = manifest.get("repositories")
    if manifest.get("schema") != "corpus-v1" or not isinstance(repositories, list):
        raise ValueError("manifest must be a corpus-v1 document")
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise ValueError(f"manifest.repositories[{index}] must be an object")
        identifier = repository.get("id")
        report_relative = repository.get("report")
        if not isinstance(identifier, str) or not isinstance(report_relative, str):
            raise ValueError(f"manifest.repositories[{index}] has invalid identity")
        report_path = reports_root.joinpath(*_relative(report_relative, "report path").parts)
        diagnostics = _diagnostics(_load_json(report_path), f"report for {identifier}")
        result[identifier] = {item["id"]: item["rule_id"] for item in diagnostics}
    return result


def _review_classifications(
    actual: dict[str, dict[str, str]], review_path: Path
) -> dict[str, dict[str, tuple[str, str, str]]]:
    review = _exact_fields(_load_json(review_path), {"repositories", "schema"}, "corpus review")
    if review["schema"] != "corpus-review-v1" or not isinstance(review["repositories"], list):
        raise ValueError("corpus review must be a corpus-review-v1 document")
    reviewed: dict[str, dict[str, tuple[str, str, str]]] = {}
    for repository_index, repository_value in enumerate(review["repositories"]):
        repository = _exact_fields(
            repository_value,
            {"diagnostics", "id"},
            f"corpus review.repositories[{repository_index}]",
        )
        identifier = repository["id"]
        if not isinstance(identifier, str) or identifier not in actual:
            raise ValueError(f"review names unknown repository: {identifier}")
        if identifier in reviewed or not isinstance(repository["diagnostics"], list):
            raise ValueError(f"duplicate or invalid review repository: {identifier}")
        classifications: dict[str, tuple[str, str, str]] = {}
        for diagnostic_index, diagnostic_value in enumerate(repository["diagnostics"]):
            diagnostic = _exact_fields(
                diagnostic_value,
                {"classification", "id", "reason", "rule_id"},
                f"review for {identifier}.diagnostics[{diagnostic_index}]",
            )
            diagnostic_id = diagnostic["id"]
            rule_id = diagnostic["rule_id"]
            classification = diagnostic["classification"]
            reason = diagnostic["reason"]
            if diagnostic_id not in actual[identifier]:
                raise ValueError(f"review names unknown diagnostic {identifier}/{diagnostic_id}")
            if actual[identifier][diagnostic_id] != rule_id:
                raise ValueError(f"review rule mismatch for {identifier}/{diagnostic_id}")
            if classification not in {"allowed", "expected"}:
                raise ValueError(
                    f"review classification is invalid for {identifier}/{diagnostic_id}"
                )
            if not isinstance(reason, str) or len(reason.strip()) < 20:
                raise ValueError(f"review reason is too short for {identifier}/{diagnostic_id}")
            if diagnostic_id in classifications:
                raise ValueError(f"duplicate review diagnostic {identifier}/{diagnostic_id}")
            classifications[diagnostic_id] = (classification, rule_id, reason)
        reviewed[identifier] = classifications

    for identifier, diagnostics in actual.items():
        classifications = reviewed.get(identifier, {})
        for diagnostic_id in diagnostics:
            if diagnostic_id not in classifications:
                raise ValueError(f"unreviewed diagnostic {identifier}/{diagnostic_id}")
        for diagnostic_id in classifications:
            if diagnostic_id not in diagnostics:
                raise ValueError(f"review names absent diagnostic {identifier}/{diagnostic_id}")
    return reviewed


def apply_review(manifest_path: Path, reports_root: Path, review_path: Path) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    actual = _report_map(manifest, reports_root)
    reviewed = _review_classifications(actual, review_path)

    for repository in manifest["repositories"]:
        classifications = reviewed.get(repository["id"], {})
        repository["expected_diagnostics"] = sorted(
            [
                {"id": identifier, "rule_id": rule_id}
                for identifier, (classification, rule_id, _reason) in classifications.items()
                if classification == "expected"
            ],
            key=lambda item: item["id"].encode("utf-8"),
        )
        repository["allowed_diagnostics"] = sorted(
            [
                {"id": identifier, "rule_id": rule_id}
                for identifier, (classification, rule_id, _reason) in classifications.items()
                if classification == "allowed"
            ],
            key=lambda item: item["id"].encode("utf-8"),
        )
    _atomic_json(manifest_path, manifest)
    return manifest


def _normalize_review_value(value: Any, repository_id: str) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if key == "file":
                if not isinstance(item, str):
                    raise ValueError("diagnostic span file must be a string")
                prefix = repository_id + "/"
                normalized[key] = item[len(prefix) :] if item.startswith(prefix) else item
            else:
                normalized[key] = _normalize_review_value(item, repository_id)
        return normalized
    if isinstance(value, list):
        return [_normalize_review_value(item, repository_id) for item in value]
    return value


def _diagnostic_review_key(diagnostic: dict[str, Any], repository_id: str) -> bytes:
    diagnostic = _exact_fields(diagnostic, DIAGNOSTIC_FIELDS, "review rebase diagnostic")
    trace = diagnostic["trace"]
    if not isinstance(trace, list):
        raise ValueError("review rebase diagnostic trace must be an array")
    core = {
        key: _normalize_review_value(value, repository_id)
        for key, value in diagnostic.items()
        if key not in {"id", "trace"}
    }
    trace_shape: list[dict[str, Any]] = []
    for index, value in enumerate(trace):
        if not isinstance(value, dict):
            raise ValueError(f"review rebase trace[{index}] must be an object")
        shape = {
            key: _normalize_review_value(item, repository_id)
            for key, item in value.items()
            if key not in {"node_id", "span"}
        }
        if "span" in value:
            span = value["span"]
            if not isinstance(span, dict) or not isinstance(span.get("file"), str):
                raise ValueError(f"review rebase trace[{index}].span is invalid")
            shape["span"] = _normalize_review_value({"file": span["file"]}, repository_id)
        trace_shape.append(shape)
    return _canonical_content({"diagnostic": core, "trace_shape": trace_shape})


def _rebase_documents(
    manifest_path: Path,
    reports_root: Path,
    *,
    legacy: bool,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    manifest = _exact_fields(
        _load_json(manifest_path),
        {"repositories", "schema"},
        "corpus manifest",
    )
    if manifest["schema"] != "corpus-v1" or not isinstance(manifest["repositories"], list):
        raise ValueError("review rebase manifest must be a corpus-v1 document")
    result: dict[str, list[dict[str, Any]]] = {}
    for index, value in enumerate(manifest["repositories"]):
        repository = _exact_fields(
            value,
            CORPUS_REPOSITORY_FIELDS,
            f"corpus manifest.repositories[{index}]",
        )
        identifier = repository["id"]
        if not isinstance(identifier, str) or identifier in result:
            raise ValueError("review rebase manifest contains an invalid or duplicate repository")
        report_relative = _relative(repository["report"], "review rebase report path")
        report_path = reports_root.joinpath(*report_relative.parts)
        report = _load_json(report_path)
        result[identifier] = (
            _legacy_diagnostics(report, f"legacy report for {identifier}")
            if legacy
            else _diagnostics(report, f"fresh report for {identifier}")
        )
    return manifest, result


def _semantic_index(
    diagnostics: list[dict[str, Any]], repository_id: str, label: str
) -> dict[bytes, dict[str, Any]]:
    result: dict[bytes, dict[str, Any]] = {}
    for diagnostic in diagnostics:
        key = _diagnostic_review_key(diagnostic, repository_id)
        if key in result:
            raise ValueError(f"{label} has ambiguous review semantics for {repository_id}")
        result[key] = diagnostic
    return result


def rebase_review(
    old_manifest_path: Path,
    old_reports_root: Path,
    old_review_path: Path,
    new_manifest_path: Path,
    new_reports_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Explicitly map reviewed report-v1 diagnostics onto equivalent report-v2 diagnostics."""
    old_manifest, old_documents = _rebase_documents(
        old_manifest_path, old_reports_root, legacy=True
    )
    new_manifest, new_documents = _rebase_documents(
        new_manifest_path, new_reports_root, legacy=False
    )
    old_actual = {
        repository_id: {item["id"]: item["rule_id"] for item in diagnostics}
        for repository_id, diagnostics in old_documents.items()
    }
    reviewed = _review_classifications(old_actual, old_review_path)
    old_repositories = {item["id"]: item for item in old_manifest["repositories"]}
    new_repositories = {item["id"]: item for item in new_manifest["repositories"]}
    if set(old_repositories) != set(new_repositories):
        raise ValueError("review rebase repository set changed")

    rebased: list[dict[str, Any]] = []
    for repository_id in sorted(old_repositories, key=lambda value: value.encode("utf-8")):
        old_repository = dict(old_repositories[repository_id])
        new_repository = dict(new_repositories[repository_id])
        old_repository.pop("expected_diagnostics")
        old_repository.pop("allowed_diagnostics")
        new_repository.pop("expected_diagnostics")
        new_repository.pop("allowed_diagnostics")
        if old_repository != new_repository:
            raise ValueError(
                f"review rebase immutable repository identity changed: {repository_id}"
            )

        old_index = _semantic_index(old_documents[repository_id], repository_id, "legacy reports")
        new_index = _semantic_index(new_documents[repository_id], repository_id, "fresh reports")
        if set(old_index) != set(new_index):
            raise ValueError(f"review rebase diagnostic semantics changed: {repository_id}")
        classifications = reviewed.get(repository_id, {})
        diagnostics: list[dict[str, str]] = []
        for key, old_diagnostic in old_index.items():
            classification, rule_id, reason = classifications[old_diagnostic["id"]]
            new_diagnostic = new_index[key]
            if new_diagnostic["rule_id"] != rule_id:
                raise ValueError(f"review rebase rule changed: {repository_id}")
            diagnostics.append(
                {
                    "classification": classification,
                    "id": new_diagnostic["id"],
                    "reason": reason,
                    "rule_id": rule_id,
                }
            )
        if diagnostics:
            rebased.append(
                {
                    "diagnostics": sorted(diagnostics, key=lambda item: item["id"].encode("utf-8")),
                    "id": repository_id,
                }
            )
    result = {"repositories": rebased, "schema": "corpus-review-v1"}
    _atomic_json(output_path, result)
    return result


class GitHubSource:
    def __init__(self, token: str, *, pages: int = 10) -> None:
        if not token or "\x00" in token:
            raise ValueError("GitHub token is empty or invalid")
        if type(pages) is not int or not 1 <= pages <= 10:
            raise ValueError("GitHub code search pages must be between 1 and 10")
        self._token = token
        self._pages = pages

    def _request(self, path: str, parameters: dict[str, str] | None = None) -> Any:
        query = "" if not parameters else "?" + urlencode(parameters)
        url = f"https://api.github.com/{path}{query}"
        for attempt in range(8):
            request = Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "User-Agent": "workflow-verifier-corpus/0.1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                method="GET",
            )
            try:
                with urlopen(request, timeout=30) as response:
                    payload = response.read(MAX_SOURCE_BYTES * 2)
                return json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
            except HTTPError as error:
                retryable = error.code in {403, 429, 500, 502, 503, 504}
                if not retryable or attempt == 7:
                    raise RuntimeError(f"GitHub API {path} returned HTTP {error.code}") from error
                reset = error.headers.get("X-RateLimit-Reset")
                delay = (
                    min(30, max(2, int(reset) - int(time.time()) + 1))
                    if reset
                    else min(30, 2**attempt)
                )
                time.sleep(delay)
            except (TimeoutError, UnicodeError, URLError, json.JSONDecodeError) as error:
                if attempt == 7:
                    raise RuntimeError(f"GitHub API {path} failed: {error}") from error
                time.sleep(min(30, 2**attempt))
        raise RuntimeError(f"GitHub API {path} exhausted retries")

    @staticmethod
    def _content(document: Any, label: str) -> bytes:
        if not isinstance(document, dict) or document.get("type") != "file":
            raise ValueError(f"{label} is not a regular GitHub blob")
        content = document.get("content")
        if document.get("encoding") != "base64" or not isinstance(content, str):
            raise ValueError(f"{label} has no inline base64 content")
        try:
            canonical = content.replace("\r", "").replace("\n", "")
            return base64.b64decode(canonical, validate=True)
        except ValueError as error:
            raise ValueError(f"{label} contains invalid base64") from error

    def candidates(self, provider: str) -> Iterable[Candidate]:
        if provider not in PROVIDER_QUERIES:
            raise ValueError(f"unsupported provider search: {provider}")
        seen: set[str] = set()
        for page in range(1, self._pages + 1):
            document = self._request(
                "search/code",
                {
                    "page": str(page),
                    "per_page": "100",
                    "q": PROVIDER_QUERIES[provider],
                },
            )
            items = document.get("items") if isinstance(document, dict) else None
            if not isinstance(items, list):
                raise RuntimeError("GitHub code search returned no item array")
            if not items:
                return
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("repository"), dict):
                    continue
                full_name = item["repository"].get("full_name")
                workflow_path = item.get("path")
                if not isinstance(full_name, str) or not isinstance(workflow_path, str):
                    continue
                identity = full_name.lower()
                if identity in seen:
                    continue
                candidate = Candidate(provider, full_name, workflow_path)
                try:
                    _provider_path(provider, workflow_path)
                    _repository_id(candidate)
                except ValueError:
                    continue
                seen.add(identity)
                yield candidate

    def fetch(self, candidate: Candidate) -> Snapshot:
        _repository_id(candidate)
        repository = self._request(f"repos/{candidate.full_name}")
        if (
            not isinstance(repository, dict)
            or repository.get("archived") is not False
            or repository.get("disabled") is not False
            or repository.get("fork") is not False
        ):
            raise ValueError("repository is archived, disabled, forked, or malformed")
        license_summary = repository.get("license")
        license_expression = (
            license_summary.get("spdx_id") if isinstance(license_summary, dict) else None
        )
        if license_expression not in PERMISSIVE_LICENSES:
            raise ValueError(
                f"repository license is not reviewed permissive SPDX: {license_expression}"
            )
        branch = repository.get("default_branch")
        html_url = repository.get("html_url")
        if not isinstance(branch, str) or not branch or not isinstance(html_url, str):
            raise ValueError("repository has no default branch or canonical URL")
        commit = self._request(f"repos/{candidate.full_name}/commits/{quote(branch, safe='')}")
        revision = commit.get("sha") if isinstance(commit, dict) else None
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            raise ValueError("default branch did not resolve to an immutable commit")
        workflow_document = self._request(
            f"repos/{candidate.full_name}/contents/{quote(candidate.workflow_path, safe='/')}",
            {"ref": revision},
        )
        license_document = self._request(f"repos/{candidate.full_name}/license", {"ref": revision})
        license_value = (
            license_document.get("license") if isinstance(license_document, dict) else None
        )
        exact_license = license_value.get("spdx_id") if isinstance(license_value, dict) else None
        license_path = license_document.get("path") if isinstance(license_document, dict) else None
        if exact_license != license_expression or not isinstance(license_path, str):
            raise ValueError("license evidence differs from repository SPDX metadata")
        return Snapshot(
            license_bytes=self._content(license_document, "license evidence"),
            license_expression=license_expression,
            license_path=license_path,
            revision=revision,
            url=html_url.rstrip("/") + ".git",
            workflow_bytes=self._content(workflow_document, "workflow source"),
            workflow_path=candidate.workflow_path,
        )


def _github_token() -> str:
    environment_token = os.environ.get("GITHUB_TOKEN")
    if environment_token:
        return environment_token
    try:
        completed = subprocess.run(
            ["gh", "auth", "token"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"cannot obtain GitHub token: {error}") from error
    token = completed.stdout.decode("utf-8", errors="strict").strip()
    if completed.returncode != 0 or not token:
        raise RuntimeError("gh auth token did not return an authenticated token")
    return token


def analyzer_command(path: Path) -> Analyzer:
    analyzer = path.resolve(strict=True)

    def run(checkout: Path) -> dict[str, Any]:
        corpus_root = next(
            (parent for parent in checkout.parents if parent.name == "corpus"),
            None,
        )
        if corpus_root is None:
            raise RuntimeError("corpus checkout must be nested below a corpus directory")
        relative_checkout = checkout.relative_to(corpus_root)
        if len(relative_checkout.parts) != 3 or relative_checkout.parts[0] not in PROVIDERS:
            raise RuntimeError("corpus checkout must have provider/owner/repository identity")
        try:
            completed = subprocess.run(
                [
                    str(analyzer),
                    "check",
                    "--persona",
                    "audit",
                    "--format",
                    "json",
                    relative_checkout.as_posix(),
                ],
                cwd=corpus_root,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(f"analyzer failed to execute: {error}") from error
        if completed.returncode not in {0, 1, 3}:
            detail = completed.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"analyzer returned exit {completed.returncode}: {detail}")
        try:
            value = json.loads(completed.stdout.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError(f"analyzer did not return report-v2 JSON: {error}") from error
        if not isinstance(value, dict):
            raise RuntimeError("analyzer report must be an object")
        return value

    return run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    acquire_parser = subcommands.add_parser("acquire")
    acquire_parser.add_argument("--analyzer", required=True, type=Path)
    acquire_parser.add_argument("--output", required=True, type=Path)
    acquire_parser.add_argument("--pages", type=int, default=10)
    acquire_parser.add_argument("--per-provider", type=int, default=100)
    acquire_parser.add_argument("--workers", type=int, default=8)
    refresh_parser = subcommands.add_parser("refresh")
    refresh_parser.add_argument("--analyzer", required=True, type=Path)
    refresh_parser.add_argument("--evaluation", required=True, type=Path)
    refresh_parser.add_argument("--output", required=True, type=Path)
    refresh_parser.add_argument("--workers", type=int, default=8)
    review_parser = subcommands.add_parser("apply-review")
    review_parser.add_argument("--manifest", required=True, type=Path)
    review_parser.add_argument("--reports-root", required=True, type=Path)
    review_parser.add_argument("--review", required=True, type=Path)
    rebase_parser = subcommands.add_parser("rebase-review")
    rebase_parser.add_argument("--old-manifest", required=True, type=Path)
    rebase_parser.add_argument("--old-reports-root", required=True, type=Path)
    rebase_parser.add_argument("--old-review", required=True, type=Path)
    rebase_parser.add_argument("--new-manifest", required=True, type=Path)
    rebase_parser.add_argument("--new-reports-root", required=True, type=Path)
    rebase_parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "acquire":
            manifest = acquire(
                GitHubSource(_github_token(), pages=arguments.pages),
                analyzer_command(arguments.analyzer),
                arguments.output,
                per_provider=arguments.per_provider,
                workers=arguments.workers,
            )
            print(
                "corpus acquisition: "
                f"{len(manifest['repositories'])} immutable licensed repositories"
            )
        elif arguments.command == "refresh":
            manifest = refresh(
                arguments.evaluation,
                analyzer_command(arguments.analyzer),
                arguments.output,
                workers=arguments.workers,
            )
            print(
                f"corpus refresh: {len(manifest['repositories'])} immutable repositories reanalyzed"
            )
        elif arguments.command == "apply-review":
            manifest = apply_review(arguments.manifest, arguments.reports_root, arguments.review)
            print(
                "corpus review: "
                f"{len(manifest['repositories'])} repositories exhaustively classified"
            )
        else:
            review = rebase_review(
                arguments.old_manifest,
                arguments.old_reports_root,
                arguments.old_review,
                arguments.new_manifest,
                arguments.new_reports_root,
                arguments.output,
            )
            diagnostics = sum(len(item["diagnostics"]) for item in review["repositories"])
            print(
                f"corpus review rebase: {diagnostics} diagnostics mapped by exact primary semantics"
            )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"corpus preparation: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
