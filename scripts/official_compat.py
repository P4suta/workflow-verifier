#!/usr/bin/env python3
"""Analyze acquired official CI snapshots twice without executing project code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from scripts.fetch_official_projects import (
        PROVIDERS,
        REVISION,
        _snapshot_digest,
        load_manifest,
    )
except ModuleNotFoundError:  # Direct `python scripts/official_compat.py` execution.
    from fetch_official_projects import (  # type: ignore[no-redef]
        PROVIDERS,
        REVISION,
        _snapshot_digest,
        load_manifest,
    )


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ACQUISITION_FIELDS = {"manifest_digest", "mode", "projects", "schema"}
ACQUIRED_PROJECT_FIELDS = {
    "files",
    "id",
    "provider",
    "repository",
    "revision",
    "snapshot_digest",
    "tree",
}
SEVERITIES = ("critical", "error", "warning", "note")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str, *, limit: int) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {label} {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if not 0 < len(raw) <= limit:
        raise ValueError(f"{label} has an invalid size")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {label}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object")
    return document, raw


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_acquisition(
    manifest_path: Path,
    snapshots: Path,
    *,
    allow_latest: bool,
) -> tuple[list[dict[str, Any]], str, str]:
    manifest, manifest_digest = load_manifest(manifest_path)
    acquisition_path = snapshots / "acquisition-v1.json"
    acquisition, acquisition_raw = _load_json(
        acquisition_path, "official-project acquisition", limit=1024 * 1024
    )
    if set(acquisition) != ACQUISITION_FIELDS:
        raise ValueError("official-project acquisition has unexpected fields")
    if acquisition["schema"] != "official-project-acquisition-v1":
        raise ValueError("official-project acquisition schema is invalid")
    mode = acquisition["mode"]
    if mode not in {"pinned", "latest"} or (mode == "latest" and not allow_latest):
        raise ValueError("fixed compatibility gate requires pinned acquisition")
    if acquisition["manifest_digest"] != manifest_digest:
        raise ValueError("acquisition manifest digest does not match")
    projects = acquisition["projects"]
    if not isinstance(projects, list) or len(projects) != len(manifest["projects"]):
        raise ValueError("acquisition project set is incomplete")
    acquired_by_id: dict[str, dict[str, Any]] = {}
    for index, project in enumerate(projects):
        if not isinstance(project, dict) or set(project) != ACQUIRED_PROJECT_FIELDS:
            raise ValueError(f"acquisition projects[{index}] has unexpected fields")
        identifier = project["id"]
        if not isinstance(identifier, str) or identifier in acquired_by_id:
            raise ValueError("acquisition contains a missing or duplicate project id")
        if project["provider"] not in PROVIDERS:
            raise ValueError(f"{identifier} has an unsupported provider")
        if not isinstance(project["files"], int) or project["files"] < 1:
            raise ValueError(f"{identifier} has no acquired CI files")
        if not isinstance(project["revision"], str) or not REVISION.fullmatch(project["revision"]):
            raise ValueError(f"{identifier} has an invalid commit")
        if not isinstance(project["tree"], str) or not REVISION.fullmatch(project["tree"]):
            raise ValueError(f"{identifier} has an invalid tree")
        if not isinstance(project["snapshot_digest"], str) or not DIGEST.fullmatch(
            project["snapshot_digest"]
        ):
            raise ValueError(f"{identifier} has an invalid snapshot digest")
        acquired_by_id[identifier] = project

    ordered: list[dict[str, Any]] = []
    for expected in manifest["projects"]:
        actual = acquired_by_id.get(expected["id"])
        if actual is None:
            raise ValueError(f"acquisition omits {expected['id']}")
        for field in ("id", "provider", "repository"):
            if actual[field] != expected[field]:
                raise ValueError(f"{expected['id']} acquisition {field} does not match")
        if mode == "pinned":
            for field in ("revision", "tree"):
                if actual[field] != expected[field]:
                    raise ValueError(f"{expected['id']} acquisition {field} drifted")
        project_root = snapshots / expected["id"]
        if project_root.is_symlink() or not project_root.is_dir():
            raise ValueError(f"{expected['id']} snapshot directory is missing or a symlink")
        snapshot_digest, files = _snapshot_digest(project_root)
        if snapshot_digest != actual["snapshot_digest"] or files != actual["files"]:
            raise ValueError(f"{expected['id']} snapshot bytes do not match acquisition")
        ordered.append(actual)
    return ordered, manifest_digest, _digest(acquisition_raw)


def _run_analyzer(analyzer: Path, cwd: Path, target: str, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError(f"{target} analysis exceeded 60 seconds")
    environment = dict(os.environ)
    environment.update(
        {
            "ALL_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    try:
        completed = subprocess.run(
            [
                str(analyzer),
                "check",
                "--cache-mode",
                "off",
                "--persona",
                "audit",
                "--format",
                "json",
                target,
            ],
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=max(0.1, remaining),
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"{target} analysis exceeded 60 seconds") from error
    except OSError as error:
        raise ValueError(f"cannot start analyzer for {target}: {error}") from error
    if len(completed.stdout) > 128 * 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
        raise ValueError(f"{target} analyzer output exceeded its bound")
    if completed.returncode == 4 or b"internal error:" in completed.stderr.lower():
        raise ValueError(f"{target} analyzer encountered an internal error")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{target} analyzer returned {completed.returncode}: {detail}")
    return completed.stdout


def _report_summary(raw: bytes, project: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if not 0 < len(raw) <= 128 * 1024 * 1024:
        raise ValueError(f"{project['id']} report has an invalid size")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{project['id']} emitted invalid JSON: {error}") from error
    if not isinstance(report, dict) or report.get("schema") != "report-v2":
        raise ValueError(f"{project['id']} did not emit report-v2")
    report_digest = report.get("digest")
    if not isinstance(report_digest, str) or not DIGEST.fullmatch(report_digest):
        raise ValueError(f"{project['id']} report digest is invalid")
    graphs = report.get("graphs")
    inputs = report.get("inputs")
    diagnostics = report.get("diagnostics")
    if not isinstance(graphs, list) or not graphs:
        raise ValueError(f"{project['id']} did not detect a workflow graph")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError(f"{project['id']} did not analyze any CI inputs")
    if not isinstance(diagnostics, list):
        raise ValueError(f"{project['id']} diagnostics are malformed")
    detected = {graph.get("provider") for graph in graphs if isinstance(graph, dict)}
    if detected != {project["provider"]}:
        raise ValueError(
            f"{project['id']} provider detection was {sorted(str(item) for item in detected)}"
        )
    counts = {severity: 0 for severity in SEVERITIES}
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            raise ValueError(f"{project['id']} contains a malformed diagnostic")
        if diagnostic.get("rule_id") == "YAML-SYNTAX":
            raise ValueError(f"{project['id']} rejected valid upstream YAML")
        severity = diagnostic.get("severity")
        if severity not in counts:
            raise ValueError(f"{project['id']} contains an unknown diagnostic severity")
        counts[severity] += 1
    counts["total"] = len(diagnostics)
    tool = report.get("tool")
    if (
        not isinstance(tool, dict)
        or tool.get("name") != "workflow-verifier"
        or not isinstance(tool.get("version"), str)
    ):
        raise ValueError(f"{project['id']} report tool identity is invalid")
    semantic_report = json.loads(json.dumps(report))
    semantic_report.pop("digest", None)
    semantic_tool = semantic_report.get("tool")
    if isinstance(semantic_tool, dict):
        semantic_tool.pop("binary_digest", None)
        semantic_build = semantic_tool.get("build")
        if isinstance(semantic_build, dict):
            semantic_build.pop("source_commit", None)
    semantic_digest = _digest(
        json.dumps(
            semantic_report,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    return (
        {
            "diagnostics": counts,
            "files": project["files"],
            "graphs": len(graphs),
            "id": project["id"],
            "inputs": len(inputs),
            "provider": project["provider"],
            "report_digest": report_digest,
            "report_sha256": _digest(raw),
            "revision": project["revision"],
            "semantic_digest": semantic_digest,
            "snapshot_digest": project["snapshot_digest"],
            "tree": project["tree"],
        },
        tool["version"],
    )


def analyze(
    manifest_path: Path,
    snapshots: Path,
    analyzer: Path,
    *,
    allow_latest: bool = False,
) -> dict[str, Any]:
    projects, manifest_digest, acquisition_digest = _validate_acquisition(
        manifest_path, snapshots, allow_latest=allow_latest
    )
    analyzer = analyzer.resolve(strict=True)
    if analyzer.is_symlink() or not analyzer.is_file():
        raise ValueError("analyzer must be a regular non-symlink file")
    summaries = []
    versions: set[str] = set()
    for project in projects:
        deadline = time.monotonic() + 60.0
        first = _run_analyzer(analyzer, snapshots, project["id"], deadline)
        second = _run_analyzer(analyzer, snapshots, project["id"], deadline)
        if first != second:
            raise ValueError(f"{project['id']} report is not deterministic")
        summary, version = _report_summary(first, project)
        summaries.append(summary)
        versions.add(version)
    if len(versions) != 1:
        raise ValueError("official-project reports disagree on tool version")
    provider_counts = {
        provider: sum(project["provider"] == provider for project in summaries)
        for provider in PROVIDERS
    }
    return {
        "acquisition_digest": acquisition_digest,
        "failures": [],
        "manifest_digest": manifest_digest,
        "passed": True,
        "projects": summaries,
        "providers": provider_counts,
        "repositories": len(summaries),
        "schema": "official-compat-v1",
        "tool_version": next(iter(versions)),
    }


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, raw: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _comparison_projection(document: Any, label: str) -> Any:
    if not isinstance(document, dict) or document.get("schema") != "official-compat-v1":
        raise ValueError(f"{label} is not official-compat-v1")
    projects = document.get("projects")
    if not isinstance(projects, list):
        raise ValueError(f"{label} projects are malformed")
    projected = json.loads(json.dumps(document))
    for index, project in enumerate(projected["projects"]):
        if not isinstance(project, dict):
            raise ValueError(f"{label} project {index} is malformed")
        for field in ("report_digest", "report_sha256", "semantic_digest"):
            if not isinstance(project.get(field), str) or not DIGEST.fullmatch(project[field]):
                raise ValueError(f"{label} project {index} {field} is invalid")
        project.pop("report_digest")
        project.pop("report_sha256")
    return projected


def _verify_expected(raw: bytes, expected: Path, expected_digest: Path | None) -> None:
    expected_document, expected_raw = _load_json(
        expected, "expected official compatibility report", limit=4 * 1024 * 1024
    )
    actual_document = json.loads(raw.decode("utf-8"))
    if _comparison_projection(actual_document, "actual official compatibility report") != (
        _comparison_projection(expected_document, "expected official compatibility report")
    ):
        raise ValueError("official compatibility report differs from the fixed report")
    if expected_digest is not None:
        try:
            recorded = expected_digest.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise ValueError(f"cannot read official report digest: {error}") from error
        if not DIGEST.fullmatch(recorded) or recorded != _digest(expected_raw):
            raise ValueError("official compatibility report digest does not match")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("official/official-projects-v1.json"))
    parser.add_argument("--snapshots", required=True, type=Path)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--expected-digest", type=Path)
    parser.add_argument("--allow-latest", action="store_true")
    arguments = parser.parse_args()
    if arguments.expected_digest is not None and arguments.expected is None:
        parser.error("--expected-digest requires --expected")
    try:
        result = analyze(
            arguments.manifest,
            arguments.snapshots,
            arguments.analyzer,
            allow_latest=arguments.allow_latest,
        )
        raw = _canonical(result)
        if arguments.expected is not None:
            _verify_expected(raw, arguments.expected, arguments.expected_digest)
        _atomic_write(arguments.output, raw)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"official compatibility gate: {error}", file=sys.stderr)
        return 2
    print(
        f"official compatibility gate: {result['repositories']} repositories; report={_digest(raw)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
