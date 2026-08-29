from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any


def canonical(value: Any, *, newline: bool = False) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + suffix
    ).encode("utf-8")


def domain_digest(domain: bytes, value: Any) -> str:
    digest = hashlib.sha256()
    for field in (domain, canonical(value)):
        digest.update(len(field).to_bytes(8, byteorder="big"))
        digest.update(field)
    return "sha256:" + digest.hexdigest()


def diagnostic(
    identifier: str = "diag_" + "1" * 64,
    rule_id: str = "WV-SUPPLY-001",
    *,
    severity: str = "warning",
    message: str = "reviewed fixture",
) -> dict[str, Any]:
    return {
        "confidence": "high",
        "id": identifier,
        "message": message,
        "rule_id": rule_id,
        "severity": severity,
        "span": {
            "source": 0,
            "start": {"byte": 0, "column": 1, "line": 1},
            "stop": {"byte": 1, "column": 2, "line": 1},
        },
    }


def report_document(
    *,
    diagnostics: list[dict[str, Any]] | None = None,
    persona: str = "audit",
    provider: str = "github",
    paths: list[str] | None = None,
    commit: str | None = None,
    target: str = "test-target",
    properties: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    diagnostics = [] if diagnostics is None else deepcopy(diagnostics)
    if paths is None:
        paths = {
            "azure": ["azure-pipelines.yml"],
            "circleci": [".circleci/config.yml"],
            "github": [".github/workflows/ci.yml"],
            "gitlab": [".gitlab-ci.yml"],
        }[provider]
    sources = [
        {
            "digest": "sha256:" + hashlib.sha256(path.encode("utf-8")).hexdigest(),
            "id": index,
            "path": path,
        }
        for index, path in enumerate(paths)
    ]
    document: dict[str, Any] = {
        "completeness": {"reasons": [], "state": "complete"},
        "diagnostics": diagnostics,
        "gate": {"exit_code": 0, "result": "pass"},
        "inputs": {
            "config": {
                "digest": "sha256:" + "0" * 64,
                "origin": "built-in",
                "trust": "built-in",
            },
            "lock": {"digest": "sha256:" + "0" * 64},
            "manifest_digest": "sha256:" + "1" * 64,
            "sources": sources,
        },
        "persona": persona,
        "properties": [] if properties is None else deepcopy(properties),
        "providers": [f"{provider}-semantic-v1"],
        "schema": "workflow-verifier-report/1",
        "summary": {
            "diagnostics": len(diagnostics),
            "edges": 0,
            "nodes": 0,
            "properties": 0 if properties is None else len(properties),
            "sources": len(sources),
            "unknown_properties": 0,
            "violated_properties": 0,
        },
        "tool": {
            "commit": commit,
            "compiler": "rustc test",
            "name": "workflow-verifier",
            "target": target,
            "version": "0.1.0",
        },
    }
    semantic = deepcopy(document)
    semantic.pop("tool")
    document["analysis_digest"] = domain_digest(b"workflow-verifier-report/1/analysis", semantic)
    authenticated = deepcopy(document)
    document["digest"] = domain_digest(b"workflow-verifier-report/1/document", authenticated)
    return document


def report_bytes(**kwargs: Any) -> bytes:
    return canonical(report_document(**kwargs), newline=True)
