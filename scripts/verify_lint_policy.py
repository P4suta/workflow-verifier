#!/usr/bin/env python3
"""Reject suppressions that can hide first-party Rust lint failures."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

ALLOW_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*allow\s*\(", re.MULTILINE)
CFG_ALLOW_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*cfg_attr\s*\([^\]]*\ballow\s*\(", re.DOTALL)
EXPECT_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*expect\s*\((.*?)\)\s*\]", re.DOTALL)
REASON = re.compile(r'\breason\s*=\s*"(?:[^"\\]|\\.)+"')
LINT_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:::[a-z][a-z0-9_]*)*$")
LINT_GROUPS = {
    "warnings",
    "unused",
    "deprecated_safe",
    "future_incompatible",
    "keyword_idents",
    "let_underscore",
    "nonstandard_style",
    "refining_impl_trait",
    "rust_2018_compatibility",
    "rust_2018_idioms",
    "rust_2021_compatibility",
    "rust_2024_compatibility",
    "unknown_or_malformed_diagnostic_attributes",
    "clippy::all",
    "clippy::cargo",
    "clippy::complexity",
    "clippy::correctness",
    "clippy::nursery",
    "clippy::pedantic",
    "clippy::perf",
    "clippy::restriction",
    "clippy::style",
    "clippy::suspicious",
}
RUST_SOURCE_ROOTS = ("src", "tests", "helpers", "crates")
FIRST_PARTY_FLAG_PATHS = (
    ".cargo",
    ".circleci",
    ".github",
    ".gitlab-ci.yml",
    "scripts",
    "azure-pipelines.yml",
    "Cargo.toml",
    "justfile",
    "mise.toml",
)
RUST_ALLOW_FLAG = re.compile(
    r"(?:^|[\s\"'])-A(?:[\s\"']|(?:clippy|rustdoc|rustc)::|"
    r"[a-z][a-z0-9_]*_[a-z0-9_]+\b|warnings\b|unused\b)",
    re.MULTILINE,
)


def relative(path: pathlib.Path, root: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def rust_source_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    paths = [root / "build.rs", root / "src" / "main.rs", root / "src" / "lib.rs"]
    for directory in RUST_SOURCE_ROOTS:
        base = root / directory
        if base.is_dir():
            paths.extend(base.rglob("*.rs"))
    for path in sorted(set(path for path in paths if path.is_file())):
        source = path.read_text(encoding="utf-8")
        name = relative(path, root)
        if ALLOW_ATTRIBUTE.search(source):
            errors.append(f"{name} contains a forbidden allow attribute")
        if CFG_ALLOW_ATTRIBUTE.search(source):
            errors.append(f"{name} contains cfg_attr(..., allow(...))")
        for match in EXPECT_ATTRIBUTE.finditer(source):
            body = match.group(1)
            line = source.count("\n", 0, match.start()) + 1
            if REASON.search(body) is None:
                errors.append(f"{name}:{line} expect attribute needs a non-empty reason")
            lint_source = REASON.sub("", body)
            lint_names = [item.strip() for item in lint_source.split(",") if item.strip()]
            if not lint_names:
                errors.append(f"{name}:{line} expect attribute names no lint")
            for lint in lint_names:
                if lint in LINT_GROUPS:
                    errors.append(f"{name}:{line} expect attribute names lint group {lint}")
                elif LINT_NAME.fullmatch(lint) is None:
                    errors.append(f"{name}:{line} expect attribute has invalid lint name {lint!r}")
    return errors


def lint_level_allows(value: object, trail: tuple[str, ...] = ()) -> list[str]:
    errors: list[str] = []
    if isinstance(value, str) and value.lower() == "allow":
        errors.append(".".join(trail))
    elif isinstance(value, dict):
        if str(value.get("level", "")).lower() == "allow":
            errors.append(".".join(trail))
        for name, child in value.items():
            if name != "level":
                errors.extend(lint_level_allows(child, trail + (str(name),)))
    return errors


def manifest_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    manifests = sorted(path for path in root.rglob("Cargo.toml") if "target" not in path.parts)
    for path in manifests:
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            errors.append(f"{relative(path, root)} cannot be parsed: {error}")
            continue
        scopes = []
        if isinstance(document.get("lints"), dict):
            scopes.append(("lints", document["lints"]))
        workspace = document.get("workspace")
        if isinstance(workspace, dict) and isinstance(workspace.get("lints"), dict):
            scopes.append(("workspace.lints", workspace["lints"]))
        for prefix, scope in scopes:
            for lint in lint_level_allows(scope, (prefix,)):
                errors.append(f"{relative(path, root)} sets explicit lint allow at {lint}")

    root_manifest = root / "Cargo.toml"
    if root_manifest.is_file():
        document = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
        workspace_lints = document.get("workspace", {}).get("lints", {})
        rust = workspace_lints.get("rust", {})
        clippy = workspace_lints.get("clippy", {})
        required = {
            "workspace.lints.rust.unfulfilled_lint_expectations": (
                rust.get("unfulfilled_lint_expectations"),
                "deny",
            ),
            "workspace.lints.clippy.allow_attributes": (
                clippy.get("allow_attributes"),
                "forbid",
            ),
            "workspace.lints.clippy.allow_attributes_without_reason": (
                clippy.get("allow_attributes_without_reason"),
                "deny",
            ),
        }
        for name, (actual, expected) in required.items():
            if actual != expected:
                errors.append(f"Cargo.toml {name} is {actual!r}; expected {expected!r}")
    return errors


def first_party_flag_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    candidates: list[pathlib.Path] = []
    for entry in FIRST_PARTY_FLAG_PATHS:
        path = root / entry
        if path.is_file():
            candidates.append(path)
        elif path.is_dir():
            candidates.extend(candidate for candidate in path.rglob("*") if candidate.is_file())
    for path in sorted(set(candidates)):
        if path.resolve() == pathlib.Path(__file__).resolve() or "tests" in path.parts:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        if RUST_ALLOW_FLAG.search(source):
            errors.append(f"{relative(path, root)} contains forbidden first-party -A flag")
    return errors


def repository_errors(root: pathlib.Path = ROOT) -> list[str]:
    return rust_source_errors(root) + manifest_errors(root) + first_party_flag_errors(root)


def run() -> None:
    errors = repository_errors()
    if errors:
        for error in errors:
            print(f"lint policy: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("lint policy: no allow attributes, lint-group expectations, manifest allows, or -A flags")


if __name__ == "__main__":
    run()
