#!/usr/bin/env python3
"""Enforce the analyzer's one-way Dune layer graph and module ownership."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib
from collections import namedtuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
PARTIAL_EXPRESSIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("assert false", re.compile(r"\bassert\s+false\b")),
    ("List.hd", re.compile(r"\bList\.hd\b")),
    ("List.tl", re.compile(r"\bList\.tl\b")),
    ("List.nth", re.compile(r"\bList\.nth\b")),
    ("List.find", re.compile(r"\bList\.find\b")),
    ("Option.get", re.compile(r"\bOption\.get\b")),
    ("Result.get_ok", re.compile(r"\bResult\.get_ok\b")),
    ("Result.get_error", re.compile(r"\bResult\.get_error\b")),
    ("Hashtbl.find", re.compile(r"\bHashtbl\.find\b")),
    ("invalid_arg", re.compile(r"\binvalid_arg\b")),
    ("failwith", re.compile(r"\bfailwith\b")),
    ("Obj.magic", re.compile(r"\bObj\.magic\b")),
    ("Bytes.unsafe_to_string", re.compile(r"\bBytes\.unsafe_to_string\b")),
)

EXPECTED_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "wv_foundation": ("unix",),
    "wv_syntax": ("wv_foundation",),
    "wv_domain": ("wv_foundation",),
    "wv_frontend": ("wv_foundation", "wv_syntax", "wv_domain"),
    "wv_verifier": ("wv_foundation", "wv_domain"),
    "wv_product": (
        "otoml",
        "wv_foundation",
        "wv_syntax",
        "wv_domain",
        "wv_frontend",
        "wv_verifier",
    ),
    "wv_sandbox": ("wv_foundation", "wv_domain", "wv_frontend", "wv_verifier"),
    "wv_application": (
        "cmdliner",
        "wv_foundation",
        "wv_syntax",
        "wv_domain",
        "wv_frontend",
        "wv_verifier",
        "wv_product",
        "wv_sandbox",
    ),
}
EXTERNAL_DEPENDENCIES = {"cmdliner", "otoml", "unix"}

EXPECTED_RUST_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "workflow-verifier-foundation": (),
    "workflow-verifier-syntax": ("workflow-verifier-foundation",),
    "workflow-verifier-domain": ("workflow-verifier-foundation",),
    "workflow-verifier-frontend": (
        "workflow-verifier-domain",
        "workflow-verifier-foundation",
        "workflow-verifier-syntax",
    ),
    "workflow-verifier-verifier": (
        "workflow-verifier-domain",
        "workflow-verifier-foundation",
    ),
    "workflow-verifier-product": (
        "workflow-verifier-domain",
        "workflow-verifier-foundation",
        "workflow-verifier-frontend",
        "workflow-verifier-syntax",
        "workflow-verifier-verifier",
    ),
    "workflow-verifier-sandbox": (
        "workflow-verifier-domain",
        "workflow-verifier-foundation",
        "workflow-verifier-frontend",
        "workflow-verifier-verifier",
    ),
    "workflow-verifier-engine": (
        "workflow-verifier-domain",
        "workflow-verifier-foundation",
        "workflow-verifier-frontend",
        "workflow-verifier-product",
        "workflow-verifier-sandbox",
        "workflow-verifier-syntax",
        "workflow-verifier-verifier",
    ),
    "workflow-verifier-cli": (
        "workflow-verifier-domain",
        "workflow-verifier-engine",
        "workflow-verifier-foundation",
        "workflow-verifier-frontend",
        "workflow-verifier-product",
        "workflow-verifier-sandbox",
        "workflow-verifier-syntax",
        "workflow-verifier-verifier",
    ),
    "workflow-verifier-conformance": (
        "workflow-verifier-foundation",
        "workflow-verifier-product",
    ),
}

EXPECTED_RUST_ADAPTER_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "workflow-verifier-cli": ("workflow-verifier-helper-runtime",),
    "workflow-verifier-sandbox": ("workflow-verifier-runner-protocol",),
}

ALLOWED_RUST_EXTERNAL_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "workflow-verifier-foundation": ("caseless", "sha2", "unicode-normalization"),
    "workflow-verifier-syntax": (),
    "workflow-verifier-domain": (),
    "workflow-verifier-frontend": (),
    "workflow-verifier-verifier": (),
    "workflow-verifier-product": ("serde", "toml"),
    "workflow-verifier-sandbox": (),
    "workflow-verifier-engine": (),
}

RUST_CORE_CRATES = tuple(ALLOWED_RUST_EXTERNAL_DEPENDENCIES)
RUST_FORBIDDEN_CORE_APIS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("std::fs", re.compile(r"\bstd::fs\b")),
    ("std::net", re.compile(r"\bstd::net\b")),
    ("std::process", re.compile(r"\bstd::process\b")),
    ("std::env", re.compile(r"\bstd::env\b")),
)
RUST_PARTIAL_EXPRESSIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("unreachable!", re.compile(r"\bunreachable!\s*\(")),
    ("panic!", re.compile(r"\bpanic!\s*\(")),
    ("unsafe block", re.compile(r"\bunsafe\s*(?:fn|trait|impl|\{)")),
    ("static mut", re.compile(r"\bstatic\s+mut\b")),
)

Library = namedtuple("Library", "path name modules dependencies wrapped")


def stanza(source: str, name: str, *, required: bool = True) -> tuple[str, ...]:
    match = re.search(rf"\({re.escape(name)}\b([^()]*)\)", source, re.DOTALL)
    if match is None:
        if required:
            raise ValueError(f"missing ({name} ...) stanza")
        return ()
    return tuple(re.findall(r"[A-Za-z0-9_.+-]+", match.group(1)))


def parse_library(path: str, source: str) -> Library:
    names = stanza(source, "name")
    if len(names) != 1:
        raise ValueError(f"{path}: library needs exactly one name")
    wrapped = stanza(source, "wrapped")
    if wrapped not in {("false",), ("true",)}:
        raise ValueError(f"{path}: wrapped must be explicit")
    return Library(
        path=path,
        name=names[0],
        modules=stanza(source, "modules"),
        dependencies=stanza(source, "libraries", required=False),
        wrapped=wrapped == ("true",),
    )


def graph_errors(graph: dict[str, tuple[str, ...]]) -> list[str]:
    errors: list[str] = []
    for name, dependencies in sorted(graph.items()):
        for dependency in dependencies:
            if dependency not in graph and dependency not in EXTERNAL_DEPENDENCIES:
                errors.append(f"{name} depends on unknown internal library {dependency}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str, trail: tuple[str, ...]) -> None:
        if name in visiting:
            start = trail.index(name)
            errors.append("dependency cycle: " + " -> ".join(trail[start:] + (name,)))
            return
        if name in visited:
            return
        visiting.add(name)
        for dependency in graph.get(name, ()):
            if dependency in graph:
                visit(dependency, trail + (dependency,))
        visiting.remove(name)
        visited.add(name)

    for name in sorted(graph):
        visit(name, (name,))
    return errors


def validate_dependencies(actual: dict[str, tuple[str, ...]]) -> list[str]:
    errors: list[str] = []
    for name in sorted(set(EXPECTED_DEPENDENCIES) | set(actual)):
        expected = EXPECTED_DEPENDENCIES.get(name)
        dependencies = actual.get(name)
        if expected is None:
            errors.append(f"unexpected internal library {name}")
        elif dependencies is None:
            errors.append(f"missing internal library {name}")
        elif dependencies != expected:
            errors.append(f"{name} dependencies are {dependencies!r}; expected {expected!r}")
    errors.extend(graph_errors(actual))
    return errors


def validate_rust_dependencies(actual: dict[str, tuple[str, ...]]) -> list[str]:
    errors: list[str] = []
    for name in sorted(set(EXPECTED_RUST_DEPENDENCIES) | set(actual)):
        expected = EXPECTED_RUST_DEPENDENCIES.get(name)
        dependencies = actual.get(name)
        if expected is None:
            errors.append(f"unexpected Rust analyzer crate {name}")
        elif dependencies is None:
            errors.append(f"missing Rust analyzer crate {name}")
        elif dependencies != expected:
            errors.append(f"{name} dependencies are {dependencies!r}; expected {expected!r}")
    errors.extend(graph_errors(actual))
    return errors


def partial_expression_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for path in sorted((root / "lib").rglob("*.ml*")):
        source = path.read_text(encoding="utf-8")
        for expression, pattern in PARTIAL_EXPRESSIONS:
            if pattern.search(source):
                relative = path.relative_to(root).as_posix()
                errors.append(f"{relative} contains partial expression {expression!r}")
    return errors


def rust_core_source_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    for crate in RUST_CORE_CRATES:
        directory = root / "crates" / crate.removeprefix("workflow-verifier-") / "src"
        if not directory.exists():
            continue
        library = directory / "lib.rs"
        if not library.is_file() or "#![forbid(unsafe_code)]" not in library.read_text(
            encoding="utf-8"
        ):
            errors.append(
                f"{library.relative_to(root).as_posix()} must forbid unsafe_code at the crate root"
            )
        for path in sorted(directory.rglob("*.rs")):
            source = path.read_text(encoding="utf-8")
            relative = path.relative_to(root).as_posix()
            for api, pattern in RUST_FORBIDDEN_CORE_APIS:
                if pattern.search(source):
                    errors.append(f"{relative} contains forbidden core API {api!r}")
            for expression, pattern in RUST_PARTIAL_EXPRESSIONS:
                if pattern.search(source):
                    errors.append(f"{relative} contains partial expression {expression!r}")
    return errors


def rust_repository_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    actual: dict[str, tuple[str, ...]] = {}
    adapters: dict[str, tuple[str, ...]] = {}
    externals: dict[str, tuple[str, ...]] = {}
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        relative = manifest.relative_to(root).as_posix()
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
            package = document["package"]
            name = package["name"]
            dependencies = document.get("dependencies", {})
        except (KeyError, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            errors.append(f"{relative}: cannot parse Cargo package: {error}")
            continue
        if name not in EXPECTED_RUST_DEPENDENCIES:
            errors.append(f"{relative}: unexpected Rust analyzer package {name!r}")
            continue
        if package.get("publish") is not False:
            errors.append(f"{relative}: package.publish must be false")
        internal = tuple(sorted(dep for dep in dependencies if dep in EXPECTED_RUST_DEPENDENCIES))
        adapter = tuple(
            sorted(
                dep
                for dep in dependencies
                if dep
                in {
                    item
                    for values in EXPECTED_RUST_ADAPTER_DEPENDENCIES.values()
                    for item in values
                }
            )
        )
        external = tuple(
            sorted(dep for dep in dependencies if dep not in set(internal) | set(adapter))
        )
        actual[name] = internal
        adapters[name] = adapter
        externals[name] = external

    errors.extend(validate_rust_dependencies(actual))
    for name, expected in sorted(EXPECTED_RUST_ADAPTER_DEPENDENCIES.items()):
        if adapters.get(name, ()) != expected:
            errors.append(
                f"{name} adapter dependencies are {adapters.get(name, ())!r}; expected {expected!r}"
            )
    for name, expected in sorted(ALLOWED_RUST_EXTERNAL_DEPENDENCIES.items()):
        if externals.get(name, ()) != expected:
            errors.append(
                f"{name} external dependencies are {externals.get(name, ())!r}; expected {expected!r}"
            )
    errors.extend(rust_core_source_errors(root))
    return errors


def repository_errors(root: pathlib.Path = ROOT) -> list[str]:
    errors: list[str] = []
    libraries: list[Library] = []
    for dune in sorted((root / "lib").glob("*/dune")):
        try:
            libraries.append(
                parse_library(
                    dune.relative_to(root).as_posix(),
                    dune.read_text(encoding="utf-8"),
                )
            )
        except ValueError as error:
            errors.append(str(error))

    actual = {library.name: library.dependencies for library in libraries}
    if len(actual) != len(libraries):
        errors.append("internal library names must be unique")
    errors.extend(validate_dependencies(actual))

    owners: dict[str, str] = {}
    for library in libraries:
        if library.wrapped:
            errors.append(f"{library.name} must remain private and explicitly unwrapped")
        directory = root / pathlib.PurePosixPath(library.path).parent
        sources = tuple(
            sorted({path.stem for pattern in ("*.ml", "*.mli") for path in directory.glob(pattern)})
        )
        if sources != tuple(sorted(library.modules)):
            errors.append(
                f"{library.name} declares {tuple(sorted(library.modules))!r} but owns {sources!r}"
            )
        for module in library.modules:
            previous = owners.setdefault(module, library.name)
            if previous != library.name:
                errors.append(f"module {module} is owned by both {previous} and {library.name}")
    errors.extend(partial_expression_errors(root))
    errors.extend(rust_repository_errors(root))
    return errors


def run() -> None:
    errors = repository_errors()
    if errors:
        for error in errors:
            print(f"architecture gate: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "architecture gate: OCaml reference and Rust product layers are one-way, private, pure, and panic-free"
    )


if __name__ == "__main__":
    run()
