#!/usr/bin/env python3
"""Enforce the analyzer's one-way Dune layer graph and module ownership."""

from __future__ import annotations

from collections import namedtuple
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "wv_foundation": (),
    "wv_syntax": ("wv_foundation",),
    "wv_domain": ("wv_foundation",),
    "wv_frontend": ("wv_foundation", "wv_syntax", "wv_domain"),
    "wv_verifier": ("wv_foundation", "wv_domain"),
    "wv_product": (
        "wv_foundation",
        "wv_syntax",
        "wv_domain",
        "wv_frontend",
        "wv_verifier",
    ),
    "wv_sandbox": ("wv_foundation", "wv_domain", "wv_verifier"),
    "wv_application": (
        "wv_foundation",
        "wv_syntax",
        "wv_domain",
        "wv_frontend",
        "wv_verifier",
        "wv_product",
        "wv_sandbox",
    ),
}

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
            if dependency not in graph:
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
            errors.append(
                f"{name} dependencies are {dependencies!r}; expected {expected!r}"
            )
    errors.extend(graph_errors(actual))
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
            sorted(
                {
                    path.stem
                    for pattern in ("*.ml", "*.mli")
                    for path in directory.glob(pattern)
                }
            )
        )
        if sources != tuple(sorted(library.modules)):
            errors.append(
                f"{library.name} declares {tuple(sorted(library.modules))!r} "
                f"but owns {sources!r}"
            )
        for module in library.modules:
            previous = owners.setdefault(module, library.name)
            if previous != library.name:
                errors.append(f"module {module} is owned by both {previous} and {library.name}")
    return errors


def run() -> None:
    errors = repository_errors()
    if errors:
        for error in errors:
            print(f"architecture gate: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "architecture gate: 8 private layers, one-way dependencies, unique module ownership"
    )


if __name__ == "__main__":
    run()
