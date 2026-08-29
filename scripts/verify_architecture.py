#!/usr/bin/env python3
"""Enforce one-way OCaml-library and Rust-module architecture boundaries."""

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

EXPECTED_RUST_MODULE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "foundation": (),
    "syntax": ("foundation",),
    "domain": ("foundation",),
    "frontend": ("domain", "foundation", "syntax"),
    "verifier": ("domain", "foundation"),
    "product": ("domain", "foundation", "frontend", "syntax", "verifier"),
    "sandbox": ("domain", "foundation", "runner_protocol", "verifier"),
    "engine": ("domain", "foundation", "frontend", "product", "syntax", "verifier"),
    "application": (
        "domain",
        "engine",
        "foundation",
        "frontend",
        "helper_runtime",
        "product",
        "sandbox",
        "syntax",
        "verifier",
    ),
    "runner_protocol": (),
    "helper_runtime": ("runner_protocol",),
    "conformance": (
        "application",
        "domain",
        "engine",
        "foundation",
        "frontend",
        "product",
        "sandbox",
        "syntax",
        "verifier",
    ),
}

ALLOWED_RUST_EXTERNAL_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "foundation": ("caseless", "sha2", "unicode_normalization"),
    "syntax": (),
    "domain": (),
    "frontend": (),
    "verifier": (),
    "product": ("serde", "serde_json", "toml"),
    "sandbox": (),
    "engine": (),
    "application": (
        "rustls",
        "rustls_native_certs",
        "serde_json",
        "toml",
        "url",
        "zeroize",
    ),
    "runner_protocol": (),
    "helper_runtime": ("same_file",),
    "conformance": (),
}

RUST_MODULES = tuple(EXPECTED_RUST_MODULE_DEPENDENCIES)
RUST_CORE_MODULES = (
    "foundation",
    "syntax",
    "domain",
    "frontend",
    "verifier",
    "product",
    "sandbox",
    "engine",
)
RUST_EXTERNAL_CRATES = {
    dependency
    for dependencies in ALLOWED_RUST_EXTERNAL_DEPENDENCIES.values()
    for dependency in dependencies
}
EXPECTED_PRIVATE_PACKAGES = {
    "workflow-verifier-conformance",
    "workflow-verifier-helper-conformance",
    "workflow-verifier-linux-helper",
    "workflow-verifier-macos-helper",
    "workflow-verifier-oci-helper",
    "workflow-verifier-vm-agent",
    "workflow-verifier-windows-helper",
}
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


def validate_rust_module_dependencies(actual: dict[str, tuple[str, ...]]) -> list[str]:
    errors: list[str] = []
    for name in sorted(set(EXPECTED_RUST_MODULE_DEPENDENCIES) | set(actual)):
        expected = EXPECTED_RUST_MODULE_DEPENDENCIES.get(name)
        dependencies = actual.get(name)
        if expected is None:
            errors.append(f"unexpected Rust implementation module {name}")
        elif dependencies is None:
            errors.append(f"missing Rust implementation module {name}")
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
    library = root / "src" / "lib.rs"
    if not library.is_file() or "#![forbid(unsafe_code)]" not in library.read_text(
        encoding="utf-8"
    ):
        errors.append("src/lib.rs must forbid unsafe_code at the package root")
    for module in RUST_CORE_MODULES:
        directory = root / "src" / module
        if not directory.exists():
            continue
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


def rust_module_dependencies(source: str, owner: str) -> tuple[str, ...]:
    direct = set(
        re.findall(
            rf"\bcrate::({'|'.join(map(re.escape, RUST_MODULES))})\b",
            source,
        )
    )
    direct.update(
        re.findall(r"\bcrate::internal::(runner_protocol|helper_runtime|conformance)\b", source)
    )
    direct.discard(owner)
    return tuple(sorted(direct))


def rust_external_dependencies(source: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            dependency
            for dependency in RUST_EXTERNAL_CRATES
            if re.search(rf"\b{re.escape(dependency)}::", source)
        )
    )


def cargo_dependency_tables(document: dict[str, object]) -> list[dict[str, object]]:
    tables: list[dict[str, object]] = []
    dependencies = document.get("dependencies", {})
    if isinstance(dependencies, dict):
        tables.append(dependencies)
    targets = document.get("target", {})
    if isinstance(targets, dict):
        for target in targets.values():
            if isinstance(target, dict):
                dependencies = target.get("dependencies", {})
                if isinstance(dependencies, dict):
                    tables.append(dependencies)
    return tables


def rust_package_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    root_manifest = root / "Cargo.toml"
    try:
        document = tomllib.loads(root_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        return [f"Cargo.toml: cannot parse root package: {error}"]
    package = document.get("package", {})
    if not isinstance(package, dict) or package.get("name") != "workflow-verifier":
        errors.append("Cargo.toml must define the sole public package workflow-verifier")
    if isinstance(package, dict) and package.get("publish") is False:
        errors.append("workflow-verifier must remain publishable")
    expected_include = {
        "/Cargo.toml",
        "/Cargo.lock",
        "/build.rs",
        "/src/**/*.rs",
        "/README.md",
        "/CHANGELOG.md",
        "/LICENSE-APACHE",
        "/LICENSE-MIT",
    }
    if not isinstance(package, dict) or set(package.get("include", ())) != expected_include:
        errors.append(
            "workflow-verifier package.include must be the reviewed public-crate allowlist"
        )
    for dependencies in cargo_dependency_tables(document):
        for name, specification in dependencies.items():
            if isinstance(specification, dict) and "path" in specification:
                errors.append(f"public package has forbidden path dependency {name}")

    workspace = document.get("workspace", {})
    members = workspace.get("members", ()) if isinstance(workspace, dict) else ()
    workspace_package = workspace.get("package", {}) if isinstance(workspace, dict) else {}
    workspace_version = (
        workspace_package.get("version") if isinstance(workspace_package, dict) else None
    )
    if not isinstance(workspace_version, str):
        errors.append("Cargo workspace package version must be a string")
    manifests = [root_manifest]
    manifests.extend(root / member / "Cargo.toml" for member in members if member != ".")
    packages: dict[str, tuple[pathlib.Path, dict[str, object]]] = {}
    for manifest in manifests:
        relative = manifest.relative_to(root).as_posix()
        try:
            member_document = tomllib.loads(manifest.read_text(encoding="utf-8"))
            member_package = member_document["package"]
            name = member_package["name"]
        except (KeyError, OSError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
            errors.append(f"{relative}: cannot parse Cargo package: {error}")
            continue
        if name in packages:
            errors.append(f"duplicate Cargo package name {name}")
        packages[name] = (manifest, member_document)

    public = {
        name for name, (_, item) in packages.items() if item["package"].get("publish") is not False
    }
    private = set(packages) - public
    if public != {"workflow-verifier"}:
        errors.append(
            f"publishable Cargo packages are {sorted(public)!r}; expected ['workflow-verifier']"
        )
    if private != EXPECTED_PRIVATE_PACKAGES:
        errors.append(
            f"private Cargo packages are {sorted(private)!r}; expected {sorted(EXPECTED_PRIVATE_PACKAGES)!r}"
        )

    for name, (manifest, member_document) in sorted(packages.items()):
        if name == "workflow-verifier":
            continue
        package = member_document["package"]
        if package.get("publish") is not False:
            errors.append(f"{manifest.relative_to(root).as_posix()}: package.publish must be false")
        dependency = member_document.get("dependencies", {}).get("workflow-verifier-internal")
        expected_feature = (
            "conformance-support" if name == "workflow-verifier-conformance" else "internal-support"
        )
        if not isinstance(dependency, dict):
            errors.append(f"{name} must depend on the root package as workflow-verifier-internal")
            continue
        expected = {
            "package": "workflow-verifier",
            "path": "../..",
            "version": f"={workspace_version}",
            "default-features": False,
            "features": [expected_feature],
        }
        if dependency != expected:
            errors.append(
                f"{name} internal root dependency is {dependency!r}; expected {expected!r}"
            )
    return errors


def rust_visibility_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    library = (root / "src" / "lib.rs").read_text(encoding="utf-8")
    public_modules = set(re.findall(r"(?m)^pub\s+mod\s+([a-zA-Z_][a-zA-Z0-9_]*)", library))
    if public_modules != {"internal"}:
        errors.append(
            f"src/lib.rs public modules are {sorted(public_modules)!r}; expected ['internal']"
        )
    for module in RUST_MODULES:
        if re.search(rf"(?m)^pub\s+mod\s+{re.escape(module)}\b", library):
            errors.append(f"src/lib.rs leaks private implementation module {module}")
    internal = (root / "src" / "internal.rs").read_text(encoding="utf-8")
    internal_modules = set(re.findall(r"(?m)^pub\s+mod\s+([a-zA-Z_][a-zA-Z0-9_]*)", internal))
    expected = {"conformance", "helper_runtime", "runner_protocol"}
    if internal_modules != expected:
        errors.append(
            f"src/internal.rs exports {sorted(internal_modules)!r}; expected {sorted(expected)!r}"
        )
    if "#[doc(hidden)]\npub mod internal;" not in library:
        errors.append("src/lib.rs must doc-hide the non-SemVer internal module")
    return errors


def rust_repository_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    actual: dict[str, tuple[str, ...]] = {}
    for name in RUST_MODULES:
        directory = root / "src" / name
        if not directory.is_dir():
            errors.append(f"missing Rust implementation directory src/{name}")
            continue
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(directory.rglob("*.rs"))
        )
        actual[name] = rust_module_dependencies(source, name)
        expected_external = ALLOWED_RUST_EXTERNAL_DEPENDENCIES[name]
        external = rust_external_dependencies(source)
        if external != expected_external:
            errors.append(
                f"{name} external dependencies are {external!r}; expected {expected_external!r}"
            )

    errors.extend(validate_rust_module_dependencies(actual))
    errors.extend(rust_package_errors(root))
    errors.extend(rust_visibility_errors(root))
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
