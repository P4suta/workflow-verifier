#!/usr/bin/env python3
"""Synchronize derived release metadata from the Cargo workspace version."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = rf"(?:{NUMERIC_IDENTIFIER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(
    rf"^{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}"
    rf"(?:-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@dataclass
class Sources:
    root: Path
    values: dict[Path, str] = field(default_factory=dict)

    def read(self, relative: str | Path) -> str:
        relative_path = Path(relative)
        if relative_path not in self.values:
            path = self.root / relative_path
            try:
                self.values[relative_path] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise ValueError(f"cannot read {relative_path.as_posix()}: {error}") from error
        return self.values[relative_path]

    def replace(self, relative: str | Path, source: str) -> None:
        self.values[Path(relative)] = source


SURFACES = (
    (
        "dune-project",
        "dune-project",
        re.compile(r"(?m)^(\(version[ \t]+)([^\s)]+)(\)[ \t]*\r?$)"),
    ),
    (
        "generated opam",
        "workflow-verifier.opam",
        re.compile(r'(?m)^(version:[ \t]*")([^"\r\n]+)("[ \t]*\r?$)'),
    ),
    (
        "locked opam (OCaml 5.5)",
        "workflow-verifier.opam.locked",
        re.compile(r'(?m)^(version:[ \t]*")([^"\r\n]+)("[ \t]*\r?$)'),
    ),
    (
        "locked opam (OCaml 5.4)",
        "workflow-verifier.opam.locked-ocaml54",
        re.compile(r'(?m)^(version:[ \t]*")([^"\r\n]+)("[ \t]*\r?$)'),
    ),
    (
        "OCaml Product_version",
        "lib/foundation/product_version.ml",
        re.compile(r'(?m)^(let version[ \t]*=[ \t]*")([^"\r\n]+)("[ \t]*\r?$)'),
    ),
    (
        "manual page",
        "man/workflow-verifier.1",
        re.compile(
            r'(?m)^(\.TH[ \t]+WORKFLOW-VERIFIER[ \t]+1[ \t]+"[^"]+"[ \t]+'
            r'"workflow-verifier[ \t]+)([^"\s]+)("[ \t]*\r?$)'
        ),
    ),
)


def _toml(source: str, label: str) -> dict[str, object]:
    try:
        return tomllib.loads(source)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"cannot parse {label}: {error}") from error


def cargo_version(root: Path = ROOT) -> str:
    try:
        source = (root / "Cargo.toml").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read Cargo.toml: {error}") from error
    document = _toml(source, "Cargo.toml")
    try:
        workspace = document["workspace"]
        workspace_package = workspace["package"]  # type: ignore[index]
        version = workspace_package["version"]  # type: ignore[index]
    except (KeyError, TypeError) as error:
        raise ValueError("Cargo workspace package version is missing") from error
    if not isinstance(version, str):
        raise ValueError("Cargo workspace package version must be a string")
    if SEMVER.fullmatch(version) is None:
        raise ValueError(f"Cargo workspace version is not SemVer: {version}")
    return version


def _replace_single(
    sources: Sources,
    label: str,
    relative: str,
    pattern: re.Pattern[str],
    version: str,
) -> None:
    source = sources.read(relative)
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        state = "missing" if not matches else "duplicated"
        raise ValueError(f"{label} version marker is {state}")
    match = matches[0]
    sources.replace(
        relative,
        source[: match.start(2)] + version + source[match.end(2) :],
    )


def _replace_project_version(sources: Sources, version: str) -> None:
    relative = "pyproject.toml"
    source = sources.read(relative)
    lines = source.splitlines(keepends=True)
    headers = [index for index, line in enumerate(lines) if line.strip() == "[project]"]
    if len(headers) != 1:
        state = "missing" if not headers else "duplicated"
        raise ValueError(f"Python project table is {state}")
    start = headers[0] + 1
    end = next(
        (index for index in range(start, len(lines)) if lines[index].lstrip().startswith("[")),
        len(lines),
    )
    pattern = re.compile(
        r'^([ \t]*version[ \t]*=[ \t]*")([^"\r\n]+)'
        r'("[ \t]*(?:#[^\r\n]*)?(?:\r?\n)?)$'
    )
    matches = [(index, pattern.fullmatch(lines[index])) for index in range(start, end)]
    matches = [(index, match) for index, match in matches if match is not None]
    if len(matches) != 1:
        state = "missing" if not matches else "duplicated"
        raise ValueError(f"Python project version marker is {state}")
    index, match = matches[0]
    assert match is not None
    lines[index] = match.group(1) + version + match.group(3)
    sources.replace(relative, "".join(lines))


def _workspace_manifests(
    root: Path, sources: Sources
) -> tuple[dict[Path, dict[str, object]], dict[Path, str]]:
    root_document = _toml(sources.read("Cargo.toml"), "Cargo.toml")
    workspace = root_document.get("workspace")
    if not isinstance(workspace, dict):
        raise ValueError("Cargo workspace table is missing")
    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise ValueError("Cargo workspace members must be a string array")

    relative_manifests: list[Path] = []
    for member in members:
        assert isinstance(member, str)
        matches = [root] if member == "." else sorted(root.glob(member))
        if not matches:
            raise ValueError(f"Cargo workspace member is missing: {member}")
        for match in matches:
            manifest = (match / "Cargo.toml").resolve()
            try:
                relative = manifest.relative_to(root.resolve())
            except ValueError as error:
                raise ValueError(
                    f"Cargo workspace member escapes the repository: {member}"
                ) from error
            relative_manifests.append(relative)

    documents: dict[Path, dict[str, object]] = {}
    package_names: dict[Path, str] = {}
    for relative in relative_manifests:
        if relative in documents:
            raise ValueError(f"duplicate Cargo workspace member: {relative.as_posix()}")
        document = _toml(sources.read(relative), relative.as_posix())
        package = document.get("package")
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise ValueError(f"{relative.as_posix()}: Cargo package name is missing")
        if package.get("version") != {"workspace": True}:
            raise ValueError(
                f"{relative.as_posix()}: package version must inherit workspace.package.version"
            )
        documents[relative] = document
        package_names[(root / relative).parent.resolve()] = package["name"]
    return documents, package_names


def _dependency_tables(document: dict[str, object]) -> Iterator[dict[str, object]]:
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = document.get(key)
        if isinstance(table, dict):
            yield table
    workspace = document.get("workspace")
    if isinstance(workspace, dict):
        table = workspace.get("dependencies")
        if isinstance(table, dict):
            yield table
    targets = document.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target.get(key)
                if isinstance(table, dict):
                    yield table


def _replace_path_dependency(
    sources: Sources,
    manifest: Path,
    dependency: str,
    path_value: str,
    version: str,
) -> None:
    source = sources.read(manifest)
    key = rf'(?:{re.escape(dependency)}|"{re.escape(dependency)}"|\'{re.escape(dependency)}\')'
    assignment = re.compile(rf"^[ \t]*{key}[ \t]*=[ \t]*\{{[^\r\n]*\}}[ \t]*$", re.MULTILINE)
    path_pattern = re.compile(rf'\bpath[ \t]*=[ \t]*"{re.escape(path_value)}"')
    candidates = [
        match for match in assignment.finditer(source) if path_pattern.search(match.group())
    ]
    if len(candidates) != 1:
        state = "missing" if not candidates else "duplicated"
        raise ValueError(f"{manifest.as_posix()}: inline path dependency {dependency} is {state}")
    match = candidates[0]
    line = match.group()
    version_pattern = re.compile(r'\bversion[ \t]*=[ \t]*"([^"]+)"')
    versions = list(version_pattern.finditer(line))
    if len(versions) != 1:
        state = "missing" if not versions else "duplicated"
        raise ValueError(
            f"{manifest.as_posix()}: exact version for path dependency {dependency} is {state}"
        )
    version_match = versions[0]
    replacement = line[: version_match.start(1)] + f"={version}" + line[version_match.end(1) :]
    sources.replace(manifest, source[: match.start()] + replacement + source[match.end() :])


def _sync_path_dependencies(
    root: Path,
    sources: Sources,
    documents: dict[Path, dict[str, object]],
    package_names: dict[Path, str],
    version: str,
) -> None:
    workspace_directories = set(package_names)
    for manifest, document in documents.items():
        for table in _dependency_tables(document):
            for dependency, specification in table.items():
                if not isinstance(specification, dict) or "path" not in specification:
                    continue
                path_value = specification.get("path")
                if not isinstance(path_value, str):
                    raise ValueError(
                        f"{manifest.as_posix()}: path for dependency {dependency} must be a string"
                    )
                target = ((root / manifest).parent / path_value).resolve()
                if target not in workspace_directories:
                    continue
                if "version" not in specification:
                    raise ValueError(
                        f"{manifest.as_posix()}: workspace path dependency {dependency} "
                        "must have an exact version"
                    )
                _replace_path_dependency(sources, manifest, dependency, path_value, version)


def _sync_cargo_lock(sources: Sources, package_names: dict[Path, str], version: str) -> None:
    relative = Path("Cargo.lock")
    source = sources.read(relative)
    block_pattern = re.compile(r"(?ms)^\[\[package\]\]\r?\n.*?(?=^\[\[package\]\]|\Z)")
    for package_name in sorted(package_names.values()):
        blocks = []
        for block in block_pattern.finditer(source):
            body = block.group()
            name = re.search(r'(?m)^name[ \t]*=[ \t]*"([^"]+)"[ \t]*\r?$', body)
            if name is not None and name.group(1) == package_name and "\nsource = " not in body:
                blocks.append(block)
        if len(blocks) != 1:
            state = "missing" if not blocks else "duplicated"
            raise ValueError(f"Cargo.lock workspace package {package_name} is {state}")
        block = blocks[0]
        body = block.group()
        versions = list(re.finditer(r'(?m)^(version[ \t]*=[ \t]*")([^"\r\n]+)("[ \t]*\r?$)', body))
        if len(versions) != 1:
            state = "missing" if not versions else "duplicated"
            raise ValueError(f"Cargo.lock version for {package_name} is {state}")
        version_match = versions[0]
        replacement = body[: version_match.start(2)] + version + body[version_match.end(2) :]
        source = source[: block.start()] + replacement + source[block.end() :]
    sources.replace(relative, source)


def synchronize(root: Path = ROOT, *, check: bool = False) -> tuple[str, tuple[str, ...]]:
    root = root.resolve()
    version = cargo_version(root)
    sources = Sources(root)
    for label, relative, pattern in SURFACES:
        _replace_single(sources, label, relative, pattern, version)
    _replace_project_version(sources, version)
    documents, package_names = _workspace_manifests(root, sources)
    _sync_path_dependencies(root, sources, documents, package_names, version)
    _sync_cargo_lock(sources, package_names, version)

    changed = tuple(
        sorted(
            relative.as_posix()
            for relative, updated in sources.values.items()
            if (root / relative).read_text(encoding="utf-8") != updated
        )
    )
    if check and changed:
        raise ValueError("release version surfaces are out of sync: " + ", ".join(changed))
    if not check:
        for relative in changed:
            (root / relative).write_text(sources.values[Path(relative)], encoding="utf-8")
    return version, changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    try:
        version, changed = synchronize(arguments.root, check=arguments.check)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"release version sync: {error}", file=sys.stderr)
        return 1
    if arguments.check:
        print(f"release version sync: {version}; all derived surfaces match Cargo")
    elif changed:
        print(f"release version sync: {version}; updated {', '.join(changed)}")
    else:
        print(f"release version sync: {version}; already synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
