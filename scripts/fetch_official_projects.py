#!/usr/bin/env python3
"""Acquire pinned official CI YAML snapshots without executing project code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

PROVIDERS = ("github", "gitlab", "azure", "circleci")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PROJECT_FIELDS = {"id", "paths", "provider", "repository", "revision", "tree"}
YAML_SUFFIXES = {".yml", ".yaml"}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_path(raw: Any, label: str) -> PurePosixPath:
    if not isinstance(raw, str):
        raise ValueError(f"{label} must be a string")
    path = PurePosixPath(raw)
    if (
        not raw
        or "\\" in raw
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in raw.split("/"))
    ):
        raise ValueError(f"{label} is not a safe relative POSIX path")
    return path


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read official-project manifest {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("official-project manifest must be a regular non-symlink file")
    if not 0 < len(raw) <= 1024 * 1024:
        raise ValueError("official-project manifest has an invalid size")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse official-project manifest: {error}") from error
    if not isinstance(document, dict) or set(document) != {"projects", "schema"}:
        raise ValueError("official-project manifest has unexpected fields")
    if document["schema"] != "official-projects-v1":
        raise ValueError("official-project manifest schema must be official-projects-v1")
    projects = document["projects"]
    if not isinstance(projects, list) or len(projects) != 8:
        raise ValueError("official-project manifest must contain exactly eight projects")
    seen: set[str] = set()
    provider_counts = {provider: 0 for provider in PROVIDERS}
    for index, project in enumerate(projects):
        label = f"projects[{index}]"
        if not isinstance(project, dict) or set(project) != PROJECT_FIELDS:
            raise ValueError(f"{label} has unexpected fields")
        identifier = project["id"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError(f"{label}.id is invalid")
        if identifier in seen:
            raise ValueError(f"duplicate project id {identifier}")
        seen.add(identifier)
        provider = project["provider"]
        if provider not in PROVIDERS:
            raise ValueError(f"{label}.provider is unsupported")
        provider_counts[provider] += 1
        parsed = urlparse(project["repository"] if isinstance(project["repository"], str) else "")
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError(f"{label}.repository must be an HTTPS Git URL")
        for field in ("revision", "tree"):
            if not isinstance(project[field], str) or not REVISION.fullmatch(project[field]):
                raise ValueError(f"{label}.{field} is not a full Git object ID")
        paths = project["paths"]
        if not isinstance(paths, list) or not paths or len(paths) > 64:
            raise ValueError(f"{label}.paths must be a bounded nonempty list")
        normalized = [_safe_path(value, f"{label}.paths").as_posix() for value in paths]
        if len(normalized) != len(set(normalized)):
            raise ValueError(f"{label}.paths contains duplicates")
    if any(count != 2 for count in provider_counts.values()):
        raise ValueError("official-project manifest must contain two projects per provider")
    return document, _digest_bytes(raw)


def _git(
    arguments: list[str],
    *,
    cwd: Path,
    deadline: float,
    input_bytes: bytes | None = None,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("repository acquisition exceeded 60 seconds")
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            env=environment,
            input=input_bytes,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            capture_output=True,
            shell=False,
            timeout=max(0.1, remaining),
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("repository acquisition exceeded 60 seconds") from error
    except OSError as error:
        raise ValueError(f"cannot start Git: {error}") from error
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"Git {' '.join(arguments[:2])} failed: {message}")
    return completed.stdout


def _selected(relative: PurePosixPath, paths: list[str]) -> bool:
    value = relative.as_posix()
    return any(value == prefix or value.startswith(prefix + "/") for prefix in paths)


def _snapshot_digest(root: Path) -> tuple[str, int]:
    files: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            raise ValueError(f"snapshot contains a symlink or special file: {path}")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(root).as_posix()
            _safe_path(relative, "snapshot path")
            files.append((relative, path))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    digest = hashlib.sha256()
    for relative, path in files:
        raw = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    return "sha256:" + digest.hexdigest(), len(files)


def _tree_entries(raw: bytes, paths: list[str]) -> None:
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, _kind, _object_id = metadata.decode("ascii").split(" ", 2)
            relative = PurePosixPath(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise ValueError("Git tree contains an undecodable entry") from error
        _safe_path(relative.as_posix(), "Git tree path")
        if _selected(relative, paths) and mode in {"120000", "160000"}:
            raise ValueError(f"selected CI source is a symlink or submodule: {relative}")


def _acquire_project(project: dict[str, Any], output: Path, mode: str) -> dict[str, Any]:
    deadline = time.monotonic() + 60.0
    paths = list(project["paths"])
    with tempfile.TemporaryDirectory(prefix=f".{project['id']}.", dir=output.parent) as temporary:
        checkout = Path(temporary) / "checkout"
        checkout.mkdir()
        _git(["init", "--quiet"], cwd=checkout, deadline=deadline)
        _git(
            ["remote", "add", "origin", project["repository"]],
            cwd=checkout,
            deadline=deadline,
        )
        target = project["revision"] if mode == "pinned" else "HEAD"
        _git(
            ["fetch", "--quiet", "--depth=1", "--filter=blob:none", "--no-tags", "origin", target],
            cwd=checkout,
            deadline=deadline,
        )
        revision = (
            _git(["rev-parse", "FETCH_HEAD"], cwd=checkout, deadline=deadline)
            .decode("ascii")
            .strip()
        )
        if not REVISION.fullmatch(revision):
            raise ValueError(f"{project['id']} resolved an invalid commit")
        if mode == "pinned" and revision != project["revision"]:
            raise ValueError(f"{project['id']} did not resolve the pinned commit")
        commit = _git(["cat-file", "-p", revision], cwd=checkout, deadline=deadline).decode("utf-8")
        first = commit.splitlines()[0] if commit else ""
        if not first.startswith("tree ") or not REVISION.fullmatch(first[5:]):
            raise ValueError(f"{project['id']} commit has no valid tree")
        tree = first[5:]
        if mode == "pinned" and tree != project["tree"]:
            raise ValueError(f"{project['id']} tree does not match the manifest")
        tree_entries = _git(
            ["ls-tree", "-r", "-z", "--full-tree", revision, "--", *paths],
            cwd=checkout,
            deadline=deadline,
        )
        _tree_entries(tree_entries, paths)
        _git(["sparse-checkout", "init", "--no-cone"], cwd=checkout, deadline=deadline)
        patterns = "".join(f"/{path}\n/{path}/\n" for path in paths).encode("utf-8")
        _git(
            ["sparse-checkout", "set", "--no-cone", "--stdin"],
            cwd=checkout,
            deadline=deadline,
            input_bytes=patterns,
        )
        _git(["checkout", "--quiet", "--detach", revision], cwd=checkout, deadline=deadline)

        output.mkdir()
        copied = 0
        for source in checkout.rglob("*"):
            if source == checkout / ".git" or checkout / ".git" in source.parents:
                continue
            metadata = source.lstat()
            relative = PurePosixPath(source.relative_to(checkout).as_posix())
            if not _selected(relative, paths):
                continue
            if source.is_symlink() or not (
                stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
            ):
                raise ValueError(f"selected CI source is a symlink or special file: {relative}")
            if stat.S_ISREG(metadata.st_mode) and source.suffix.lower() in YAML_SUFFIXES:
                destination = output.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination, follow_symlinks=False)
                copied += 1
        if copied == 0:
            raise ValueError(f"{project['id']} sparse checkout contains no CI YAML")
        if time.monotonic() > deadline:
            raise ValueError(f"{project['id']} acquisition exceeded 60 seconds")
    snapshot_digest, files = _snapshot_digest(output)
    return {
        "files": files,
        "id": project["id"],
        "provider": project["provider"],
        "repository": project["repository"],
        "revision": revision,
        "snapshot_digest": snapshot_digest,
        "tree": tree,
    }


def acquire(manifest_path: Path, destination: Path, *, mode: str) -> dict[str, Any]:
    if mode not in {"pinned", "latest"}:
        raise ValueError("acquisition mode must be pinned or latest")
    manifest, manifest_digest = load_manifest(manifest_path)
    if destination.exists() or destination.is_symlink():
        raise ValueError("official-project destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{destination.name}.", dir=destination.parent
    ) as temporary:
        staging = Path(temporary) / "snapshots"
        staging.mkdir()
        projects = []
        for project in manifest["projects"]:
            projects.append(_acquire_project(project, staging / project["id"], mode))
        result = {
            "manifest_digest": manifest_digest,
            "mode": mode,
            "projects": projects,
            "schema": "official-project-acquisition-v1",
        }
        (staging / "acquisition-v1.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(staging, destination)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("official/official-projects-v1.json"))
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--mode", choices=("pinned", "latest"), default="pinned")
    arguments = parser.parse_args()
    try:
        result = acquire(arguments.manifest, arguments.destination, mode=arguments.mode)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"official-project acquisition: {error}", file=sys.stderr)
        return 2
    print(
        f"official-project acquisition: {len(result['projects'])} repositories; "
        f"mode={result['mode']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
