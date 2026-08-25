#!/usr/bin/env python3
"""Build and verify deterministic candidate release artifacts.

This tool deliberately does not fetch runtime capsules, kernels, or signing
credentials.  It packages exact local build outputs, proves two-build byte
identity, creates the static source/schema assets, and reconstructs the final
Windows archives from independently Authenticode-verified executables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict

try:
    from scripts.package_release import build_package
except ModuleNotFoundError:
    from package_release import build_package  # type: ignore[no-redef]


class PlatformContract(TypedDict):
    analyzer: str
    helpers: set[str]
    suffix: str


PLATFORMS: dict[str, PlatformContract] = {
    "linux-x86_64": {
        "analyzer": "workflow-verifier",
        "helpers": {
            "workflow-verifier-linux-helper",
            "workflow-verifier-oci-helper",
            "workflow-verifier-vm-agent",
        },
        "suffix": ".tar.gz",
    },
    "windows-x86_64": {
        "analyzer": "workflow-verifier.exe",
        "helpers": {
            "workflow-verifier-vm-agent.exe",
            "workflow-verifier-windows-helper.exe",
        },
        "suffix": ".zip",
    },
    "macos-arm64": {
        "analyzer": "workflow-verifier",
        "helpers": {
            "workflow-verifier-macos-helper",
            "workflow-verifier-vm-agent",
            "workflow-verifier-vm-shim",
        },
        "suffix": ".tar.gz",
    },
    "macos-x86_64": {
        "analyzer": "workflow-verifier",
        "helpers": {
            "workflow-verifier-macos-helper",
            "workflow-verifier-vm-agent",
            "workflow-verifier-vm-shim",
        },
        "suffix": ".tar.gz",
    },
}
REQUIRED_FRAGMENT_ROLES = {
    **{platform: {"helper", "product"} for platform in PLATFORMS},
    "source": {"corresponding-source", "schema-bundle", "source"},
}
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
ROLE = re.compile(r"^[a-z][a-z0-9-]*$")
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024


def _sha256_bytes(contents: bytes) -> str:
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, contents: bytes) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect {label}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"{label} must be a nonempty regular non-symlink file")
    return metadata


def _directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect {label}: {error}") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink directory")
    return path.resolve(strict=True)


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} resolves outside the build workspace") from error
    return resolved


def _logical(value: str, label: str) -> str:
    candidate = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError(f"{label} is not a safe archive path")
    return candidate.as_posix()


def build_path_prefix_map(source: str) -> str:
    """Encode one target/source pair using OCaml's BUILD_PATH_PREFIX_MAP grammar."""
    if not source or "\x00" in source:
        raise ValueError("build path prefix must be nonempty and NUL-free")
    encoded = source.replace("%", "%#").replace(":", "%.").replace("=", "%+")
    return ".=" + encoded


def _walk_files(root: Path, workspace: Path, logical_root: str) -> list[tuple[str, Path]]:
    checked_root = _inside(root, workspace, logical_root)
    if not checked_root.is_dir():
        raise ValueError(f"{logical_root} must be a directory")
    pending = [(checked_root, PurePosixPath(logical_root))]
    files: list[tuple[str, Path]] = []
    folded: set[str] = set()
    while pending:
        directory, logical_directory = pending.pop()
        entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        for entry in entries:
            logical = logical_directory / entry.name
            name = _logical(logical.as_posix(), "install entry")
            folded_name = name.casefold()
            if folded_name in folded:
                raise ValueError(f"case-fold collision in install tree: {name}")
            folded.add(folded_name)
            entry_path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((entry_path, logical))
                continue
            if stat.S_ISLNK(metadata.st_mode):
                target = _inside(entry_path, workspace, name)
                target_metadata = target.stat()
                if not stat.S_ISREG(target_metadata.st_mode) or target_metadata.st_size <= 0:
                    raise ValueError(f"install link target is not a nonempty regular file: {name}")
                files.append((name, target))
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
                raise ValueError(f"invalid install entry: {name}")
            files.append((name, entry_path))
    if not files:
        raise ValueError(f"{logical_root} contains no files")
    return files


def _materialize(files: list[tuple[str, Path]], root: Path) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    names: set[str] = set()
    for logical, source in files:
        name = _logical(logical, "release entry")
        if name in names:
            raise ValueError(f"duplicate release entry: {name}")
        names.add(name)
        _regular(source, name)
        destination = root.joinpath(*PurePosixPath(name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        result.append((name, destination))
    return result


def _helper_spec(value: str) -> tuple[str, Path]:
    logical, separator, raw_path = value.partition("=")
    if not separator or not raw_path:
        raise argparse.ArgumentTypeError("helper must use ARCHIVE_PATH=SOURCE_PATH")
    try:
        checked = _logical(logical, "helper archive path")
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not checked.startswith("bin/"):
        raise argparse.ArgumentTypeError("helper archive path must be below bin/")
    return checked, Path(raw_path)


def package_install(
    *,
    install_root: Path,
    workspace_root: Path,
    platform: str,
    version: str,
    helpers: list[tuple[str, Path]],
    output: Path,
    helpers_output: Path,
) -> None:
    if platform not in PLATFORMS:
        raise ValueError(f"unsupported release platform: {platform}")
    if not VERSION.fullmatch(version):
        raise ValueError("release version is invalid")
    workspace = _directory(workspace_root, "build workspace")
    install = _inside(install_root, workspace, "install root")
    if install_root.is_symlink() or not install.is_dir():
        raise ValueError("install root must be a non-symlink directory")

    platform_contract = PLATFORMS[platform]
    analyzer = install / "bin" / str(platform_contract["analyzer"])
    analyzer_source = _inside(analyzer, workspace, "installed analyzer")
    _regular(analyzer_source, "installed analyzer")
    public_files: list[tuple[str, Path]] = [
        (f"bin/{platform_contract['analyzer']}", analyzer_source),
        *_walk_files(install / "doc" / "workflow-verifier", workspace, "doc/workflow-verifier"),
        *_walk_files(install / "share" / "workflow-verifier", workspace, "share/workflow-verifier"),
    ]
    man = _inside(install / "man" / "man1" / "workflow-verifier.1", workspace, "man page")
    _regular(man, "man page")
    public_files.append(("man/man1/workflow-verifier.1", man))

    helper_names = {PurePosixPath(logical).name for logical, _path in helpers}
    if helper_names != platform_contract["helpers"]:
        raise ValueError(
            f"helper inventory mismatch for {platform}: "
            f"missing={sorted(platform_contract['helpers'] - helper_names)}, "
            f"unknown={sorted(helper_names - platform_contract['helpers'])}"
        )
    helper_files: list[tuple[str, Path]] = []
    for logical, source in helpers:
        checked = _inside(source, workspace, f"helper {logical}")
        _regular(checked, f"helper {logical}")
        helper_files.append((logical, checked))

    with tempfile.TemporaryDirectory(prefix="workflow-verifier-package-") as temporary:
        staging = Path(temporary)
        staged_product = _materialize([*public_files, *helper_files], staging / "product")
        staged_helpers = _materialize(helper_files, staging / "helpers")
        build_package(platform, version, staged_product, output)
        build_package(platform, version, staged_helpers, helpers_output)


def _artifact_record(role: str, first: Path, second: Path) -> dict[str, str]:
    if not ROLE.fullmatch(role):
        raise ValueError(f"invalid reproducibility artifact role: {role}")
    _regular(first, f"first {role} artifact")
    _regular(second, f"second {role} artifact")
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    if first_bytes != second_bytes:
        raise ValueError(f"two clean builds differ for {role}: {first.name} != {second.name}")
    if first.name != second.name:
        raise ValueError(f"two clean builds use different artifact names for {role}")
    return {"digest": _sha256_bytes(first_bytes), "name": first.name, "role": role}


def write_fragment(
    *,
    platform: str,
    subject_commit: str,
    source_date_epoch: int,
    artifacts: list[tuple[str, Path, Path]],
    output: Path,
) -> None:
    if platform not in REQUIRED_FRAGMENT_ROLES:
        raise ValueError(f"unsupported reproducibility platform: {platform}")
    if not REVISION.fullmatch(subject_commit):
        raise ValueError("subject commit must be exact lowercase 40-hex")
    if source_date_epoch < 1:
        raise ValueError("SOURCE_DATE_EPOCH must be a positive integer")
    records = [_artifact_record(role, first, second) for role, first, second in artifacts]
    roles = {record["role"] for record in records}
    if len(roles) != len(records) or roles != REQUIRED_FRAGMENT_ROLES[platform]:
        raise ValueError(
            f"reproducibility roles mismatch for {platform}: "
            f"missing={sorted(REQUIRED_FRAGMENT_ROLES[platform] - roles)}, "
            f"unknown={sorted(roles - REQUIRED_FRAGMENT_ROLES[platform])}"
        )
    document = {
        "artifacts": sorted(records, key=lambda item: item["role"]),
        "platform": platform,
        "schema": "reproducibility-fragment-v1",
        "source_date_epoch": source_date_epoch,
        "subject_commit": subject_commit,
    }
    _atomic_write(output, _canonical(document))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key}")
        result[key] = value
    return result


def _fragment(path: Path) -> dict[str, Any]:
    _regular(path, "reproducibility fragment")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("reproducibility fragment exceeds 1 MiB")
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON number {constant}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid reproducibility fragment: {error}") from error
    if raw != _canonical(value):
        raise ValueError("reproducibility fragment must be canonical JSON")
    fields = {"artifacts", "platform", "schema", "source_date_epoch", "subject_commit"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("reproducibility fragment fields are not exact")
    if value["schema"] != "reproducibility-fragment-v1":
        raise ValueError("unsupported reproducibility fragment schema")
    return value


def aggregate_fragments(*, fragments: list[Path], subject_commit: str, output: Path) -> None:
    if not REVISION.fullmatch(subject_commit):
        raise ValueError("subject commit must be exact lowercase 40-hex")
    by_platform: dict[str, dict[str, Any]] = {}
    source_date_epoch: int | None = None
    names: set[str] = set()
    records: list[dict[str, str]] = []
    for path in fragments:
        value = _fragment(path)
        platform = value["platform"]
        if platform not in REQUIRED_FRAGMENT_ROLES or platform in by_platform:
            raise ValueError(f"unknown or duplicate reproducibility platform: {platform}")
        if value["subject_commit"] != subject_commit:
            raise ValueError(f"stale reproducibility fragment for {platform}")
        epoch = value["source_date_epoch"]
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise ValueError(f"invalid SOURCE_DATE_EPOCH for {platform}")
        if source_date_epoch is None:
            source_date_epoch = epoch
        elif source_date_epoch != epoch:
            raise ValueError("reproducibility fragments use different SOURCE_DATE_EPOCH values")
        artifacts = value["artifacts"]
        if not isinstance(artifacts, list):
            raise ValueError(f"artifact records are not an array for {platform}")
        roles: set[str] = set()
        for index, record in enumerate(artifacts):
            if not isinstance(record, dict) or set(record) != {"digest", "name", "role"}:
                raise ValueError(f"artifact record {platform}[{index}] fields are not exact")
            role = record["role"]
            name = record["name"]
            digest = record["digest"]
            if (
                not isinstance(role, str)
                or not isinstance(name, str)
                or not isinstance(digest, str)
                or not ROLE.fullmatch(role)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                or PurePosixPath(name).name != name
            ):
                raise ValueError(f"invalid artifact record {platform}[{index}]")
            if role in roles or name in names:
                raise ValueError(
                    f"duplicate reproducibility role or artifact name: {platform}/{role}"
                )
            roles.add(role)
            names.add(name)
            records.append({"digest": digest, "name": name, "platform": platform, "role": role})
        if roles != REQUIRED_FRAGMENT_ROLES[platform]:
            raise ValueError(f"reproducibility fragment roles contradict {platform}")
        by_platform[platform] = value
    if set(by_platform) != set(REQUIRED_FRAGMENT_ROLES):
        raise ValueError(
            "reproducibility platform coverage mismatch; "
            f"missing={sorted(set(REQUIRED_FRAGMENT_ROLES) - set(by_platform))}"
        )
    document = {
        "details": {
            "artifacts": sorted(records, key=lambda item: (item["platform"], item["role"])),
            "builds_per_artifact": 2,
            "path_remapping": True,
            "source_date_epoch": source_date_epoch,
        },
        "findings": [],
        "gate": "reproducible-build",
        "schema": "release-gate-v1",
        "status": "pass",
        "subject_commit": subject_commit,
    }
    _atomic_write(output, _canonical(document))


def _run(repository: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repository.as_posix()}", *arguments],
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(arguments)} failed: {error}")
    if binary:
        return result.stdout
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        raise ValueError("git returned non-UTF-8 text") from error


def _git_blob(repository: Path, revision: str, path: str) -> bytes:
    return _run(repository, ["show", f"{revision}:{path}"], binary=True)  # type: ignore[return-value]


def build_source_assets(
    *,
    repository: Path,
    subject_commit: str,
    version: str,
    output_dir: Path,
    fragment: Path,
) -> None:
    if not REVISION.fullmatch(subject_commit):
        raise ValueError("subject commit must be exact lowercase 40-hex")
    if not VERSION.fullmatch(version):
        raise ValueError("release version is invalid")
    root = _directory(repository, "repository")
    if _run(root, ["rev-parse", "HEAD"]) != subject_commit:
        raise ValueError("checked-out HEAD does not equal the candidate commit")
    epoch_text = _run(root, ["show", "-s", "--format=%ct", subject_commit])
    if not isinstance(epoch_text, str) or not epoch_text.isascii() or not epoch_text.isdigit():
        raise ValueError("candidate commit has no valid timestamp")
    epoch = int(epoch_text)
    schema_names_text = _run(root, ["ls-tree", "-r", "--name-only", subject_commit, "schema"])
    if not isinstance(schema_names_text, str):
        raise AssertionError("git text result was not text")
    schema_names = schema_names_text.splitlines()
    if not schema_names or any(
        not name.startswith("schema/") or not name.endswith(".schema.json") for name in schema_names
    ):
        raise ValueError("candidate commit has an invalid schema inventory")

    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("source asset output must be a non-symlink directory")
    source_name = f"workflow-verifier-{version}-source.tar.gz"
    corresponding_name = f"workflow-verifier-{version}-corresponding-source.tar.gz"
    schemas_name = f"workflow-verifier-{version}-schemas.tar.gz"
    source_output = output_dir / source_name
    corresponding_output = output_dir / corresponding_name
    schemas_output = output_dir / schemas_name
    for output in (source_output, corresponding_output, schemas_output, fragment):
        if output.exists() or output.is_symlink():
            raise ValueError(f"source asset output already exists: {output}")

    with tempfile.TemporaryDirectory(prefix="workflow-verifier-source-") as temporary:
        staging = Path(temporary)
        first_source = staging / "first" / source_name
        second_source = staging / "second" / source_name
        first_source.parent.mkdir()
        second_source.parent.mkdir()
        prefix = f"workflow-verifier-{version}/"
        for destination in (first_source, second_source):
            _run(
                root,
                [
                    "archive",
                    "--format=tar.gz",
                    f"--prefix={prefix}",
                    f"--output={destination}",
                    subject_commit,
                ],
            )

        schema_files: list[tuple[str, Path]] = []
        for name in schema_names:
            logical = _logical(name, "schema path")
            destination = staging / "schema-input" / PurePosixPath(logical).name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_git_blob(root, subject_commit, name))
            _regular(destination, f"schema {name}")
            schema_files.append((logical, destination))
        first_schemas = staging / "first" / schemas_name
        second_schemas = staging / "second" / schemas_name
        build_package("schemas", version, schema_files, first_schemas)
        build_package("schemas", version, schema_files, second_schemas)

        first_corresponding = staging / "first" / corresponding_name
        second_corresponding = staging / "second" / corresponding_name
        first_corresponding.write_bytes(first_source.read_bytes())
        second_corresponding.write_bytes(second_source.read_bytes())
        write_fragment(
            platform="source",
            subject_commit=subject_commit,
            source_date_epoch=epoch,
            artifacts=[
                ("source", first_source, second_source),
                ("corresponding-source", first_corresponding, second_corresponding),
                ("schema-bundle", first_schemas, second_schemas),
            ],
            output=fragment,
        )
        _atomic_write(source_output, first_source.read_bytes())
        _atomic_write(corresponding_output, first_corresponding.read_bytes())
        _atomic_write(schemas_output, first_schemas.read_bytes())


def _zip_inputs(archive: Path, version: str) -> tuple[str, list[tuple[str, bytes]]]:
    _regular(archive, "unsigned Windows archive")
    prefix = f"workflow-verifier-{version}-windows-x86_64"
    entries: list[tuple[str, bytes]] = []
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    with zipfile.ZipFile(archive, "r") as source:
        infos = source.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("unsigned Windows archive entry count is outside the limit")
        for info in infos:
            if info.is_dir() or info.flag_bits & 0x1:
                raise ValueError("unsigned Windows archive contains a directory or encrypted entry")
            raw_name = info.filename
            logical = _logical(raw_name, "unsigned Windows archive entry")
            expected_prefix = prefix + "/"
            if not logical.startswith(expected_prefix):
                raise ValueError("unsigned Windows archive has an unexpected root")
            relative = _logical(logical[len(expected_prefix) :], "Windows payload path")
            if logical in names or logical.casefold() in folded:
                raise ValueError("unsigned Windows archive contains duplicate/colliding paths")
            names.add(logical)
            folded.add(logical.casefold())
            mode = info.external_attr >> 16
            if mode and not stat.S_ISREG(mode):
                raise ValueError("unsigned Windows archive contains a non-regular entry")
            total += info.file_size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("unsigned Windows archive exceeds the expanded size limit")
            contents = source.read(info)
            if len(contents) != info.file_size or not contents:
                raise ValueError("unsigned Windows archive contains an empty or truncated entry")
            entries.append((relative, contents))
    return prefix, entries


def repackage_windows(
    *,
    unsigned_archive: Path,
    signed_directory: Path,
    version: str,
    output: Path,
    helpers_output: Path,
) -> None:
    if not VERSION.fullmatch(version):
        raise ValueError("release version is invalid")
    signed_root = _directory(signed_directory, "signed executable directory")
    _prefix, entries = _zip_inputs(unsigned_archive, version)
    expected_executables = {
        "workflow-verifier.exe",
        "workflow-verifier-vm-agent.exe",
        "workflow-verifier-windows-helper.exe",
    }
    unsigned_executables = {
        PurePosixPath(name).name for name, _contents in entries if name.lower().endswith(".exe")
    }
    if unsigned_executables != expected_executables:
        raise ValueError("unsigned Windows payload executable inventory is not exact")

    signed: dict[str, Path] = {}
    pending = [signed_root]
    while pending:
        directory = pending.pop()
        for entry in os.scandir(directory):
            metadata = entry.stat(follow_symlinks=False)
            path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("signed output contains a link or special file")
            if not entry.name.lower().endswith(".exe"):
                raise ValueError(f"signed output contains an unexpected file: {entry.name}")
            if entry.name in signed or entry.name.casefold() in {
                name.casefold() for name in signed
            }:
                raise ValueError(f"signed output contains duplicate executable {entry.name}")
            if metadata.st_size <= 0:
                raise ValueError(f"signed executable is empty: {entry.name}")
            signed[entry.name] = path
    if set(signed) != expected_executables:
        raise ValueError(
            "signed Windows executable inventory mismatch; "
            f"missing={sorted(expected_executables - set(signed))}, "
            f"unknown={sorted(set(signed) - expected_executables)}"
        )

    with tempfile.TemporaryDirectory(prefix="workflow-verifier-signed-windows-") as temporary:
        staging = Path(temporary)
        product_files: list[tuple[str, Path]] = []
        helper_files: list[tuple[str, Path]] = []
        for logical, unsigned_contents in entries:
            basename = PurePosixPath(logical).name
            destination = staging.joinpath(*PurePosixPath(logical).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if basename in signed:
                signed_contents = signed[basename].read_bytes()
                if signed_contents == unsigned_contents:
                    raise ValueError(f"signing did not transform {basename}")
                destination.write_bytes(signed_contents)
                if basename != "workflow-verifier.exe":
                    helper_files.append((logical, destination))
            else:
                destination.write_bytes(unsigned_contents)
            product_files.append((logical, destination))
        build_package("windows-x86_64", version, product_files, output)
        build_package("windows-x86_64", version, helper_files, helpers_output)


def _record_spec(value: str) -> tuple[str, Path, Path]:
    fields = value.split("=", 2)
    if len(fields) != 3 or not all(fields):
        raise argparse.ArgumentTypeError("artifact pair must use ROLE=FIRST=SECOND")
    return fields[0], Path(fields[1]), Path(fields[2])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    package = commands.add_parser("package-install")
    package.add_argument("--install-root", required=True, type=Path)
    package.add_argument("--workspace-root", required=True, type=Path)
    package.add_argument("--platform", required=True, choices=tuple(PLATFORMS))
    package.add_argument("--version", required=True)
    package.add_argument("--helper", action="append", default=[], type=_helper_spec)
    package.add_argument("--output", required=True, type=Path)
    package.add_argument("--helpers-output", required=True, type=Path)

    record = commands.add_parser("record")
    record.add_argument("--platform", required=True, choices=tuple(REQUIRED_FRAGMENT_ROLES))
    record.add_argument("--subject-commit", required=True)
    record.add_argument("--source-date-epoch", required=True, type=int)
    record.add_argument("--artifact", action="append", default=[], type=_record_spec)
    record.add_argument("--output", required=True, type=Path)

    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--subject-commit", required=True)
    aggregate.add_argument("--fragment", action="append", default=[], type=Path)
    aggregate.add_argument("--output", required=True, type=Path)
    aggregate.add_argument("fragment_paths", nargs="*", type=Path)

    source = commands.add_parser("source-assets")
    source.add_argument("--repository", required=True, type=Path)
    source.add_argument("--subject-commit", required=True)
    source.add_argument("--version", required=True)
    source.add_argument("--output-dir", required=True, type=Path)
    source.add_argument("--fragment", required=True, type=Path)

    windows = commands.add_parser("repackage-windows")
    windows.add_argument("--unsigned-archive", required=True, type=Path)
    windows.add_argument("--signed-directory", required=True, type=Path)
    windows.add_argument("--version", required=True)
    windows.add_argument("--output", required=True, type=Path)
    windows.add_argument("--helpers-output", required=True, type=Path)

    prefix_map = commands.add_parser("prefix-map")
    prefix_map.add_argument("source")

    arguments = parser.parse_args()
    if arguments.command == "package-install":
        package_install(
            install_root=arguments.install_root,
            workspace_root=arguments.workspace_root,
            platform=arguments.platform,
            version=arguments.version,
            helpers=arguments.helper,
            output=arguments.output,
            helpers_output=arguments.helpers_output,
        )
    elif arguments.command == "record":
        write_fragment(
            platform=arguments.platform,
            subject_commit=arguments.subject_commit,
            source_date_epoch=arguments.source_date_epoch,
            artifacts=arguments.artifact,
            output=arguments.output,
        )
    elif arguments.command == "aggregate":
        aggregate_fragments(
            fragments=[*arguments.fragment, *arguments.fragment_paths],
            subject_commit=arguments.subject_commit,
            output=arguments.output,
        )
    elif arguments.command == "source-assets":
        build_source_assets(
            repository=arguments.repository,
            subject_commit=arguments.subject_commit,
            version=arguments.version,
            output_dir=arguments.output_dir,
            fragment=arguments.fragment,
        )
    elif arguments.command == "repackage-windows":
        repackage_windows(
            unsigned_archive=arguments.unsigned_archive,
            signed_directory=arguments.signed_directory,
            version=arguments.version,
            output=arguments.output,
            helpers_output=arguments.helpers_output,
        )
    elif arguments.command == "prefix-map":
        print(build_path_prefix_map(arguments.source))
    else:
        raise AssertionError("unreachable candidate artifact command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
