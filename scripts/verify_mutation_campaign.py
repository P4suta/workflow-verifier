#!/usr/bin/env python3
"""Plan and verify a complete, catalog-reconciled mutation campaign."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import tomllib
from typing import Any

if __package__:
    from scripts.verify_mutation_report import verify as verify_report
else:
    from verify_mutation_report import verify as verify_report


BALANCED_FAMILIES = (
    "boolean-connective",
    "boolean-literal",
    "comparison",
    "condition-negation",
    "constructor-replacement",
    "float-arithmetic",
    "integer-arithmetic",
    "match-arm",
    "return-replacement",
)
STRONG_FAMILIES = BALANCED_FAMILIES + ("if-branch",)
ALL_FAMILIES = STRONG_FAMILIES + ("sequence-deletion",)
PROFILE_FAMILIES = {
    "balanced": frozenset(BALANCED_FAMILIES),
    "strong": frozenset(STRONG_FAMILIES),
    "all": frozenset(ALL_FAMILIES),
}
MANIFEST_FIELDS = {"schema", "shards"}
SHARD_FIELDS = {"name", "prefixes"}
CATALOG_FIELDS = {
    "document_type",
    "schema_version",
    "workspace",
    "profile",
    "selection",
    "mutants",
    "skips",
}
MUTANT_FIELDS = {
    "id",
    "full_id",
    "path",
    "range",
    "family",
    "rule",
    "original",
    "replacement",
    "source_digest",
}
RANGE_FIELDS = {
    "start_byte",
    "end_byte",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX20 = re.compile(r"^[0-9a-f]{20}$")
RULE = re.compile(r"^[a-z0-9-]+@[1-9][0-9]*$")
SHARD_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class CampaignError(ValueError):
    """A mutation campaign input or proof is invalid."""


@dataclass(frozen=True)
class Shard:
    name: str
    prefixes: tuple[str, ...]

    def selects(self, full_id: str) -> bool:
        return any(full_id.startswith(prefix) for prefix in self.prefixes)


@dataclass(frozen=True)
class Plan:
    manifest_path: Path
    manifest_digest: str
    profile: str
    configured_paths: tuple[str, ...]
    configured_families: tuple[str, ...]
    shards: tuple[Shard, ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(shard.name for shard in self.shards)

    def shard(self, name: str) -> Shard:
        for shard in self.shards:
            if shard.name == name:
                return shard
        raise CampaignError(f"unknown mutation shard: {name}")

    def assignment(self, full_id: str) -> Shard:
        selected = [shard for shard in self.shards if shard.selects(full_id)]
        if len(selected) != 1:
            raise CampaignError(
                f"catalog mutant {full_id} is assigned to {len(selected)} shards"
            )
        return selected[0]


@dataclass(frozen=True)
class Catalog:
    document: dict[str, Any]
    digest: str
    mutants: dict[str, dict[str, Any]]
    partitions: dict[str, dict[str, dict[str, Any]]]

    @property
    def active_names(self) -> tuple[str, ...]:
        return tuple(name for name in sorted(self.partitions) if self.partitions[name])


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise CampaignError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise CampaignError(f"{label} has unknown fields: {', '.join(extra)}")


def _read_regular(path: Path, label: str, maximum: int = 256 * 1024 * 1024) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CampaignError(f"cannot inspect {label} {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise CampaignError(f"{label} must be a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise CampaignError(f"{label} has an invalid size: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise CampaignError(f"cannot read {label} {path}: {error}") from error


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    raw = _read_regular(path, label)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot parse {label} {path}: {error}") from error
    if not isinstance(document, dict):
        raise CampaignError(f"{label} must be a JSON object")
    return document, "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CampaignError(f"{label} must be a canonical relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CampaignError(f"{label} must be a safe relative path")
    if path.suffix != ".ml":
        raise CampaignError(f"{label} must name an OCaml implementation file")
    return path.as_posix()


def _string_array(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        requirement = "a nonempty" if nonempty else "an"
        raise CampaignError(f"{label} must be {requirement} array")
    if any(not isinstance(item, str) or not item for item in value):
        raise CampaignError(f"{label} must contain nonempty strings")
    if len(set(value)) != len(value):
        raise CampaignError(f"{label} must not contain duplicates")
    return value


def _glob_regex(pattern: str) -> re.Pattern[str]:
    if not pattern or "\\" in pattern or pattern.startswith("/"):
        raise CampaignError(f"mutation glob must be canonical and relative: {pattern!r}")
    if any(part in {"", ".", ".."} for part in pattern.split("/")):
        raise CampaignError(f"mutation glob contains an unsafe component: {pattern!r}")
    output = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    output.append("(?:.*/)?")
                    index += 1
                else:
                    output.append(".*")
                continue
            output.append("[^/]*")
        elif char == "?":
            output.append("[^/]")
        else:
            output.append(re.escape(char))
        index += 1
    output.append("$")
    return re.compile("".join(output))


def _load_config(path: Path, workspace: Path) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    raw = _read_regular(path, "mutation configuration", maximum=4 * 1024 * 1024)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise CampaignError(f"cannot parse mutation configuration {path}: {error}") from error
    mutation = document.get("mutation")
    if not isinstance(mutation, dict):
        raise CampaignError("mutation configuration is missing [mutation]")
    profile = mutation.get("profile", "balanced")
    if profile not in PROFILE_FAMILIES:
        raise CampaignError(f"unknown mutation profile: {profile!r}")
    includes = _string_array(mutation.get("include"), "mutation.include")
    excludes = _string_array(mutation.get("exclude", []), "mutation.exclude", nonempty=False)
    include_patterns = [_glob_regex(pattern) for pattern in includes]
    exclude_patterns = [_glob_regex(pattern) for pattern in excludes]
    configured_paths: list[str] = []
    try:
        candidates = workspace.rglob("*.ml")
        for candidate in candidates:
            relative = candidate.relative_to(workspace).as_posix()
            metadata = candidate.lstat()
            if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                continue
            if any(pattern.fullmatch(relative) for pattern in include_patterns) and not any(
                pattern.fullmatch(relative) for pattern in exclude_patterns
            ):
                configured_paths.append(relative)
    except OSError as error:
        raise CampaignError(f"cannot enumerate mutation sources: {error}") from error
    if not configured_paths:
        raise CampaignError("mutation configuration selects no OCaml source files")
    operators = mutation.get("operators")
    if operators is None:
        configured_families = PROFILE_FAMILIES[profile]
    else:
        requested = _string_array(operators, "mutation.operators")
        unknown = sorted(set(requested) - set(ALL_FAMILIES))
        if unknown:
            raise CampaignError(f"unknown mutation families: {', '.join(unknown)}")
        configured_families = PROFILE_FAMILIES[profile].intersection(requested)
    if not configured_families:
        raise CampaignError("mutation configuration selects no operator families")
    return profile, tuple(sorted(configured_paths)), tuple(sorted(configured_families))


def load_plan(manifest_path: Path, config_path: Path, workspace: Path) -> Plan:
    workspace = workspace.resolve()
    document, manifest_digest = _load_json(manifest_path, "mutation shard manifest")
    _exact_fields(document, MANIFEST_FIELDS, "mutation shard manifest")
    if document["schema"] != "mutation-shards-v1":
        raise CampaignError("mutation shard manifest has an unknown schema")
    rows = document["shards"]
    if not isinstance(rows, list) or not rows:
        raise CampaignError("mutation shard manifest must contain shards")
    shards: list[Shard] = []
    for index, row in enumerate(rows):
        label = f"mutation shard {index}"
        if not isinstance(row, dict):
            raise CampaignError(f"{label} must be an object")
        _exact_fields(row, SHARD_FIELDS, label)
        name = row["name"]
        if not isinstance(name, str) or not SHARD_NAME.fullmatch(name):
            raise CampaignError(f"{label}.name is invalid")
        prefixes = tuple(sorted(_string_array(row["prefixes"], f"{label}.prefixes")))
        if any(not re.fullmatch(r"[0-9a-f]", prefix) for prefix in prefixes):
            raise CampaignError(f"{label}.prefixes must contain lowercase hexadecimal nibbles")
        shards.append(Shard(name=name, prefixes=prefixes))
    shards.sort(key=lambda shard: shard.name)
    if len({shard.name for shard in shards}) != len(shards):
        raise CampaignError("mutation shard names must be unique")
    profile, configured_paths, configured_families = _load_config(config_path, workspace)
    for prefix in "0123456789abcdef":
        owners = [shard.name for shard in shards if shard.selects(prefix + "0" * 63)]
        if not owners:
            raise CampaignError(f"mutation ID prefix {prefix} has no shard")
        if len(owners) > 1:
            raise CampaignError(
                f"mutation ID prefix {prefix} is assigned more than once: {', '.join(owners)}"
            )
    return Plan(
        manifest_path=manifest_path,
        manifest_digest=manifest_digest,
        profile=profile,
        configured_paths=configured_paths,
        configured_families=configured_families,
        shards=tuple(shards),
    )


def _validate_mutant(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CampaignError(f"{label} must be an object")
    _exact_fields(value, MUTANT_FIELDS, label)
    identifier = value["id"]
    full_id = value["full_id"]
    if (
        not isinstance(identifier, str)
        or not HEX20.fullmatch(identifier)
        or not isinstance(full_id, str)
        or not HEX64.fullmatch(full_id)
        or identifier != full_id[:20]
    ):
        raise CampaignError(f"{label} has an invalid identity")
    value["path"] = _safe_path(value["path"], f"{label}.path")
    if not isinstance(value["family"], str) or value["family"] not in ALL_FAMILIES:
        raise CampaignError(f"{label} has an unknown family")
    if not isinstance(value["rule"], str) or not RULE.fullmatch(value["rule"]):
        raise CampaignError(f"{label} has an invalid rule")
    for field in ("original", "replacement"):
        if not isinstance(value[field], str) or not value[field]:
            raise CampaignError(f"{label}.{field} must be a nonempty string")
    if value["original"] == value["replacement"]:
        raise CampaignError(f"{label} does not change the source expression")
    if not isinstance(value["source_digest"], str) or not HEX64.fullmatch(value["source_digest"]):
        raise CampaignError(f"{label} has an invalid source digest")
    range_value = value["range"]
    if not isinstance(range_value, dict):
        raise CampaignError(f"{label}.range must be an object")
    _exact_fields(range_value, RANGE_FIELDS, f"{label}.range")
    minimums = {
        "start_byte": 0,
        "end_byte": 1,
        "start_line": 1,
        "start_column": 0,
        "end_line": 1,
        "end_column": 0,
    }
    for field, minimum in minimums.items():
        item = range_value[field]
        if type(item) is not int or item < minimum:
            raise CampaignError(f"{label}.range.{field} is invalid")
    if range_value["end_byte"] <= range_value["start_byte"]:
        raise CampaignError(f"{label}.range byte interval is empty or reversed")
    if (range_value["end_line"], range_value["end_column"]) < (
        range_value["start_line"],
        range_value["start_column"],
    ):
        raise CampaignError(f"{label}.range line interval is reversed")
    return value


def load_catalog(plan: Plan, catalog_path: Path) -> Catalog:
    document, digest = _load_json(catalog_path, "mutation catalog")
    _exact_fields(document, CATALOG_FIELDS, "mutation catalog")
    if document["document_type"] != "ocaml-mutants.catalog-v1" or document["schema_version"] != 1:
        raise CampaignError("mutation catalog has an unknown schema")
    if document["profile"] != plan.profile or document["selection"] != "all":
        raise CampaignError("mutation catalog profile or selection does not match the campaign")
    workspace = document["workspace"]
    if not isinstance(workspace, dict) or set(workspace) != {"digest", "toolchain"}:
        raise CampaignError("mutation catalog workspace is malformed")
    if not isinstance(workspace["digest"], str) or not HEX64.fullmatch(workspace["digest"]):
        raise CampaignError("mutation catalog has an invalid workspace digest")
    if not isinstance(workspace["toolchain"], str) or not workspace["toolchain"]:
        raise CampaignError("mutation catalog has an invalid toolchain identity")
    if not isinstance(document["skips"], list):
        raise CampaignError("mutation catalog skip evidence must be an array")
    rows = document["mutants"]
    if not isinstance(rows, list) or not rows:
        raise CampaignError("mutation catalog is vacuous")
    mutants: dict[str, dict[str, Any]] = {}
    partitions = {shard.name: {} for shard in plan.shards}
    for index, row in enumerate(rows):
        mutant = _validate_mutant(row, f"catalog mutant {index}")
        full_id = mutant["full_id"]
        if full_id in mutants:
            raise CampaignError(f"mutation catalog contains duplicate mutant {full_id}")
        if mutant["path"] not in plan.configured_paths:
            raise CampaignError(
                f"catalog mutant {full_id} selects unconfigured path {mutant['path']}"
            )
        if mutant["family"] not in plan.configured_families:
            raise CampaignError(
                f"catalog mutant {full_id} selects unconfigured family {mutant['family']}"
            )
        shard = plan.assignment(full_id)
        mutants[full_id] = mutant
        partitions[shard.name][full_id] = mutant
    return Catalog(document=document, digest=digest, mutants=mutants, partitions=partitions)


def _report_mutants(report_path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    document, _ = _load_json(report_path, "mutation report")
    rows = document.get("mutants")
    if not isinstance(rows, list):
        raise CampaignError("mutation report mutant collection is malformed")
    mutants: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("mutant"), dict):
            raise CampaignError(f"mutation result {index} is malformed")
        mutant = _validate_mutant(row["mutant"], f"mutation result {index}.mutant")
        full_id = mutant["full_id"]
        if full_id in mutants:
            raise CampaignError(f"mutation report contains duplicate mutant {full_id}")
        mutants[full_id] = mutant
    return document, mutants


def verify_shard(
    plan: Plan, catalog_path: Path, shard_name: str, report_path: Path
) -> dict[str, Any]:
    shard = plan.shard(shard_name)
    catalog = load_catalog(plan, catalog_path)
    document, actual = _report_mutants(report_path)
    expected = catalog.partitions[shard.name]
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        details = []
        if missing:
            details.append(f"missing {len(missing)}")
        if extra:
            details.append(f"unexpected {len(extra)}")
        if not details:
            details.append("mutant metadata differs")
        raise CampaignError(
            f"mutation shard {shard.name} does not match its catalog partition "
            f"({', '.join(details)})"
        )
    workspace = document.get("workspace")
    catalog_workspace = catalog.document["workspace"]
    if (
        not isinstance(workspace, dict)
        or workspace.get("digest") != catalog_workspace["digest"]
    ):
        raise CampaignError(
            f"mutation shard {shard.name} workspace digest does not match the catalog"
        )
    if workspace.get("toolchain") != catalog_workspace["toolchain"]:
        raise CampaignError(f"mutation shard {shard.name} toolchain does not match the catalog")
    expected_selection = "mutants:" + ",".join(sorted(expected))
    if document.get("profile") != plan.profile or document.get("selection") != {
        "description": expected_selection
    }:
        raise CampaignError(f"mutation shard {shard.name} profile or selection is invalid")
    prefixes = sorted(
        {
            str(PurePosixPath(mutant["path"]).parent) + "/"
            for mutant in expected.values()
        }
    )
    try:
        gate = verify_report(report_path, prefixes)
    except ValueError as error:
        raise CampaignError(f"mutation shard {shard.name}: {error}") from error
    if not gate["passed"]:
        raise CampaignError(
            f"mutation shard {shard.name} failed: {'; '.join(gate['failures'])}"
        )
    return gate


def aggregate(plan: Plan, catalog_path: Path, evidence_dir: Path) -> dict[str, Any]:
    catalog = load_catalog(plan, catalog_path)
    expected_names = {f"mutation-report-{name}.json" for name in catalog.active_names}
    actual_names = {path.name for path in evidence_dir.glob("mutation-report-*.json")}
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing:
        raise CampaignError(f"mutation campaign is missing shard reports: {', '.join(missing)}")
    if extra:
        raise CampaignError(f"mutation campaign has unexpected shard reports: {', '.join(extra)}")
    shards: list[dict[str, Any]] = []
    totals = {
        "detected": 0,
        "expected_survivors": 0,
        "mutants": 0,
        "unexpected_survivors": 0,
    }
    for name in catalog.active_names:
        report_path = evidence_dir / f"mutation-report-{name}.json"
        gate = verify_shard(plan, catalog_path, name, report_path)
        for field in totals:
            totals[field] += gate[field]
        shards.append(
            {
                "detected": gate["detected"],
                "expected_survivors": gate["expected_survivors"],
                "mutants": gate["mutants"],
                "name": name,
                "report_digest": gate["report_digest"],
                "unexpected_survivors": gate["unexpected_survivors"],
            }
        )
    if totals["mutants"] != len(catalog.mutants):
        raise CampaignError("mutation campaign totals do not match the complete catalog")
    return {
        "catalog_digest": catalog.digest,
        "detected": totals["detected"],
        "expected_survivors": totals["expected_survivors"],
        "failures": [],
        "manifest_digest": plan.manifest_digest,
        "mutants": totals["mutants"],
        "passed": True,
        "profile": plan.profile,
        "schema": "mutation-campaign-v1",
        "shards": shards,
        "unexpected_survivors": totals["unexpected_survivors"],
        "workspace_digest": catalog.document["workspace"]["digest"],
    }


def _atomic_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise CampaignError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _github_output(path: Path, matrix: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CampaignError(f"cannot inspect GitHub output file {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise CampaignError("GitHub output must be a regular non-symlink file")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"matrix={matrix}\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise CampaignError(f"cannot write GitHub output: {error}") from error


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--workspace", default=Path("."), type=Path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan")
    _common(plan_parser)
    plan_parser.add_argument("--catalog", required=True, type=Path)
    plan_parser.add_argument("--github-output", type=Path)
    select_parser = commands.add_parser("select")
    _common(select_parser)
    select_parser.add_argument("--shard", required=True)
    select_parser.add_argument("--field", required=True, choices=("mutants",))
    select_parser.add_argument("--catalog", required=True, type=Path)
    verify_parser = commands.add_parser("verify-shard")
    _common(verify_parser)
    verify_parser.add_argument("--catalog", required=True, type=Path)
    verify_parser.add_argument("--shard", required=True)
    verify_parser.add_argument("--report", required=True, type=Path)
    verify_parser.add_argument("--output", required=True, type=Path)
    aggregate_parser = commands.add_parser("aggregate")
    _common(aggregate_parser)
    aggregate_parser.add_argument("--catalog", required=True, type=Path)
    aggregate_parser.add_argument("--evidence-dir", required=True, type=Path)
    aggregate_parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        plan = load_plan(arguments.manifest, arguments.config, arguments.workspace)
        if arguments.command == "plan":
            catalog = load_catalog(plan, arguments.catalog)
            matrix = json.dumps(
                {"shard": list(catalog.active_names)}, separators=(",", ":")
            )
            if arguments.github_output is not None:
                _github_output(arguments.github_output, matrix)
            print(matrix)
        elif arguments.command == "select":
            catalog = load_catalog(plan, arguments.catalog)
            plan.shard(arguments.shard)
            values = tuple(sorted(catalog.partitions[arguments.shard]))
            if not values:
                raise CampaignError(f"mutation shard {arguments.shard} is vacuous")
            print("\n".join(values))
        elif arguments.command == "verify-shard":
            result = verify_shard(plan, arguments.catalog, arguments.shard, arguments.report)
            _atomic_json(arguments.output, result)
            print(
                f"mutation shard {arguments.shard}: "
                f"{result['detected']}/{result['mutants']} detected"
            )
        else:
            result = aggregate(plan, arguments.catalog, arguments.evidence_dir)
            _atomic_json(arguments.output, result)
            print(
                f"mutation campaign: {result['detected']}/{result['mutants']} detected "
                f"across {len(result['shards'])} shards"
            )
    except (CampaignError, OSError) as error:
        print(f"mutation campaign: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
