#!/usr/bin/env python3
"""Measure cold, warm, and incremental commands from a shell-free suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


MODES = ("cold", "incremental", "warm")
ROOT_FIELDS = {"schema", "environment", "scenarios"}
SCENARIO_FIELDS = {"id", "cwd", "modes"}
MODE_FIELDS = {"setup", "before_each", "command", "timeout_seconds"}
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")


def _load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect performance suite {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"performance suite must be a nonempty regular file: {path}")
    if metadata.st_size > 4 * 1024 * 1024:
        raise ValueError(f"performance suite is too large: {path}")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse performance suite {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("performance suite must be an object")
    return document, "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return path


def _argv(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 128
        or any(
            not isinstance(argument, str)
            or not argument
            or "\x00" in argument
            or len(argument) > 16_384
            for argument in value
        )
    ):
        raise ValueError(f"{label} must be a bounded nonempty argv array")
    return value


def _commands(value: Any, label: str) -> list[list[str]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError(f"{label} must be a bounded array of argv arrays")
    return [_argv(command, f"{label}[{index}]") for index, command in enumerate(value)]


def _native_argv(argv: list[str], cwd: Path) -> list[str]:
    executable = argv[0]
    if not os.path.isabs(executable) and ("/" in executable or "\\" in executable):
        return [str((cwd / executable).resolve()), *argv[1:]]
    return argv


def _run(argv: list[str], cwd: Path, timeout: int, environment: dict[str, str], label: str) -> None:
    try:
        completed = subprocess.run(
            _native_argv(argv, cwd),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{label} exceeded {timeout} seconds") from error
    except OSError as error:
        raise RuntimeError(f"{label} could not start: {error}") from error
    if len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
        raise RuntimeError(f"{label} emitted more than 1 MiB")
    if completed.returncode != 0:
        raise RuntimeError(f"{label} returned exit {completed.returncode}")


def measure(
    suite_path: Path,
    workspace: Path,
    *,
    revision: str,
    samples: int,
) -> dict[str, Any]:
    if not REVISION.fullmatch(revision):
        raise ValueError("revision must be a lowercase 40-character commit")
    if type(samples) is not int or not 1 <= samples <= 1000:
        raise ValueError("samples must be between 1 and 1000")
    try:
        workspace_metadata = workspace.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect benchmark workspace {workspace}: {error}") from error
    if workspace.is_symlink() or not stat.S_ISDIR(workspace_metadata.st_mode):
        raise ValueError("benchmark workspace must be a directory, not a symlink")
    workspace_resolved = workspace.resolve()

    document, suite_digest = _load(suite_path)
    _exact_fields(document, ROOT_FIELDS, "performance suite")
    if document["schema"] != "performance-suite-v1":
        raise ValueError("performance suite schema must be performance-suite-v1")
    raw_environment = document["environment"]
    if (
        not isinstance(raw_environment, dict)
        or not raw_environment
        or any(not isinstance(key, str) or not key for key in raw_environment)
        or any(not isinstance(value, str) or not value for value in raw_environment.values())
    ):
        raise ValueError("performance suite environment must be a nonempty string map")
    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("performance suite scenarios must be a nonempty array")

    parsed: list[tuple[str, Path, dict[str, dict[str, Any]]]] = []
    seen: set[str] = set()
    for index, scenario in enumerate(scenarios):
        label = f"performance suite scenarios[{index}]"
        if not isinstance(scenario, dict):
            raise ValueError(f"{label} must be an object")
        _exact_fields(scenario, SCENARIO_FIELDS, label)
        identifier = scenario["id"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError(f"{label}.id is invalid")
        if identifier in seen:
            raise ValueError(f"duplicate performance scenario {identifier}")
        seen.add(identifier)
        relative = _safe_relative(scenario["cwd"], f"{label}.cwd")
        cwd = workspace.joinpath(*relative.parts)
        try:
            cwd_resolved = cwd.resolve(strict=True)
            cwd_resolved.relative_to(workspace_resolved)
        except (OSError, ValueError) as error:
            raise ValueError(f"{label}.cwd escapes or does not exist in workspace") from error
        if cwd.is_symlink() or not cwd.is_dir():
            raise ValueError(f"{label}.cwd must be a directory, not a symlink")
        modes = scenario["modes"]
        if not isinstance(modes, dict) or set(modes) != set(MODES):
            raise ValueError(f"{label}.modes must contain exactly cold, incremental, and warm")
        parsed_modes: dict[str, dict[str, Any]] = {}
        for mode in MODES:
            mode_value = modes[mode]
            mode_label = f"{label}.modes.{mode}"
            if not isinstance(mode_value, dict):
                raise ValueError(f"{mode_label} must be an object")
            _exact_fields(mode_value, MODE_FIELDS, mode_label)
            timeout = mode_value["timeout_seconds"]
            if type(timeout) is not int or not 1 <= timeout <= 3600:
                raise ValueError(f"{mode_label}.timeout_seconds must be between 1 and 3600")
            parsed_modes[mode] = {
                "before_each": _commands(mode_value["before_each"], f"{mode_label}.before_each"),
                "command": _argv(mode_value["command"], f"{mode_label}.command"),
                "setup": _commands(mode_value["setup"], f"{mode_label}.setup"),
                "timeout_seconds": timeout,
            }
        parsed.append((identifier, cwd, parsed_modes))

    result_scenarios: list[dict[str, Any]] = []
    for identifier, cwd, modes in sorted(parsed, key=lambda item: item[0].encode("utf-8")):
        result_modes: dict[str, Any] = {}
        for mode in MODES:
            specification = modes[mode]
            environment = dict(os.environ)
            environment.update(
                {
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "WORKFLOW_VERIFIER_BENCHMARK_MODE": mode,
                }
            )
            for index, command in enumerate(specification["setup"]):
                _run(command, cwd, specification["timeout_seconds"], environment, f"{identifier}/{mode} setup {index}")
            durations: list[int] = []
            for sample in range(samples):
                for index, command in enumerate(specification["before_each"]):
                    _run(
                        command,
                        cwd,
                        specification["timeout_seconds"],
                        environment,
                        f"{identifier}/{mode} before_each {sample}/{index}",
                    )
                started = time.perf_counter_ns()
                _run(
                    specification["command"],
                    cwd,
                    specification["timeout_seconds"],
                    environment,
                    f"{identifier}/{mode} sample {sample}",
                )
                duration = time.perf_counter_ns() - started
                durations.append(max(duration, 1))
            result_modes[mode] = {"samples_ns": durations}
        result_scenarios.append({"id": identifier, "modes": result_modes})
    environment = dict(raw_environment)
    environment["suite_digest"] = suite_digest
    return {
        "environment": dict(sorted(environment.items())),
        "regression_explanations": [],
        "revision": revision,
        "scenarios": result_scenarios,
        "schema": "performance-v1",
    }


def _atomic_json(path: Path, value: Any) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.samples < 5:
        parser.error("publication measurements require at least five samples")
    try:
        result = measure(
            arguments.suite,
            arguments.workspace,
            revision=arguments.revision,
            samples=arguments.samples,
        )
        _atomic_json(arguments.output, result)
    except (ValueError, RuntimeError) as error:
        print(f"performance measurement: {error}", file=sys.stderr)
        return 2
    print(
        f"performance measurement: {len(result['scenarios'])} scenarios x "
        f"{len(MODES)} modes x {arguments.samples} samples"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
