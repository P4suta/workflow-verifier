#!/usr/bin/env python3
"""Run mutation work inside a fail-closed Linux resource envelope."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, NoReturn

try:
    import resource as _resource
except ImportError:  # pragma: no cover - exercised by the Windows CI import
    _resource = None


SCHEMA = "mutation-resource-guard-v1"
LIMITS = (
    ("address_space_bytes", "RLIMIT_AS", 1_610_612_736),
    ("core_file_bytes", "RLIMIT_CORE", 0),
    ("file_bytes", "RLIMIT_FSIZE", 268_435_456),
    ("open_files", "RLIMIT_NOFILE", 1024),
    ("processes", "RLIMIT_NPROC", 256),
)


def contract() -> dict[str, int | str]:
    return {**{name: limit for name, _, limit in LIMITS}, "schema": SCHEMA}


def _validated_resources(resources: Any) -> list[tuple[int, int]]:
    resolved: list[tuple[int, int]] = []
    for _, symbol, limit in LIMITS:
        if not hasattr(resources, symbol):
            raise RuntimeError(f"resource module lacks {symbol}")
        resolved.append((getattr(resources, symbol), limit))
    if not hasattr(resources, "RLIM_INFINITY"):
        raise RuntimeError("resource module lacks RLIM_INFINITY")
    for method in ("getrlimit", "setrlimit"):
        if not callable(getattr(resources, method, None)):
            raise RuntimeError(f"resource module lacks {method}")
    return resolved


def _not_looser(limit: int, current: int, infinity: int) -> int:
    return limit if current == infinity else min(limit, current)


def apply_limits(resources: Any) -> None:
    resolved = _validated_resources(resources)
    infinity = resources.RLIM_INFINITY
    planned: list[tuple[int, tuple[int, int]]] = []
    for identifier, requested in resolved:
        soft, hard = resources.getrlimit(identifier)
        target = _not_looser(requested, soft, infinity)
        target = _not_looser(target, hard, infinity)
        if type(target) is not int or target < 0:
            raise RuntimeError("resource module returned an invalid existing limit")
        planned.append((identifier, (target, target)))
    for identifier, value in planned:
        resources.setrlimit(identifier, value)


def command_after_separator(arguments: list[str]) -> list[str]:
    if not arguments or arguments[0] != "--":
        raise ValueError("command must follow an explicit -- separator")
    command = arguments[1:]
    if not command or any(not argument or "\x00" in argument for argument in command):
        raise ValueError("command must be a nonempty NUL-free argv vector")
    return command


def _linux_resources() -> Any:
    if sys.platform != "linux" or _resource is None:
        raise RuntimeError("mutation resource guard requires Linux rlimit controls")
    _validated_resources(_resource)
    return _resource


def _exec(command: list[str], resources: Any) -> NoReturn:
    apply_limits(resources)
    environment = dict(os.environ)
    environment["WORKFLOW_VERIFIER_MUTATION_RESOURCE_GUARD"] = SCHEMA
    os.execvpe(command[0], command, environment)


def main(arguments: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    try:
        resources = _linux_resources()
        if arguments == ["--check"]:
            apply_limits(resources)
            print(json.dumps(contract(), sort_keys=True, separators=(",", ":")))
            return 0
        _exec(command_after_separator(arguments), resources)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"mutation resource guard: {error}", file=sys.stderr)
        return 2
    raise AssertionError("exec returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
