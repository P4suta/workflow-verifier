#!/usr/bin/env python3
"""Measure baseline and candidate in period-balanced cycles on one runner."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Callable

try:
    from scripts.measure_performance import measure
except ModuleNotFoundError:  # Direct script execution from the repository root.
    from measure_performance import measure


REVISION = re.compile(r"^[0-9a-f]{40}$")
PAIR_DESIGN = "period-balanced-v2"
PERIOD_BALANCED_BLOCK = (
    "baseline",
    "current",
    "current",
    "baseline",
    "current",
    "baseline",
    "baseline",
    "current",
)
PERIOD_BALANCED_CYCLE = PERIOD_BALANCED_BLOCK + tuple(
    "current" if name == "baseline" else "baseline"
    for name in PERIOD_BALANCED_BLOCK
)
Measurer = Callable[..., dict[str, Any]]


def _merge(reports: list[dict[str, Any]], revision: str, expected_samples: int) -> dict[str, Any]:
    if not reports:
        raise ValueError("period-balanced measurement produced no reports")
    result = copy.deepcopy(reports[0])
    if result.get("schema") != "performance-v1" or result.get("revision") != revision:
        raise ValueError("period-balanced measurement returned the wrong identity")
    environment = result.get("environment")
    if not isinstance(environment, dict) or "pair_design" in environment:
        raise ValueError("performance environment must reserve pair_design for the orchestrator")
    for scenario in result["scenarios"]:
        for mode in scenario["modes"].values():
            mode["samples_ns"] = []

    for observation_index, report in enumerate(reports):
        if (
            report.get("schema") != "performance-v1"
            or report.get("revision") != revision
            or report.get("environment") != environment
            or report.get("regression_explanations") != result.get("regression_explanations")
        ):
            raise ValueError(f"period-balanced observation {observation_index} changed report identity")
        scenarios = report.get("scenarios")
        if not isinstance(scenarios, list) or len(scenarios) != len(result["scenarios"]):
            raise ValueError(f"period-balanced observation {observation_index} changed scenarios")
        for scenario_index, scenario in enumerate(scenarios):
            target = result["scenarios"][scenario_index]
            if scenario.get("id") != target.get("id") or set(scenario.get("modes", {})) != set(target["modes"]):
                raise ValueError(f"period-balanced observation {observation_index} changed scenario shape")
            for mode_name, mode in scenario["modes"].items():
                samples = mode.get("samples_ns")
                if not isinstance(samples, list) or any(type(value) is not int or value <= 0 for value in samples):
                    raise ValueError(f"period-balanced observation {observation_index} has invalid samples")
                target["modes"][mode_name]["samples_ns"].extend(samples)
    for scenario in result["scenarios"]:
        for mode_name, mode in scenario["modes"].items():
            if len(mode["samples_ns"]) != expected_samples:
                raise ValueError(f"period-balanced result has the wrong sample count for {scenario['id']}/{mode_name}")
    result["environment"] = {**environment, "pair_design": PAIR_DESIGN}
    return result


def measure_pair(
    suite: Path,
    baseline_workspace: Path,
    baseline_revision: str,
    current_workspace: Path,
    current_revision: str,
    *,
    samples: int,
    measurer: Measurer = measure,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not REVISION.fullmatch(baseline_revision) or not REVISION.fullmatch(current_revision):
        raise ValueError("baseline and current revisions must be lowercase 40-character commits")
    if baseline_revision == current_revision:
        raise ValueError("performance comparison requires different revisions")
    if type(samples) is not int or samples < 8 or samples % 8 != 0:
        raise ValueError("sample count must be a positive multiple of eight")
    reports: dict[str, list[dict[str, Any]]] = {"baseline": [], "current": []}
    specifications = {
        "baseline": (baseline_workspace, baseline_revision),
        "current": (current_workspace, current_revision),
    }
    sequence = PERIOD_BALANCED_CYCLE * (samples // 8)
    for name in sequence:
        workspace, revision = specifications[name]
        reports[name].append(
            measurer(suite, workspace, revision=revision, samples=1)
        )
    return (
        _merge(reports["baseline"], baseline_revision, samples),
        _merge(reports["current"], current_revision, samples),
    )


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
    parser.add_argument("--baseline-workspace", required=True, type=Path)
    parser.add_argument("--baseline-revision", required=True)
    parser.add_argument("--current-workspace", required=True, type=Path)
    parser.add_argument("--current-revision", required=True)
    parser.add_argument("--samples", type=int, default=24)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        baseline, current = measure_pair(
            arguments.suite,
            arguments.baseline_workspace,
            arguments.baseline_revision,
            arguments.current_workspace,
            arguments.current_revision,
            samples=arguments.samples,
        )
        _atomic_json(arguments.output_dir / "baseline.json", baseline)
        _atomic_json(arguments.output_dir / "current.json", current)
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        print(f"period-balanced performance measurement: {error}", file=sys.stderr)
        return 2
    print(
        "period-balanced performance measurement: "
        f"{arguments.samples} single-sample periods per revision"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
