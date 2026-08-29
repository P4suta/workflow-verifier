#!/usr/bin/env python3
"""Compare deterministic performance ledgers and reject unexplained regressions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT_FIELDS = {
    "schema",
    "revision",
    "environment",
    "scenarios",
    "regression_explanations",
}
SCENARIO_FIELDS = {"id", "samples_ns"}
EXPLANATION_FIELDS = {"scenario", "reason", "review"}
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect performance ledger {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"performance ledger must be a nonempty regular file: {path}")
    if metadata.st_size > 16 * 1024 * 1024:
        raise ValueError(f"performance ledger is too large: {path}")
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse performance ledger {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"performance ledger must be an object: {path}")
    return document, "sha256:" + hashlib.sha256(raw).hexdigest()


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown fields: {', '.join(extra)}")


def _median(samples: list[int]) -> Fraction:
    ordered = sorted(samples)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return Fraction(ordered[middle], 1)
    return Fraction(ordered[middle - 1] + ordered[middle], 2)


def _fraction_string(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"


def _percentage(value: Fraction) -> str:
    decimal = Decimal(value.numerator) / Decimal(value.denominator)
    return f"{decimal.quantize(Decimal('0.001'), rounding=ROUND_HALF_UP):.3f}"


def _review_url(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS review URL")
    return value


def _validate(
    document: dict[str, Any], label: str
) -> tuple[dict[str, list[int]], dict[str, dict[str, str]]]:
    _exact_fields(document, ROOT_FIELDS, label)
    if document["schema"] != "performance-v2":
        raise ValueError(f"{label}.schema must be performance-v2")
    revision = document["revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError(f"{label}.revision must be a lowercase 40-character commit")
    environment = document["environment"]
    if (
        not isinstance(environment, dict)
        or not environment
        or any(not isinstance(key, str) or not key for key in environment)
        or any(not isinstance(value, str) or not value for value in environment.values())
    ):
        raise ValueError(f"{label}.environment must be a nonempty string map")
    scenarios = document["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError(f"{label}.scenarios must be a nonempty array")
    parsed_scenarios: dict[str, list[int]] = {}
    for index, scenario in enumerate(scenarios):
        scenario_label = f"{label}.scenarios[{index}]"
        if not isinstance(scenario, dict):
            raise ValueError(f"{scenario_label} must be an object")
        _exact_fields(scenario, SCENARIO_FIELDS, scenario_label)
        identifier = scenario["id"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError(f"{scenario_label}.id is invalid")
        if identifier in parsed_scenarios:
            raise ValueError(f"{label} contains duplicate scenario {identifier}")
        samples = scenario["samples_ns"]
        if (
            not isinstance(samples, list)
            or not samples
            or any(type(sample) is not int or sample <= 0 for sample in samples)
        ):
            raise ValueError(f"{scenario_label}.samples_ns must be positive integers")
        parsed_scenarios[identifier] = samples

    raw_explanations = document["regression_explanations"]
    if not isinstance(raw_explanations, list):
        raise ValueError(f"{label}.regression_explanations must be an array")
    explanations: dict[str, dict[str, str]] = {}
    for index, explanation in enumerate(raw_explanations):
        explanation_label = f"{label}.regression_explanations[{index}]"
        if not isinstance(explanation, dict):
            raise ValueError(f"{explanation_label} must be an object")
        _exact_fields(explanation, EXPLANATION_FIELDS, explanation_label)
        scenario = explanation["scenario"]
        reason = explanation["reason"]
        if scenario not in parsed_scenarios:
            raise ValueError(f"{explanation_label} names an unknown measurement")
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            raise ValueError(f"{explanation_label}.reason must contain a substantive explanation")
        review = _review_url(explanation["review"], f"{explanation_label}.review")
        if scenario in explanations:
            raise ValueError(f"{label} contains duplicate explanation for {scenario}")
        explanations[scenario] = {
            "reason": reason.strip(),
            "review": review,
        }
    return parsed_scenarios, explanations


def compare(baseline_path: Path, current_path: Path) -> dict[str, Any]:
    baseline, baseline_digest = _load(baseline_path)
    current, current_digest = _load(current_path)
    baseline_scenarios, baseline_explanations = _validate(baseline, "baseline")
    current_scenarios, explanations = _validate(current, "current")
    if baseline_explanations:
        raise ValueError("baseline must not carry regression explanations")
    if baseline["environment"] != current["environment"]:
        raise ValueError("baseline and current environment must match exactly")
    if set(baseline_scenarios) != set(current_scenarios):
        raise ValueError("baseline and current scenario sets must match exactly")

    comparisons: list[dict[str, Any]] = []
    regressions: set[str] = set()
    for scenario in sorted(baseline_scenarios, key=lambda value: value.encode("utf-8")):
        baseline_median = _median(baseline_scenarios[scenario])
        current_median = _median(current_scenarios[scenario])
        change = (current_median - baseline_median) * 100 / baseline_median
        regressed = current_median * 100 > baseline_median * 110
        explanation = explanations.get(scenario)
        if regressed:
            regressions.add(scenario)
        status = (
            "explained-regression"
            if regressed and explanation is not None
            else "regression"
            if regressed
            else "within-limit"
        )
        comparisons.append(
            {
                "baseline_median_ns": _fraction_string(baseline_median),
                "change_percent": _percentage(change),
                "current_median_ns": _fraction_string(current_median),
                "explanation": explanation,
                "scenario": scenario,
                "status": status,
            }
        )
    stale = sorted(set(explanations) - regressions)
    if stale:
        raise ValueError(
            f"current explanation for {stale[0]} is stale because no regression exists"
        )
    failures = [
        f"{row['scenario']} regressed by {row['change_percent']}% without review"
        for row in comparisons
        if row["status"] == "regression"
    ]
    return {
        "baseline": {"digest": baseline_digest, "revision": baseline["revision"]},
        "comparisons": comparisons,
        "current": {"digest": current_digest, "revision": current["revision"]},
        "environment": dict(sorted(current["environment"].items())),
        "failures": failures,
        "passed": not failures,
        "schema": "performance-comparison-v2",
        "threshold_percent": "10.000",
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
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = compare(arguments.baseline, arguments.current)
        _atomic_json(arguments.output, result)
    except ValueError as error:
        print(f"performance gate: {error}", file=sys.stderr)
        return 2
    if not result["passed"]:
        for failure in result["failures"]:
            print(f"performance gate: {failure}", file=sys.stderr)
        return 1
    print(f"performance gate: {len(result['comparisons'])} comparisons passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
