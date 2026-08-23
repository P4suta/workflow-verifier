#!/usr/bin/env python3
"""Run and validate a bounded AFL++ campaign for the OCaml YAML harness."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any


def build_command(
    afl_fuzz: Path,
    seeds: Path,
    output: Path,
    target: Path,
    *,
    seconds: int,
    memory_mb: int,
) -> list[str]:
    if not 1 <= seconds <= 86_400:
        raise ValueError("fuzz duration must be between 1 and 86400 seconds")
    if not 64 <= memory_mb <= 65_536:
        raise ValueError("fuzz memory limit must be between 64 and 65536 MiB")
    return [
        afl_fuzz.as_posix(),
        "-V",
        str(seconds),
        "-m",
        str(memory_mb),
        "-M",
        "default",
        "-i",
        seeds.as_posix(),
        "-o",
        output.as_posix(),
        "--",
        target.as_posix(),
        "--input",
        "@@",
    ]


def _findings(path: Path) -> list[Path]:
    if not path.is_dir():
        raise ValueError(f"AFL++ result directory is missing: {path}")
    return sorted(
        (
            item
            for item in path.iterdir()
            if item.is_file()
            and not item.is_symlink()
            and not item.name.lower().startswith("readme")
            and not item.name.startswith(".")
        ),
        key=lambda item: item.name.encode("utf-8"),
    )


def validate_results(output: Path) -> dict[str, int]:
    instance = output / "default"
    stats_path = instance / "fuzzer_stats"
    if not stats_path.is_file() or stats_path.is_symlink():
        raise ValueError("AFL++ campaign did not produce default/fuzzer_stats")
    stats: dict[str, str] = {}
    for line in stats_path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in stats:
            raise ValueError(f"AFL++ fuzzer_stats contains duplicate key {key}")
        stats[key] = value.strip()
    try:
        execs_done = int(stats["execs_done"])
        corpus_count = int(stats.get("corpus_count", stats.get("paths_total", "")))
    except (KeyError, ValueError) as error:
        raise ValueError("AFL++ fuzzer_stats omits numeric execution/corpus counters") from error
    if execs_done <= 0 or corpus_count <= 0:
        raise ValueError("AFL++ campaign executed no inputs or retained no corpus")
    crashes = _findings(instance / "crashes")
    hangs = _findings(instance / "hangs")
    if crashes:
        count = len(crashes)
        amount = "one" if count == 1 else str(count)
        raise ValueError(f"AFL++ found {amount} crashing input{'s' if count != 1 else ''}")
    if hangs:
        count = len(hangs)
        amount = "one" if count == 1 else str(count)
        raise ValueError(f"AFL++ found {amount} hanging input{'s' if count != 1 else ''}")
    return {"corpus_count": corpus_count, "execs_done": execs_done}


def _regular_executable(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect fuzz executable {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"fuzz executable must be a nonempty regular non-symlink file: {path}")


def _seed_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect fuzz seed corpus {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"fuzz seed corpus must be a directory, not a symlink: {path}")
    seeds = list(path.iterdir())
    if not seeds:
        raise ValueError("fuzz seed corpus is empty")
    for seed in seeds:
        metadata = seed.lstat()
        if seed.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
            raise ValueError(f"fuzz seed must be a nonempty regular non-symlink file: {seed}")


def run(
    afl_fuzz: Path,
    seeds: Path,
    output: Path,
    target: Path,
    *,
    seconds: int,
    memory_mb: int,
) -> dict[str, int]:
    _regular_executable(afl_fuzz)
    _regular_executable(target)
    _seed_directory(seeds)
    if output.is_symlink():
        raise ValueError(f"fuzz output cannot be a symlink: {output}")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"fuzz output must not already contain results: {output}")
    environment = dict(os.environ)
    environment.update(
        {
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            "AFL_NO_UI": "1",
            "AFL_SKIP_CPUFREQ": "1",
        }
    )
    command = build_command(
        afl_fuzz,
        seeds,
        output,
        target,
        seconds=seconds,
        memory_mb=memory_mb,
    )
    try:
        completed = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=seconds + 60,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("AFL++ exceeded its bounded campaign deadline") from error
    except OSError as error:
        raise RuntimeError(f"cannot execute AFL++: {error}") from error
    if len(completed.stdout) > 4 * 1024 * 1024 or len(completed.stderr) > 4 * 1024 * 1024:
        raise RuntimeError("AFL++ emitted more than 4 MiB of process output")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"AFL++ returned exit {completed.returncode}: {detail}")
    return validate_results(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--afl-fuzz", type=Path)
    parser.add_argument("--seeds", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--memory-mb", type=int, default=1024)
    arguments = parser.parse_args()
    executable = arguments.afl_fuzz
    if executable is None:
        found = shutil.which("afl-fuzz")
        if found is None:
            print("AFL++ executable afl-fuzz is unavailable", file=sys.stderr)
            return 2
        executable = Path(found)
    try:
        result: dict[str, Any] = run(
            executable,
            arguments.seeds,
            arguments.output,
            arguments.target,
            seconds=arguments.seconds,
            memory_mb=arguments.memory_mb,
        )
    except (ValueError, RuntimeError) as error:
        print(f"coverage-guided fuzz gate: {error}", file=sys.stderr)
        return 1
    result["schema"] = "afl-campaign-summary-v1"
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
