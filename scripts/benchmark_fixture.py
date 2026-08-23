#!/usr/bin/env python3
"""Prepare a deterministic four-provider workload for performance measurement."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
import tempfile


FILES = {
    ".workflow-verifier.toml": """version = 1
persona = "audit"
frontends = ["github", "gitlab", "azure", "circleci"]
offline = true
""",
    ".gitlab-ci.yml": """stages: [test]
verify:
  stage: test
  script:
    - printf 'gitlab\\n'
""",
    "azure-pipelines.yml": """trigger:
  - main
jobs:
  - job: verify
    steps:
      - script: printf 'azure\\n'
""",
    ".circleci/config.yml": """version: 2.1
jobs:
  verify:
    docker:
      - image: cimg/base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: printf 'circleci\\n'
workflows:
  verify:
    jobs: [verify]
""",
}


def _github(variant: str) -> str:
    return f"""name: performance-{variant}
on: push
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - shell: sh
        run: printf '{variant}\\n'
"""


def _directory(path: Path, label: str) -> None:
    if path.exists():
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} is not a regular directory and may be a symlink")
    else:
        path.mkdir()


def _write(path: Path, source: str) -> None:
    _directory(path.parent, f"parent for {path.name}")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"benchmark file {path} is not a regular file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(source)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def prepare(workspace: Path, mode: str) -> Path:
    if mode not in {"reset", "toggle"}:
        raise ValueError("benchmark fixture mode must be reset or toggle")
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("benchmark workspace must be a regular directory")
    build = workspace / "_build"
    _directory(build, "benchmark build root")
    root = build / "performance-workload"
    _directory(root, "benchmark workload root")
    github = root / ".github"
    _directory(github, "GitHub fixture root")
    workflows = github / "workflows"
    _directory(workflows, "GitHub workflow root")
    circleci = root / ".circleci"
    _directory(circleci, "CircleCI fixture root")

    workflow = workflows / "ci.yml"
    if mode == "reset" or not workflow.exists():
        variant = "variant-a"
    else:
        current = workflow.read_text(encoding="utf-8")
        variant = "variant-b" if "variant-a" in current else "variant-a"
    for relative, source in FILES.items():
        _write(root / relative, source)
    _write(workflow, _github(variant))
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--mode", choices=("reset", "toggle"), required=True)
    arguments = parser.parse_args()
    try:
        root = prepare(arguments.workspace, arguments.mode)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"benchmark fixture: {error}", file=sys.stderr)
        return 2
    print(root.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
