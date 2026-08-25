#!/usr/bin/env python3
"""Prepare a deterministic four-provider workload for performance measurement."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from pathlib import Path

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

SCENARIOS = ("four-provider", "arcade-scale")
ARCADE_REPOSITORIES = 64
ARCADE_VARIABLES = 778
ARCADE_GATED_STAGES = 2
ARCADE_DISPLAY_PADDING = 1050


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


def _arcade_scale(variant: str) -> str:
    """Generate a stable Azure graph with Arcade-like resources and gates.

    Azure's ``bash`` key keeps historical baselines from mistaking the
    ``stages``/``script`` content shape for GitLab before checking the path.
    """
    lines = [
        "trigger:\n",
        "  branches:\n",
        "    include: [main]\n",
        "resources:\n",
        "  repositories:\n",
    ]
    for index in range(ARCADE_REPOSITORIES):
        lines.extend(
            [
                f"    - repository: dependency_{index:03d}\n",
                "      type: github\n",
                f"      name: dotnet/dependency-{index:03d}\n",
                f"      ref: {'%040x' % (index + 1)}\n",
            ]
        )
    lines.append("variables:\n")
    for index in range(ARCADE_VARIABLES):
        lines.extend(
            [
                f"  - name: arcadeVariable{index:03d}\n",
                f"    value: value-{index:03d}\n",
            ]
        )
    lines.append("stages:\n")
    for stage in range(ARCADE_GATED_STAGES):
        lines.extend(
            [
                f"  - stage: release_{stage:03d}\n",
                f"    displayName: Release train {stage:03d} "
                + ("cross-platform-artifact-validation-" * ARCADE_DISPLAY_PADDING)
                + "\n",
                "    condition: succeeded()\n",
                "    jobs:\n",
                f"      - deployment: approve_{stage:03d}\n",
                f"        displayName: Protected environment {stage:03d}\n",
                f"        environment: production-{stage:03d}\n",
                "        strategy:\n",
                "          runOnce:\n",
                "            deploy:\n",
                "              steps:\n",
                "                - checkout: none\n",
                f"                - bash: echo approve-{stage:03d}\n",
                f"      - job: build_{stage:03d}\n",
                f"        displayName: Build leg {stage:03d}\n",
                f"        dependsOn: approve_{stage:03d}\n",
                "        pool:\n",
                "          vmImage: ubuntu-24.04\n",
                "        variables:\n",
                f"          localArtifact: artifact-{stage:03d}\n",
                "        steps:\n",
                "          - checkout: self\n",
                "            persistCredentials: false\n",
                f"          - checkout: dependency_{stage % ARCADE_REPOSITORIES:03d}\n",
                "          - task: Cache@2\n",
                "            inputs:\n",
                f"              key: arcade-{stage:03d}-$(Agent.OS)\n",
                f"              path: $(Pipeline.Workspace)/cache-{stage:03d}\n",
                f"          - bash: echo build-{stage:03d} $(arcadeVariable{stage:03d})\n",
                "            displayName: Compile repository leg\n",
                f"          - publish: $(Build.ArtifactStagingDirectory)/{stage:03d}\n",
                f"            artifact: arcade-{stage:03d}\n",
                f"      - job: validate_{stage:03d}\n",
                f"        displayName: Validate leg {stage:03d}\n",
                f"        dependsOn: build_{stage:03d}\n",
                "        pool:\n",
                "          vmImage: windows-2025\n",
                "        steps:\n",
                "          - checkout: none\n",
                "          - download: current\n",
                f"            artifact: arcade-{stage:03d}\n",
                f"          - bash: echo validate-{stage:03d}\n",
                "            displayName: Validate artifact\n",
                "          - task: PublishTestResults@2\n",
                "            inputs:\n",
                f"              testResultsFiles: results-{stage:03d}.xml\n",
            ]
        )
    lines.extend(
        [
            "  - stage: benchmark_variant\n",
            "    jobs:\n",
            "      - job: marker\n",
            "        steps:\n",
            f"          - bash: echo {variant}\n",
        ]
    )
    return "".join(lines)


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


def prepare(workspace: Path, mode: str, scenario: str = "four-provider") -> Path:
    if mode not in {"reset", "toggle"}:
        raise ValueError("benchmark fixture mode must be reset or toggle")
    if scenario not in SCENARIOS:
        raise ValueError("benchmark fixture scenario is unsupported")
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("benchmark workspace must be a regular directory")
    build = workspace / "_build"
    _directory(build, "benchmark build root")
    root = build / (
        "performance-workload" if scenario == "four-provider" else "performance-arcade-scale"
    )
    _directory(root, "benchmark workload root")
    if scenario == "arcade-scale":
        pipeline = root / "azure-pipelines.yml"
        if mode == "reset" or not pipeline.exists():
            variant = "variant-a"
        else:
            current = pipeline.read_text(encoding="utf-8")
            variant = "variant-b" if "echo variant-a" in current else "variant-a"
        _write(
            root / ".workflow-verifier.toml",
            'version = 1\npersona = "audit"\nfrontends = ["azure"]\noffline = true\n',
        )
        _write(pipeline, _arcade_scale(variant))
        return root
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
    parser.add_argument("--scenario", choices=SCENARIOS, default="four-provider")
    arguments = parser.parse_args()
    try:
        root = prepare(arguments.workspace, arguments.mode, arguments.scenario)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"benchmark fixture: {error}", file=sys.stderr)
        return 2
    print(root.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
