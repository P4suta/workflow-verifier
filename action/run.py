from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CREDENTIAL_ENV = "WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN"
HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)


class ActionInputError(ValueError):
    pass


def action_input(name: str) -> str:
    value = os.environ.get(name, "")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ActionInputError(f"{name} contains a forbidden control character")
    return value


def run_child(arguments: list[str], environment: dict[str, str], *, quiet: bool = False) -> int:
    try:
        completed = subprocess.run(
            arguments,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"cannot execute workflow-verifier: {error}") from error
    return completed.returncode


def main() -> int:
    binary = action_input("WV_ACTION_BINARY") or "workflow-verifier"
    target = action_input("WV_ACTION_PATH") or "."
    persona = action_input("WV_ACTION_PERSONA") or "gate"
    report_format = action_input("WV_ACTION_FORMAT") or "json"
    output = action_input("WV_ACTION_OUTPUT") or "workflow-verifier-report.json"
    config = action_input("WV_ACTION_CONFIG")
    resolve = action_input("WV_ACTION_RESOLVE") or "false"
    token = action_input("WV_ACTION_GITHUB_TOKEN")
    github_host = action_input("WV_ACTION_GITHUB_HOST") or "github.com"
    network_profile = action_input("WV_ACTION_NETWORK_PROFILE")

    if persona not in {"gate", "audit", "paranoid"}:
        raise ActionInputError("persona must be gate, audit, or paranoid")
    if report_format not in {"json", "sarif"}:
        raise ActionInputError("format must be json or sarif")
    if resolve not in {"true", "false"}:
        raise ActionInputError("resolve must be exactly true or false")
    if not HOST.fullmatch(github_host):
        raise ActionInputError("github-host must be a canonical lowercase DNS host")
    if network_profile and resolve != "true":
        raise ActionInputError("network-profile requires resolve=true")

    base_environment = dict(os.environ)
    base_environment.pop("WV_ACTION_GITHUB_TOKEN", None)
    base_environment.pop(CREDENTIAL_ENV, None)
    common = ["--config", config] if config else []
    temporary_root = Path(action_input("RUNNER_TEMP") or tempfile.gettempdir())
    temporary_root.mkdir(parents=True, exist_ok=True)
    action_temporary = Path(
        tempfile.mkdtemp(prefix="workflow-verifier-action-", dir=temporary_root)
    )
    lock = action_temporary / "workflow-verifier.lock"
    try:
        if resolve == "true":
            resolve_arguments = [
                binary,
                "resolve",
                "--allow-network",
                "--lockfile",
                str(lock),
                *common,
            ]
            if network_profile:
                resolve_arguments.extend(["--network-profile", network_profile])
            resolve_environment = dict(base_environment)
            if token:
                resolve_environment[CREDENTIAL_ENV] = token
                resolve_arguments.extend(
                    [
                        "--auth-from-env",
                        f"github@{github_host}={CREDENTIAL_ENV}",
                    ]
                )
            resolve_arguments.append(target)
            status = run_child(resolve_arguments, resolve_environment, quiet=True)
            if status != 0:
                return status

        report = Path(output).resolve()
        check_arguments = [
            binary,
            "check",
            "--persona",
            persona,
            "--format",
            report_format,
            "--output",
            str(report),
            *common,
        ]
        if resolve == "true":
            check_arguments.extend(["--lockfile", str(lock)])
        check_arguments.append(target)
        status = run_child(check_arguments, base_environment)
        if status != 0:
            return status
        if not report.is_file() or report.is_symlink():
            raise RuntimeError("workflow-verifier did not create a regular report")
        github_output = action_input("GITHUB_OUTPUT")
        if github_output:
            with Path(github_output).open("a", encoding="utf-8", newline="\n") as destination:
                destination.write(f"report={report}\n")
        return 0
    finally:
        shutil.rmtree(action_temporary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActionInputError, RuntimeError) as error:
        print(f"workflow-verifier action: {error}", file=sys.stderr)
        raise SystemExit(2) from None
