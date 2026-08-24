from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from unittest import mock

from scripts import mutation_resource_guard


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class FakeResource:
    RLIMIT_AS = 1
    RLIMIT_CORE = 2
    RLIMIT_FSIZE = 3
    RLIMIT_NOFILE = 4
    RLIMIT_NPROC = 5
    RLIM_INFINITY = -1

    def __init__(self) -> None:
        self.current = {
            self.RLIMIT_AS: (self.RLIM_INFINITY, self.RLIM_INFINITY),
            self.RLIMIT_CORE: (self.RLIM_INFINITY, self.RLIM_INFINITY),
            self.RLIMIT_FSIZE: (128, 128),
            self.RLIMIT_NOFILE: (2048, 4096),
            self.RLIMIT_NPROC: (512, 1024),
        }
        self.applied: list[tuple[int, tuple[int, int]]] = []

    def getrlimit(self, resource: int) -> tuple[int, int]:
        return self.current[resource]

    def setrlimit(self, resource: int, value: tuple[int, int]) -> None:
        self.applied.append((resource, value))
        self.current[resource] = value


class MutationResourceGuardTests(unittest.TestCase):
    def test_contract_is_canonical_and_bounded(self) -> None:
        self.assertEqual(
            mutation_resource_guard.contract(),
            {
                "address_space_bytes": 1_610_612_736,
                "core_file_bytes": 0,
                "file_bytes": 268_435_456,
                "open_files": 1024,
                "processes": 256,
                "schema": "mutation-resource-guard-v1",
            },
        )

    def test_guard_never_raises_an_existing_hard_limit(self) -> None:
        resources = FakeResource()
        mutation_resource_guard.apply_limits(resources)
        self.assertEqual(
            resources.applied,
            [
                (resources.RLIMIT_AS, (1_610_612_736, 1_610_612_736)),
                (resources.RLIMIT_CORE, (0, 0)),
                (resources.RLIMIT_FSIZE, (128, 128)),
                (resources.RLIMIT_NOFILE, (1024, 1024)),
                (resources.RLIMIT_NPROC, (256, 256)),
            ],
        )

    def test_missing_kernel_control_fails_closed(self) -> None:
        class IncompleteResource:
            RLIMIT_AS = 1

        with self.assertRaisesRegex(RuntimeError, "RLIMIT_CORE"):
            mutation_resource_guard.apply_limits(IncompleteResource())

    def test_empty_command_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "command"):
            mutation_resource_guard.command_after_separator([])
        with self.assertRaisesRegex(ValueError, "separator"):
            mutation_resource_guard.command_after_separator(["true"])

    def test_every_mutation_stage_is_guarded_and_single_job(self) -> None:
        configuration = tomllib.loads(
            (REPOSITORY_ROOT / ".ocaml-mutants.toml").read_text(encoding="utf-8")
        )
        stages = configuration["test"]["stages"]
        self.assertGreaterEqual(len(stages), 1)
        for stage in stages:
            with self.subTest(stage=stage["name"]):
                command = stage["command"]
                self.assertEqual(
                    command[:5],
                    [
                        "python3",
                        "-B",
                        "scripts/mutation_resource_guard.py",
                        "--",
                        "dune",
                    ],
                )
                self.assertNotIn("--jobs=1", command)
                jobs = command.index("-j")
                self.assertEqual(command[jobs + 1], "1")

    def test_check_mode_applies_limits_before_attesting(self) -> None:
        resources = FakeResource()
        with (
            mock.patch.object(
                mutation_resource_guard, "_linux_resources", return_value=resources
            ),
            mock.patch("builtins.print") as printed,
        ):
            self.assertEqual(mutation_resource_guard.main(["--check"]), 0)
        self.assertEqual(len(resources.applied), 5)
        printed.assert_called_once_with(
            '{"address_space_bytes":1610612736,"core_file_bytes":0,'
            '"file_bytes":268435456,"open_files":1024,"processes":256,'
            '"schema":"mutation-resource-guard-v1"}'
        )

    @unittest.skipUnless(sys.platform == "linux", "the production guard is Linux-only")
    def test_check_mode_emits_the_canonical_contract(self) -> None:
        script = Path(mutation_resource_guard.__file__).resolve()
        completed = subprocess.run(
            [sys.executable, "-B", str(script), "--check"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout,
            '{"address_space_bytes":1610612736,"core_file_bytes":0,'
            '"file_bytes":268435456,"open_files":1024,"processes":256,'
            '"schema":"mutation-resource-guard-v1"}\n',
        )


if __name__ == "__main__":
    unittest.main()
