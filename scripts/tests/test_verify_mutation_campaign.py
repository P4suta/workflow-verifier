import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.verify_mutation_campaign import (
    CampaignError,
    aggregate,
    load_catalog,
    load_plan,
    verify_shard,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def mutation(identifier: str, path: str) -> dict[str, object]:
    full_id = identifier * 64
    return {
        "id": full_id[:20],
        "full_id": full_id,
        "path": path,
        "range": {
            "start_byte": 1,
            "end_byte": 2,
            "start_line": 1,
            "start_column": 0,
            "end_line": 1,
            "end_column": 1,
        },
        "family": "boolean-literal",
        "rule": "boolean-literal@1",
        "original": "true",
        "replacement": "false",
        "source_digest": "a" * 64,
    }


def result(mutant: dict[str, object]) -> dict[str, object]:
    return {
        "mutant": mutant,
        "outcome": "killed",
        "error": None,
        "duration_seconds": 0.1,
        "cached": False,
        "stages": [],
        "timeout_confirmed": False,
        "timeout_retry": None,
        "expected_survivor": False,
        "expectation": None,
        "stdout": {"contents": "", "truncated": False, "total_bytes": 0},
        "stderr": {"contents": "", "truncated": False, "total_bytes": 0},
    }


def catalog_mutant(mutant: dict[str, object]) -> dict[str, object]:
    return {
        field: mutant[field]
        for field in ("id", "full_id", "path", "range", "family", "rule")
    }


def report(mutants: list[dict[str, object]]) -> dict[str, object]:
    count = len(mutants)
    return {
        "document_type": "ocaml-mutants.run-report-v1",
        "schema_version": 1,
        "run_id": "test-run",
        "status": "completed",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "workspace": {"digest": "b" * 64, "toolchain": "OCaml 5.5.0"},
        "profile": "balanced",
        "selection": {
            "description": "mutants:"
            + ",".join(str(mutant["full_id"]) for mutant in mutants)
        },
        "test": {
            "command": ["dune", "runtest", "--force"],
            "baseline_duration_seconds": 1.0,
            "timeout_seconds": 10.0,
            "stages": [],
        },
        "cache": {"mode": "off", "key": "unavailable"},
        "summary": {
            "kind": "complete",
            "total": count,
            "executed": count,
            "not_run": 0,
            "killed": count,
            "survived": 0,
            "timeout": 0,
            "unconfirmed_timeouts": 0,
            "inconclusive": 0,
            "error": 0,
            "expected_survivors": 0,
            "unexpected_survivors": 0,
            "unfulfilled_expectations": 0,
            "detected": count,
            "score": 100.0,
        },
        "mutants": [result(mutant) for mutant in mutants],
        "not_run": [],
        "expectations": [],
        "failure": None,
        "skips": [],
        "warnings": [],
    }


class MutationCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "lib/domain").mkdir(parents=True)
        (self.root / "lib/verifier").mkdir(parents=True)
        (self.root / "lib/domain/condition.ml").write_text("let enabled = true\n")
        (self.root / "lib/verifier/verifier.ml").write_text("let safe = true\n")
        self.config = self.root / ".ocaml-mutants.toml"
        self.config.write_text(
            """version = 1

[mutation]
profile = "balanced"
include = ["lib/domain/*.ml", "lib/verifier/*.ml"]
exclude = []
operators = ["boolean-literal"]
""",
            encoding="utf-8",
        )
        self.manifest = self.root / "mutation-shards-v1.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema": "mutation-shards-v1",
                    "max_mutants_per_shard": 128,
                    "shards": [
                        {
                            "name": f"hex-{prefix}",
                            "prefixes": [prefix],
                        }
                        for prefix in "0123456789abcdef"
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.domain = mutation("1", "lib/domain/condition.ml")
        self.verifier = mutation("2", "lib/verifier/verifier.ml")
        self.catalog = self.root / "mutation-catalog.json"
        self.catalog.write_text(
            json.dumps(
                {
                    "document_type": "ocaml-mutants.catalog-v1",
                    "schema_version": 1,
                    "workspace": {"digest": "b" * 64, "toolchain": "OCaml 5.5.0"},
                    "profile": "balanced",
                    "selection": "all",
                    "mutants": [catalog_mutant(self.domain), catalog_mutant(self.verifier)],
                    "skips": [],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_grouped_two_nibble_manifest(self) -> dict[str, object]:
        alphabet = "0123456789abcdef"
        shards = []
        for first in alphabet:
            for start in range(0, len(alphabet), 4):
                prefixes = [first + second for second in alphabet[start : start + 4]]
                shards.append(
                    {
                        "name": f"hex-{prefixes[0]}-{prefixes[-1]}",
                        "prefixes": prefixes,
                    }
                )
        document: dict[str, object] = {
            "schema": "mutation-shards-v1",
            "max_mutants_per_shard": 96,
            "shards": shards,
        }
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        return document

    def write_report(self, name: str, mutants: list[dict[str, object]]) -> Path:
        path = self.root / f"mutation-report-{name}.json"
        path.write_text(json.dumps(report(mutants)), encoding="utf-8")
        (self.root / f"mutation-runner-exit-{name}.txt").write_bytes(b"0\n")
        return path

    def write_surviving_report(
        self, name: str, mutant: dict[str, object]
    ) -> Path:
        document = report([mutant])
        document["mutants"][0]["outcome"] = "survived"
        document["summary"].update(
            {
                "detected": 0,
                "killed": 0,
                "score": 0.0,
                "survived": 1,
                "unexpected_survivors": 1,
            }
        )
        path = self.root / f"mutation-report-{name}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        (self.root / f"mutation-runner-exit-{name}.txt").write_bytes(b"1\n")
        return path

    def test_complete_catalog_partition_and_aggregate_pass(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        self.assertEqual(plan.names[0], "hex-0")
        self.assertEqual(plan.names[-1], "hex-f")
        domain_report = self.write_report("hex-1", [self.domain])
        gate = verify_shard(
            plan, self.catalog, "hex-1", domain_report, runner_exit_code=0
        )
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["mutants"], 1)
        self.write_report("hex-2", [self.verifier])
        campaign = aggregate(plan, self.catalog, self.root)
        self.assertTrue(campaign["passed"])
        self.assertEqual(campaign["mutants"], 2)
        self.assertEqual(campaign["detected"], 2)
        self.assertEqual([item["name"] for item in campaign["shards"]], ["hex-1", "hex-2"])

    def test_missing_catalog_mutant_from_shard_fails_closed(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        empty = self.write_report("hex-1", [])
        with self.assertRaisesRegex(CampaignError, "catalog partition"):
            verify_shard(
                plan, self.catalog, "hex-1", empty, runner_exit_code=0
            )

    def test_mutant_assigned_to_wrong_shard_fails_closed(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        wrong = self.write_report("hex-1", [self.verifier])
        with self.assertRaisesRegex(CampaignError, "catalog partition"):
            verify_shard(
                plan, self.catalog, "hex-1", wrong, runner_exit_code=0
            )

    def test_overlapping_manifest_selector_is_rejected(self) -> None:
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["shards"][2]["prefixes"] = ["1"]
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "assigned more than once"):
            load_plan(self.manifest, self.config, self.root)

    def test_manifest_must_cover_every_hex_prefix(self) -> None:
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["shards"] = document["shards"][:-1]
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "has no shard"):
            load_plan(self.manifest, self.config, self.root)

    def test_grouped_two_nibble_partition_is_complete(self) -> None:
        self.write_grouped_two_nibble_manifest()
        plan = load_plan(self.manifest, self.config, self.root)
        self.assertEqual(len(plan.shards), 64)
        self.assertEqual(plan.assignment("00" + "0" * 62).name, "hex-00-03")
        self.assertEqual(plan.assignment("03" + "f" * 62).name, "hex-00-03")
        self.assertEqual(plan.assignment("04" + "0" * 62).name, "hex-04-07")
        self.assertEqual(plan.assignment("ff" + "f" * 62).name, "hex-fc-ff")

    def test_repository_manifest_uses_complete_64_shard_partition(self) -> None:
        plan = load_plan(
            REPOSITORY_ROOT / "scripts/mutation-shards-v1.json",
            REPOSITORY_ROOT / ".ocaml-mutants.toml",
            REPOSITORY_ROOT,
        )
        self.assertEqual(len(plan.shards), 64)
        self.assertEqual(plan.names[0], "hex-00-03")
        self.assertEqual(plan.names[-1], "hex-fc-ff")
        self.assertEqual(plan.max_mutants_per_shard, 96)
        self.assertEqual(sum(len(shard.prefixes) for shard in plan.shards), 256)

    def test_catalog_partition_cannot_exceed_declared_worker_bound(self) -> None:
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["max_mutants_per_shard"] = 1
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        second = mutation("1", "lib/domain/condition.ml")
        second["full_id"] = "10" + "0" * 62
        second["id"] = second["full_id"][:20]
        self.catalog.write_text(
            json.dumps(
                {
                    "document_type": "ocaml-mutants.catalog-v1",
                    "schema_version": 1,
                    "workspace": {"digest": "b" * 64, "toolchain": "OCaml 5.5.0"},
                    "profile": "balanced",
                    "selection": "all",
                    "mutants": [
                        catalog_mutant(self.domain),
                        catalog_mutant(second),
                    ],
                    "skips": [],
                }
            ),
            encoding="utf-8",
        )
        plan = load_plan(self.manifest, self.config, self.root)
        with self.assertRaisesRegex(CampaignError, "exceeds declared maximum"):
            load_catalog(plan, self.catalog)

    def test_two_nibble_partition_rejects_a_gap(self) -> None:
        document = self.write_grouped_two_nibble_manifest()
        document["shards"][0]["prefixes"].remove("03")
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "prefix 03 has no shard"):
            load_plan(self.manifest, self.config, self.root)

    def test_two_nibble_partition_rejects_an_overlap(self) -> None:
        document = self.write_grouped_two_nibble_manifest()
        document["shards"][1]["prefixes"].append("03")
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "prefix 03 is assigned more than once"):
            load_plan(self.manifest, self.config, self.root)

    def test_prefix_partition_rejects_parent_child_overlap(self) -> None:
        document = self.write_grouped_two_nibble_manifest()
        document["shards"].append({"name": "hex-parent-0", "prefixes": ["0"]})
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "prefix 00 is assigned more than once"):
            load_plan(self.manifest, self.config, self.root)

    def test_prefixes_are_bounded_lowercase_hexadecimal(self) -> None:
        cases = (
            ("A0", "lowercase hexadecimal"),
            ("", "nonempty strings"),
            ("0" * 65, "lowercase hexadecimal"),
        )
        for invalid, message in cases:
            with self.subTest(invalid=invalid):
                document = self.write_grouped_two_nibble_manifest()
                document["shards"][0]["prefixes"][0] = invalid
                self.manifest.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(CampaignError, message):
                    load_plan(self.manifest, self.config, self.root)

    def test_report_metadata_must_match_catalog(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        path = self.write_report("hex-1", [self.domain])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["workspace"]["digest"] = "c" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "workspace digest"):
            verify_shard(
                plan, self.catalog, "hex-1", path, runner_exit_code=0
            )

    def test_survivor_is_preserved_as_failed_shard_and_campaign_evidence(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        domain_report = self.write_surviving_report("hex-1", self.domain)
        gate = verify_shard(
            plan, self.catalog, "hex-1", domain_report, runner_exit_code=1
        )
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["runner_exit_code"], 1)
        self.assertEqual(gate["unexpected_survivors"], 1)
        self.assertEqual(gate["failures"], ["one unexpected mutant survived"])

        self.write_report("hex-2", [self.verifier])
        campaign = aggregate(plan, self.catalog, self.root)
        self.assertFalse(campaign["passed"])
        self.assertEqual(campaign["unexpected_survivors"], 1)
        self.assertEqual(
            campaign["failures"], ["hex-1: one unexpected mutant survived"]
        )

    def test_runner_exit_code_must_agree_with_the_authenticated_gate(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        passing = self.write_report("hex-1", [self.domain])
        with self.assertRaisesRegex(CampaignError, "runner exit code"):
            verify_shard(
                plan, self.catalog, "hex-1", passing, runner_exit_code=1
            )

        failing = self.write_surviving_report("hex-1", self.domain)
        with self.assertRaisesRegex(CampaignError, "runner exit code"):
            verify_shard(
                plan, self.catalog, "hex-1", failing, runner_exit_code=0
            )

    def test_catalog_mutant_metadata_is_strict(self) -> None:
        plan = load_plan(self.manifest, self.config, self.root)
        document = json.loads(self.catalog.read_text(encoding="utf-8"))
        document["mutants"][0]["range"]["start_byte"] = True
        document["mutants"][0]["rule"] = "unversioned"
        self.catalog.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(CampaignError, "range|rule"):
            load_catalog(plan, self.catalog)

    def test_direct_script_cli_is_runnable(self) -> None:
        script = Path(__file__).resolve().parents[1] / "verify_mutation_campaign.py"
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                "select",
                "--manifest",
                str(self.manifest),
                "--config",
                str(self.config),
                "--workspace",
                str(self.root),
                "--shard",
                "hex-1",
                "--field",
                "mutants",
                "--catalog",
                str(self.catalog),
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "1" * 64 + "\n")

    def test_verify_shard_cli_writes_failed_gate_before_exiting_one(self) -> None:
        script = Path(__file__).resolve().parents[1] / "verify_mutation_campaign.py"
        report_path = self.write_surviving_report("hex-1", self.domain)
        output = self.root / "mutation-gate-hex-1.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                "verify-shard",
                "--manifest",
                str(self.manifest),
                "--config",
                str(self.config),
                "--workspace",
                str(self.root),
                "--catalog",
                str(self.catalog),
                "--shard",
                "hex-1",
                "--report",
                str(report_path),
                "--runner-exit",
                str(self.root / "mutation-runner-exit-hex-1.txt"),
                "--output",
                str(output),
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertTrue(output.is_file())
        gate = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["runner_exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
