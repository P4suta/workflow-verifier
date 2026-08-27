from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

from scripts.fetch_official_projects import _snapshot_digest, load_manifest
from scripts.official_compat import _canonical, _run_analyzer, _verify_expected, analyze


def report(provider: str, *, rule_id: str = "WV-SUPPLY-001") -> bytes:
    value = {
        "completeness": {},
        "configuration": {},
        "diagnostics": [
            {
                "capabilities": [],
                "confidence": "high",
                "evidence": [],
                "fix": None,
                "id": "diagnostic",
                "message": "summary is intentionally excluded from public evidence",
                "rule_id": rule_id,
                "severity": "warning" if rule_id != "YAML-SYNTAX" else "error",
                "span": {},
                "trace": [],
            }
        ],
        "digest": None,
        "gate": {},
        "graphs": [{"provider": provider}],
        "inputs": [{"digest": "sha256:" + "b" * 64, "path": "ci.yml"}],
        "lock": None,
        "persona": "audit",
        "properties": [],
        "provider_profiles": [],
        "schema": "report-v3",
        "semantic_digest": None,
        "snapshot": {},
        "summary": {},
        "tool": {
            "build": {
                "binary_digest": "sha256:" + "c" * 64,
                "compiler": "rustc fixture",
                "implementation": "rust",
                "source_commit": None,
                "target": "fixture-target",
            },
            "name": "workflow-verifier",
            "version": "0.1.0",
        },
    }
    semantic = deepcopy(value)
    semantic.pop("digest")
    semantic.pop("semantic_digest")
    semantic["tool"].pop("build")
    value["semantic_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(semantic, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
    )
    authenticated = deepcopy(value)
    authenticated.pop("digest")
    value["digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(authenticated, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
    )
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"


class OfficialCompatibilityTests(unittest.TestCase):
    @mock.patch("scripts.official_compat.subprocess.run")
    def test_analyzer_uses_the_strict_explicit_cache_contract(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(returncode=0, stdout=report("github"), stderr=b"")

        result = _run_analyzer(Path("workflow-verifier"), Path("."), "fixture", 1e18)

        self.assertEqual(result, report("github"))
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[1:4], ["check", "--cache-mode", "off"])
        self.assertNotIn("--no-cache", arguments)

    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        manifest = Path("official/official-projects-v1.json").resolve()
        document, manifest_digest = load_manifest(manifest)
        snapshots = root / "snapshots"
        snapshots.mkdir()
        acquired = []
        for project in document["projects"]:
            project_root = snapshots / project["id"]
            project_root.mkdir()
            (project_root / "ci.yml").write_text("jobs: {}\n", encoding="utf-8")
            snapshot_digest, files = _snapshot_digest(project_root)
            acquired.append(
                {
                    "files": files,
                    "id": project["id"],
                    "provider": project["provider"],
                    "repository": project["repository"],
                    "revision": project["revision"],
                    "snapshot_digest": snapshot_digest,
                    "tree": project["tree"],
                }
            )
        (snapshots / "acquisition-v1.json").write_text(
            json.dumps(
                {
                    "manifest_digest": manifest_digest,
                    "mode": "pinned",
                    "projects": acquired,
                    "schema": "official-project-acquisition-v1",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        analyzer = root / "workflow-verifier.exe"
        analyzer.write_bytes(b"fixture")
        return manifest, snapshots, analyzer

    def test_all_projects_finish_deterministically_and_findings_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, snapshots, analyzer = self.fixture(Path(temporary))

            def run(_analyzer: Path, _cwd: Path, target: str, _deadline: float) -> bytes:
                acquisition = json.loads((snapshots / "acquisition-v1.json").read_text())
                provider = next(
                    item["provider"] for item in acquisition["projects"] if item["id"] == target
                )
                return report(provider)

            with mock.patch("scripts.official_compat._run_analyzer", side_effect=run):
                result = analyze(manifest, snapshots, analyzer)
            self.assertTrue(result["passed"])
            self.assertEqual(result["repositories"], 8)
            self.assertEqual(
                result["providers"],
                {provider: 2 for provider in ("github", "gitlab", "azure", "circleci")},
            )
            self.assertTrue(all(item["diagnostics"]["warning"] == 1 for item in result["projects"]))
            self.assertTrue(
                all(item["semantic_digest"].startswith("sha256:") for item in result["projects"])
            )
            self.assertTrue(
                all(
                    item["semantic_digest"]
                    == json.loads(report(item["provider"]))["semantic_digest"]
                    for item in result["projects"]
                )
            )
            self.assertNotIn("message", json.dumps(result))

    def test_legacy_or_tampered_reports_are_rejected_as_product_evidence(self) -> None:
        document = json.loads(report("github"))
        document["schema"] = "report-v2"
        legacy = json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        from scripts.official_compat import _report_summary

        with self.assertRaisesRegex(ValueError, "report-v3"):
            _report_summary(legacy, {"id": "fixture", "provider": "github", "files": 1})

        document = json.loads(report("github"))
        document["summary"] = {"tampered": True}
        tampered = json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "digest"):
            _report_summary(tampered, {"id": "fixture", "provider": "github", "files": 1})

    def test_expected_baseline_ignores_only_platform_bound_report_digests(self) -> None:
        base = {
            "projects": [
                {
                    "id": "fixture",
                    "report_digest": "sha256:" + "1" * 64,
                    "report_sha256": "sha256:" + "2" * 64,
                    "semantic_digest": "sha256:" + "3" * 64,
                }
            ],
            "schema": "official-compat-v1",
        }
        actual = json.loads(json.dumps(base))
        actual["projects"][0]["report_digest"] = "sha256:" + "4" * 64
        actual["projects"][0]["report_sha256"] = "sha256:" + "5" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "expected.json"
            expected_raw = _canonical(base)
            expected.write_bytes(expected_raw)
            checksum = root / "expected.sha256"
            checksum.write_text(
                "sha256:" + hashlib.sha256(expected_raw).hexdigest() + "\n",
                encoding="ascii",
            )
            _verify_expected(_canonical(actual), expected, checksum)
            actual["projects"][0]["semantic_digest"] = "sha256:" + "6" * 64
            with self.assertRaisesRegex(ValueError, "differs"):
                _verify_expected(_canonical(actual), expected, checksum)

    def test_yaml_false_positive_nondeterminism_and_snapshot_tamper_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, snapshots, analyzer = self.fixture(Path(temporary))
            acquisition = json.loads((snapshots / "acquisition-v1.json").read_text())
            providers = {item["id"]: item["provider"] for item in acquisition["projects"]}

            with mock.patch(
                "scripts.official_compat._run_analyzer",
                side_effect=lambda _a, _c, target, _d: report(
                    providers[target], rule_id="YAML-SYNTAX"
                ),
            ):
                with self.assertRaisesRegex(ValueError, "valid upstream YAML"):
                    analyze(manifest, snapshots, analyzer)

            calls = 0

            def drifting(_a: Path, _c: Path, target: str, _d: float) -> bytes:
                nonlocal calls
                calls += 1
                raw = report(providers[target])
                return raw if calls % 2 else raw.replace(b"diagnostic", b"different", 1)

            with mock.patch("scripts.official_compat._run_analyzer", side_effect=drifting):
                with self.assertRaisesRegex(ValueError, "not deterministic"):
                    analyze(manifest, snapshots, analyzer)

            first = snapshots / acquisition["projects"][0]["id"] / "ci.yml"
            first.write_text("tampered: true\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "snapshot bytes"):
                analyze(manifest, snapshots, analyzer)


if __name__ == "__main__":
    unittest.main()
