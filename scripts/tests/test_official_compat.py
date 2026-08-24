from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.fetch_official_projects import _snapshot_digest, load_manifest
from scripts.official_compat import analyze


def report(provider: str, *, rule_id: str = "WV-SUPPLY-001") -> bytes:
    value = {
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
        "digest": "sha256:" + "a" * 64,
        "graphs": [{"provider": provider}],
        "inputs": [{"digest": "sha256:" + "b" * 64, "path": "ci.yml"}],
        "persona": "audit",
        "properties": [],
        "schema": "report-v1",
        "summary": {},
        "tool": {"name": "workflow-verifier", "version": "0.1.0"},
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"


class OfficialCompatibilityTests(unittest.TestCase):
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
                provider = next(item["provider"] for item in acquisition["projects"] if item["id"] == target)
                return report(provider)

            with mock.patch("scripts.official_compat._run_analyzer", side_effect=run):
                result = analyze(manifest, snapshots, analyzer)
            self.assertTrue(result["passed"])
            self.assertEqual(result["repositories"], 8)
            self.assertEqual(result["providers"], {provider: 2 for provider in ("github", "gitlab", "azure", "circleci")})
            self.assertTrue(all(item["diagnostics"]["warning"] == 1 for item in result["projects"]))
            self.assertNotIn("message", json.dumps(result))

    def test_yaml_false_positive_nondeterminism_and_snapshot_tamper_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, snapshots, analyzer = self.fixture(Path(temporary))
            acquisition = json.loads((snapshots / "acquisition-v1.json").read_text())
            providers = {item["id"]: item["provider"] for item in acquisition["projects"]}

            with mock.patch(
                "scripts.official_compat._run_analyzer",
                side_effect=lambda _a, _c, target, _d: report(providers[target], rule_id="YAML-SYNTAX"),
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
