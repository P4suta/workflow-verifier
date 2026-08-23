from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.verify_release_evidence import PLATFORMS, PROVIDERS, verify


REVISION = "a" * 40
TAG = "v1.2.3"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(root: Path) -> Path:
    repositories = []
    for provider in PROVIDERS:
        for index in range(100):
            repositories.append(
                {
                    "allowed": [],
                    "expected": ["known"] if index == 0 else [],
                    "id": f"{provider}-{index:03d}",
                    "missing": [],
                    "provider": provider,
                    "report_digest": "sha256:" + "b" * 64,
                    "revision": f"{index + 1:040x}",
                    "source_digest": "sha256:" + "c" * 64,
                    "unexpected": [],
                    "url": f"https://example.test/{provider}/{index}",
                }
            )
    corpus = root / "corpus-report-v1.json"
    write_json(
        corpus,
        {
            "failures": [],
            "manifest_digest": "sha256:" + "d" * 64,
            "metrics": {
                "allowed": 0,
                "false_negative": 0,
                "false_positive": 0,
                "precision": "1.000000",
                "recall": "1.000000",
                "true_positive": 4,
            },
            "passed": True,
            "providers": {provider: 100 for provider in PROVIDERS},
            "repositories": repositories,
            "schema": "corpus-report-v1",
        },
    )

    performance = []
    for platform in PLATFORMS:
        path = root / "performance" / f"{platform}.json"
        write_json(
            path,
            {
                "baseline": {"digest": "sha256:" + "e" * 64, "revision": "1" * 40},
                "comparisons": [
                    {
                        "baseline_median_ns": "100",
                        "change_percent": "0.000",
                        "current_median_ns": "100",
                        "explanation": None,
                        "mode": mode,
                        "scenario": "four-provider-analysis",
                        "status": "within-limit",
                    }
                    for mode in ("cold", "incremental", "warm")
                ],
                "current": {"digest": "sha256:" + "f" * 64, "revision": REVISION},
                "environment": {"executor": "approved-runner"},
                "failures": [],
                "passed": True,
                "schema": "performance-comparison-v1",
                "threshold_percent": "10.000",
            },
        )
        performance.append(
            {
                "digest": digest(path),
                "path": path.relative_to(root).as_posix(),
                "platform": platform,
                "review": "https://github.com/P4suta/workflow-verifier/issues/10",
            }
        )

    report = root / "independent-security-review.pdf"
    report.write_bytes(b"independent review report")
    bundle = root / "independent-security-review.pdf.sigstore.json"
    write_json(bundle, {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"})
    manifest = root / "release-evidence-v1.json"
    write_json(
        manifest,
        {
            "corpus": {
                "digest": digest(corpus),
                "path": corpus.name,
                "review": "https://github.com/P4suta/workflow-verifier/issues/9",
            },
            "performance": performance,
            "revision": REVISION,
            "schema": "release-evidence-v1",
            "security_review": {
                "bundle_digest": digest(bundle),
                "bundle_path": bundle.name,
                "certificate_identity": "https://github.com/reviewer/audit/.github/workflows/sign.yml@refs/tags/v1",
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                "decision": "approved",
                "independence": "The reviewer did not implement or maintain the reviewed code.",
                "report_digest": digest(report),
                "report_path": report.name,
                "review": "https://github.com/P4suta/workflow-verifier/issues/11",
                "reviewer": "Independent Security Lab",
            },
            "tag": TAG,
        },
    )
    return manifest


class ReleaseEvidenceTests(unittest.TestCase):
    def test_complete_digest_bound_external_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            result = verify(manifest, revision=REVISION, tag=TAG)
            self.assertEqual(result["report"], "independent-security-review.pdf")
            self.assertEqual(result["bundle"], "independent-security-review.pdf.sigstore.json")

    def test_tampered_file_or_wrong_candidate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            (root / "corpus-report-v1.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                verify(manifest, revision=REVISION, tag=TAG)
            fixture(root)
            with self.assertRaisesRegex(ValueError, "revision"):
                verify(manifest, revision="9" * 40, tag=TAG)

    def test_failed_or_incomplete_publication_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["security_review"]["decision"] = "rejected"
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "approved"):
                verify(manifest, revision=REVISION, tag=TAG)

            manifest = fixture(root)
            performance_path = root / document["performance"][0]["path"]
            comparison = json.loads(performance_path.read_text(encoding="utf-8"))
            comparison["passed"] = False
            write_json(performance_path, comparison)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["performance"][0]["digest"] = digest(performance_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "performance.*pass"):
                verify(manifest, revision=REVISION, tag=TAG)

    def test_review_signature_must_be_external_and_workflow_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["security_review"]["certificate_identity"] = (
                "https://github.com/P4suta/workflow-verifier/.github/workflows/sign.yml@refs/tags/v1"
            )
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "outside"):
                verify(manifest, revision=REVISION, tag=TAG)

            document["security_review"]["certificate_identity"] = "https://example.test/reviewer"
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "tagged GitHub Actions"):
                verify(manifest, revision=REVISION, tag=TAG)


if __name__ == "__main__":
    unittest.main()
