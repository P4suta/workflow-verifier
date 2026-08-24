from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.verify_release_evidence import (
    MAINTAINER_EMAIL,
    MAINTAINER_PUBLIC_KEY,
    PLATFORMS,
    PROVIDERS,
    REQUIRED_SECURITY_SCOPE,
    _verify_repository_relation,
    _verify_signature,
    verify,
)


SUBJECT = "a" * 40
EVIDENCE = "b" * 40
TAG = "v0.1.0"
REVIEW = "https://github.com/P4suta/workflow-verifier/pull/2"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def corpus_fixture(root: Path) -> Path:
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
                    "report_digest": "sha256:" + "c" * 64,
                    "revision": f"{index + 1:040x}",
                    "source_digest": "sha256:" + "d" * 64,
                    "unexpected": [],
                    "url": f"https://example.test/{provider}/{index}",
                }
            )
    path = root / "corpus-report-v1.json"
    write_json(
        path,
        {
            "failures": [],
            "manifest_digest": "sha256:" + "e" * 64,
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
    return path


def official_fixture(root: Path) -> Path:
    projects = []
    for provider in PROVIDERS:
        for index in range(2):
            projects.append(
                {
                    "diagnostics": {
                        "critical": 0,
                        "error": index,
                        "note": 0,
                        "total": index + 1,
                        "warning": 1,
                    },
                    "files": 1,
                    "graphs": 1,
                    "id": f"{provider}-{index}",
                    "inputs": 1,
                    "provider": provider,
                    "report_digest": "sha256:" + "1" * 64,
                    "report_sha256": "sha256:" + "2" * 64,
                    "revision": f"{index + 1:040x}",
                    "snapshot_digest": "sha256:" + "3" * 64,
                    "tree": f"{index + 3:040x}",
                }
            )
    path = root / "official-compat-v1.json"
    write_json(
        path,
        {
            "acquisition_digest": "sha256:" + "4" * 64,
            "failures": [],
            "manifest_digest": "sha256:" + "5" * 64,
            "passed": True,
            "projects": projects,
            "providers": {provider: 2 for provider in PROVIDERS},
            "repositories": 8,
            "schema": "official-compat-v1",
            "tool_version": "0.1.0",
        },
    )
    return path


def fixture(root: Path) -> Path:
    corpus = corpus_fixture(root)
    official = official_fixture(root)
    performance = []
    for platform in PLATFORMS:
        path = root / "performance" / f"{platform}.json"
        write_json(
            path,
            {
                "baseline": {"digest": "sha256:" + "6" * 64, "revision": "1" * 40},
                "comparisons": [
                    {
                        "baseline_median_ns": "100",
                        "change_percent": "0.000",
                        "current_median_ns": "100",
                        "explanation": None,
                        "mode": mode,
                        "scenario": scenario,
                        "status": "within-limit",
                    }
                    for scenario in ("four-provider-analysis", "arcade-scale-analysis")
                    for mode in ("cold", "incremental", "warm")
                ],
                "current": {"digest": "sha256:" + "7" * 64, "revision": SUBJECT},
                "environment": {"executor": "approved-runner", "platform": platform},
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
            }
        )

    attestation = root / "maintainer-security-attestation-v1.json"
    write_json(
        attestation,
        {
            "completed_at": "2026-08-25T00:00:00+09:00",
            "decision": "approve",
            "findings": [
                {
                    "due_date": None,
                    "id": "WV-SEC-001",
                    "owner": None,
                    "severity": "high",
                    "status": "resolved",
                    "summary": "Resolved parser denial-of-service finding.",
                    "tracking_url": None,
                }
            ],
            "maintainer": "P4suta",
            "planned_tag": TAG,
            "residual_risks": [],
            "review": REVIEW,
            "schema": "maintainer-security-attestation-v1",
            "scope": sorted(REQUIRED_SECURITY_SCOPE),
            "subject_commit": SUBJECT,
        },
    )
    signature = root / "maintainer-security-attestation-v1.json.sig"
    signature.write_text("dummy detached signature\n", encoding="ascii")
    (root / "maintainer-allowed-signers").write_text(
        f"{MAINTAINER_EMAIL} {MAINTAINER_PUBLIC_KEY}\n", encoding="ascii"
    )
    manifest = root / "release-evidence-v2.json"
    write_json(
        manifest,
        {
            "corpus": {"digest": digest(corpus), "path": corpus.name},
            "maintainer": "P4suta",
            "official_compat": {"digest": digest(official), "path": official.name},
            "performance": performance,
            "planned_tag": TAG,
            "review": REVIEW,
            "schema": "release-evidence-v2",
            "security_attestation": {
                "digest": digest(attestation),
                "path": attestation.name,
                "signature_digest": digest(signature),
                "signature_path": signature.name,
            },
            "subject_commit": SUBJECT,
        },
    )
    return manifest


def verify_fixture(manifest: Path, *, revision: str = EVIDENCE) -> dict[str, str]:
    with (
        patch("scripts.verify_release_evidence._verify_repository_relation") as relation,
        patch("scripts.verify_release_evidence._verify_signature") as signature,
    ):
        result = verify(manifest, revision=revision, tag=TAG)
    relation.assert_called_once()
    signature.assert_called_once()
    return result


class ReleaseEvidenceTests(unittest.TestCase):
    def test_complete_two_commit_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            result = verify_fixture(manifest)
            self.assertEqual(result["subject_commit"], SUBJECT)
            self.assertEqual(result["attestation"], "maintainer-security-attestation-v1.json")

    def test_tampered_file_or_wrong_candidate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            (root / "corpus-report-v1.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                verify_fixture(manifest)
            manifest = fixture(root)
            with self.assertRaisesRegex(ValueError, "child"):
                verify_fixture(manifest, revision=SUBJECT)

    def test_incomplete_security_attestation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            attestation_path = root / document["security_attestation"]["path"]
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            attestation["findings"][0]["status"] = "accepted"
            attestation["findings"][0]["tracking_url"] = REVIEW
            attestation["findings"][0]["owner"] = "P4suta"
            attestation["findings"][0]["due_date"] = "2026-09-30"
            write_json(attestation_path, attestation)
            document["security_attestation"]["digest"] = digest(attestation_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "critical and high"):
                verify_fixture(manifest)

            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            attestation_path = root / document["security_attestation"]["path"]
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            attestation["scope"].pop()
            write_json(attestation_path, attestation)
            document["security_attestation"]["digest"] = digest(attestation_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "scope"):
                verify_fixture(manifest)

    def test_accepted_risk_requires_tracking_owner_and_due_date(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            attestation_path = root / document["security_attestation"]["path"]
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            attestation["residual_risks"] = [
                {
                    "description": "Tracked medium residual risk.",
                    "due_date": None,
                    "id": "WV-RISK-001",
                    "owner": "P4suta",
                    "severity": "medium",
                    "tracking_url": REVIEW,
                }
            ]
            write_json(attestation_path, attestation)
            document["security_attestation"]["digest"] = digest(attestation_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "due_date"):
                verify_fixture(manifest)

    def test_performance_and_official_reports_bind_subject_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            official_path = root / document["official_compat"]["path"]
            official = json.loads(official_path.read_text(encoding="utf-8"))
            official["tool_version"] = "0.1.0-dev"
            write_json(official_path, official)
            document["official_compat"]["digest"] = digest(official_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "tool version"):
                verify_fixture(manifest)

    def test_performance_requires_the_arcade_scale_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            record = document["performance"][0]
            performance_path = root / record["path"]
            performance = json.loads(performance_path.read_text(encoding="utf-8"))
            performance["comparisons"] = [
                comparison
                for comparison in performance["comparisons"]
                if comparison["scenario"] != "arcade-scale-analysis"
            ]
            write_json(performance_path, performance)
            record["digest"] = digest(performance_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "required scenarios"):
                verify_fixture(manifest)

    def test_performance_report_binds_its_platform_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            record = document["performance"][0]
            performance_path = root / record["path"]
            performance = json.loads(performance_path.read_text(encoding="utf-8"))
            performance["environment"]["platform"] = "windows-x86_64"
            write_json(performance_path, performance)
            record["digest"] = digest(performance_path)
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "platform identity"):
                verify_fixture(manifest)

    def test_repository_relation_requires_single_parent_scoped_signed_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            evidence = repository / "release-evidence" / "release-evidence-v2.json"
            evidence.parent.mkdir()
            evidence.write_text("{}\n", encoding="utf-8")

            def valid_git(_repository: Path, arguments: list[str]) -> bytes:
                if arguments == ["rev-parse", "--show-toplevel"]:
                    return f"{repository}\n".encode()
                if arguments[0:2] == ["rev-parse", "--verify"]:
                    return f"{EVIDENCE}\n".encode()
                if arguments[0] == "rev-list":
                    return f"{EVIDENCE} {SUBJECT}\n".encode()
                if arguments[0] == "diff-tree":
                    return b"release-evidence/release-evidence-v2.json\0"
                if arguments[0:2] == ["cat-file", "commit"]:
                    return (
                        b"tree " + b"1" * 40 + b"\nparent " + SUBJECT.encode() + b"\n"
                        b"author Yasunobu <" + MAINTAINER_EMAIL.encode() + b"> 1 +0000\n"
                        b"gpgsig -----BEGIN SSH SIGNATURE-----\n continuation\n\nmessage\n"
                    )
                raise AssertionError(arguments)

            with patch("scripts.verify_release_evidence._git", side_effect=valid_git):
                _verify_repository_relation(repository, evidence, EVIDENCE, SUBJECT)

            def unrelated_git(repo: Path, arguments: list[str]) -> bytes:
                if arguments[0] == "diff-tree":
                    return b"README.md\0"
                return valid_git(repo, arguments)

            with (
                patch("scripts.verify_release_evidence._git", side_effect=unrelated_git),
                self.assertRaisesRegex(ValueError, "only release-evidence"),
            ):
                _verify_repository_relation(repository, evidence, EVIDENCE, SUBJECT)

    def test_pinned_allowed_signer_cannot_be_substituted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attestation = root / "attestation.json"
            signature = root / "attestation.json.sig"
            attestation.write_text("{}\n", encoding="utf-8")
            signature.write_text("signature\n", encoding="ascii")
            (root / "maintainer-allowed-signers").write_text(
                f"{MAINTAINER_EMAIL} ssh-ed25519 {'A' * 68}\n", encoding="ascii"
            )
            with self.assertRaisesRegex(ValueError, "pinned P4suta key"):
                _verify_signature(root, attestation, signature, attestation.read_bytes())

    def test_relative_manifest_root_resolves_signature_subprocess_paths(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            absolute_root = Path(temporary)
            root = absolute_root.relative_to(Path.cwd())
            attestation = root / "maintainer-security-attestation-v1.json"
            signature = root / "maintainer-security-attestation-v1.json.sig"
            attestation.write_text("{}\n", encoding="utf-8")
            signature.write_text("signature\n", encoding="ascii")
            (root / "maintainer-allowed-signers").write_bytes(
                f"{MAINTAINER_EMAIL} {MAINTAINER_PUBLIC_KEY}\n".encode("ascii")
            )
            with patch("scripts.verify_release_evidence._run", return_value=b"") as run:
                _verify_signature(root, attestation, signature, attestation.read_bytes())

            command = run.call_args.args[0]
            self.assertEqual(run.call_args.kwargs["cwd"], absolute_root.resolve())
            self.assertEqual(
                Path(command[command.index("-f") + 1]),
                (absolute_root / "maintainer-allowed-signers").resolve(),
            )
            self.assertEqual(
                Path(command[command.index("-s") + 1]),
                (absolute_root / signature.name).resolve(),
            )

    def test_raw_parent_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["corpus"]["path"] = "reports/../corpus-report-v1.json"
            write_json(manifest, document)
            with self.assertRaisesRegex(ValueError, "safe relative"):
                verify_fixture(manifest)


if __name__ == "__main__":
    unittest.main()
