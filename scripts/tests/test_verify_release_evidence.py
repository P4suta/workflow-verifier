from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_release_evidence import (
    DISCLOSURES,
    MAINTAINER_EMAIL,
    PLATFORMS,
    REQUIRED_GATES,
    SIGNATURE_NAMESPACE,
    SIGSTORE_IDENTITY,
    SIGSTORE_ISSUER,
    SIGSTORE_MEDIA_TYPE,
    _verify_repository_relation,
    _verify_signature,
    _verify_sigstore_bundle,
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
        newline="\n",
    )


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def record(path: Path, root: Path) -> dict[str, str]:
    return {"digest": digest(path), "path": path.relative_to(root).as_posix()}


def payload(
    root: Path,
    *,
    name: str,
    kind: str,
    platform: str,
) -> tuple[dict[str, object], dict[str, object]]:
    path = root / "artifacts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(f"payload:{name}\n".encode())
    signature_path = root / "signatures" / f"{name}.bundle"
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_bytes(f"signature:{name}\n".encode())
    signature_kind = "sigstore"
    if kind in {"helper", "product"} and platform == "windows-x86_64":
        signature_kind = "authenticode+sigstore"
    elif kind in {"helper", "product"} and platform.startswith("macos-"):
        signature_kind = "ad-hoc+sigstore"
    artifact: dict[str, object] = {
        "digest": digest(path),
        "kind": kind,
        "name": name,
        "path": path.relative_to(root).as_posix(),
        "platform": platform,
        "signature": {
            "digest": digest(signature_path),
            "kind": signature_kind,
            "path": signature_path.relative_to(root).as_posix(),
        },
    }
    sbom_path = root / "sbom" / f"{name}.spdx.json"
    write_json(
        sbom_path,
        {
            "name": name,
            "packages": [{"name": "workflow-verifier", "versionInfo": "0.1.0"}],
            "relationships": [
                {
                    "relatedSpdxElement": "SPDXRef-Package",
                    "relationshipType": "DESCRIBES",
                    "spdxElementId": "SPDXRef-DOCUMENT",
                }
            ],
            "spdxVersion": "SPDX-2.3",
        },
    )
    sbom: dict[str, object] = {
        "digest": digest(sbom_path),
        "kind": "sbom-spdx",
        "name": f"{name}.spdx.json",
        "path": sbom_path.relative_to(root).as_posix(),
        "platform": "any",
        "subject": name,
    }
    return artifact, sbom


def fixture(root: Path) -> Path:
    artifacts: list[dict[str, object]] = []
    spdx: list[dict[str, object]] = []
    for platform in PLATFORMS:
        suffix = "zip" if platform.startswith("windows-") else "tar.gz"
        artifact, sbom = payload(
            root,
            name=f"workflow-verifier-{platform}.{suffix}",
            kind="product",
            platform=platform,
        )
        artifacts.append(artifact)
        spdx.append(sbom)
    auxiliary = [
        ("workflow-verifier-0.1.0-source.tar.gz", "source"),
        ("workflow-verifier-runtime-capsule.tar", "runtime-capsule"),
        ("workflow-verifier-schemas.tar", "schema-bundle"),
        ("workflow-verifier-corresponding-source.tar", "corresponding-source"),
    ]
    for name, kind in auxiliary:
        artifact, sbom = payload(root, name=name, kind=kind, platform="any")
        artifacts.append(artifact)
        spdx.append(sbom)
    for platform in PLATFORMS:
        artifact, sbom = payload(
            root,
            name=f"workflow-verifier-helpers-{platform}.tar",
            kind="helper",
            platform=platform,
        )
        artifacts.append(artifact)
        spdx.append(sbom)
    for platform in ("macos-arm64", "macos-x86_64"):
        artifact, sbom = payload(
            root,
            name=f"workflow-verifier-boot-{platform}.tar",
            kind="macos-boot-bundle",
            platform=platform,
        )
        artifacts.append(artifact)
        spdx.append(sbom)
    artifacts.extend(spdx)
    cyclonedx = root / "sbom" / "workflow-verifier.cdx.json"
    write_json(
        cyclonedx,
        {
            "bomFormat": "CycloneDX",
            "components": [{"name": item["name"], "type": "file"} for item in artifacts],
            "specVersion": "1.6",
        },
    )
    artifacts.append(
        {
            "digest": digest(cyclonedx),
            "kind": "sbom-cyclonedx",
            "name": "workflow-verifier.cdx.json",
            "path": cyclonedx.relative_to(root).as_posix(),
            "platform": "any",
        }
    )
    notices = root / "THIRD_PARTY_NOTICES.txt"
    notices.write_text("Dependency notices\n", encoding="utf-8")
    artifacts.append(
        {
            "digest": digest(notices),
            "kind": "third-party-notices",
            "name": notices.name,
            "path": notices.name,
            "platform": "any",
        }
    )

    gates: list[dict[str, object]] = []
    for gate in sorted(REQUIRED_GATES):
        evidence = root / "gates" / f"{gate}.json"
        write_json(
            evidence,
            {
                "findings": [],
                "gate": gate,
                "schema": "release-gate-v1",
                "status": "pass",
                "subject_commit": SUBJECT,
            },
        )
        gates.append(
            {
                "evidence": record(evidence, root),
                "id": gate,
                "status": "pass",
                "subject_commit": SUBJECT,
            }
        )

    audit_path = root / "maintainer-self-audit-v2.json"
    write_json(
        audit_path,
        {
            "disclosures": DISCLOSURES,
            "findings": [],
            "independent_audit": False,
            "maintainer": "P4suta",
            "planned_tag": TAG,
            "review": REVIEW,
            "schema": "maintainer-self-audit-v2",
            "scope": ["implementation", "threat-model", "release-controls"],
            "subject_commit": SUBJECT,
        },
    )
    audit_signature = root / "maintainer-self-audit-v2.json.sig"
    audit_signature.write_text("signed fixture\n", encoding="utf-8")
    (root / "maintainer-allowed-signers").write_text(
        f"{MAINTAINER_EMAIL} ssh-ed25519 AAAAfixture\n", encoding="utf-8"
    )
    source = next(item for item in artifacts if item["kind"] == "source")
    manifest = root / "release-evidence-v3.json"
    write_json(
        manifest,
        {
            "artifacts": artifacts,
            "candidate": {
                "product_commit": SUBJECT,
                "source_archive_digest": source["digest"],
            },
            "disclosures": DISCLOSURES,
            "gates": gates,
            "maintainer": "P4suta",
            "planned_tag": TAG,
            "review": REVIEW,
            "schema": "release-evidence-v3",
            "self_audit": {
                "digest": digest(audit_path),
                "independent": False,
                "path": audit_path.name,
                "signature_digest": digest(audit_signature),
                "signature_path": audit_signature.name,
                "sole_maintainer": True,
            },
        },
    )
    return manifest


def document(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class ReleaseEvidenceV3Tests(unittest.TestCase):
    def verify_fixture(self, manifest: Path) -> dict[str, str]:
        with (
            patch("scripts.verify_release_evidence._verify_signature") as signature,
            patch("scripts.verify_release_evidence._verify_sigstore_bundle"),
        ):
            values = verify(
                manifest,
                revision=EVIDENCE,
                tag=TAG,
                repository=None,
            )
        signature.assert_called_once()
        return values

    def test_sigstore_bundle_is_standard_offline_and_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload_path = root / "payload.tar.gz"
            payload_path.write_bytes(b"payload\n")
            bundle = root / "payload.sigstore.json"
            write_json(
                bundle,
                {
                    "mediaType": SIGSTORE_MEDIA_TYPE,
                    "messageSignature": {"messageDigest": {"digest": "AA=="}},
                    "verificationMaterial": {"tlogEntries": [{}]},
                },
            )
            with patch("scripts.verify_release_evidence._run", return_value=b"") as run:
                _verify_sigstore_bundle(
                    bundle,
                    payload_path,
                    cosign="cosign-3.1.3",
                    label="fixture",
                    subject_commit=SUBJECT,
                )
            arguments = run.call_args.args[0]
            self.assertIn("--offline", arguments)
            self.assertIn(SIGSTORE_IDENTITY, arguments)
            self.assertIn(SIGSTORE_ISSUER, arguments)
            self.assertIn("P4suta/workflow-verifier", arguments)
            self.assertIn(SUBJECT, arguments)
            self.assertEqual(arguments[-1], str(payload_path))

            write_json(bundle, {"base64Signature": "legacy", "cert": "bad"})
            with self.assertRaisesRegex(ValueError, "legacy bundles are rejected"):
                _verify_sigstore_bundle(
                    bundle,
                    payload_path,
                    cosign="cosign-3.1.3",
                    label="fixture",
                    subject_commit=SUBJECT,
                )

    def test_complete_v3_evidence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            values = self.verify_fixture(manifest)
            self.assertEqual(values["subject_commit"], SUBJECT)

    def test_missing_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            value = document(manifest)
            value["gates"] = value["gates"][1:]
            write_json(manifest, value)
            with self.assertRaisesRegex(ValueError, "gates mismatch"):
                self.verify_fixture(manifest)

    def test_stale_candidate_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            value = document(manifest)
            value["gates"][0]["subject_commit"] = "c" * 40
            write_json(manifest, value)
            with self.assertRaisesRegex(ValueError, "stale candidate"):
                self.verify_fixture(manifest)

    def test_different_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            artifact = root / document(manifest)["artifacts"][0]["path"]
            artifact.write_bytes(b"different payload\n")
            with self.assertRaisesRegex(ValueError, "digest.*mismatch"):
                self.verify_fixture(manifest)

    def test_every_helper_platform_and_both_macos_boot_architectures_are_required(self) -> None:
        cases = (
            ("helper", "windows-x86_64", "helper bundles for all four"),
            ("macos-boot-bundle", "macos-arm64", "both architecture-specific"),
        )
        for kind, platform, message in cases:
            with self.subTest(kind=kind, platform=platform):
                with tempfile.TemporaryDirectory() as temporary:
                    manifest = fixture(Path(temporary))
                    value = document(manifest)
                    value["artifacts"] = [
                        artifact
                        for artifact in value["artifacts"]
                        if not (artifact["kind"] == kind and artifact["platform"] == platform)
                    ]
                    write_json(manifest, value)
                    with self.assertRaisesRegex(ValueError, message):
                        self.verify_fixture(manifest)

    def test_failed_gate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            value = document(manifest)
            value["gates"][0]["status"] = "fail"
            write_json(manifest, value)
            with self.assertRaisesRegex(ValueError, "did not pass"):
                self.verify_fixture(manifest)

    def test_invalid_signature_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = fixture(root)
            signature_path = root / document(manifest)["artifacts"][0]["signature"]["path"]
            signature_path.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ValueError, "signature.digest mismatch"):
                self.verify_fixture(manifest)

    def test_unclassified_or_high_scanner_finding_is_rejected(self) -> None:
        for severity, classification, expected in (
            ("medium", "unclassified", "unclassified"),
            ("high", "true-positive", "blocking high"),
        ):
            with self.subTest(severity=severity, classification=classification):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = fixture(root)
                    value = document(manifest)
                    gate = next(item for item in value["gates"] if item["id"] == "codeql")
                    evidence = root / gate["evidence"]["path"]
                    evidence_value = document(evidence)
                    evidence_value["findings"] = [
                        {
                            "classification": classification,
                            "id": "scanner-1",
                            "resolution": "reviewed",
                            "severity": severity,
                        }
                    ]
                    write_json(evidence, evidence_value)
                    gate["evidence"]["digest"] = digest(evidence)
                    write_json(manifest, value)
                    with self.assertRaisesRegex(ValueError, expected):
                        self.verify_fixture(manifest)

    def test_noncanonical_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = fixture(Path(temporary))
            manifest.write_text(json.dumps(document(manifest), indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical JSON"):
                self.verify_fixture(manifest)

    def test_repository_relation_requires_exact_evidence_only_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            manifest = repository / "release-evidence" / "release-evidence-v3.json"
            manifest.parent.mkdir()
            manifest.write_text("{}\n", encoding="utf-8", newline="\n")

            def valid_git(_repository: Path, arguments: list[str]) -> bytes:
                if arguments[0] == "rev-parse":
                    commit = EVIDENCE if EVIDENCE in arguments[-1] else SUBJECT
                    return commit.encode() + b"\n"
                if arguments[0] == "rev-list":
                    return f"{EVIDENCE} {SUBJECT}\n".encode()
                if arguments[0] == "diff-tree":
                    return b"release-evidence/release-evidence-v3.json\n"
                raise AssertionError(arguments)

            with patch("scripts.verify_release_evidence._git", side_effect=valid_git):
                _verify_repository_relation(repository, manifest, EVIDENCE, SUBJECT)

    def test_ssh_signature_uses_fixed_identity_and_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "maintainer-allowed-signers").write_text("fixture\n", encoding="utf-8")
            signature = root / "audit.sig"
            signature.write_text("fixture\n", encoding="utf-8")
            with patch("scripts.verify_release_evidence._run", return_value=b"") as run:
                _verify_signature(root, signature, b"attestation\n")
            arguments = run.call_args.args[0]
            self.assertIn(MAINTAINER_EMAIL, arguments)
            self.assertIn(SIGNATURE_NAMESPACE, arguments)


if __name__ == "__main__":
    unittest.main()
