#!/usr/bin/env python3
"""Verify release-evidence-v4 and its evidence-only child commit offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.package_crate import inspect_crate
except ModuleNotFoundError:  # Direct execution from the repository root.
    from package_crate import inspect_crate  # type: ignore[no-redef]

PLATFORMS = (
    "linux-x86_64",
    "linux-arm64",
    "windows-x86_64",
    "macos-arm64",
    "macos-x86_64",
)
MAINTAINER = "P4suta"
MAINTAINER_EMAIL = "42543015+P4suta@users.noreply.github.com"
SIGNATURE_NAMESPACE = "workflow-verifier-release"
SIGSTORE_ISSUER = "https://token.actions.githubusercontent.com"
SIGSTORE_IDENTITY = (
    r"^https://github\.com/P4suta/workflow-verifier/\.github/workflows/"
    r"(candidate|sign-windows)\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?)$"
)
SIGSTORE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
REVIEW_URL = re.compile(
    r"^https://github\.com/P4suta/workflow-verifier/(?:issues|pull)/[1-9][0-9]*(?:#[^\s]+)?$"
)

ROOT_FIELDS = {
    "artifacts",
    "candidate",
    "disclosures",
    "gates",
    "maintainer",
    "planned_tag",
    "review",
    "schema",
    "self_audit",
}
REQUIRED_GATES = {
    "unit",
    "static-quality",
    "fuzz",
    "mutation",
    "corpus-400",
    "determinism",
    "performance-5-platform",
    "sandbox-oci",
    "sandbox-linux-native",
    "sandbox-windows-appcontainer",
    "sandbox-macos-vm",
    "clean-install",
    "reproducible-build",
    "codeql",
    "dependency-security",
    "secret-scan",
    "license",
    "sbom",
    "signatures",
    "malware",
    "self-audit",
}
ARTIFACT_KINDS = {
    "product",
    "source",
    "runtime-capsule",
    "macos-boot-bundle",
    "helper",
    "schema-bundle",
    "sbom-spdx",
    "sbom-cyclonedx",
    "third-party-notices",
    "corresponding-source",
    "crate-package",
}
SIGNED_KINDS = {
    "product",
    "source",
    "runtime-capsule",
    "macos-boot-bundle",
    "helper",
    "schema-bundle",
    "corresponding-source",
}
REQUIRED_ARTIFACT_KINDS = {
    "product",
    "source",
    "runtime-capsule",
    "macos-boot-bundle",
    "helper",
    "schema-bundle",
    "sbom-spdx",
    "sbom-cyclonedx",
    "third-party-notices",
    "corresponding-source",
    "crate-package",
}
DISCLOSURES = {
    "independent_audit": "sole-maintainer-self-audit",
    "macos_distribution": ("ad-hoc-signature-and-sigstore-no-developer-id-or-notarization"),
}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key}")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _reject_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON number {value}")


def _load_json(
    path: Path,
    label: str,
    *,
    limit: int = 16 * 1024 * 1024,
    canonical: bool = False,
) -> tuple[Any, bytes]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect {label}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > limit:
        raise ValueError(f"{label} size is outside 1..{limit} bytes")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {label}: {error}") from error
    if canonical and raw != _canonical(value):
        raise ValueError(f"{label} must be canonical JSON with one trailing newline")
    return value, raw


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        raise ValueError(
            f"{label} fields mismatch; missing={sorted(fields - actual)}, "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def _object(value: Any, *, required: set[str], allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    missing = required - actual
    unknown = actual - allowed
    if missing or unknown:
        raise ValueError(
            f"{label} fields mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a path string")
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise ValueError(f"{label} is not a safe root-relative path")
    return path


def _resolve_file(root: Path, value: Any, label: str) -> tuple[str, Path]:
    relative = _safe_relative(value, label)
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"cannot resolve evidence root: {error}") from error
    candidate = root.joinpath(*relative.parts)
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValueError(f"cannot inspect {label}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} must not traverse a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
        metadata = candidate.lstat()
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} escapes or is unreadable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError(f"{label} must name a nonempty regular file")
    return relative.as_posix(), candidate


def _verify_digest(path: Path, expected: Any, label: str) -> None:
    expected = _digest(expected, label)
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{label} mismatch: expected {expected}, found {actual}")


def _file(root: Path, record: Any, label: str) -> tuple[str, Path]:
    item = _exact(record, {"digest", "path"}, label)
    relative, path = _resolve_file(root, item["path"], f"{label}.path")
    _verify_digest(path, item["digest"], f"{label}.digest")
    return relative, path


def _verify_sigstore_bundle(
    bundle: Path,
    payload: Path,
    *,
    cosign: str,
    label: str,
    subject_commit: str,
) -> None:
    document, _ = _load_json(bundle, f"{label} Sigstore bundle")
    if (
        not isinstance(document, dict)
        or document.get("mediaType") != SIGSTORE_MEDIA_TYPE
        or not isinstance(document.get("verificationMaterial"), dict)
        or not isinstance(document.get("messageSignature"), dict)
    ):
        raise ValueError(
            f"{label} must be a standardized Sigstore v0.3 bundle; legacy bundles are rejected"
        )
    _run(
        [
            cosign,
            "verify-blob",
            "--offline",
            "--bundle",
            str(bundle),
            "--certificate-identity-regexp",
            SIGSTORE_IDENTITY,
            "--certificate-oidc-issuer",
            SIGSTORE_ISSUER,
            "--certificate-github-workflow-repository",
            "P4suta/workflow-verifier",
            "--certificate-github-workflow-sha",
            subject_commit,
            str(payload),
        ]
    )


def _signature(
    root: Path,
    value: Any,
    label: str,
    *,
    payload: Path,
    cosign: str,
    subject_commit: str,
) -> tuple[str, Path, str]:
    record = _exact(value, {"digest", "kind", "path"}, label)
    kind = record["kind"]
    if kind not in {"sigstore", "authenticode+sigstore", "ad-hoc+sigstore"}:
        raise ValueError(f"{label}.kind is unsupported")
    relative, path = _resolve_file(root, record["path"], f"{label}.path")
    _verify_digest(path, record["digest"], f"{label}.digest")
    _verify_sigstore_bundle(
        path,
        payload,
        cosign=cosign,
        label=label,
        subject_commit=subject_commit,
    )
    return relative, path, kind


def _expected_signature(kind: str, platform: str) -> str:
    if kind in {"helper", "product"} and platform == "windows-x86_64":
        return "authenticode+sigstore"
    if kind in {"helper", "product"} and platform in {"macos-arm64", "macos-x86_64"}:
        return "ad-hoc+sigstore"
    return "sigstore"


def _verify_spdx(path: Path, subject: str) -> None:
    document, _ = _load_json(path, f"SPDX SBOM for {subject}")
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError(f"SPDX SBOM for {subject} must use SPDX-2.3")
    if document.get("name") != subject:
        raise ValueError(f"SPDX SBOM subject mismatch for {subject}")
    if not isinstance(document.get("packages"), list) or not document["packages"]:
        raise ValueError(f"SPDX SBOM for {subject} has no dependency packages")
    if not isinstance(document.get("relationships"), list):
        raise ValueError(f"SPDX SBOM for {subject} has no relationships")


def _verify_cyclonedx(path: Path) -> None:
    document, _ = _load_json(path, "aggregate CycloneDX SBOM")
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("aggregate SBOM must be CycloneDX")
    if not isinstance(document.get("components"), list) or not document["components"]:
        raise ValueError("aggregate CycloneDX SBOM has no components")


def _verify_gate(path: Path, gate: str, subject_commit: str) -> None:
    document, _ = _load_json(path, f"{gate} gate evidence")
    record = _object(
        document,
        required={"schema", "gate", "status", "subject_commit", "findings"},
        allowed={"schema", "gate", "status", "subject_commit", "findings", "details"},
        label=f"{gate} gate evidence",
    )
    if (
        record["schema"] != "release-gate-v1"
        or record["gate"] != gate
        or record["status"] != "pass"
        or record["subject_commit"] != subject_commit
    ):
        raise ValueError(f"{gate} gate evidence is stale or not passing")
    findings = record["findings"]
    if not isinstance(findings, list):
        raise ValueError(f"{gate} gate findings must be an array")
    for index, finding in enumerate(findings):
        item = _exact(
            finding,
            {"classification", "id", "resolution", "severity"},
            f"{gate} finding[{index}]",
        )
        values = (
            item["id"],
            item["severity"],
            item["classification"],
            item["resolution"],
        )
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError(f"{gate} finding[{index}] has an empty classification field")
        if item["severity"].lower() in {"critical", "high"}:
            raise ValueError(f"{gate} contains a blocking {item['severity']} finding")
        if item["classification"].lower() == "unclassified":
            raise ValueError(f"{gate} contains an unclassified finding")


def _run(arguments: list[str], *, cwd: Path | None = None, stdin: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            input=stdin,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise ValueError(f"cannot execute {arguments[0]}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{' '.join(arguments)} failed: {detail}")
    return completed.stdout


def _git(repository: Path, arguments: Iterable[str]) -> bytes:
    return _run(
        ["git", "-c", f"safe.directory={repository.resolve()}", *arguments],
        cwd=repository,
    )


def _verify_repository_relation(
    repository: Path, manifest_path: Path, revision: str, subject_commit: str
) -> None:
    evidence_commit = (
        _git(repository, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
        .decode("ascii", errors="strict")
        .strip()
    )
    product_commit = (
        _git(repository, ["rev-parse", "--verify", f"{subject_commit}^{{commit}}"])
        .decode("ascii", errors="strict")
        .strip()
    )
    if evidence_commit != revision or product_commit != subject_commit:
        raise ValueError("release evidence revision or product commit is not exact")
    relation = _git(repository, ["rev-list", "--parents", "-n", "1", revision])
    parents = relation.decode("ascii", errors="strict").strip().split()
    if parents != [revision, subject_commit]:
        raise ValueError(
            "release evidence commit must be the single-parent child of product commit"
        )
    changed = (
        _git(
            repository,
            [
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                subject_commit,
                revision,
            ],
        )
        .decode("utf-8", errors="strict")
        .splitlines()
    )
    if not changed or any(not path.startswith("release-evidence/") for path in changed):
        raise ValueError("release evidence child commit must be evidence-only")
    try:
        relative_manifest = (
            manifest_path.resolve(strict=True)
            .relative_to(repository.resolve(strict=True))
            .as_posix()
        )
    except (OSError, ValueError) as error:
        raise ValueError("release evidence manifest is outside the repository") from error
    if relative_manifest not in changed:
        raise ValueError("release evidence child commit does not add the verified manifest")


def _verify_signature(root: Path, signature: Path, raw: bytes) -> None:
    allowed = root / "maintainer-allowed-signers"
    try:
        metadata = allowed.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect maintainer allowed signers: {error}") from error
    if allowed.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("maintainer allowed signers must be a regular non-symlink file")
    _run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(allowed),
            "-I",
            MAINTAINER_EMAIL,
            "-n",
            SIGNATURE_NAMESPACE,
            "-s",
            str(signature),
        ],
        stdin=raw,
    )


def _verify_self_audit(
    root: Path,
    value: Any,
    *,
    subject_commit: str,
    tag: str,
    review: str,
    disclosures: dict[str, str],
) -> tuple[str, str]:
    record = _exact(
        value,
        {
            "digest",
            "independent",
            "path",
            "signature_digest",
            "signature_path",
            "sole_maintainer",
        },
        "self_audit",
    )
    if record["independent"] is not False or record["sole_maintainer"] is not True:
        raise ValueError("self audit must disclose sole-maintainer and no independent audit")
    attestation_relative, attestation = _resolve_file(root, record["path"], "self_audit.path")
    signature_relative, signature = _resolve_file(
        root, record["signature_path"], "self_audit.signature_path"
    )
    _verify_digest(attestation, record["digest"], "self_audit.digest")
    _verify_digest(signature, record["signature_digest"], "self_audit.signature_digest")
    document, raw = _load_json(attestation, "maintainer self audit", canonical=True)
    audit = _exact(
        document,
        {
            "disclosures",
            "findings",
            "independent_audit",
            "maintainer",
            "planned_tag",
            "review",
            "schema",
            "scope",
            "subject_commit",
        },
        "maintainer self audit",
    )
    if (
        audit["schema"] != "maintainer-self-audit-v2"
        or audit["subject_commit"] != subject_commit
        or audit["planned_tag"] != tag
        or audit["maintainer"] != MAINTAINER
        or audit["review"] != review
        or audit["independent_audit"] is not False
        or audit["disclosures"] != disclosures
        or audit["findings"] != []
        or not isinstance(audit["scope"], list)
        or not audit["scope"]
        or not all(isinstance(item, str) and item for item in audit["scope"])
    ):
        raise ValueError("maintainer self audit is stale, incomplete, or has unresolved findings")
    _verify_signature(root, signature, raw)
    return attestation_relative, signature_relative


def verify(
    manifest_path: Path,
    *,
    revision: str,
    tag: str,
    repository: Path | None = Path("."),
    cosign: str = "cosign",
) -> dict[str, str]:
    if not REVISION.fullmatch(revision):
        raise ValueError("revision must be an exact 40-character lowercase commit")
    if not TAG.fullmatch(tag):
        raise ValueError("tag is not a supported release tag")
    manifest, _ = _load_json(
        manifest_path,
        "release evidence manifest",
        limit=4 * 1024 * 1024,
        canonical=True,
    )
    manifest = _exact(manifest, ROOT_FIELDS, "release evidence manifest")
    if manifest["schema"] != "release-evidence-v4":
        raise ValueError("release evidence schema must be release-evidence-v4")
    if manifest["planned_tag"] != tag:
        raise ValueError("release evidence planned_tag does not match the release tag")
    if manifest["maintainer"] != MAINTAINER:
        raise ValueError("release evidence maintainer must be P4suta")
    review = manifest["review"]
    if not isinstance(review, str) or not REVIEW_URL.fullmatch(review):
        raise ValueError("release evidence review must be a repository issue or pull request")
    disclosures = _exact(manifest["disclosures"], set(DISCLOSURES), "disclosures")
    if disclosures != DISCLOSURES:
        raise ValueError("release exceptions must disclose macOS trust and sole-maintainer audit")
    candidate = _exact(
        manifest["candidate"],
        {"product_commit", "source_archive_digest"},
        "candidate",
    )
    subject_commit = candidate["product_commit"]
    if not isinstance(subject_commit, str) or not REVISION.fullmatch(subject_commit):
        raise ValueError("candidate.product_commit must be an exact commit")
    source_archive_digest = _digest(
        candidate["source_archive_digest"], "candidate.source_archive_digest"
    )
    root = manifest_path.parent

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("release evidence needs artifacts")
    names: set[str] = set()
    paths: set[str] = set()
    kinds: set[str] = set()
    product_platforms: set[str] = set()
    helper_platforms: set[str] = set()
    macos_boot_platforms: set[str] = set()
    payload_names: set[str] = set()
    spdx_subjects: set[str] = set()
    cyclonedx = 0
    source_artifacts = 0
    crate_packages = 0
    crate_digest = ""
    for index, raw in enumerate(artifacts):
        label = f"artifact[{index}]"
        item = _object(
            raw,
            required={"digest", "kind", "name", "path", "platform"},
            allowed={
                "digest",
                "kind",
                "name",
                "path",
                "platform",
                "signature",
                "subject",
            },
            label=label,
        )
        name = item["name"]
        kind = item["kind"]
        platform = item["platform"]
        if not isinstance(name, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", name):
            raise ValueError(f"{label}.name is not portable")
        if kind not in ARTIFACT_KINDS:
            raise ValueError(f"{label}.kind is unsupported")
        if platform not in {"any", *PLATFORMS}:
            raise ValueError(f"{label}.platform is unsupported")
        relative, path = _resolve_file(root, item["path"], f"{label}.path")
        _verify_digest(path, item["digest"], f"{label}.digest")
        if name in names or relative in paths:
            raise ValueError("artifact names and paths must be unique")
        names.add(name)
        paths.add(relative)
        kinds.add(kind)
        if kind == "product":
            if platform not in PLATFORMS or platform in product_platforms:
                raise ValueError("product artifact platforms must be unique and supported")
            product_platforms.add(platform)
        elif kind == "helper":
            if platform not in PLATFORMS or platform in helper_platforms:
                raise ValueError("helper bundle platforms must be unique and supported")
            helper_platforms.add(platform)
        elif kind == "macos-boot-bundle":
            if platform not in {"macos-arm64", "macos-x86_64"} or platform in macos_boot_platforms:
                raise ValueError(
                    "macOS boot bundle platforms must be unique and architecture-specific"
                )
            macos_boot_platforms.add(platform)
        if kind == "source":
            source_artifacts += 1
            if item["digest"] != source_archive_digest:
                raise ValueError("candidate source archive digest does not match source artifact")
        if kind == "crate-package":
            crate_packages += 1
            expected_name = f"workflow-verifier-{tag.removeprefix('v')}.crate"
            if platform != "any" or name != expected_name:
                raise ValueError("crate package name or platform contradicts the planned tag")
            inspect_crate(path, version=tag.removeprefix("v"), subject_commit=subject_commit)
            crate_digest = item["digest"]
        if kind in SIGNED_KINDS:
            payload_names.add(name)
            if "signature" not in item:
                raise ValueError(f"{label} is missing a signature record")
            _, _, signature_kind = _signature(
                root,
                item["signature"],
                f"{label}.signature",
                payload=path,
                cosign=cosign,
                subject_commit=subject_commit,
            )
            expected = _expected_signature(kind, platform)
            if signature_kind != expected:
                raise ValueError(f"{label} signature kind {signature_kind} contradicts {platform}")
        elif "signature" in item:
            _signature(
                root,
                item["signature"],
                f"{label}.signature",
                payload=path,
                cosign=cosign,
                subject_commit=subject_commit,
            )
        if kind == "sbom-spdx":
            subject = item.get("subject")
            if not isinstance(subject, str) or not subject or subject in spdx_subjects:
                raise ValueError("SPDX artifacts need unique payload subjects")
            spdx_subjects.add(subject)
            _verify_spdx(path, subject)
        elif kind == "sbom-cyclonedx":
            cyclonedx += 1
            _verify_cyclonedx(path)
        elif "subject" in item:
            raise ValueError(f"{label}.subject is only valid for SPDX artifacts")
    if product_platforms != set(PLATFORMS):
        raise ValueError("release evidence must contain all five product platforms")
    if helper_platforms != set(PLATFORMS):
        raise ValueError("release evidence must contain helper bundles for all five platforms")
    if macos_boot_platforms != {"macos-arm64", "macos-x86_64"}:
        raise ValueError(
            "release evidence must contain both architecture-specific macOS boot bundles"
        )
    if source_artifacts != 1:
        raise ValueError("release evidence must contain exactly one source archive")
    if crate_packages != 1:
        raise ValueError("release evidence must contain exactly one crates.io package")
    if not REQUIRED_ARTIFACT_KINDS.issubset(kinds):
        raise ValueError(
            f"release evidence omits artifact kinds {sorted(REQUIRED_ARTIFACT_KINDS - kinds)}"
        )
    if spdx_subjects != payload_names:
        raise ValueError(
            "SPDX coverage mismatch; "
            f"missing={sorted(payload_names - spdx_subjects)}, "
            f"unknown={sorted(spdx_subjects - payload_names)}"
        )
    if cyclonedx != 1:
        raise ValueError("release evidence needs exactly one aggregate CycloneDX SBOM")

    gates = manifest["gates"]
    if not isinstance(gates, list):
        raise ValueError("release evidence gates must be an array")
    seen_gates: set[str] = set()
    for index, raw in enumerate(gates):
        gate = _exact(
            raw,
            {"evidence", "id", "status", "subject_commit"},
            f"gate[{index}]",
        )
        gate_id = gate["id"]
        if not isinstance(gate_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", gate_id):
            raise ValueError(f"gate[{index}].id is invalid")
        if gate_id in seen_gates:
            raise ValueError(f"duplicate gate {gate_id}")
        if gate["status"] != "pass":
            raise ValueError(f"gate {gate_id} did not pass")
        if gate["subject_commit"] != subject_commit:
            raise ValueError(f"gate {gate_id} is bound to a stale candidate")
        _, evidence_path = _file(root, gate["evidence"], f"gate[{index}].evidence")
        _verify_gate(evidence_path, gate_id, subject_commit)
        seen_gates.add(gate_id)
    if seen_gates != REQUIRED_GATES:
        raise ValueError(
            "release gates mismatch; "
            f"missing={sorted(REQUIRED_GATES - seen_gates)}, "
            f"unknown={sorted(seen_gates - REQUIRED_GATES)}"
        )

    attestation, signature = _verify_self_audit(
        root,
        manifest["self_audit"],
        subject_commit=subject_commit,
        tag=tag,
        review=review,
        disclosures=disclosures,
    )
    if repository is not None:
        _verify_repository_relation(repository, manifest_path, revision, subject_commit)
    return {
        "attestation": attestation,
        "signature": signature,
        "subject_commit": subject_commit,
        "crate_digest": crate_digest,
    }


def _append_github_output(path: Path, values: dict[str, str]) -> None:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("GitHub output must be a regular non-symlink file")
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key in ("attestation", "signature", "subject_commit", "crate_digest"):
                stream.write(f"{key}={values[key]}\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ValueError(f"cannot write GitHub output {path}: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()
    try:
        values = verify(
            arguments.manifest,
            revision=arguments.revision,
            tag=arguments.tag,
            repository=arguments.repository,
            cosign=arguments.cosign,
        )
        if arguments.github_output is not None:
            _append_github_output(arguments.github_output, values)
    except ValueError as error:
        print(f"release evidence gate: {error}", file=sys.stderr)
        return 1
    print(
        "release evidence gate: candidate, artifacts, SBOMs, all quality gates, "
        "crate package, signatures, disclosures, and signed sole-maintainer self-audit verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
