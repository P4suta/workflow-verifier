#!/usr/bin/env python3
"""Generate deterministic SPDX 2.3 JSON and SHA-256 release checksums."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
COMPONENT_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
ARTIFACT_KINDS = {
    "corresponding-source",
    "helper",
    "macos-boot-bundle",
    "product",
    "runtime-capsule",
    "schema-bundle",
    "source",
}
RELATIONSHIPS = {
    "build": "BUILD_DEPENDENCY_OF",
    "content": "CONTAINS",
    "runtime": "DEPENDS_ON",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: Path) -> tuple[str, Path, str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect release artifact {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError(f"release artifact must be a nonempty regular non-symlink file: {path}")
    name = path.name
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"release artifact has an unsafe name: {path}")
    return name, path, sha256(path)


def _atomic_text(path: Path, contents: str) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def generate(
    artifacts: list[Path],
    output: Path,
    checksums: Path,
    version: str,
) -> None:
    if not VERSION.fullmatch(version):
        raise ValueError("release version must be a stable SemVer-compatible identifier")
    if not artifacts:
        raise ValueError("at least one release artifact is required")
    if output.resolve() == checksums.resolve():
        raise ValueError("SPDX and checksum outputs must be distinct")
    files = sorted(
        (_artifact(path) for path in artifacts),
        key=lambda item: item[0].encode("utf-8"),
    )
    names = [name for name, _path, _digest in files]
    if len(names) != len(set(names)):
        raise ValueError("release artifact basenames must be unique")
    output_paths = {output.resolve(), checksums.resolve()}
    if any(path.resolve() in output_paths for _name, path, _digest in files):
        raise ValueError("release metadata outputs cannot also be input artifacts")

    spdx_files = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-workflow-verifier",
        }
    ]
    for index, (name, _path, digest) in enumerate(files):
        spdx_id = f"SPDXRef-File-{index}"
        spdx_files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "copyrightText": "NOASSERTION",
                "fileName": name,
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-workflow-verifier",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )

    namespace_seed = (
        version + "\n" + "".join(f"{digest}  {name}\n" for name, _path, digest in files)
    )
    namespace = hashlib.sha256(namespace_seed.encode("utf-8")).hexdigest()
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: workflow-verifier-sbom/1"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-Package-workflow-verifier"],
        "documentNamespace": f"https://workflow-verifier.dev/sbom/{namespace}",
        "files": spdx_files,
        "name": "workflow-verifier",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-workflow-verifier",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "MIT OR Apache-2.0",
                "licenseDeclared": "MIT OR Apache-2.0",
                "name": "workflow-verifier",
                "supplier": "NOASSERTION",
                "versionInfo": version,
            }
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    _atomic_text(
        output,
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    _atomic_text(
        checksums,
        "".join(f"{digest}  {name}\n" for name, _path, digest in files),
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate dependency manifest field {key}")
        result[key] = value
    return result


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def _load_components(path: Path) -> list[dict[str, Any]]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect dependency manifest {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise ValueError("dependency manifest must be a nonempty regular non-symlink file")
    if metadata.st_size > 1024 * 1024:
        raise ValueError("dependency manifest exceeds 1 MiB")
    try:
        raw = path.read_bytes()
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON number {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid dependency manifest: {error}") from error
    if raw != _canonical(document).encode("utf-8"):
        raise ValueError("dependency manifest must be canonical JSON")
    if not isinstance(document, dict) or set(document) != {"components", "schema"}:
        raise ValueError("dependency manifest fields must be exactly components and schema")
    if document["schema"] != "sbom-components-v1":
        raise ValueError("unsupported dependency manifest schema")
    components = document["components"]
    if not isinstance(components, list) or not components:
        raise ValueError("dependency manifest requires at least one component")
    ids: set[str] = set()
    purls: set[str] = set()
    checked: list[dict[str, Any]] = []
    fields = {"applies_to", "id", "license", "name", "purl", "relationship", "version"}
    for index, component in enumerate(components):
        if not isinstance(component, dict) or set(component) != fields:
            raise ValueError(f"component[{index}] fields are not exact")
        identifier = component["id"]
        if not isinstance(identifier, str) or not COMPONENT_ID.fullmatch(identifier):
            raise ValueError(f"component[{index}].id is invalid")
        if identifier in ids:
            raise ValueError(f"duplicate component id {identifier}")
        ids.add(identifier)
        for field in ("license", "name", "purl", "version"):
            value = component[field]
            if not isinstance(value, str) or not value or any(ord(char) < 0x20 for char in value):
                raise ValueError(f"component[{index}].{field} is invalid")
        if (
            component["version"].lower() in {"latest", "unknown"}
            or "replace" in component["version"].lower()
        ):
            raise ValueError(f"component[{index}].version must be exact")
        if not component["purl"].startswith("pkg:") or component["purl"] in purls:
            raise ValueError(f"component[{index}].purl is invalid or duplicated")
        purls.add(component["purl"])
        relationship = component["relationship"]
        if relationship not in RELATIONSHIPS:
            raise ValueError(f"component[{index}].relationship is invalid")
        applies_to = component["applies_to"]
        if (
            not isinstance(applies_to, list)
            or not applies_to
            or not all(isinstance(kind, str) for kind in applies_to)
            or len(applies_to) != len(set(applies_to))
            or applies_to != sorted(applies_to)
            or any(kind != "all" and kind not in ARTIFACT_KINDS for kind in applies_to)
        ):
            raise ValueError(f"component[{index}].applies_to is invalid")
        checked.append(component)
    if [component["id"] for component in checked] != sorted(ids):
        raise ValueError("dependency components must be sorted by id")
    return checked


def _applies(component: dict[str, Any], kind: str) -> bool:
    return "all" in component["applies_to"] or kind in component["applies_to"]


def _spdx_dependency(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "SPDXID": f"SPDXRef-Dependency-{component['id']}",
        "downloadLocation": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": component["purl"],
                "referenceType": "purl",
            }
        ],
        "filesAnalyzed": False,
        "licenseConcluded": component["license"],
        "licenseDeclared": component["license"],
        "name": component["name"],
        "supplier": "NOASSERTION",
        "versionInfo": component["version"],
    }


def _spdx_payload(
    *,
    name: str,
    digest: str,
    version: str,
    kind: str,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    selected = [component for component in components if _applies(component, kind)]
    if not selected:
        raise ValueError(f"artifact kind {kind} has no declared dependency components")
    root_id = "SPDXRef-Package-release-payload"
    seed = f"{version}\n{name}\n{digest}\n{kind}\n".encode()
    relationships: list[dict[str, str]] = [
        {
            "relatedSpdxElement": root_id,
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
    ]
    for component in selected:
        dependency_id = f"SPDXRef-Dependency-{component['id']}"
        relationship = RELATIONSHIPS[component["relationship"]]
        if relationship == "BUILD_DEPENDENCY_OF":
            relationships.append(
                {
                    "relatedSpdxElement": root_id,
                    "relationshipType": relationship,
                    "spdxElementId": dependency_id,
                }
            )
        else:
            relationships.append(
                {
                    "relatedSpdxElement": dependency_id,
                    "relationshipType": relationship,
                    "spdxElementId": root_id,
                }
            )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: workflow-verifier-sbom/2"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [root_id],
        "documentNamespace": (
            "https://workflow-verifier.dev/sbom/" + hashlib.sha256(seed).hexdigest()
        ),
        "files": [
            {
                "SPDXID": "SPDXRef-File-release-payload",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "copyrightText": "NOASSERTION",
                "fileName": name,
                "licenseConcluded": "NOASSERTION",
            }
        ],
        "name": name,
        "packages": [
            {
                "SPDXID": root_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "MIT OR Apache-2.0",
                "licenseDeclared": "MIT OR Apache-2.0",
                "name": name,
                "supplier": "NOASSERTION",
                "versionInfo": version,
            },
            *[_spdx_dependency(component) for component in selected],
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def _cyclonedx_component(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "bom-ref": f"dependency:{component['id']}",
        "licenses": [{"expression": component["license"]}],
        "name": component["name"],
        "purl": component["purl"],
        "scope": "excluded" if component["relationship"] == "build" else "required",
        "type": "library" if component["relationship"] == "runtime" else "application",
        "version": component["version"],
    }


def generate_release(
    artifacts: list[tuple[str, Path]],
    *,
    dependency_manifest: Path,
    output_dir: Path,
    cyclonedx: Path,
    checksums: Path,
    version: str,
) -> list[Path]:
    if not VERSION.fullmatch(version):
        raise ValueError("release version must be a stable SemVer-compatible identifier")
    if not artifacts:
        raise ValueError("at least one typed release artifact is required")
    if output_dir.exists():
        metadata = output_dir.lstat()
        if output_dir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("SBOM output directory must be a regular directory")
    else:
        output_dir.mkdir(parents=True)
    components = _load_components(dependency_manifest)
    typed: list[tuple[str, str, Path, str]] = []
    names: set[str] = set()
    for kind, path in artifacts:
        if kind not in ARTIFACT_KINDS:
            raise ValueError(f"unsupported artifact kind {kind}")
        name, checked_path, digest = _artifact(path)
        if name in names:
            raise ValueError("release artifact basenames must be unique")
        names.add(name)
        typed.append((kind, name, checked_path, digest))
    typed.sort(key=lambda item: item[1].encode("utf-8"))

    generated: list[Path] = []
    for kind, name, _path, digest in typed:
        destination = output_dir / f"{name}.spdx.json"
        if destination.resolve() in {path.resolve() for _, _, path, _ in typed}:
            raise ValueError("SPDX output cannot overwrite a release artifact")
        document = _spdx_payload(
            name=name,
            digest=digest,
            version=version,
            kind=kind,
            components=components,
        )
        _atomic_text(destination, _canonical(document))
        generated.append(destination)

    artifact_components = [
        {
            "bom-ref": f"artifact:{name}",
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "name": name,
            "type": "file",
            "version": version,
        }
        for _kind, name, _path, digest in typed
    ]
    dependency_components = [_cyclonedx_component(component) for component in components]
    dependencies = []
    for kind, name, _path, _digest in typed:
        depends_on = [
            f"dependency:{component['id']}"
            for component in components
            if _applies(component, kind) and component["relationship"] != "build"
        ]
        dependencies.append({"dependsOn": depends_on, "ref": f"artifact:{name}"})
    dependencies.extend(
        {"dependsOn": [], "ref": f"dependency:{component['id']}"} for component in components
    )
    serial_seed = "\n".join(f"{name}:{digest}" for _, name, _, digest in typed)
    serial = hashlib.sha256(serial_seed.encode()).hexdigest()[:32]
    cyclonedx_document = {
        "bomFormat": "CycloneDX",
        "components": [*artifact_components, *dependency_components],
        "dependencies": dependencies,
        "metadata": {
            "component": {
                "bom-ref": "application:workflow-verifier",
                "name": "workflow-verifier",
                "type": "application",
                "version": version,
            },
            "timestamp": "1970-01-01T00:00:00Z",
            "tools": {"components": [{"name": "workflow-verifier-sbom", "version": "2"}]},
        },
        "serialNumber": (
            f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}"
        ),
        "specVersion": "1.6",
        "version": 1,
    }
    _atomic_text(cyclonedx, _canonical(cyclonedx_document))
    generated.append(cyclonedx)

    checksum_inputs = [*(path for _kind, _name, path, _digest in typed), *generated]
    checksum_records = sorted(
        (_artifact(path) for path in checksum_inputs),
        key=lambda item: item[0].encode("utf-8"),
    )
    if len({name for name, _path, _digest in checksum_records}) != len(checksum_records):
        raise ValueError("artifact and SBOM basenames must be unique")
    _atomic_text(
        checksums,
        "".join(f"{digest}  {name}\n" for name, _path, digest in checksum_records),
    )
    return generated


def _typed_artifact(value: str) -> tuple[str, Path]:
    kind, separator, raw_path = value.partition("=")
    if not separator or not raw_path:
        raise argparse.ArgumentTypeError("typed artifact must use KIND=PATH")
    if kind not in ARTIFACT_KINDS:
        raise argparse.ArgumentTypeError(f"unsupported artifact kind {kind}")
    return kind, Path(raw_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cyclonedx", type=Path)
    parser.add_argument("--dependency-manifest", type=Path)
    parser.add_argument("--artifact", action="append", default=[], type=_typed_artifact)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("artifacts", nargs="*")
    arguments = parser.parse_args()
    release_mode = bool(arguments.artifact or arguments.dependency_manifest)
    if release_mode:
        required = {
            "--checksums": arguments.checksums,
            "--cyclonedx": arguments.cyclonedx,
            "--dependency-manifest": arguments.dependency_manifest,
            "--output-dir": arguments.output_dir,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing or arguments.output is not None:
            parser.error(
                "release SBOM mode requires KIND=PATH arguments or --artifact plus "
                "--dependency-manifest/--output-dir/--cyclonedx/--checksums, "
                f"and no --output; missing={','.join(missing)}"
            )
        typed_artifacts = [
            *arguments.artifact,
            *[_typed_artifact(value) for value in arguments.artifacts],
        ]
        if not typed_artifacts:
            parser.error("release SBOM mode requires at least one KIND=PATH artifact")
        generate_release(
            typed_artifacts,
            dependency_manifest=arguments.dependency_manifest,
            output_dir=arguments.output_dir,
            cyclonedx=arguments.cyclonedx,
            checksums=arguments.checksums,
            version=arguments.version,
        )
    else:
        if arguments.output is None or arguments.checksums is None or not arguments.artifacts:
            parser.error("legacy SBOM mode requires --output, --checksums, and artifacts")
        generate(
            [Path(value) for value in arguments.artifacts],
            arguments.output,
            arguments.checksums,
            arguments.version,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
