#!/usr/bin/env python3
"""Generate deterministic SPDX 2.3 JSON and SHA-256 release checksums."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")


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

    namespace_seed = version + "\n" + "".join(
        f"{digest}  {name}\n" for name, _path, digest in files
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("artifacts", nargs="+", type=Path)
    arguments = parser.parse_args()
    generate(arguments.artifacts, arguments.output, arguments.checksums, arguments.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
