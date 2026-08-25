#!/usr/bin/env python3
"""Verify the analyzer package's exact executable, schema, docs, and completion surface."""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath

SCHEMAS = {
    "backend-attestation-v1.schema.json",
    "config-v1.schema.json",
    "config-v2.schema.json",
    "conformance-manifest-v1.schema.json",
    "corpus-report-v1.schema.json",
    "corpus-review-v1.schema.json",
    "corpus-v1.schema.json",
    "determinism-comparison-v1.schema.json",
    "determinism-v1.schema.json",
    "dogfood-v1.schema.json",
    "doctor-v2.schema.json",
    "evidence-v2.schema.json",
    "lock-v1.schema.json",
    "lock-v2.schema.json",
    "maintainer-self-audit-v2.schema.json",
    "mutation-campaign-v1.schema.json",
    "mutation-gate-v1.schema.json",
    "performance-comparison-v1.schema.json",
    "performance-suite-v1.schema.json",
    "performance-v1.schema.json",
    "release-evidence-v3.schema.json",
    "release-gate-v1.schema.json",
    "release-index-v1.schema.json",
    "report-v2.schema.json",
    "reproducibility-fragment-v1.schema.json",
    "runner-v2.schema.json",
    "sandbox-audit-v1.schema.json",
    "sandbox-run-v2.schema.json",
    "scenario-v1.schema.json",
    "sbom-components-v1.schema.json",
    "source-manifest-v2.schema.json",
    "vm-image-v1.schema.json",
    "vm-observation-v1.schema.json",
    "vm-shim-request-v1.schema.json",
}


def fail(message: str) -> None:
    print(f"install-layout gate: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: verify_install_layout.py INSTALL_ROOT")

root = Path(sys.argv[1]).resolve()
if not root.is_dir():
    fail(f"install root does not exist: {root}")

files = sorted(path for path in root.rglob("*") if path.is_file())
relative = [path.relative_to(root).as_posix() for path in files]
executables = [
    path for path in relative if path in {"bin/workflow-verifier", "bin/workflow-verifier.exe"}
]
if len(executables) != 1:
    fail(f"expected one workflow-verifier executable, found {executables}")

schemas = {f"share/workflow-verifier/{name}" for name in SCHEMAS}
installed_schemas = {
    path
    for path in relative
    if path.startswith("share/workflow-verifier/") and path.endswith(".schema.json")
}
missing = schemas - installed_schemas
unexpected = installed_schemas - schemas
if missing:
    fail(f"missing schemas: {', '.join(sorted(missing))}")
if unexpected:
    fail(f"non-public schemas leaked into analyzer install: {', '.join(sorted(unexpected))}")

required_support = {
    "share/workflow-verifier/completions/_workflow-verifier",
    "share/workflow-verifier/completions/workflow-verifier.bash",
    "share/workflow-verifier/completions/workflow-verifier.fish",
    "share/workflow-verifier/completions/workflow-verifier.ps1",
}
missing_support = required_support - set(relative)
if missing_support:
    fail(f"missing completion assets: {', '.join(sorted(missing_support))}")

required_examples = {
    "share/workflow-verifier/conformance/manifest-v1.json",
    "share/workflow-verifier/examples/scenario-v1.json",
    "share/workflow-verifier/examples/trusted-policy-v2.toml",
    "share/workflow-verifier/spec/canonical-contracts.md",
    "share/workflow-verifier/spec/provider-lowering.md",
}
missing_examples = required_examples - set(relative)
if missing_examples:
    fail(f"missing specs, examples, or conformance data: {', '.join(sorted(missing_examples))}")

if not any(path.endswith("/workflow-verifier.1") for path in relative):
    fail("missing workflow-verifier(1) manual")
if not any(path.endswith("/compatibility.md") for path in relative):
    fail("missing installed compatibility documentation")
if not any(path.endswith("/THIRD_PARTY_NOTICES.md") for path in relative):
    fail("missing installed third-party notices")

for path in relative:
    if PurePosixPath(path).suffix in {".cmi", ".cma", ".cmxa", ".cmx", ".a"}:
        fail(f"private analyzer library leaked into install: {path}")

print(
    f"install-layout gate: {len(executables)} executable, "
    f"{len(schemas)} schemas, docs and four completions"
)
