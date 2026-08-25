# Compatibility policy

Version 0.1 publishes strict, language-independent contracts for canonical
UTF-8 JSON, paths, snapshots, provider lowering, unknown values, diagnostics,
fixes, scenarios, runners, and evidence.

The current product protocols are `config-v2`, `source-manifest-v2`,
`report-v2`, `scenario-v1`, `runner-v2`, `sandbox-run-v2`, and
`evidence-v2`. Unknown or duplicate fields, duplicate JSON keys, invalid
UTF-8, wrong types, unsupported enum values, and unknown protocol versions are
rejected. Existing version names never acquire new meaning; field-set or
semantic changes require a new protocol version.

`config-v1` and `lock-v1` are accepted only by the validated `migrate`
command. A legacy report, runner, sandbox result, or evidence object is never
interpreted as a current object. New locks use `lock-v2`.

OCaml 5.5 with Dune 3.24.2 is the release toolchain. OCaml 5.4 is a compatibility
gate. Rust helpers use Rust 1.98 with MSRV 1.85. JSON, SARIF, lockfiles, evidence,
and fix patches are LF-canonical. Raw report bytes must repeat for the same
snapshot, semantic profile, and binary provenance. The four-platform gate
retains each raw report digest but compares canonical report semantics after
removing only the authenticated root digest, binary digest, and bound source
commit; lockfiles and fix patches remain byte-identical across platforms.

The helper boundary requires an exact helper digest, backend-attestation-v1
identity, runner-v2 plan, requested controls, and backend type. A mismatch is
exit 5 and cannot select a weaker fallback.

Before 1.0, a minor release may add CLI or schema versions. Published schema
names and meanings remain immutable. Future Rust analyzers must pass every valid
and invalid conformance vector, canonical byte expectation, and digest generated
from the language-independent contracts.
