# Compatibility policy

The analyzer package installs exactly one executable plus the `config-v1` and
`report-v1` schemas. `lock-v1`, `lock-v2`, `runner-v1`, and `evidence-v1` remain
versioned repository protocols for resolver and helper implementations; they do
not expand the analyzer package surface. New locks use `lock-v2` semantic
summaries. `lock-v1` remains readable, but its digest-only entries retain a
machine-readable missing-semantic-evidence state.

Sandbox run/audit, backend attestation, VM image/request/observation, corpus,
performance, mutation, determinism, and composed release-evidence documents are
also strict versioned repository protocols. Their schemas travel with source
and release evidence, but they are not additional analyzer configuration or
report entry points.

Canonical v1 objects are strict: producers and consumers reject unknown fields
and unknown protocol versions. A field-set change therefore requires a new
schema version. Existing field meaning is never changed in place. Rule
identifiers become stable after the first release candidate.

Supported analyzer compilers are OCaml 5.4 and 5.5 with Dune 3.21 or newer.
Generated JSON, SARIF, lockfiles, and fix patches use LF and are byte-identical
on Windows, Linux, and macOS for the same UTF-8 input tree.

The native helper boundary is compatible only when schema version, plan digest,
helper identity, control digest, and backend type all match. Unknown fields or
versions are never interpreted optimistically. Analyzer and helpers may be
distributed separately, but compatibility failure is exit 5 and cannot trigger
a weaker fallback.
