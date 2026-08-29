# Contract policy

Version 0.1 is unreleased and exposes one contract for each product document.
The Rust binary is the only shipped implementation. The OCaml executable is a
development-only semantic oracle and is neither installed nor distributed.

The current analysis contracts are `config-v2`, `lock-v2`,
`workflow-verifier-report/1`, and `workflow-verifier-graph/1`. Check reports do
not contain graph bodies. Graph documents use a source table, dense numeric node
IDs, numeric edge endpoints, and omit default-valued fields. SHA-256 values are
typed internally and rendered as lowercase `sha256:` strings only at document
boundaries.

Unknown or duplicate fields, duplicate JSON keys, invalid UTF-8, wrong types,
unsupported enum values, and unknown protocol names are rejected. The product
does not accept or migrate superseded config, lock, report, graph, cache, or CLI
contracts. A future incompatible change replaces the contract and all owned
fixtures together; it does not add a compatibility adapter.

Static commands are deterministic, stateless, offline by default, and read only
files that can affect their result. LSP alone owns an incremental analysis
session. Sandbox planning and execution retain a separate complete repository
snapshot because runtime jobs may access arbitrary repository files.

The helper boundary requires an exact helper digest,
`backend-attestation-v1` identity, `runner-v2` plan, requested controls, and
backend type. A mismatch is exit 5 and cannot select a weaker fallback.

Rust 1.98 is the product toolchain with MSRV 1.85. The single OCaml reference
job uses OCaml 5.5 and Dune 3.24.2. JSON, SARIF, lockfiles, evidence, and fix
patches are LF-canonical. Five-platform determinism compares tool-independent
analysis semantics while retaining each complete report digest as provenance.
