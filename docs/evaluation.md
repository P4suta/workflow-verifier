# Evaluation and publication gates

Evaluation evidence is a release input, not a number copied into documentation.
The analyzer accepts a release candidate only when the immutable corpus,
performance, mutation, fuzzing, and cross-platform determinism gates all produce
machine-readable evidence.

## Required evidence

- `corpus-report-v1` covers at least 100 distinct, license-reviewed repositories
  for each provider. Precision must be at least 95% and recall over the owned
  vulnerability fixtures must be 100%.
- Separate `performance-comparison-v1` ledgers compare the retained OCaml
  reference and shipped Rust CLI in cold, warm, and incremental modes on an
  identical declared environment. Each implementation independently rejects an
  increase above 10% unless it has a substantive explanation and HTTPS review
  reference; no minimum improvement is required.
- `official-compat-v1` summarizes two fixed repositories for each provider.
  Sparse acquisition authenticates the pinned commit and tree and copies only
  selected CI definitions. Analysis then runs twice without network access,
  allows security diagnostics, but rejects internal errors, provider drift,
  `YAML-SYNTAX` on valid upstream input, nondeterministic bytes, or a repository
  that exceeds its 60-second shared deadline. Public evidence retains counts
  and digests, not diagnostic messages.
- Each `mutation-gate-v1` authenticates one complete catalog-bound shard and
  binds its runner exit code and canonical `mutation-resource-guard-v1`
  attestation to the verified report. The same fail-closed Linux resource
  envelope wraps baseline measurements, every mutant test stage, and the
  shard orchestrator; a baseline must therefore prove that unmodified tests fit
  before exceeding the envelope can detect a mutant. Every survivor must be
  detected or reviewed as equivalent. A quality failure still emits the raw
  report and a machine-readable failed gate; it never discards the evidence.
- `mutation-campaign-v1` binds those reports to one pinned-runner catalog and
  proves that their immutable full-ID union has no omission, duplication, or
  metadata substitution. Both passing and complete-but-failing campaigns are
  representable, while only a passing campaign can satisfy publication.
  The mutation pipeline also runs the pinned 402-case yaml-test-suite through
  each worker's private Dune build directory. One catalog job reads the exact
  immutable Git tree, selects only real case directories containing regular
  `in.yaml` blobs, and exports 1,887 regular files without dereferencing the
  upstream `name/` and `tags/` symlink aliases. Every shard rejects the artifact
  unless its case/file ledger and independently pinned tree SHA-256 recompute
  exactly. The suite remains under the ignored build root outside the mutation
  runner's source snapshot and crosses that boundary through one explicit
  read-only path capability. Every runner-managed Dune stage also receives a
  per-mutant build directory, so a lock collision cannot be counted as a kill.
  Captured subprocess bytes retain a raw SHA-256; invalid UTF-8 is replaced at
  the JSON evidence boundary with an explicit encoding-error count.
  A separate semantic fingerprint stage covers typed configuration failures,
  every policy selector and capability/effect name, cross-shell source/sink
  boundaries, graph algorithms, fixed-point dataflow, and all verifier personas.
  Fingerprint updates therefore require an intentional test review rather than
  silently accepting changed behavior.
- `determinism-v2` executes report-v3, lockfile, and fix generation twice on
  each platform and requires raw byte identity locally.
  `determinism-comparison-v2` byte-compares lock and fix output across Linux
  x86_64, Linux arm64, Windows x86_64, macOS arm64, and macOS x86_64. It
  requires one report `semantic_digest` across all five while retaining each
  platform's full report digest, binary identity, and target as provenance.
- `dogfood-v1` requires zero diagnostics while analyzing the repository's real
  GitHub, GitLab, Azure, and CircleCI entrypoints, exercises every public CLI
  surface, recomputes the OCI evidence hash chain, and binds the verified audit
  tail and static/runtime reconciliation to the execution plan.
- The AFL campaign must execute a nonempty corpus and finish with no crash or
  hang artifact.

The corresponding schemas live in `schema/`. Evidence generators reject
duplicate JSON keys, symlinks, path traversal, missing samples, empty campaigns,
and partial source coverage. They write outputs atomically.

Publication inputs are composed by `release-evidence-v4`. Candidate commit `C`
contains the release code and version; its single evidence-only child `E`
contains measurements of `C` and is the future tag target. The manifest binds
`C` and the planned tag to the corpus report, fixed official compatibility
report, five platform performance comparisons, and signed sole-maintainer
security attestation. `scripts/verify_release_evidence.py` validates the `E` to
`C` parent relation and changed paths, nested proof states, every digest, the
pinned maintainer SSH identity and namespace, and all fail-closed risk rules.

## Reviewed acquisition inputs

The public repository does not manufacture a 400-repository result or a
performance baseline. `scripts/prepare_corpus.py acquire` performs explicit,
credential-free source acquisition and records immutable source and permissive
license evidence. Its separate `apply-review` phase requires every observed
diagnostic to receive a reasoned `expected` or `allowed` decision. The security
self-attestation remains separately signed release evidence; no missing input
is converted into success.

After analyzer changes, `scripts/prepare_corpus.py refresh` first verifies all
recorded source digests and then reanalyzes those exact snapshots into a new
transaction without network access. The source evaluation is immutable; the
new reports receive a fresh exhaustive review before promotion.

When a schema migration changes generated diagnostic or graph-node identities,
`rebase-review` is an explicit aid rather than an implicit report migration. It
accepts authenticated `report-v1` only on its named legacy side and authenticated
`report-v3` only on its fresh side. Repository revision/source/license identity,
the complete primary diagnostic semantics, and trace label/file shape must form
a unique bijection. Generated IDs, the old corpus-root path prefix, graph-node
IDs, and auxiliary trace coordinates are the only ignored values. Any added,
missing, ambiguous, or semantically changed finding is rejected and must be
reviewed from the fresh draft.

Local entry points are exposed by `just corpus-acquire`, `just corpus-refresh`,
`just corpus-rebase-review`, `just corpus-review`, `just corpus`,
`just performance-measure`, `just performance-pair`,
`just performance-measure-rust`, `just performance-pair-rust`,
`just performance-gate`, `just mutation-gate`, `just mutation-campaign`,
`just determinism-probe`, and `just determinism-compare`.
`just official-fetch`, `just official-compat`, and
`just release-evidence REVISION TAG` close the fixed compatibility and evidence
composition gates. Equivalent `mise` tasks use the conventional `evaluation/`,
`performance/`, `_build/`, and `release-evidence/` paths.
