# Evaluation and publication gates

Evaluation evidence is a release input, not a number copied into documentation.
The analyzer accepts a release candidate only when the immutable corpus,
performance, mutation, fuzzing, and cross-platform determinism gates all produce
machine-readable evidence.

## Required evidence

- `corpus-report-v1` covers at least 100 distinct, license-reviewed repositories
  for each provider. Precision must be at least 95% and recall over the owned
  vulnerability fixtures must be 100%.
- `performance-comparison-v1` compares cold, warm, and incremental samples on an
  identical declared environment. An increase above 10% needs a substantive
  explanation and an HTTPS review reference.
- Each `mutation-gate-v1` authenticates one complete catalog-bound shard and
  requires every survivor to be detected or reviewed as equivalent.
- `mutation-campaign-v1` binds those reports to one pinned-runner catalog and
  proves that their immutable full-ID union has no omission, duplication, or
  metadata substitution.
- `determinism-comparison-v1` byte-compares report, lockfile, and fix output from
  Linux x86-64, Windows x86-64, macOS arm64, and macOS x86-64.
- `dogfood-v1` requires zero diagnostics while analyzing the repository's real
  GitHub, GitLab, Azure, and CircleCI entrypoints, exercises every public CLI
  surface, recomputes the OCI evidence hash chain, and binds the verified audit
  tail and static/runtime reconciliation to the execution plan.
- The AFL campaign must execute a nonempty corpus and finish with no crash or
  hang artifact.

The corresponding schemas live in `schema/`. Evidence generators reject
duplicate JSON keys, symlinks, path traversal, missing samples, empty campaigns,
and partial source coverage. They write outputs atomically.

The externally reviewed publication inputs are composed by
`release-evidence-v1`. Its manifest binds the release tag and exact commit to
the corpus report, four platform performance comparisons, and the independent
review report and Sigstore bundle. `scripts/verify_release_evidence.py` verifies
the nested proof states, recomputes every digest, rejects a performance
self-comparison, and exposes only validated paths and certificate identities to
the release workflow. Pinned Cosign then verifies the review signature.

## Reviewed acquisition inputs

The public repository does not manufacture a 400-repository result or a
performance baseline. `scripts/prepare_corpus.py acquire` performs explicit,
credential-free source acquisition and records immutable source and permissive
license evidence. Its separate `apply-review` phase requires every observed
diagnostic to receive a reasoned `expected` or `allowed` decision. The
independent security review remains separately signed release evidence; no
missing input is converted into success.

After analyzer changes, `scripts/prepare_corpus.py refresh` first verifies all
recorded source digests and then reanalyzes those exact snapshots into a new
transaction without network access. The source evaluation is immutable; the
new reports receive a fresh exhaustive review before promotion.

Local entry points are exposed by `just corpus-acquire`, `just corpus-refresh`,
`just corpus-review`, `just corpus`, `just performance-measure`,
`just performance-gate`, `just mutation-gate`, `just mutation-campaign`,
`just determinism-probe`, and `just determinism-compare`.
`just release-evidence REVISION TAG` closes the external-evidence composition
gate. Equivalent `mise` tasks use the conventional `evaluation/`,
`performance/`, `_build/`, and `release-evidence/` paths.
