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
- `mutation-gate-v1` proves that the configured analyzer-core source prefixes
  were actually mutated and that every survivor is either detected or reviewed
  as equivalent.
- `determinism-comparison-v1` byte-compares report, lockfile, and fix output from
  Linux x86-64, Windows x86-64, macOS arm64, and macOS x86-64.
- The AFL campaign must execute a nonempty corpus and finish with no crash or
  hang artifact.

The corresponding schemas live in `schema/`. Evidence generators reject
duplicate JSON keys, symlinks, path traversal, missing samples, empty campaigns,
and partial source coverage. They write outputs atomically.

## Deliberately external inputs

The public repository does not manufacture a 400-repository result or a
performance baseline. Corpus selection, SPDX review, expected diagnostics, and
the independent security review require human evidence. Release automation must
be given those reviewed inputs; their absence is a failed publication gate, not
an `Unknown` converted into success.

Local entry points are exposed by `just corpus`, `just performance-measure`,
`just performance-gate`, `just mutation-gate`, `just determinism-probe`, and
`just determinism-compare`. Equivalent `mise` tasks use the conventional
`evaluation/`, `performance/`, and `_build/` paths.
