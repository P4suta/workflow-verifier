# Evaluation corpus

The release corpus is evidence-owned data. A reviewed `corpus-v1` manifest names
every repository by credential-free HTTPS URL and exact 40-character commit,
the canonical digest of its checked-out bytes, SPDX license evidence, its
`workflow-verifier-report/1` path, and the exact diagnostics classified as
expected or allowed.

`scripts/corpus_gate.py` independently recomputes source and license digests,
rejects VCS metadata and symlinks, matches diagnostic IDs and rule IDs, and
enforces the release minimum of 100 unique repositories per provider. It also
requires at least one owned vulnerability expectation for every provider and
enforces precision >= 95% and recall = 100%.

Large third-party snapshots are never fabricated or silently downloaded by
`check`. `just corpus-acquire` explicitly searches public GitHub repositories,
pins each default branch to a 40-character commit, retains only MIT,
Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, or 0BSD license evidence, and
atomically builds 100 snapshots plus real `workflow-verifier-report/1`
documents per provider.

`just corpus-refresh` verifies every recorded source digest, copies the exact
immutable snapshots into a new transaction, and reruns the analyzer without
network access. It never edits the reviewed input in place. Promote the staged
output only after its reports have been classified and the release gate passes.

Acquisition writes `evaluation/review-draft-v1.json`. Reviewers classify every
observed diagnostic in `evaluation/review-v1.json` with an `expected` or
`allowed` decision and a substantive reason. `just corpus-review` rejects
missing, stale, duplicate, or rule-mismatched decisions before updating the
manifest. `just corpus` then enforces provider counts, precision, recall,
source/license digests, and known-vulnerability coverage.

The checked-in reports are the first `workflow-verifier-report/1` refresh and
the checked-in manifest deliberately contains no classifications. Its
`review-draft-v1.json` records all 951 observations; no `review-v1.json` is
present until that draft receives a fresh exhaustive human review. Consequently
the release corpus gate fails closed rather than inheriting decisions keyed by
superseded report IDs.

Copy the resulting passing `corpus-report-v1.json` into evidence-only commit
`E` and bind its exact SHA-256 digest in `release-evidence-v4.json`. The
protected tag workflow checks all provider counts, precision, recall,
known-vulnerability coverage, nested diagnostic results, and the digest before
publication.
