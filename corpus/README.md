# Evaluation corpus

The release corpus is evidence-owned data. A reviewed `corpus-v1` manifest names
every repository by credential-free HTTPS URL and exact 40-character commit,
the canonical digest of its checked-out bytes, SPDX license evidence, its
`report-v1` path, and the exact diagnostics classified as expected or allowed.

`scripts/corpus_gate.py` independently recomputes source and license digests,
rejects VCS metadata and symlinks, matches diagnostic IDs and rule IDs, and
enforces the release minimum of 100 unique repositories per provider. It also
requires at least one owned vulnerability expectation for every provider and
enforces precision >= 95% and recall = 100%.

Large third-party snapshots are intentionally not fabricated or silently
downloaded by `check`. Place reviewed snapshots under `evaluation/corpus`, their
reports under `evaluation/reports`, and the signed-off manifest at
`evaluation/corpus-v1.json`; then run `just corpus`. Network acquisition and
license approval remain explicit release-preparation steps.
