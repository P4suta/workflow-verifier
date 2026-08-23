# Release evidence bundle

Publication requires a reviewed, digest-bound bundle committed in the exact
release tag. Create `release-evidence-v1.json` according to the repository
schema and place every referenced file below this directory. The manifest binds
the candidate tag and commit to:

- a passing `corpus-report-v1` with at least 100 reviewed repositories and a
  known-vulnerability expectation for each provider;
- passing cold, warm, and incremental comparisons against an independent
  baseline on Linux x86-64, Windows x86-64, macOS arm64, and macOS x86-64; and
- an approved independent security-review report plus its Sigstore bundle and
  exact external signing identity.

Run `just release-evidence REVISION TAG` before creating the protected tag.
The tag workflow repeats the complete structural and digest validation, then
uses pinned Cosign to verify the reviewer's signature. A missing manifest,
tampered file, self-comparison, failed metric, local-project signing identity,
or incomplete review stops publication before the publish job is eligible.

No example passing manifest is committed: release evidence names real people,
reviews, revisions, and measurements and must never be synthesized from sample
values.
