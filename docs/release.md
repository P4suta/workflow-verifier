# Release process

Release archives are built from an annotated or lightweight tag whose exact
name is `v` followed by the version in `dune-project`. The same version must be
present in the opam file, Rust workspace, CLI banner, resolver user agent, and
changelog. Development versions ending in `-dev` cannot be published.

The tag workflow builds the analyzer and only the applicable native helper on
Linux x86-64, Windows x86-64, macOS arm64, and macOS x86-64. A deterministic
packager fixes archive order, ownership, permissions, timestamps, and root
directory names. The publish job has the only write permissions. It emits an
SPDX 2.3 document and checksum manifest, signs that manifest with a short-lived
Sigstore identity, creates GitHub build-provenance and SBOM attestations, and
then creates the immutable GitHub release.

The publish job depends on the complete platform build matrix, the reusable
mutation workflow, and the reusable ordinary CI workflow. The latter exercises
both OCaml versions, all native helpers, delegated Linux attack fixtures, a
bounded AFL campaign, and byte-identical determinism probes on four release
platforms. A tag therefore cannot bypass the ordinary quality gates.
Every third-party action and container image is pinned by immutable digest.

Before tagging:

1. Run `just check` and `just version`.
2. Produce and retain a passing release-mode corpus report with at least 100
   reviewed repositories per provider and 95%/100% precision/recall.
3. Measure cold/warm/incremental performance against the approved platform
   baseline and retain a passing comparison.
4. Retain the four-platform determinism comparison, full mutation evidence,
   AFL summary, and native backend attack-fixture results.
5. Complete the independent review record in
   [security-review.md](security-review.md), update the changelog, and remove
   the development status notice only after every publication gate closes.
6. Verify the exact tag identity:

```text
python -B scripts/verify_release_version.py --tag vX.Y.Z
```

The evidence formats and local commands are specified in
[evaluation.md](evaluation.md). A missing corpus, baseline, independent review,
or platform result blocks publication; it is not an acceptable waiver.

Verify a downloaded release from the repository root with:

```text
sha256sum -c SHA256SUMS
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/P4suta/workflow-verifier/.github/workflows/release.yml@refs/tags/v' \
  SHA256SUMS
gh attestation verify workflow-verifier-X.Y.Z-linux-x86_64.tar.gz \
  --repo P4suta/workflow-verifier
```

The analyzer opam package intentionally installs one executable and only the
public config/report schemas. OCI and native helpers are separately versioned
release assets communicating over canonical JSON; installing them never adds a
foreign library to the analyzer process.
