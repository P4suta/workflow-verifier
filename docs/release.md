# Release process

Release archives use the exact version in `dune-project`, prefixed with `v` for
the tag. The opam file, Rust workspace and lockfile, CLI banner and cache key,
resolver user agent, report identity, and changelog must match. Versions ending
in `-dev` cannot be published.

The release workflow builds Linux x86-64, Windows x86-64, macOS arm64, and
macOS x86-64 packages. The deterministic packager fixes archive order,
ownership, permissions, timestamps, and root directory names. A separate
assembly job stages the verified v2 evidence, generates SPDX 2.3 and
`SHA256SUMS`, and uploads one release bundle. Manual `workflow_dispatch` runs
quality, every mutation, all four builds, evidence verification, packaging,
SBOM, and checksums, but the publish job is structurally disabled. Only a
protected `v*` tag permits checksum signing, provenance/SBOM attestations, and
GitHub Release creation.

## Two-commit evidence model

The evidence manifest cannot contain the hash of the commit that contains the
manifest itself. Publication resolves that cycle with two commits:

1. Merge candidate commit `C`, containing code, version, changelog, schemas,
   tests, and release machinery.
2. Measure `C` on every required platform and retain the passing corpus,
   official compatibility, mutation, determinism, dogfood, containment, fuzz,
   and performance evidence.
3. Create one child commit `E` whose only changed paths are
   `release-evidence/**`. Its `release-evidence-v2.json` names `C` as
   `subject_commit`; the signed self-attestation also names `C` and the planned
   tag.
4. Verify that `E` has exactly one parent, `C`, that `E` is signed and authored
   by the maintainer account, and that every changed path is evidence-only.
5. Run the publish-disabled release workflow at `E`. A future tag points to
   `E`, never `C`.

Before creating `E`:

1. Run `just check`, `mise run check`, and `just version` at `C`.
2. Require a 400-repository corpus report with 100 repositories per provider,
   precision 1.0, and recall 1.0.
3. Reacquire the fixed eight official projects, then analyze the snapshot twice
   without network access and match `official/official-compat-v1.json` exactly.
4. Retain passing cold, warm, and incremental paired performance reports on all
   four platforms, including the Arcade-scale scenario.
5. Retain the four-platform determinism comparison, complete mutation campaign,
   AFL summary, static/live dogfood, and native containment attack results.
6. Complete and sign the security attestation described in
   [security-review.md](security-review.md).

At `E`, verify the exact candidate identity:

```text
python -B scripts/verify_release_version.py --tag vX.Y.Z
just release-evidence E_COMMIT vX.Y.Z
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

The dry-run URL and every evidence digest are recorded before tagging. Missing
or tampered evidence, a performance self-comparison, unresolved critical/high
finding, untracked accepted risk, wrong parent, unrelated changed path, or bad
maintainer signature blocks publication; none is an acceptable waiver.

The tag workflow depends on the complete reusable CI and mutation workflows,
the four-platform builds, release evidence, and bundle assembly. Every
third-party action and containment image uses an immutable pin. The publish job
alone receives write, OIDC, attestation, and artifact-metadata permissions.

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

The opam package installs one analyzer executable and only the public
config/report schemas. Native helpers remain separately versioned release
assets that communicate over canonical JSON; they do not add a foreign library
to the analyzer process.
