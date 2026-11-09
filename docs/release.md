# Release procedure

> macOS artifacts use ad-hoc code signatures plus Sigstore.
> They have no Developer ID signature or Apple notarization and don't receive standard Gatekeeper trust.
>
> The security review is a signed sole-maintainer self-audit.
> The review isn't an independent audit.

## Draft release PR preparation

Release-plz prepares metadata only.
The [Release PR workflow](../.github/workflows/release-pr.yml) runs after each `main` push or a manual dispatch and opens or updates one Draft PR named `chore: release vX.Y.Z`.
Its configuration disables registry publication, Git tags, and GitHub Releases.
Those actions remain behind the protected candidate and publication process below.

The [credential guide](credential-delivery.md) defines native Doppler synchronization into the main-only release-pr environment without administrator bypass.
The synchronization supplies `RELEASE_APP_CLIENT_ID` and `RELEASE_APP_PRIVATE_KEY` as named environment secrets.
The App token action selects only workflow-verifier and requests contents and pull request write permissions.
The shared App key retains authority across its installations.
Keep the repository squash-only, use the PR title as the squash subject, require signed commits, and require the normal CI checks.
An App-authored release proposal starts ordinary pull-request CI.
If the repository becomes private, revalidate release-plz authentication when fetching an existing PR branch because checkout credentials remain unpersisted.

The first run treats the unpublished Cargo `0.1.0` as the initial release.
It keeps that version and populates the standard empty `Unreleased` changelog with a linked, dated `0.1.0` section from Git history.
Later qualifying commits use Cargo's 0.x SemVer rules described in [the version policy](version-policy.md).
The enabling PR is also the bootstrap commit: squash it with the truthful qualifying title `fix: derive product versions from Cargo metadata`.
The `release_commits` filter ignores a `ci:` or `chore:` title, so either title prevents the initial draft.
The push from that qualifying squash merge starts the first run.

When a release train is ready, freeze `main` so release-plz can't add another commit to the draft PR.
On the PR branch run:

```text
just sync-release-version
python -B scripts/sync_release_version.py --check
```

Review the derived Dune/opam/Python/manual/OCaml/Cargo dependency changes and the generated changelog, then add them as a signed maintainer commit.
Keep `main` unchanged after synchronization.
If `main` moves, let release-plz refresh the draft and repeat synchronization.
After CI passes, mark the PR ready and squash-merge it.
The exact resulting `main` commit is candidate `C`.
Release-plz never runs its `release` command.

## Protected candidate and publication

A product candidate commit `C` contains implementation, schemas, and documentation, with no passing candidate evidence.
Build the unsigned Linux x86_64, Linux arm64, Windows x86_64, macOS arm64, and macOS x86_64 payloads from `C` twice in clean roots with `SOURCE_DATE_EPOCH` and path remapping.
The two unsigned builds must be byte identical.

The protected [candidate workflow](../.github/workflows/candidate.yml) accepts an exact lowercase commit and version only when that commit is the current `main`.
The workflow creates source and schema archives twice from Git objects and builds each product/helper bundle twice in separate extracted roots.
It combines all five platform fragments and the source fragment into one `reproducible-build` gate using `release-gate-v1`.
It runs `cargo package` twice and requires byte-identical `.crate` files.
It audits the strict package inventory and packaged Cargo version control commit, then records the SHA-256 digest in `crate-package-v1`.
The Linux x86_64 build uses a digest-pinned Rocky Linux 8 root.
Every Executable and Linkable Format binary must meet the glibc 2.28 and `DT_NEEDED` policy.
Linux arm64 must pass the same compatibility floor with its native loader.
The fixed GitHub runner labels are `ubuntu-24.04-arm`, `windows-2025`, `macos-15` for arm64, and `macos-15-intel` for x86_64.
The macOS build applies timestamp-free ad-hoc signatures with fixed identifiers before comparing the two archives byte for byte.

The candidate workflow Sigstore-signs the Linux, macOS, source, corresponding source, schema, and helper archives in the protected `candidate-signing` environment.
The source prevents publication of the Action and all release assets.
crates.io publication is a separate protected job described below.
The candidate leaves the Windows product unsigned.
Run the protected [Windows signing workflow](../.github/workflows/sign-windows.yml) at the same exact `C`, supplying the successful candidate run ID, SHA-256 of `windows-unsigned-payload.zip`, exact version, and expected publisher.
The signing workflow authenticates the producer run and sends only the three executables to SSL.com.
It verifies their Authenticode chains and timestamps, deterministically repackages the product and helper archives, and Sigstore-signs both archives.
It then re-expands and verifies the final product a second time.

The workflows don't invent a capsule, kernel, root filesystem, performance result, containment result, malware result, or signature result.
Build the architecture-specific macOS boot bundles from their pinned kernel, rootfs, and static guest-agent inputs with `scripts/build_vm_bundle.py`.
Runtime capsules and any copyleft corresponding source must also come from exact inventories.
Both Linux architectures, both macOS architectures, the Windows build, and the runtime capsule must exist before verification of `release-evidence-v4`.
All real-host gates and their software bill of materials and signature records must also exist.
Until every prerequisite exists, verification must fail and maintainers must avoid creating an `E` commit or tag.

Run every required release gate on the exact candidate bytes.
The gates cover static and unit quality, fuzz and complete mutation, fresh immutable 400-repository analysis, and five-platform determinism and performance.
They include OCI/Linux/Windows/macOS containment attacks, clean installs, reproducibility, CodeQL, and dependency, secret, and license scans.
Software bill of materials checks, signature verification, malware scans, and the self-audit are also mandatory.
A gate emits strict `release-gate-v1` evidence bound to `C`.
Critical, High, or unclassified scanner findings block release.

Validate dogfood SARIF with the [official SARIF 2.1.0 Errata 01 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json).
CI downloads only the linked schema URL and verifies SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.
CI then runs `scripts/verify_sarif.py`.
A schema identity, digest, format, or document validation error blocks the gate.

Timestamp and Authenticode-sign Windows executables through the protected SSL.com cloud environment backed by a hardware security module.
Independently recheck the chain, publisher, and timestamp.
Apply an ad-hoc signature to every Mach-O with only its required entitlements.
Sigstore covers product and support assets.
Each payload has an SPDX 2.3 software bill of materials.
One combined CycloneDX document includes OCaml, Cargo, toolchains, capsules, kernels, and VM assets.
Include `THIRD_PARTY_NOTICES` and corresponding source.

Create a single-parent child commit `E` that changes only `release-evidence/**`.
Its canonical `release-evidence-v4.json` binds the candidate to exactly one product and helper bundle for every release platform.
It also binds both architecture-specific macOS boot bundles, the source archive, every remaining artifact and signature, and the exact `workflow-verifier-<version>.crate` digest.
The manifest includes all gates, both disclosures, and the detached SSH-signed `maintainer-self-audit-v2`.
Verify offline:

```text
just release-evidence E v0.1.0
```

After verification, create a separate final release index and checksum file covering product assets, evidence, SBOMs, notices, and source archive.
The index excludes its own digest to avoid a digest cycle.
Sign it with Sigstore.

The release workflow stages those exact GitHub assets without publishing them.
Its manually approved `crate-publication` job checks out candidate `C` rather than evidence commit `E`.
The job regenerates the `.crate` twice, compares its digest with `release-evidence-v4` evidence, and runs `cargo publish --locked -p workflow-verifier`.
If the exact version already exists, the job downloads the registry bytes and succeeds only when their digest matches.
A different digest or an already-acquired name with no matching version is a hard failure.
The job then installs the registry version, checks the embedded commit and CLI version, and performs a basic analysis.
The protected registry token is a first-publication bootstrap credential.
crates.io can't configure trusted publishing before the crate exists.
The workflow refuses a different later version once the registry contains the crate name.
After the initial publication, revoke that token and configure an OIDC trusted publisher before adding any future-version publication workflow.
GitHub Release, Action, tag, and opam publication remain separate approval boundaries.
Never replace a published asset or crates.io version.
Issue a fixed release.
