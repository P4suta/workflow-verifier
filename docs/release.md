# Release procedure

> macOS artifacts use ad-hoc code signatures plus Sigstore. They have no
> Developer ID signature or Apple notarization and do not receive standard
> Gatekeeper trust.
>
> The security review is a signed sole-maintainer self-audit. It is not an
> independent audit.

A product candidate commit `C` contains implementation, schemas, documentation,
and no passing candidate evidence. Build the unsigned Linux x86_64, Linux
arm64, Windows x86_64, macOS arm64, and macOS x86_64 payloads from `C` twice in clean roots with
`SOURCE_DATE_EPOCH` and path remapping. The two unsigned builds must be byte
identical.

The protected [candidate workflow](../.github/workflows/candidate.yml) accepts
an exact lowercase commit and version only when that commit is the current
`main`. It creates source and schema archives twice from Git objects, builds
each product/helper bundle twice in separate extracted roots, and aggregates
all five platform fragments plus the source fragment into one `reproducible-build`
`release-gate-v1`. Linux x86_64 is
built in a digest-pinned Rocky Linux 8 root and every ELF is checked against the
glibc 2.28 and `DT_NEEDED` policy; Linux arm64 must pass the same floor with its
native loader. The fixed GitHub runner labels are `ubuntu-24.04-arm`,
`windows-2025`, `macos-15` (arm64), and `macos-15-intel` (x86_64). The macOS
build applies timestamp-free ad-hoc signatures with fixed identifiers before
the two archive bytes are compared.

The candidate workflow Sigstore-signs the Linux, macOS, source, corresponding
source, schema, and helper archives in the protected `candidate-signing`
environment. Publication of the Action and all release assets remains disabled
in source until a separate approval adds an audited publication job. The
candidate deliberately leaves the Windows product unsigned. Run the
protected [Windows signing workflow](../.github/workflows/sign-windows.yml) at
the same exact `C`, supplying the successful candidate run id, SHA-256 of
`windows-unsigned-payload.zip`, exact version, and expected publisher. That
workflow authenticates the producer run, sends only the three executables to
SSL.com, verifies their Authenticode chains and timestamps, deterministically
repackages the product and helper archives, Sigstore-signs both archives, then
re-expands and verifies the final product a second time.

These workflows do not invent a capsule, kernel, root filesystem, performance
result, containment result, malware result, or signature result. The
architecture-specific macOS boot bundles must be made from their pinned kernel,
rootfs, and static guest-agent inputs with `scripts/build_vm_bundle.py`; runtime
capsules and any copyleft corresponding source must likewise come from exact
inventories. Until both Linux architectures, both macOS architectures, the
Windows build, runtime capsule, all real-host gates, and their SBOM/signature
records exist, `release-evidence-v4` remains
unverifiable and no `E` commit or tag may be created.

Run every required release gate against those exact bytes: static and unit
quality, fuzz and complete mutation, fresh immutable 400-repository analysis,
five-platform determinism and performance, OCI/Linux/Windows/macOS containment
attacks, clean installs, reproducibility, CodeQL, dependency/secret/license
scans, SBOM checks, signature verification, malware scans, and the self-audit.
A gate emits strict `release-gate-v1` evidence bound to `C`. Critical, High,
or unclassified scanner findings block release.

Dogfood SARIF is validated against the
[OASIS SARIF 2.1.0 Errata 01 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json).
CI downloads only that URL, verifies SHA-256
`c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`,
then runs `scripts/verify_sarif.py`; a schema identity, digest, format, or
document validation error blocks the gate.

Windows executables are timestamped and Authenticode-signed through the
protected SSL.com cloud/HSM environment, then their chain, publisher, and
timestamp are independently rechecked. Every Mach-O is ad-hoc signed with only
its required entitlements. Sigstore covers product and support assets. Each
payload has an SPDX 2.3 SBOM; one aggregate CycloneDX document includes OCaml,
Cargo, toolchains, capsules, kernels, and VM assets. THIRD_PARTY_NOTICES and
corresponding source are required.

Create a single-parent child commit `E` that changes only
`release-evidence/**`. Its canonical `release-evidence-v4.json` binds the
candidate, exactly one product and helper bundle for every release platform,
both architecture-specific macOS boot bundles, source archive, every remaining
artifact and signature, all gates, both disclosures, and the detached
SSH-signed `maintainer-self-audit-v2`.
Verify offline:

```text
just release-evidence E v0.1.0
```

After verification, create a separate final release index and checksum file
covering product assets, evidence, SBOMs, notices, and source archive. The index
does not list its own digest, which avoids a digest cycle. Sign it with Sigstore.

The protected release environment promotes those exact bytes; it does not
rebuild them. Only after final manual approval is the signed `v0.1.0` tag
attached to `E` and the GitHub Release published. Submit the same immutable,
checksum-pinned static source archive to opam. After publication, repeat
download, signature, checksum, installation, Quick Start, and offline evidence
verification from clean hosts. Never replace a published asset; issue a fixed
release.
