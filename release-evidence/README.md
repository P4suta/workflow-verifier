# Release evidence bundle

No passing candidate evidence is committed on the product commit `C`. The old
0.1 candidate evidence was discarded when the v2 protocols and trust boundary
were rebuilt.

After every required check has run against the exact unsigned artifacts from
`C`, one single-parent child commit `E` may add only `release-evidence/**`.
`release-evidence-v4.json` binds all of the following to `C` and the planned
tag:

- the four product archives, four platform-specific helper bundles, source
  archive, runtime capsule, both architecture-specific macOS boot bundles,
  schemas, corresponding source, and notices;
- the byte-reproducible `workflow-verifier-<version>.crate`, including its
  packaged Cargo VCS commit and SHA-256 digest;
- a signature record for every executable payload;
- one SPDX 2.3 SBOM per payload and one aggregate CycloneDX SBOM;
- every required quality, corpus, mutation, fuzz, determinism, performance,
  containment, clean-install, reproducibility, scanner, signature, and malware
  gate;
- the canonical, detached-SSH-signed sole-maintainer self-audit.

The verifier rejects missing gates, stale candidate identities, changed
artifacts, failed or unclassified scanner results, invalid signature records,
incomplete SBOM coverage, a non-evidence child commit, and non-canonical JSON.

Two limitations are intentionally prominent and machine-readable:

1. macOS binaries use ad-hoc code signatures and release assets use Sigstore;
   there is no Developer ID signature or Apple notarization.
2. The project has one maintainer and the signed audit is a self-audit, not an
   independent security review.

The pinned self-audit identity is in `maintainer-allowed-signers`. Sign the
exact canonical audit bytes with namespace `workflow-verifier-release`, then
verify `E` with:

```text
just release-evidence E v0.1.0
```

The candidate and Windows-signing workflows produce only evidence they can
actually observe. In particular, the candidate workflow does not synthesize a
passing runtime capsule, macOS boot bundle, real-host containment result, or
scanner result. Missing external assets or protected-environment runs therefore
keep this directory without a passing v4 manifest.

The final release index and checksum signature are created after v4 evidence
verification. They cover product assets, the evidence bundle, SBOMs, and the
source archive without including their own digest, avoiding a digest cycle.
