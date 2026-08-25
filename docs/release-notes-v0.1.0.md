# workflow-verifier v0.1.0

> **macOS trust limitation:** macOS executables are ad-hoc signed and the
> archives/checksums are signed with Sigstore. They do not have an Apple
> Developer ID signature or notarization and do not receive standard
> Gatekeeper trust. Verify the Sigstore bundle and checksum before following
> the manual launch instructions in the packaged troubleshooting guide.
>
> **Audit limitation:** this release has a signed sole-maintainer self-audit,
> not an independent security audit.

Version 0.1 provides offline semantic analysis for GitHub Actions, GitLab CI,
Azure Pipelines, and CircleCI plus concrete scenario replay through OCI,
Linux-native, Windows AppContainer, and macOS VM backends. Runtime replay is
limited to an explicit event/input/matrix/job scenario; unsupported runner
semantics are reported as `Incomplete` and are never guessed.

The release bundle includes strict public schemas, language-independent
conformance vectors, manual pages, four shell completions, English operational
documentation, a Japanese Quick Start, per-payload SPDX 2.3 SBOMs, aggregate
CycloneDX, THIRD_PARTY_NOTICES, corresponding source, signatures, and offline
release-evidence-v3.
