# Independent security review gate

An independent security review is a publication gate, not a self-attestation.
No release may be described as reviewed until a reviewer outside the
implementation team signs a report covering the commit and artifact digests.

The review scope is the parser and expression denial-of-service boundary,
untrusted/secret dataflow, authorization dominance, dependency resolution and
redirect/allowlist behavior, fix proof obligations, canonical protocol parsing,
evidence hash chains, and every native backend. The containment attack suite
must cover filesystem write and escape, network and loopback access, child
process escape, resource exhaustion, output/secret leakage, source races,
tampered plans, helpers, and VM images.

The review record must state the reviewed commit, candidate release tag,
reviewer identity and independence, methodology, environments and OS versions,
every finding with severity and disposition, residual risks, and a clear
approve/reject decision. Accepted residual risks require a maintainer, expiry,
and tracking issue. The signed report, its Sigstore bundle, and the binding
manifest are included in the release checksum manifest, SBOM, attestations, and
immutable release assets.

Before tagging, the approved report and its Sigstore bundle are placed under
`release-evidence/`. The manifest records the exact external certificate
identity and OIDC issuer. The release gate rejects signatures originating from
this implementation repository, validates the manifest and nested evidence,
and runs pinned Cosign verification before any publish permission is exercised.

The current development tree includes the review scope and reproducible attack
fixtures, but it does not claim that the required external review has occurred.
