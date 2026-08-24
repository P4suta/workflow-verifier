# Sole-maintainer security attestation

`workflow-verifier` has one maintainer, `P4suta`. The release gate records that
fact directly: the maintainer performs and signs a security self-attestation.
No second reviewer is implied.

The required scope is closed and machine checked:

- YAML parser and expression denial-of-service boundaries;
- untrusted and secret dataflow;
- authorization dominance;
- dependency resolution, redirects, and allowlists;
- fix proof obligations;
- canonical protocols and evidence hash chains; and
- OCI, Linux, Windows, and macOS native containment backends.

Containment review includes filesystem write and escape, network and loopback
access, child-process escape, resource exhaustion, output and secret leakage,
source races, tampered plans, helpers, and VM images. Static and live dogfood,
the four-platform determinism comparison, the complete mutation catalog, AFL,
the 400-repository corpus, and the pinned official-project suite are inputs to
the decision.

`maintainer-security-attestation-v1.json` records candidate commit `C`, the
planned tag, maintainer, public review URL, completion timestamp, the complete
scope, findings, residual risks, and an `approve` or `reject` decision. Critical
and high findings must be resolved. Every accepted or open lower-severity
finding and every residual risk requires an HTTPS tracking URL, accountable
owner, and non-overdue due date. The verifier fails closed on missing fields,
unknown fields, duplicate identifiers, incomplete scope, or a non-`approve`
decision.

The exact canonical JSON bytes are signed with the maintainer SSH key and the
dedicated namespace:

```text
ssh-keygen -Y sign -f MAINTAINER_KEY -n workflow-verifier-release \
  release-evidence/maintainer-security-attestation-v1.json
```

The public key and signing identity are pinned in
`release-evidence/maintainer-allowed-signers`. The v2 verifier checks the
detached signature with `ssh-keygen -Y verify`; substituting the allowed-signers
file, identity, namespace, attestation bytes, or signature is a hard failure.

Potential upstream findings are rechecked against the provider specification
and the actual input boundary. Confirmed confidential issues use the upstream
private security channel. Confirmed non-confidential issues use an existing or
new public issue after duplicate search. Unconfirmed diagnostics are not sent
upstream and remain local analysis data.
