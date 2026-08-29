# Sole-maintainer security review

Version 0.1 has no independent audit. The only release review is a signed,
machine-verifiable sole-maintainer self-audit, and release pages must disclose
that limitation prominently.

`maintainer-self-audit-v2.json` is canonical JSON bound to candidate commit
`C`, planned tag, public review URL, the implementation/threat-model/release
control scope, both accepted disclosures, and an empty findings array. Any
known finding makes the audit invalid. Its detached SSH signature uses the
identity in `release-evidence/maintainer-allowed-signers` and namespace
`workflow-verifier-release`.

```text
ssh-keygen -Y sign -n workflow-verifier-release \
  release-evidence/maintainer-self-audit-v2.json
```

`release-evidence-v4` binds the audit and signature digests. The offline
verifier fixes the maintainer identity and namespace, checks canonical bytes,
requires `independent_audit=false`, and rejects any stale subject, disclosure
change, finding, missing signature, or changed allowed-signers identity.

The review covers trust expansion through repository configuration, cache and
resolver poisoning, filesystem races and links, process and secret leakage,
scenario over-execution, backend containment, network enforcement, evidence
claims, release provenance, signing, SBOM coverage, and data-loss recovery.
The threat model is in [threat-model.md](threat-model.md).

Repository dogfood uses
[`examples/dogfood-policy-v2.toml`](../examples/dogfood-policy-v2.toml) only
with the explicit repository-trust grant. Its path-scoped, owned, expiring
suppressions document two protected boundaries. For Windows signing, strict
workflow inputs are validated before use and HSM credentials intentionally
reach the pinned SSL.com signing action. For Draft Release PR preparation, the
pinned token action uses the App private key to mint one short-lived,
repository-scoped token, and only the pinned release-plz action receives that
token. Expiry makes each exception fail closed unless it is reviewed again.
