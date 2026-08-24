# Release evidence bundle

`workflow-verifier` is maintained by one person. Publication therefore uses a
signed, explicitly named maintainer self-attestation; it does not claim an
independent review that did not occur.

Release evidence is created in two commits:

1. Candidate commit `C` contains the code, version, changelog, and release
   machinery.
2. Its single child `E` changes only `release-evidence/**` and contains
   measurements for `C`, `release-evidence-v2.json`, and the detached signed
   `maintainer-security-attestation-v1.json`.
3. The planned tag points to `E`. The verifier requires `E` to have exactly
   one parent, `C`, and rejects any non-evidence change in `E`.

The v2 manifest binds `C` and the planned tag to:

- a passing 400-repository `corpus-report-v1`, with 100 repositories for each
  supported provider and precision/recall of 1.0;
- the deterministic pinned eight-repository `official-compat-v1` report;
- passing cold, warm, and incremental comparisons against an independent
  baseline on Linux x86-64, Windows x86-64, macOS arm64, and macOS x86-64;
- the sole-maintainer security attestation and its detached SSH signature.

The attestation must cover every security scope named by its schema. Critical
and high findings must be resolved. Every accepted or open lower-severity item
and every residual risk needs an HTTPS tracking URL, accountable owner, and
non-overdue due date. The decision is fail-closed unless it is `approve`.

The trusted public key is pinned in `maintainer-allowed-signers`. Sign the exact
attestation bytes with namespace `workflow-verifier-release`, then run:

```text
just release-evidence E v0.1.0
```

No passing example manifest is committed in candidate commit `C`: real
evidence is added only by commit `E`, after all measurements of `C` complete.
