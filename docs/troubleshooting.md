# Troubleshooting

Start with `workflow-verifier doctor --format json`. doctor-v2 lists every
backend even when unavailable and provides its path, digest, signature state,
protocol, controls, required features, and failure reasons.

Exit 2 means malformed CLI input, config, scenario, or protocol. Correct the
location and suggestion printed with the error; unknown, duplicate, missing,
or extra arguments are rejected before side effects. Use `migrate` only for
config-v1 or lock-v1.

Exit 3 means analysis or planning is explicitly incomplete. Inspect
`completeness.reasons` or `status.reasons`; common causes are a resource
limit, unknown expression, unsupported provider runtime feature, unresolved
local call, missing matrix value, or missing digest-pinned tool capsule.

Exit 5 means the requested containment cannot be established. A helper selected
through `WORKFLOW_VERIFIER_*_HELPER` also needs the matching
`WORKFLOW_VERIFIER_*_HELPER_SHA256` value. The digest is rechecked immediately
before probe and execution. Network allowlists require an enforceable broker;
there is no direct-network fallback.

For macOS downloads, verify SHA256SUMS and its Sigstore bundle, then use the
documented manual launch flow. The binaries are ad-hoc signed, not notarized.
Do not disable Gatekeeper globally.
