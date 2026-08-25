# Threat model

workflow-verifier treats the analyzed repository, its workflows, repository
configuration, caches, dependency metadata, helper paths, runtime inputs, and
network responses as untrusted. Trusted policy and release trust roots must be
outside the analyzed snapshot.

The analyzer protects correctness and availability against malformed UTF-8,
YAML/JSON/TOML, ambiguous paths, links and reparse points, source swaps,
resource exhaustion, cache poisoning, resolver redirects, and partial writes.
It uses one immutable source-manifest-v2 snapshot, strict resource limits,
content digests, direct argv process launch, bounded pipes/timeouts, and atomic
same-directory replacement. A resource limit produces
`Incomplete.Resource_limit`, never a partial pass.

Scenario replay protects against accidental over-execution. Only the selected
provider entrypoint, event, inputs, matrix instance, and job DAG may execute.
Unknown expressions, calls, services, caches, artifacts, and deployments are
typed Incomplete results. Static analysis remains broader than runtime replay.

Sandbox backends protect the source and host from the replayed command under
their declared effective controls. Network is denied by default; an allowlist
requires a destination policy and an enforceable egress broker. There is no
unrestricted fallback. Secrets are named in plans, granted individually at
runtime, and stream-redacted across chunk boundaries.

Evidence-v2 distinguishes observed events from final filesystem differences.
Absence of an event does not prove that an attempt was impossible. The hash
chain is tamper evidence under a trusted-host assumption; it is not
authentication against a hostile host. Optional eBPF/audit, ETW, or guest audit
records are forensic sidecars and are never required to claim the portable core.

Out of scope for v0.1 are a malicious kernel/hypervisor/administrator, hardware
faults, provider-complete runner emulation, and proof that an unobserved action
could not occur. These limits are machine-visible as unsupported contracts or
Incomplete results, not optimistic success.
