# Sandbox protocol v1

Plans and evidence are canonical JSON: UTF-8, LF, sorted object keys, no
insignificant whitespace, and integers only. A plan binds the source digest,
lock digest, backend, controls, steps, resource limits, and secret *names*.
Secret values are transported out-of-band and must not occur in the plan.

Backends must attest each requested control. Missing namespace/AppContainer/VM,
filesystem, network, process, resource, or redaction controls produce
`Incomplete` or infrastructure exit 5; a weaker backend is never selected
implicitly. Evidence events form a SHA-256 chain over the canonical previous
digest and event body.

## Planning and completeness

The plan smart constructor validates digests, unique dependency and step IDs,
portable secret names, positive limits, and backend identity before hashing the
unsigned canonical body. Dependencies are available only with exact lock or
local-workspace digests. An unresolved dependency, unresolved execution image,
unsupported call/opaque step, or digest mismatch makes the plan `Incomplete`;
the runner cannot relabel it as successful execution.

Source input is mounted read-only from a canonical source-tree manifest. Writes
go to a scratch overlay. Network is denied unless the caller separately passes
the workflow-network opt-in. Secret values never cross the plan boundary; the
executor injects them ephemerally and redacts observations before evidence
serialization.

## Backends

- `oci:<engine>` drives Docker or Podman with argv-only process transport,
  read-only source, scratch storage, network/resource/process controls, and no
  implicit engine selection.
- `linux-native` uses a separate Rust helper for user/mount/PID/network
  namespaces, seccomp, Landlock, and delegated cgroup v2 controls.
- `windows-native` establishes an AppContainer, restricted token, and Job Object
  before starting the workload.
- `macos-vm` verifies a content-addressed VM bundle, launches the signed
  Virtualization.framework shim, and receives guest observations through the
  versioned VM-agent protocol.

Every backend first returns a typed attestation. Platform absence, unsupported
kernel facilities, a tampered helper or plan, or partial setup is an
infrastructure failure. No backend falls back to OCI or unsandboxed execution
unless that backend was explicitly selected in a new plan.

## Evidence reconciliation

Events cover backend/control attestations, process start/exit, filesystem and
network attempts, and artifact digests. Replay authenticates the entire chain
and its plan binding. Audit checks current source identity and requested
controls, then reconciles observed effects with the static effect envelope.
Unexpected observations violate the runtime property; an unobserved static
effect remains possible rather than becoming a proof of absence.
