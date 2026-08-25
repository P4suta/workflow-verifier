# Sandbox backend capabilities

| Backend | Typed runtime | Required isolation | Network enforcement | Availability decision |
|---|---|---|---|---|
| OCI (Docker/Podman) | digest-pinned OCI capsule | read-only source, scratch overlay, process/resource controls | complete deny | engine probe, platform materialization, trusted helper digest, `--pull=never` |
| Linux native | same capsule rootfs | namespaces, overlay, pivot/chroot, seccomp, cgroup v2, measured Landlock ABI | namespace deny | measured kernel features; version strings alone are insufficient |
| Windows AppContainer | windows-runtime-profile | AppContainer, restricted token, Job Object | capability-free AppContainer deny | OS build, architecture, tool/digest/signature and capability fingerprint |
| macOS VM | capsule plus boot bundle | Virtualization.framework VM and static guest agent | guest deny | architecture-specific kernel/initrd/agent digests and shim entitlement check |

Portable limits have one meaning on every backend: wall time 900 seconds, one
CPU core, 2 GiB process-tree memory, 128 processes, 16 MiB combined output, and
4 GiB/100,000-entry scratch. Requested, effective, and observed values are
recorded in evidence-v2.

The default Linux capsule contains sh/bash, coreutils, git, curl, and CA
certificates. A scenario requiring Python, PowerShell, or another tool needs a
separately digest-pinned capsule; otherwise planning is Incomplete. `doctor`
reports every backend in doctor-v2 with availability, reasons, path, digest,
signature state, protocol, controls, and required host features.

The bundled v0.1 helpers attest complete network denial. A plan that requests
an allowlisted destination also requests `egress_broker`; because the bundled
helpers do not attest that control, launch fails closed with exit 5. There is
no direct or unrestricted fallback. A future separately trusted helper may add
a destination-enforcing broker without changing `runner-v2`.
