# workflow-verifier

[![CI](https://github.com/P4suta/workflow-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/workflow-verifier/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

`workflow-verifier` is an offline-by-default semantic verifier and isolated
execution planner for GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI
2.1. All four frontends lower into one phase-aware graph, so correctness,
untrusted data, secrets, capabilities, effects, dependency integrity,
authorization dominance, and semantic changes are evaluated by one model.

The static analyzer, resolver model, policy engine, and CLI are pure OCaml.
They do not shell out to provider linters and contain no foreign bindings.
Optional OCI and native containment helpers consume a separately versioned,
canonical JSON protocol and fail closed when a requested control is absent.
Architecture is the first product requirement: private libraries form a strict
one-way dependency graph, expected incompleteness is a typed `Unknown`, and
every production change follows red/green/refactor.

## Implemented surface

- The lossless YAML CST retains spans, comments, scalar style, anchors, aliases,
  merge keys, duplicate keys, malformed regions, and exact source bytes. The
  pinned MIT `yaml-test-suite` release is exercised across all 402 cases.
- Four provider compilers produce common trigger, parameter, workflow, stage,
  job, step, call, command, gate, resource, effect, and opaque nodes. Referenced
  local actions, reusable workflows, includes, child pipelines, and templates
  are recursively compiled and linked with content-addressed workspace evidence.
- Abstract interpretation, ROBDD conditions, graph fixed points, taint,
  dominance, capabilities/effects, least privilege, supply-chain integrity,
  semantic diff, policies, and safe CST fixes retain proof state and traces.
- Explicit network resolution supports immutable GitHub source trees, GitLab
  components and project files, Azure tasks and repository templates, CircleCI
  production orbs, OCI manifests, and allowlisted direct HTTPS includes. The
  resolver separately retains exact action/task/template/orb semantic source in
  `lock-v2`; unavailable JavaScript, Docker, or task implementations remain
  explicit `Unknown` even when their metadata and archive digest are locked.
- OCI, Linux-native, Windows-native, and macOS-VM helpers implement their native
  controls behind the same canonical runner/evidence protocol.

## Development status

Version `0.1.0-dev` is **not a release candidate**. The implementation and
automated gates are present, but publication additionally requires reviewed
external evidence: the license-clear 400-repository corpus, an approved
platform performance baseline, a completed independent security review, and
successful mutation/native-containment runs on release infrastructure. Missing
evidence is never represented as a passing result. The protected tag workflow
requires a commit- and tag-bound `release-evidence-v1` bundle and verifies the
external review's Sigstore signature before its publish job can run.

## Quick start

```text
workflow-verifier check .
workflow-verifier check --format json --output report-v1.json .
workflow-verifier resolve --allow-network .
workflow-verifier explain WV-SEC-001 .
workflow-verifier graph --kind dataflow --format dot .
workflow-verifier diff ./base ./head
workflow-verifier fix .                  # prints a patch
workflow-verifier fix --apply .          # explicit source mutation
workflow-verifier sandbox plan .
workflow-verifier sandbox run --backend oci:docker .
workflow-verifier doctor
```

Resolution, dependency refresh, source mutation, secret use, workflow network,
and execution each require a separate opt-in. If the selected host cannot
establish every required containment control, execution fails with exit 5; it
never silently substitutes a weaker backend.

Exit codes are stable: `0` pass, `1` finding/policy failure, `2` input or
configuration error, `3` strict incomplete result, `4` internal failure, and
`5` sandbox infrastructure failure. The default `gate` persona fails only on
proved correctness errors and high-confidence security findings. `Unknown`
facts remain visible in every machine-readable report.

## Trust boundary

`check`, `explain`, `graph`, `diff`, and dry-run `fix` are deterministic,
read-only, and network-free. `resolve`, `fix --apply`, and `sandbox run` each
require their own explicit opt-in. Runtime observations can corroborate a
static effect; absence from a finite run never proves impossibility.

`just check` (or `mise run check`) runs local contracts, YAML conformance,
tooling, architecture/purity audits, native helper checks, and install-surface
verification. Property, AFL, mutation, corpus, performance, and determinism
tasks are named separately because some require platform tools or reviewed
evidence. Hosted CI also runs every public CLI command against all four real
provider entrypoints and independently verifies the OCI runtime evidence chain.

See [architecture](docs/architecture.md), [TDD ledger](docs/tdd.md),
[policy language](docs/policy.md), [sandbox protocol](docs/sandbox-protocol.md),
and [evaluation gates](docs/evaluation.md).
