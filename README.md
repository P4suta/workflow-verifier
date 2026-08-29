# workflow-verifier

[![CI](https://github.com/P4suta/workflow-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/workflow-verifier/actions/workflows/ci.yml)
[![CodeQL Advanced](https://github.com/P4suta/workflow-verifier/actions/workflows/codeql.yml/badge.svg)](https://github.com/P4suta/workflow-verifier/actions/workflows/codeql.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

`workflow-verifier` is an offline-by-default semantic verifier and isolated
execution planner for GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI
2.1. All four frontends lower into one phase-aware graph, so correctness,
untrusted data, secrets, capabilities, effects, dependency integrity,
authorization dominance, and semantic changes are evaluated by one model.

The shipped Rust product uses a pure core with no
filesystem, network, process, global mutable state, `unsafe`, or input-derived
panic boundary. The retained OCaml executable, `workflow-verifier-reference`,
is a development-only semantic oracle used by differential tests; it is not
included in user binary archives. The Rust application boundary uses an
embedded rustls HTTPS client and direct-argv OS process APIs for explicitly
authorized resolver and sandbox helpers.
Optional OCI and native containment helpers consume a separately versioned,
canonical JSON protocol and fail closed when a requested control is absent.
Architecture is the first product requirement: private libraries form a strict
one-way dependency graph, expected incompleteness is a typed `Unknown`, and
every production change follows red/green/refactor.

## Implemented surface

- The lossless YAML CST retains spans, comments, scalar style, anchors, aliases,
  merge keys, duplicate keys, malformed regions, and exact source bytes. The
  typed upstream pin projects the immutable MIT `yaml-test-suite` Git tree into
  402 real case directories and 1,887 regular files. Symlink aliases and
  non-case files are never followed; every worker authenticates the canonical
  manifest and its independently pinned tree SHA-256 before exercising all
  cases.
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

## Distribution limitations

macOS executables are ad-hoc signed and release checksums are signed with
Sigstore. They have no Developer ID signature or Apple notarization, so they do
not receive standard Gatekeeper trust. The release audit is a signed
sole-maintainer self-audit, not an independent security assessment. These are
the only accepted v0.1 release exceptions and are also machine-readable in
`release-evidence-v4`.

## Development status

The tree carries version `0.1.0` as the first release candidate. It is not a
published release until the protected `v0.1.0` tag exists. Publication requires
the license-clear 400-repository corpus, pinned official-project compatibility,
an approved five-platform performance baseline, complete mutation and native
containment runs, and a signed sole-maintainer self-audit. Missing evidence is
never represented as a passing result. `release-evidence-v4` binds exact
product artifacts, per-payload SBOMs, signatures, and every gate to candidate
commit `C` in an evidence-only child commit `E`; the future tag points to `E`
only after offline verification and protected promotion pass.

## Quick start

Once protected publication is complete, install the analyzer from crates.io
with the release lockfile:

```sh
cargo install --locked workflow-verifier
```

Then run it from a workflow repository:

```sh
workflow-verifier check .
workflow-verifier check --format json --output report.json .
workflow-verifier resolve --allow-network .
workflow-verifier explain WV-SEC-001 .
workflow-verifier graph --kind dataflow --format dot .
workflow-verifier diff ./base ./head
workflow-verifier fix .                  # prints a patch
workflow-verifier fix --apply .          # explicit source mutation
workflow-verifier sandbox plan --job build .
workflow-verifier sandbox run --job build --backend oci:docker .
workflow-verifier doctor
workflow-verifier auth status
workflow-verifier lsp
```

The crates.io package installs only the `workflow-verifier` executable. Native,
OCI, macOS, Windows, and VM helpers remain private packages delivered in signed
release bundles. If a requested helper is not installed and authenticated, the
CLI reports that backend as unavailable and fails closed.

Resolution, dependency refresh, source mutation, secret use, workflow network,
and execution each require a separate opt-in. If the selected host cannot
establish every required containment control, execution fails with exit 5; it
never silently substitutes a weaker backend.

Exit codes are stable: `0` pass, `1` finding/policy failure, `2` input or
configuration error, `3` strict incomplete result, `4` internal failure, and
`5` sandbox infrastructure failure. The default `gate` persona fails only on
proved correctness errors and high-confidence security findings. `Unknown`
facts remain visible in every machine-readable report.

JSON checks use the single `workflow-verifier-report/1` contract. The check
report contains gate, diagnostic, property, completeness, provenance, and input
summary data but no graph body. Use `graph --format json` for the separate
`workflow-verifier-graph/1` document with dense numeric node IDs.

The stable compatibility surface is the CLI, exit codes, JSON schemas, and
helper wire protocol. The Rust library target exists only to share protocol and
runtime code with the private helper packages; its doc-hidden `internal` module
is not a supported API and is not covered by semantic-versioning guarantees.

## GitHub Action

The official Action source is included but remains unpublished until the
candidate is approved. Once the `v0.1.0` Action tag and matching Rust binary
archive are published, install that verified binary on the runner and invoke:

```yaml
- uses: P4suta/workflow-verifier@v0.1.0
  with:
    binary: /usr/local/bin/workflow-verifier
    path: .
    format: sarif
    output: workflow-verifier.sarif
    resolve: 'true'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

The token value is never placed in argv. During explicit resolution the Action
passes only
`github@github.com=WORKFLOW_VERIFIER_ACTION_GITHUB_TOKEN` to
`--auth-from-env`, removes the credential before `check`, and deletes its
temporary lock. The Action does not trust repository configuration implicitly.

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
