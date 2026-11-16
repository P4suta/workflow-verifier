# Usage and distribution

The Rust product analyzes GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI workflows through one semantic graph.
The development-only `workflow-verifier-reference` OCaml executable serves as a differential-test oracle.

## Build from source

The first release candidate is unpublished.
From a checkout with the pinned tools installed, build the CLI with:

```sh
mise x -- cargo build --locked -p workflow-verifier
```

The commands below assume the resulting executable is on your path.
Run `target/debug/workflow-verifier` or its Windows `.exe` equivalent from the checkout instead.

## CLI

```sh
workflow-verifier check .
workflow-verifier check --format json --output report.json .
workflow-verifier resolve --allow-network .
workflow-verifier explain WV-SEC-001 .
workflow-verifier graph --kind dataflow --format dot .
workflow-verifier diff ./base ./head
workflow-verifier fix .
workflow-verifier fix --apply .
workflow-verifier policy test --config policy.toml fixtures/
workflow-verifier sandbox plan --job build .
workflow-verifier sandbox run --job build --backend oci:docker .
workflow-verifier sandbox replay evidence.json
workflow-verifier sandbox verify plan.json evidence.json
workflow-verifier sandbox audit plan.json evidence.json .
workflow-verifier doctor
workflow-verifier auth login github
workflow-verifier auth status
workflow-verifier auth logout github
workflow-verifier completion zsh
workflow-verifier version
workflow-verifier lsp
```

`policy test` evaluates every `*.expect.json` fixture sidecar under the target against the loaded policy.
`sandbox replay` prints the canonical form of recorded evidence.
`sandbox verify` checks that evidence belongs to its execution plan.
`sandbox audit` also reconciles the evidence with the plan, and with a fresh analysis when you name the source target, and exits with code 3 when it can't verify the run.
`auth login` stores a credential in the OS credential store from an interactive terminal, and `auth logout` removes it.
`completion` prints a `bash`, `zsh`, `fish`, or `powershell` completion script.
`lsp` serves the Language Server Protocol over standard input and output, and also accepts the conventional `--stdio` flag.

`check`, `explain`, `graph`, `diff`, and dry-run `fix` are read-only and network-free.
Resolution, dependency refresh, source edits, secret use, workflow network access, and execution require their own opt-in.
If a host lacks a requested containment control, execution fails with exit code 5.
Runtime observations can support a static effect; a finite run never proves that an effect is impossible.

Exit codes are 0 for pass, 1 for a finding or policy failure, 2 for invalid input or configuration, 3 for strict incompleteness, 4 for internal failure, and 5 for sandbox infrastructure failure.
The default gate persona fails on proved correctness errors and high-confidence security findings.
Unknown facts remain visible in reports.

JSON checks use `workflow-verifier-report/1`.
Use `graph --format json` for the separate `workflow-verifier-graph/1` document.
The supported compatibility surface is the CLI, exit codes, JSON schemas, and helper protocol.
The Rust library's internal modules are not a supported API.

## Distribution status

Publication requires the protected release gates and exact `release-evidence-v4` candidate evidence.
The planned macOS distribution uses ad-hoc signing without Developer ID or Apple notarization and does not receive standard Gatekeeper trust.
Its sole-maintainer self-audit is not an independent security assessment.
See [release requirements](release.md) and [evaluation evidence](evaluation.md).

Private native and OCI helpers are separate from the public CLI package.
A missing or unauthenticated helper makes that backend unavailable.

## GitHub Action

The Action source is included, but its release tag and matching binary archive remain unpublished.
After protected publication, install the verified binary and use:

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

The Action passes the resolution token through an environment binding and removes it before analysis.
It does not place the token in argv or trust repository configuration by default.

See [architecture](architecture.md), [policy](policy.md), [sandbox protocol](sandbox-protocol.md), and [contributing](../CONTRIBUTING.md).
