# workflow-verifier

A Rust CLI for offline analysis of GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI workflows.
It checks workflow semantics and trust boundaries and can plan execution through optional isolation helpers.

The first release candidate is still in development.
Published packages and Action tags are not available yet.
See [usage and distribution limits](docs/usage.md).

## Try from source

From this checkout with the pinned tools installed:

```sh
mise x -- cargo run --locked -p workflow-verifier -- check .
```

Network resolution, source edits, and sandbox execution require explicit opt-in.

## Documentation

- [CLI usage](docs/usage.md)
- [Policy language](docs/policy.md)
- [Sandbox protocol](docs/sandbox-protocol.md)
- [Architecture](docs/architecture.md)
- [Development](CONTRIBUTING.md)
- [Evaluation and releases](docs/evaluation.md)

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
