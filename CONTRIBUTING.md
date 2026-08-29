# Contributing

Contributions are welcome through focused pull requests. For significant
semantic or protocol changes, open an issue first so the proof obligation and
compatibility boundary are explicit.

Every production change follows red, green, refactor:

1. Add the smallest externally observable failing contract.
2. Implement only enough behavior to satisfy it without hiding `Unknown`.
3. Refactor responsibility to the owning architectural layer while the test
   remains green.

Run `just check` before submitting changes. At minimum, run `dune build @all`,
`dune runtest`, the Python tooling tests, and the relevant Rust workspace tests.
Commits must be signed and avoid mixing unrelated mechanical changes with
semantic behavior.

The repository is squash-only, and the squash subject is the pull request
title. Titles must use `type(optional-scope)(optional-!): summary`, where type
is one of `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`,
`chore`, `deps`, `revert`, or `style`. The summary must be nonempty. Dependabot
uses `deps(actions): ...` and `deps(rust): ...`; the automated Release PR uses
`chore: release vX.Y.Z`. Put `!` in the title for every breaking change; a
`BREAKING CHANGE` body without title `!` is insufficient. Branch protection
must require signed commits, the Conventional PR title check, and squash merge
subjects copied from the PR title.

Analyzer code must remain pure OCaml: do not add foreign stubs, dynamic
libraries, or subprocess-based linters. Optional operating-system containment
belongs under `helpers/` and communicates only through canonical runner
protocol JSON. New dependencies require a documented license, trust-boundary,
and supply-chain review.

Every new diagnostic needs positive, negative, and unknown-propagation
fixtures. Security rules also need a complete source-to-effect trace and an
explicit confidence classification.

Pull requests must explain the red test, architectural ownership, verification
performed, compatibility impact, and any evidence that remains unavailable.
Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public
issue.
