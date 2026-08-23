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
Commits must be signed, use a descriptive imperative subject, and avoid mixing
unrelated mechanical changes with semantic behavior.

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
