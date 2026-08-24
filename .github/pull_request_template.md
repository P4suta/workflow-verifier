## Purpose

Describe the user-visible semantic change and the architectural layer that owns it.

## TDD evidence

- Red contract:
- Green implementation:
- Refactor boundary:

## Verification

- [ ] Relevant OCaml contracts pass.
- [ ] Relevant Rust helper tests pass, or this change does not touch helpers.
- [ ] Python tooling tests pass, or this change does not touch tooling.
- [ ] Architecture and pure-OCaml gates pass.
- [ ] Documentation and versioned schemas are updated where required.
- [ ] New behavior includes positive, negative, and `Unknown` cases.
- [ ] No secret, private workflow, or sensitive runner evidence is included.
- [ ] Compatibility and release-note impact is described below.

## Compatibility and evidence

List protocol, report, lockfile, policy, or CLI compatibility effects and link
the corresponding evidence. Publication-affecting evidence must be complete;
an absent platform or external result keeps the release gate closed.
