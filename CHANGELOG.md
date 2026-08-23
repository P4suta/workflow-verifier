# Changelog

All notable changes are recorded here. The project follows Semantic Versioning
after the first compatibility release.

## 0.1.0-dev

- Establish the lossless YAML CST, shared CI IR, four provider frontends,
  verifier, deterministic report formats, lockfile, policy language, semantic
  diff, safe edit engine, and versioned sandbox protocol.
- Add recursive content-addressed workspace linking for local actions, reusable
  workflows, GitLab child/includes, and Azure templates without broadening
  filesystem or network authority.
- Separate user-visible dependency references from typed repository/file
  locators and implement immutable GitHub, GitLab, Azure, CircleCI, direct HTTPS,
  and OCI resolver transports.
- Add `lock-v2` exact-source dependency summaries. Composite actions, reusable
  units, templates, components, and CircleCI command/orb bodies reuse the four
  frontends; binary metadata remains explicitly incomplete, and `lock-v1`
  stays readable without hiding missing semantic evidence.
- Add OCI plus Linux, Windows, and macOS native containment helpers, VM guest
  protocol, source manifests, hash-chained evidence, replay, audit, and
  static/runtime reconciliation.
- Add declarative policy fixtures, SARIF, semantic graph/diff output,
  behavior-proved fixes, and opt-in incremental analysis cache.
- Add deterministic property contracts, AFL fuzzing, mutation evidence,
  400-repository precision/recall tooling, performance regression tooling,
  four-platform byte comparison, deterministic packages, SPDX SBOM/checksums,
  signing, and provenance attestations.
- Counterbalance baseline and candidate performance batches to remove hosted
  runner order bias, and require a commit-bound external evidence manifest plus
  a verified independent-review Sigstore identity before publication.
- Make subcommand help side-effect free, make tag publication depend on the full
  reusable CI and mutation gates, and eliminate parallel Windows AppContainer
  temporary-resource collisions with atomic runtime reservations.
- Keep literal and folded block-scalar payloads outside flow-collection
  validation, including action metadata with Markdown links, and exercise
  current `lock-v2` determinism separately from canonical `lock-v1`
  compatibility.
