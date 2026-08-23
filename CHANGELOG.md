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
- Reconcile mutation evidence against one pinned-runner catalog, distribute its
  immutable full IDs across deterministic hexadecimal shards, and require the
  completed report union to equal that catalog without omission or duplication.
- Bind each mutation shard's canonical runner exit to its report, retain raw and
  reconciled evidence on every outcome, and aggregate complete failing campaigns
  without confusing evidence generation with publication success.
- Preserve mutation subprocess evidence as valid UTF-8 even when a mutant emits
  hostile bytes, recording the retained raw SHA-256 and encoding-error count;
  give every managed Dune command its own private build directory so concurrent
  workers cannot turn lock contention into false mutant kills.
- Export the pinned 402-case yaml-test-suite directly from immutable Git blobs
  into 1,887 regular files, excluding symlink aliases and non-case content. Pin
  and reauthenticate the canonical manifest tree SHA-256 before every worker
  uses the oracle outside the analyzed snapshot.
- Add reviewed semantic fingerprints over config, policy, shell adapters,
  graph/dataflow/capability analysis, and the whole verifier so broad behavioral
  regressions fail early in the mutation stage.
- Add atomic GitHub corpus acquisition with immutable source/license evidence
  and a separate exhaustive, reason-required diagnostic review phase, plus
  digest-verified network-free reanalysis into a new transaction.
- Period-balance baseline and candidate performance one sample at a time to
  remove hosted runner order bias, and require a commit-bound external evidence
  manifest plus a verified independent-review Sigstore identity before publication.
- Make subcommand help side-effect free, make tag publication depend on the full
  reusable CI and mutation gates, and eliminate parallel Windows AppContainer
  temporary-resource collisions with atomic runtime reservations.
- Keep literal and folded block-scalar payloads outside flow-collection
  validation, including action metadata with Markdown links, and exercise
  current `lock-v2` determinism separately from canonical `lock-v1`
  compatibility.
- Preserve forward progress when a block scalar is the final CRLF-terminated
  YAML node; model GitLab inheritance/manual gates and CircleCI invocation
  aliases/parameter bindings explicitly; and distinguish observed secret,
  authorization, and permission violations from unresolved external behavior.
- Parse top-level shell pipelines and redirections so stdout, private files,
  dynamic destinations, and credential-consuming network sinks remain distinct;
  centralize command-source effect inference; and require structured approval or
  protected-ref evidence instead of authorization keywords in Gate labels.
- Reject unvalidated corpus repository paths before network fetch or cleanup, so
  a failed candidate can never escape the private acquisition transaction.
- Make the analyzer library core total: quote state is represented by closed
  variants, structured encoders own their field lists, BDD application is
  exhaustive, graph traversal carries nonempty paths, lock updates are
  transactional, invalid boundaries return `Error`, and the architecture gate
  rejects partial API regressions.
- Centralize local, commit, and SHA-256 dependency identity in the foundation
  layer so frontends, policy, and the verifier cannot disagree about mutable
  references or accept an invalid lock digest; refresh and exhaustively review
  the complete 400-repository evaluation corpus against that classification.
- Make mutation workers single-writer and observable with authenticated runner
  exits, periodic heartbeats, and four-worker hosted backpressure; reject
  process-spawn or Dune-lock failures instead of counting infrastructure faults
  as detected mutants.
