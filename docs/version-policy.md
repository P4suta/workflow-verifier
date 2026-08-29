# Version policy

Protocol names are semantic identities. Once published, a schema name and field
meaning never change. Compatible additions use a new versioned schema when
strict consumers would otherwise reject them.

The Cargo `[workspace.package].version` is the sole product-version authority.
Rust obtains its CLI, report, LSP, resolver User-Agent, and helper fallback
versions from `CARGO_PKG_VERSION`. The retained OCaml reference uses the
internal `Product_version` module. Dune, generated and locked opam metadata,
Python release-tool metadata, the manual page, Cargo.lock workspace packages,
and exact workspace path-dependency constraints are derived surfaces. Run
`just sync-release-version` after changing the Cargo authority; CI runs
`python -B scripts/sync_release_version.py --check` and rejects drift.

During 0.x this project follows Cargo's SemVer convention: compatible `feat`,
`fix`, `perf`, `refactor`, and `revert` changes increment patch. A breaking
change increments minor and must carry `!` in the squash subject, for example
`feat(parser)!: remove the legacy scalar field`. A footer alone is not the
project's breaking-change signal. `docs`, `test`, `build`, `ci`, `chore`,
`deps`, and `style` changes do not create a new version unless their title has
`!`. cargo-semver-checks remains an additional detector for Rust public API
breakage. Deprecation is announced in the changelog and migration guide. The
first stable release will add a longer compatibility window.

Release-plz owns version calculation and the linked, dated changelog sections,
but only through a Draft Release PR. It never publishes a crate, creates a tag,
or creates a GitHub Release in this repository.

Valid/invalid vectors, canonical expected bytes, and SHA-256 digests are the
cross-language authority. A future Rust implementation is compatible only when
it matches all vectors, not merely when its decoded data is similar.
