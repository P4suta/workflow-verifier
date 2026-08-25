# Version policy

Protocol names are semantic identities. Once published, a schema name and field
meaning never change. Compatible additions use a new versioned schema when
strict consumers would otherwise reject them.

During 0.x, minor releases may add or replace CLI options and schema versions.
Patch releases fix implementation defects without redefining existing
contracts. Deprecation is announced in the changelog and migration guide. The
first stable release will add a longer compatibility window.

Valid/invalid vectors, canonical expected bytes, and SHA-256 digests are the
cross-language authority. A future Rust implementation is compatible only when
it matches all vectors, not merely when its decoded data is similar.
