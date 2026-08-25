# Language-independent canonical contracts

All protocol text is UTF-8 without a BOM. JSON producers emit one object,
lexicographically sort member names by Unicode scalar byte sequence, use no
insignificant whitespace, use lowercase JSON literals and decimal integers,
escape only required characters, reject non-finite numbers, and append exactly
one LF. Consumers reject duplicate keys, invalid UTF-8, unknown fields, wrong
types, unknown enum values, and out-of-range integers.

A content digest is `sha256:` followed by 64 lowercase hexadecimal digits. A
self-digest is SHA-256 over the canonical object with its digest member omitted.
Event-chain digest input is the canonical object containing body,
previous_digest, and sequence, without the final LF. Sequence zero names the
plan digest as its previous digest.

Public paths use forward slashes, valid UTF-8, no drive prefix or leading slash,
and no empty, dot, or dot-dot segment. Locations are relative to the immutable
source-manifest-v2 root. Portable collision comparison applies Unicode
normalization and case folding; a collision is an input error, not a winner
selection.

The source manifest records every product-default or trusted-policy exclusion.
Trusted exclusion prefixes use the same portable path grammar and the canonical
exclusion set is covered by `exclusion_policy_digest` and the manifest digest.

Unknown semantic information is a typed state with a location and reason.
Unknown cannot become proved, passing, executable, or suppressed merely because
one consumer lacks a feature. Resource exhaustion is
`Incomplete.Resource_limit`.

Diagnostics sort by root-relative span, rule ID, and stable diagnostic ID.
Severity is critical, error, warning, or note. Every diagnostic includes
confidence, message, trace, capabilities, evidence, optional fix, and rule help
identity. A fix is staged, reparsed, reanalyzed, and committed only if all source
digests still match.

The conformance manifest binds valid and invalid vectors, their exact bytes,
sizes, expected accept/reject result, and SHA-256. OCaml and every future Rust
analyzer must match all entries.
