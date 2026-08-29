#![forbid(unsafe_code)]

//! Pure, deterministic primitives shared by every analyzer layer.
//!
//! This crate deliberately has no filesystem, network, process, clock, locale,
//! or global-state API. Adapters turn external bytes into these owned values at
//! the product boundary.

pub mod budget;
pub mod dependency_identity;
pub mod digest;
pub mod json;
pub mod path;
pub mod span;

pub use budget::{Budget, BudgetError, BudgetKind, BudgetTracker};
pub use dependency_identity::{
    DependencyClass, GIT_SHA1_HEX_DIGITS, SHA256_HEX_DIGITS, classify_reference,
    valid_content_digest,
};
pub use digest::{ContentDigest as Digest, DigestBuilder, content_digest, sha256_hex};
pub use json::{JsonError, JsonLimits, JsonValue};
pub use path::{PathError, PublicPath, normalize_slashes, portable_path_key};
pub use span::{Position, SourceId, Span, Utf16Position, byte_to_utf16, utf16_to_byte};
