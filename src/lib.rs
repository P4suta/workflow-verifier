#![forbid(unsafe_code)]
#![doc = "`workflow-verifier` is distributed as a command-line application.\n\nThe library target exists only so the repository's private, separately signed helper binaries can share the versioned runner protocol and runtime support. Everything under [`internal`] is doc-hidden, is not a supported Rust API, and carries no `SemVer` compatibility promise. The stable contracts are the CLI, exit codes, published JSON schemas, and helper wire protocol."]

#[cfg(feature = "cli")]
mod application;
#[cfg(feature = "cli")]
mod domain;
#[cfg(feature = "cli")]
mod engine;
#[cfg(any(feature = "cli", feature = "conformance-support"))]
mod foundation;
#[cfg(feature = "cli")]
mod frontend;
#[cfg(feature = "cli")]
mod product;
#[cfg(feature = "cli")]
mod sandbox;
#[cfg(feature = "cli")]
mod syntax;
#[cfg(feature = "cli")]
mod verifier;

/// Private implementation surface shared with repository-owned packages.
///
/// This module is deliberately excluded from the supported Rust API and may
/// change without a SemVer-major release.
#[doc(hidden)]
pub mod internal;

/// Process entry point used by this package's binary target.
#[cfg(feature = "cli")]
#[doc(hidden)]
#[must_use]
pub fn run_env() -> i32 {
    application::run_env()
}
