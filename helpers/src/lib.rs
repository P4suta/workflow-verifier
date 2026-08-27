#![forbid(unsafe_code)]

//! Compatibility package for tooling which historically selected
//! `helpers/Cargo.toml`. All helper crates now belong to the repository-root
//! workspace and share its single lock file.

/// The protocol version shared by analyzer and native helpers.
pub const RUNNER_PROTOCOL: &str = "runner-v2";
