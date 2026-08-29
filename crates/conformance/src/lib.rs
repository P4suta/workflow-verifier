#![forbid(unsafe_code)]

//! Private command wrapper around the root package's non-SemVer conformance
//! implementation.

pub use workflow_verifier_internal::internal::conformance::{
    SemanticComparison, compare_documents,
};
