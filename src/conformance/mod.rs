//! Test-only cross-implementation semantic conformance and contract surfaces.

mod semantic;

pub use semantic::{SemanticComparison, compare_documents};

// Integration contracts exercise the same layer APIs that were public only
// because the implementation used to be split into publishable-looking
// crates. They remain available under this explicitly non-SemVer namespace.
#[cfg(feature = "cli")]
pub mod application {
    pub use crate::application::{auth, lsp, network, resolver_transport};
}

#[cfg(feature = "cli")]
pub mod domain {
    pub use crate::domain::*;
}

#[cfg(feature = "cli")]
pub mod engine {
    pub use crate::engine::*;
}

pub mod foundation {
    pub use crate::foundation::*;
}

#[cfg(feature = "cli")]
pub mod frontend {
    pub use crate::frontend::*;
}

#[cfg(feature = "cli")]
pub mod product {
    pub use crate::product::*;
}

#[cfg(feature = "cli")]
pub mod sandbox {
    pub use crate::sandbox::*;
}

#[cfg(feature = "cli")]
pub mod syntax {
    pub use crate::syntax::*;
}

#[cfg(feature = "cli")]
pub mod verifier {
    pub use crate::verifier::*;
}
