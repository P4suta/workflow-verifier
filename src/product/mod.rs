#![forbid(unsafe_code)]

//! Product schemas, reports, policy, locking, diffing, and fixes.

mod config;
mod dependency_summary;
mod exit_code;
mod fixer;
mod graph_output;
mod local_linker;
mod lockfile;
mod policy;
mod policy_fixture;
mod report;
mod resolver;
mod sarif;
mod semantic_conformance;
mod semantic_diff;
mod serde_views;

pub use crate::verifier::Severity;
pub use config::{
    AllowlistEntry, AnalysisBudget, Config, ConfigParseOptions, ConfigProvenance, ConfigTrust,
    ResolverConfig, ResolverOrigin, SandboxConfig, Suppression,
};
pub use dependency_summary::DependencySummary;
pub use exit_code::{
    EXIT_CODE_FINDING, EXIT_CODE_INCOMPLETE, EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_INVALID_INPUT,
    EXIT_CODE_PASS, EXIT_CODE_SANDBOX_INFRASTRUCTURE,
};
pub use fixer::{FixProposal, FixShell};
pub use graph_output::{
    GraphDocumentView, GraphKind, authenticate_graph_document, graph_to_canonical_json,
    graph_to_dot,
};
pub use local_linker::link_local;
pub use lockfile::{LockEntry, Lockfile};
pub use policy::{
    PolicyPredicate, PolicyRule, PolicyRuleKind, PolicySelector, PolicyTrust, evaluate_policy,
    policy_predicate,
};
pub use policy_fixture::{PolicyExpectation, PolicyFixtureResult, evaluate_policy_fixture};
pub use report::{
    AnalysisProvenance, BuildInfo, CheckReportView, Gate, GateResult, ReportInput, TOOL_NAME,
    TOOL_VERSION, authenticate_check_report, canonical_provider_profiles,
};
pub use resolver::{
    DependencyFetcher, FetchedDependency, ResolutionResult, SemanticSource, immutable_revision,
    resolve_dependencies,
};
pub use sarif::SarifView;
#[doc(hidden)]
pub use semantic_conformance::SemanticConformanceView;
pub use semantic_diff::{PathChange, SemanticChange, SemanticDiff, semantic_diff};
