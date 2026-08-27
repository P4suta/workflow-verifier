#![forbid(unsafe_code)]

//! Product schemas, reports, policy, locking, diffing, and fixes.

mod config;
mod config_migration;
mod dependency_summary;
mod exit_code;
mod fixer;
mod graph_output;
mod incremental_cache;
mod local_linker;
mod lockfile;
mod policy;
mod policy_fixture;
mod report;
mod resolver;
mod sarif;
mod semantic_diff;

pub use config::{
    AllowlistEntry, AnalysisBudget, Config, ConfigParseOptions, ConfigProvenance, ConfigTrust,
    ResolverConfig, ResolverOrigin, SandboxConfig, Suppression,
};
pub use config_migration::migrate_config_v1;
pub use dependency_summary::DependencySummary;
pub use exit_code::{
    EXIT_CODE_FINDING, EXIT_CODE_INCOMPLETE, EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_INVALID_INPUT,
    EXIT_CODE_PASS, EXIT_CODE_SANDBOX_INFRASTRUCTURE,
};
pub use fixer::{FixProposal, FixShell};
pub use graph_output::{GraphKind, graph_to_canonical_json, graph_to_dot};
pub use incremental_cache::{AnalysisCacheEntry, CacheKeyInput, cache_key};
pub use local_linker::link_local;
pub use lockfile::{LockEntry, Lockfile};
pub use policy::{
    PolicyPredicate, PolicyRule, PolicyRuleKind, PolicySelector, PolicyTrust, evaluate_policy,
    policy_predicate,
};
pub use policy_fixture::{PolicyExpectation, PolicyFixtureResult, evaluate_policy_fixture};
pub use report::{
    BuildInfo, GateResult, Report, ReportInput, ReportProvenance, TOOL_NAME, TOOL_VERSION,
};
pub use resolver::{
    DependencyFetcher, FetchedDependency, ResolutionResult, SemanticSource, immutable_revision,
    resolve_dependencies,
};
pub use sarif::report_to_sarif;
pub use semantic_diff::{PathChange, SemanticChange, SemanticDiff, semantic_diff};
pub use workflow_verifier_verifier::Severity;
