#![forbid(unsafe_code)]

//! Scenario planning and fail-closed sandbox coordination.

mod audit;
mod planner;
mod runner_plan;
mod scenario;
mod source_manifest;

pub use audit::{SandboxAudit, SandboxAuditStatus};
pub use planner::{ScenarioPlan, plan_scenario};
pub use runner_plan::{Backend, RunnerPlan, RunnerPlanRequest, portable_limits};
pub use scenario::{RunnerPlatform, Scenario};
pub use source_manifest::{
    ManifestBudget, ManifestEntry, ManifestEntryKind, ManifestExclusion,
    SOURCE_MANIFEST_V2_MIN_ENTRIES, SOURCE_MANIFEST_V2_MIN_FILE_BYTES,
    SOURCE_MANIFEST_V2_MIN_SNAPSHOT_BYTES, SourceFile, SourceManifest,
};
pub use workflow_verifier_runner_protocol::{
    Control, Dependency, Evidence, Limits, Outcome, PlanStatus, RunResult, Step, ValidatedPlan,
    validate_plan,
};
