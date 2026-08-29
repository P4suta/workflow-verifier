use std::path::Path;

use workflow_verifier_internal::internal::runner_protocol::{
    Control, Descriptor, LaunchError, RunResult, ValidatedPlan, validate_launch,
};

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod namespaces;
#[cfg(target_os = "linux")]
mod platform;
#[cfg(target_os = "linux")]
mod seccomp;

const CONTROLS: &[Control] = &[
    Control::SourceReadOnly,
    Control::ScratchOverlay,
    Control::NetworkDeny,
    Control::ProcessIsolation,
    Control::ResourceLimits,
    Control::SecretRedaction,
    Control::Namespace,
    Control::Seccomp,
    Control::Landlock,
    Control::CgroupV2,
];

/// Returns the exact protocol identity and atomically probed controls.
#[must_use]
pub fn descriptor() -> Descriptor {
    let reasons = platform_reasons();
    Descriptor {
        id: "linux-native",
        version: env!("CARGO_PKG_VERSION"),
        platform: "linux",
        available: reasons.is_empty(),
        controls: CONTROLS.to_vec(),
        reasons,
    }
}

#[cfg(target_os = "linux")]
fn platform_reasons() -> Vec<String> {
    platform::probe()
}

#[cfg(not(target_os = "linux"))]
fn platform_reasons() -> Vec<String> {
    vec![format!(
        "linux-native requires Linux, current platform is {}",
        std::env::consts::OS
    )]
}

/// Validates and executes a runner plan under namespace, `Landlock`, seccomp,
/// and cgroup v2 containment. No weaker backend is selected implicitly.
///
/// # Errors
///
/// Returns a fail-closed error when validation, containment setup, source
/// verification, process execution, or evidence collection fails.
pub fn launch(plan: &ValidatedPlan, source_root: &str) -> Result<RunResult, LaunchError> {
    launch_with_exclusions(plan, source_root, &[])
}

#[doc(hidden)]
pub fn launch_with_exclusions(
    plan: &ValidatedPlan,
    source_root: &str,
    trusted_exclusions: &[String],
) -> Result<RunResult, LaunchError> {
    let descriptor = descriptor();
    validate_launch(&descriptor, plan)?;
    platform_launch(
        plan,
        Path::new(source_root),
        trusted_exclusions,
        &descriptor,
    )
}

/// Handles private broker and capability-probe modes before normal protocol
/// dispatch. These modes never execute without first installing their controls.
#[doc(hidden)]
#[must_use]
pub fn broker_main(arguments: &[String]) -> Option<i32> {
    platform_broker_main(arguments)
}

#[cfg(target_os = "linux")]
fn platform_broker_main(arguments: &[String]) -> Option<i32> {
    platform::broker_main(arguments)
}

#[cfg(not(target_os = "linux"))]
fn platform_broker_main(_arguments: &[String]) -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
fn platform_launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    trusted_exclusions: &[String],
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    platform::launch(plan, source_root, trusted_exclusions, descriptor)
}

#[cfg(not(target_os = "linux"))]
fn platform_launch(
    _plan: &ValidatedPlan,
    _source_root: &Path,
    _trusted_exclusions: &[String],
    _descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    Err(LaunchError::UnsupportedPlatform {
        backend: "linux-native".to_owned(),
        platform: std::env::consts::OS.to_owned(),
    })
}
