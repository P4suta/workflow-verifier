use std::path::Path;

use workflow_verifier_runner_protocol::{
    Control, Descriptor, LaunchError, RunResult, ValidatedPlan, validate_launch,
};

#[cfg(target_os = "windows")]
mod platform;

const CONTROLS: &[Control] = &[
    Control::SourceReadOnly,
    Control::ScratchOverlay,
    Control::NetworkDeny,
    Control::ProcessIsolation,
    Control::ResourceLimits,
    Control::SecretRedaction,
    Control::AppContainer,
    Control::RestrictedToken,
    Control::JobObject,
];

/// Returns the exact protocol identity and atomically probed controls.
#[must_use]
pub fn descriptor() -> Descriptor {
    let reasons = platform_reasons();
    Descriptor {
        id: "windows-native",
        version: env!("CARGO_PKG_VERSION"),
        platform: "windows",
        available: reasons.is_empty(),
        controls: CONTROLS.to_vec(),
        reasons,
    }
}

#[cfg(target_os = "windows")]
fn platform_reasons() -> Vec<String> {
    platform::probe()
}

#[cfg(not(target_os = "windows"))]
fn platform_reasons() -> Vec<String> {
    vec![format!(
        "windows-native requires Windows, current platform is {}",
        std::env::consts::OS
    )]
}

/// Validates and executes a runner plan under `AppContainer`, restricted-token,
/// and Job Object containment. No weaker backend is selected implicitly.
///
/// # Errors
///
/// Returns a fail-closed error when validation, containment setup, source
/// verification, process execution, or evidence collection fails.
pub fn launch(plan: &ValidatedPlan, source_root: &str) -> Result<RunResult, LaunchError> {
    let descriptor = descriptor();
    validate_launch(&descriptor, plan)?;
    platform_launch(plan, Path::new(source_root), &descriptor)
}

#[cfg(target_os = "windows")]
fn platform_launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    platform::launch(plan, source_root, descriptor)
}

#[cfg(not(target_os = "windows"))]
fn platform_launch(
    _plan: &ValidatedPlan,
    _source_root: &Path,
    _descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    Err(LaunchError::UnsupportedPlatform {
        backend: "windows-native".to_owned(),
        platform: std::env::consts::OS.to_owned(),
    })
}
