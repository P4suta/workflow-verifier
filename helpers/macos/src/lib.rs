use std::path::Path;

use workflow_verifier_runner_protocol::{
    Control, Descriptor, LaunchError, RunResult, ValidatedPlan, validate_launch,
};

mod bundle;
mod controller;
#[cfg(target_os = "macos")]
mod platform;

pub use bundle::VmBundle;
pub use controller::{VmExecution, VmTransport, execute_vm_step};

const CONTROLS: &[Control] = &[
    Control::SourceReadOnly,
    Control::ScratchOverlay,
    Control::NetworkDeny,
    Control::ProcessIsolation,
    Control::ResourceLimits,
    Control::SecretRedaction,
    Control::VirtualMachine,
];

/// Returns the exact protocol identity and atomically probed controls.
#[must_use]
pub fn descriptor() -> Descriptor {
    let reasons = platform_reasons();
    Descriptor {
        id: "macos-vm",
        version: env!("CARGO_PKG_VERSION"),
        platform: "macos",
        available: reasons.is_empty(),
        controls: CONTROLS.to_vec(),
        reasons,
    }
}

#[cfg(target_os = "macos")]
fn platform_reasons() -> Vec<String> {
    platform::probe()
}

#[cfg(not(target_os = "macos"))]
fn platform_reasons() -> Vec<String> {
    vec![format!(
        "macos-vm requires macOS, current platform is {}",
        std::env::consts::OS
    )]
}

/// Validates and executes a runner plan through the signed macOS VM shim.
/// No process-level or weaker sandbox fallback is selected implicitly.
///
/// # Errors
///
/// Returns a fail-closed error when validation, bundle verification, VM
/// containment setup, process execution, or evidence collection fails.
pub fn launch(plan: &ValidatedPlan, source_root: &str) -> Result<RunResult, LaunchError> {
    let descriptor = descriptor();
    validate_launch(&descriptor, plan)?;
    platform_launch(plan, Path::new(source_root), &descriptor)
}

#[cfg(target_os = "macos")]
fn platform_launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    platform::launch(plan, source_root, descriptor)
}

#[cfg(not(target_os = "macos"))]
fn platform_launch(
    _plan: &ValidatedPlan,
    _source_root: &Path,
    _descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    Err(LaunchError::UnsupportedPlatform {
        backend: "macos-vm".to_owned(),
        platform: std::env::consts::OS.to_owned(),
    })
}
