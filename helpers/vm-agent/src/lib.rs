use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use workflow_verifier_internal::internal::runner_protocol::vm::Observation;

#[cfg(target_os = "linux")]
mod platform;

/// Validates a guest path as a confined location below `/workspace`.
///
/// # Errors
///
/// Rejects host paths, parent traversal, empty components, and every path
/// outside the writable workspace share.
pub fn guest_working_directory(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    let safe = matches!(components.first(), Some(Component::RootDir))
        && matches!(components.get(1), Some(Component::Normal(name)) if *name == "workspace")
        && components
            .iter()
            .skip(2)
            .all(|component| matches!(component, Component::Normal(_)));
    if safe {
        Ok(path.to_path_buf())
    } else {
        Err(format!(
            "guest working directory escapes /workspace: {value}"
        ))
    }
}

/// Publishes a canonical guest observation with write-sync-rename semantics.
///
/// # Errors
///
/// Refuses to overwrite an existing response and returns I/O failures from
/// creation, writing, synchronization, or atomic rename.
pub fn write_observation(path: &Path, observation: &Observation) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite VM observation {}",
            path.display()
        ));
    }
    let temporary = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(std::ffi::OsStr::to_str)
            .map_or(String::new(), |extension| format!("{extension}."))
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("create VM observation: {error}"))?;
        file.write_all(observation.canonical_json().as_bytes())
            .map_err(|error| format!("write VM observation: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync VM observation: {error}"))?;
        drop(file);
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("publish VM observation: {error}"))?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync VM observation directory: {error}"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

/// Runs the Linux PID-1 guest agent.
///
/// # Errors
///
/// Returns an infrastructure reason when guest mounts, request validation,
/// cgroup setup, workload supervision, response publication, or shutdown fails.
pub fn run() -> Result<(), String> {
    platform_run()
}

#[cfg(target_os = "linux")]
fn platform_run() -> Result<(), String> {
    platform::run()
}

#[cfg(not(target_os = "linux"))]
fn platform_run() -> Result<(), String> {
    Err(format!(
        "workflow-verifier-vm-agent requires Linux, current platform is {}",
        std::env::consts::OS
    ))
}
