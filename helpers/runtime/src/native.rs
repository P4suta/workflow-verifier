use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use workflow_verifier_runner_protocol::{
    Descriptor, Evidence, EvidenceBody, LaunchError, Outcome, RunResult, Step, ValidatedPlan,
    controls_digest, validate_launch,
};

use crate::{ChangeKind, PrivateSourceTree, ProcessObservation, ScratchTree, source_snapshot};

/// Supplies only the explicitly named secrets requested by a runner plan.
pub trait SecretProvider {
    fn value(&self, name: &str) -> Option<String>;
}

/// Reads secrets from the helper process environment at the last responsible moment.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentSecrets;

impl SecretProvider for EnvironmentSecrets {
    fn value(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Deterministic secret provider used by tests and embedders.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MapSecrets(BTreeMap<String, String>);

impl<const N: usize> From<[(String, String); N]> for MapSecrets {
    fn from(entries: [(String, String); N]) -> Self {
        Self(entries.into())
    }
}

impl SecretProvider for MapSecrets {
    fn value(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

/// A single step after source verification and workspace-path confinement.
pub struct NativeStepRequest<'a> {
    pub plan: &'a ValidatedPlan,
    pub step: &'a Step,
    pub source_root: &'a Path,
    pub scratch_root: &'a Path,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
}

/// Private filesystem roots that an OS adapter must authorize atomically
/// before the runtime emits control attestations.
pub struct NativeSandboxRequest<'a> {
    pub plan: &'a ValidatedPlan,
    pub source_root: &'a Path,
    pub scratch_root: &'a Path,
}

/// Optional backend-owned parents for the runtime's two private filesystem
/// views. Keeping the choices independent prevents writable-scratch grants
/// from leaking into the read-only source view through inheritance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeStorageParents {
    /// Parent for the immutable private source copy.
    pub source_parent: Option<PathBuf>,
    /// Parent for the mutable private scratch copy.
    pub scratch_parent: Option<PathBuf>,
}

/// Operating-system containment boundary used by the common evidence runner.
pub trait NativeSandbox {
    /// Selects backend-owned parents for the private source and scratch trees.
    /// Each omitted parent defaults independently to the controller's temporary
    /// directory.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the backend cannot obtain its isolated
    /// storage parents.
    fn storage_parents(&mut self) -> Result<NativeStorageParents, String> {
        Ok(NativeStorageParents::default())
    }

    /// Installs every advertised control for the private source and scratch roots.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific reason when the complete containment session
    /// cannot be installed. Callers must treat this as an infrastructure failure.
    fn prepare(&mut self, request: &NativeSandboxRequest<'_>) -> Result<(), String>;

    /// Executes one step inside the already prepared containment session.
    ///
    /// # Errors
    ///
    /// Returns a platform-specific reason when the contained process cannot be
    /// created, observed, or terminated according to the plan limits.
    fn run(&mut self, request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String>;
}

/// Small adapter for deterministic tests and simple embedders.
pub struct ClosureSandbox<P, R> {
    prepare: P,
    run: R,
}

impl<P, R> ClosureSandbox<P, R> {
    #[must_use]
    pub fn new(prepare: P, run: R) -> Self {
        Self { prepare, run }
    }
}

impl<P, R> NativeSandbox for ClosureSandbox<P, R>
where
    P: for<'a> FnMut(&NativeSandboxRequest<'a>) -> Result<(), String>,
    R: for<'a> FnMut(&NativeStepRequest<'a>) -> Result<ProcessObservation, String>,
{
    fn prepare(&mut self, request: &NativeSandboxRequest<'_>) -> Result<(), String> {
        (self.prepare)(request)
    }

    fn run(&mut self, request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String> {
        (self.run)(request)
    }
}

fn workspace_relative(value: &str) -> Result<PathBuf, LaunchError> {
    let normalized = value.replace('\\', "/");
    let relative = if normalized == "/workspace" {
        ""
    } else {
        normalized.strip_prefix("/workspace/").ok_or_else(|| {
            LaunchError::InvalidPlan(format!(
                "working directory must stay below /workspace: {value}"
            ))
        })?
    };
    let path = Path::new(relative);
    if path.components().any(|component| {
        !matches!(component, Component::Normal(_))
            || component
                .as_os_str()
                .to_str()
                .is_none_or(|name| name.contains(':') || name.contains('\0'))
    }) {
        return Err(LaunchError::InvalidPlan(format!(
            "working directory is not a safe workspace path: {value}"
        )));
    }
    Ok(path.to_path_buf())
}

fn secret_values(plan: &ValidatedPlan, provider: &impl SecretProvider) -> Vec<(String, String)> {
    plan.secret_names
        .iter()
        .filter_map(|name| provider.value(name).map(|value| (name.clone(), value)))
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn redact_text(value: &str, secrets: &[(String, String)]) -> String {
    secrets.iter().fold(value.to_owned(), |text, (_, secret)| {
        if secret.is_empty() {
            text
        } else {
            text.replace(secret, "***")
        }
    })
}

fn observation_outcome(step: &Step, observation: &ProcessObservation) -> Outcome {
    if observation.timed_out {
        Outcome::TimedOut {
            step: step.id.clone(),
        }
    } else if observation.output_exceeded {
        Outcome::OutputLimitExceeded {
            step: step.id.clone(),
        }
    } else if observation.code == Some(0) {
        Outcome::Completed
    } else {
        Outcome::StepFailed {
            step: step.id.clone(),
            code: observation.code,
        }
    }
}

fn record_changes(evidence: &mut Evidence, scratch: &ScratchTree) -> Result<(), LaunchError> {
    for change in scratch.changes().map_err(LaunchError::Infrastructure)? {
        evidence.append(EvidenceBody::FilesystemAccess {
            path: change.path.clone(),
            operation: match change.kind {
                ChangeKind::Added | ChangeKind::Modified => "write".to_owned(),
                ChangeKind::Deleted => "delete".to_owned(),
            },
            allowed: true,
        });
        if change.kind != ChangeKind::Deleted {
            let digest = change.digest.ok_or_else(|| {
                LaunchError::Infrastructure("non-deleted scratch change has no digest".to_owned())
            })?;
            evidence.append(EvidenceBody::ArtifactRecorded {
                path: change.path,
                digest,
            });
        }
    }
    Ok(())
}

/// Runs a native plan while keeping source/scratch, secret, outcome, and
/// evidence semantics identical across operating-system containment adapters.
///
/// The adapter closure is the sole platform-specific boundary. It must create
/// the process only after all controls named by its available descriptor are
/// atomically installed.
///
/// # Errors
///
/// Fails closed before launch on an unavailable backend, source mismatch,
/// unsafe workspace path, or scratch setup error. Adapter failures are treated
/// as sandbox infrastructure failures and have secret values redacted.
pub fn execute_native<S, N>(
    plan: &ValidatedPlan,
    descriptor: &Descriptor,
    source_root: &Path,
    secrets: &S,
    sandbox: &mut N,
) -> Result<RunResult, LaunchError>
where
    S: SecretProvider,
    N: NativeSandbox,
{
    validate_launch(descriptor, plan)?;
    let source_root = source_root
        .canonicalize()
        .map_err(|error| LaunchError::Infrastructure(error.to_string()))?;
    let baseline = source_snapshot(&source_root).map_err(LaunchError::Infrastructure)?;
    if baseline.manifest.digest != plan.source_digest {
        return Err(LaunchError::InvalidPlan(format!(
            "source digest mismatch: plan {}, actual {}",
            plan.source_digest, baseline.manifest.digest
        )));
    }
    let secret_values = secret_values(plan, secrets);
    let storage = sandbox
        .storage_parents()
        .map_err(|error| LaunchError::Infrastructure(redact_text(&error, &secret_values)))?;
    let source_storage = storage.source_parent.unwrap_or_else(std::env::temp_dir);
    let scratch_storage = storage.scratch_parent.unwrap_or_else(std::env::temp_dir);
    let source_view = PrivateSourceTree::prepare_in(&source_root, &baseline, &source_storage)
        .map_err(LaunchError::Infrastructure)?;
    let scratch = ScratchTree::prepare_in(&source_root, baseline, &scratch_storage)
        .map_err(LaunchError::Infrastructure)?;
    sandbox
        .prepare(&NativeSandboxRequest {
            plan,
            source_root: source_view.path(),
            scratch_root: scratch.path(),
        })
        .map_err(|error| LaunchError::Infrastructure(redact_text(&error, &secret_values)))?;
    let mut evidence = Evidence::new(plan.digest.clone());
    evidence.append(EvidenceBody::BackendAttested {
        id: descriptor.id.to_owned(),
        version: descriptor.version.to_owned(),
        platform: descriptor.platform.to_owned(),
        controls_digest: controls_digest(&plan.controls),
    });
    for control in &plan.controls {
        evidence.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }

    let mut outcome = Outcome::Completed;
    for step in &plan.steps {
        let relative = workspace_relative(&step.working_directory)?;
        let working_directory = scratch.path().join(relative);
        if !working_directory.is_dir() {
            return Err(LaunchError::InvalidPlan(format!(
                "working directory does not exist in scratch: {}",
                step.working_directory
            )));
        }
        let mut environment = step.environment.clone();
        for (name, value) in &secret_values {
            environment.insert(name.clone(), value.clone());
        }
        let request = NativeStepRequest {
            plan,
            step,
            source_root: source_view.path(),
            scratch_root: scratch.path(),
            working_directory,
            environment,
        };
        let (executable, arguments) = step
            .argv
            .split_first()
            .ok_or_else(|| LaunchError::InvalidPlan(format!("step {} has empty argv", step.id)))?;
        evidence.append(EvidenceBody::ProcessStarted {
            executable: redact_text(executable, &secret_values),
            argv: arguments
                .iter()
                .map(|argument| redact_text(argument, &secret_values))
                .collect(),
        });
        let observation = sandbox
            .run(&request)
            .map_err(|error| LaunchError::Infrastructure(redact_text(&error, &secret_values)))?;
        for (name, value) in &secret_values {
            if contains(&observation.output, value.as_bytes()) {
                evidence.append(EvidenceBody::SecretRedacted { name: name.clone() });
            }
        }
        evidence.append(EvidenceBody::ProcessExited {
            code: observation.code.unwrap_or(-1),
        });
        outcome = observation_outcome(step, &observation);
        if outcome != Outcome::Completed {
            break;
        }
    }

    record_changes(&mut evidence, &scratch)?;
    Ok(RunResult { evidence, outcome })
}

#[cfg(test)]
mod tests {
    use super::workspace_relative;

    #[test]
    fn workspace_mapping_rejects_escape_and_host_paths() {
        assert_eq!(
            workspace_relative("/workspace/nested").expect("safe path"),
            std::path::PathBuf::from("nested")
        );
        assert!(workspace_relative("/workspace/../outside").is_err());
        assert!(workspace_relative("C:/host").is_err());
        assert!(workspace_relative("/source").is_err());
    }
}
