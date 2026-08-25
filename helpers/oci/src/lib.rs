//! OCI execution backend with an argv-only engine boundary.

use std::collections::BTreeSet;
use std::io::{Read, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub use workflow_verifier_helper_runtime::SourceManifest;
use workflow_verifier_helper_runtime::{
    ChangeKind, ProcessObservation, ScratchTree, run_command, source_snapshot,
};
use workflow_verifier_runner_protocol::{
    BACKEND_ATTESTATION_SCHEMA, Control, Evidence, EvidenceBody, PlanStatus, Step, ValidatedPlan,
    controls_digest, quote_json, sha256_hex, validate_plan,
};
pub use workflow_verifier_runner_protocol::{Outcome, RunResult};

const REQUIRED_CONTROLS: &[Control] = &[
    Control::SourceReadOnly,
    Control::ScratchOverlay,
    Control::NetworkDeny,
    Control::ProcessIsolation,
    Control::ResourceLimits,
    Control::SecretRedaction,
];

fn engine_path(path: &str) -> String {
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}

fn mount(source: &str, target: &str, readonly: bool) -> String {
    let source = engine_path(source);
    format!(
        "type=bind,src={source},dst={target}{}",
        if readonly { ",readonly" } else { "" }
    )
}

/// Builds an OCI engine argument vector without invoking a command shell.
#[must_use]
pub fn build_arguments(
    plan: &ValidatedPlan,
    step: &Step,
    source_root: &str,
    scratch_root: &str,
) -> Vec<String> {
    let mut arguments = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--pull".to_owned(),
        "never".to_owned(),
        "--read-only".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--cpus".to_owned(),
        "1".to_owned(),
        "--pids-limit".to_owned(),
        plan.limits.processes.to_string(),
        "--memory".to_owned(),
        format!("{}m", plan.limits.memory_mb),
    ];
    if plan.controls.contains(&Control::NetworkDeny) {
        arguments.extend(["--network".to_owned(), "none".to_owned()]);
    }
    arguments.extend([
        "--mount".to_owned(),
        mount(source_root, "/source", true),
        "--mount".to_owned(),
        mount(scratch_root, "/workspace", false),
        "--tmpfs".to_owned(),
        "/tmp:rw,noexec,nosuid,nodev".to_owned(),
        "--workdir".to_owned(),
        step.working_directory.clone(),
    ]);
    let secret_names = plan.secret_names.iter().collect::<BTreeSet<_>>();
    for name in &plan.secret_names {
        arguments.extend(["--env".to_owned(), name.clone()]);
    }
    for (name, value) in &step.environment {
        if !secret_names.contains(name) {
            arguments.extend(["--env".to_owned(), format!("{name}={value}")]);
        }
    }
    arguments.push(step.image.clone());
    arguments.extend(step.argv.clone());
    arguments
}

/// Hashes the complete source tree using the canonical cross-language manifest.
///
/// # Errors
///
/// Rejects unreadable paths, symlinks, special files, and non-UTF-8 paths.
pub fn source_manifest(root: &Path) -> Result<SourceManifest, String> {
    source_snapshot(root).map(|snapshot| snapshot.manifest)
}

fn redacted_output(output: &[u8], secrets: &[(String, String)]) -> String {
    let mut text = String::from_utf8_lossy(output).into_owned();
    for (_, value) in secrets {
        if !value.is_empty() {
            text = text.replace(value, "***");
        }
    }
    text.trim().to_owned()
}

fn redacted_bytes(output: &[u8], secrets: &[(String, String)]) -> Vec<u8> {
    secrets.iter().fold(output.to_vec(), |input, (_, secret)| {
        let needle = secret.as_bytes();
        if needle.is_empty() {
            return input;
        }
        let mut redacted = Vec::with_capacity(input.len());
        let mut offset = 0;
        while offset < input.len() {
            if input[offset..].starts_with(needle) {
                redacted.extend_from_slice(b"***");
                offset += needle.len();
            } else {
                redacted.push(input[offset]);
                offset += 1;
            }
        }
        redacted
    })
}

fn classify_observation(
    step: &str,
    observation: &ProcessObservation,
    secrets: &[(String, String)],
) -> Result<Outcome, String> {
    if observation.timed_out {
        Ok(Outcome::TimedOut {
            step: step.to_owned(),
        })
    } else if observation.output_exceeded {
        Ok(Outcome::OutputLimitExceeded {
            step: step.to_owned(),
        })
    } else if observation.code == Some(125) {
        let detail = redacted_output(&observation.output, secrets);
        Err(if detail.is_empty() {
            "OCI engine failed before the workflow command started".to_owned()
        } else {
            format!("OCI engine failed before the workflow command started: {detail}")
        })
    } else if observation.code == Some(0) {
        Ok(Outcome::Completed)
    } else {
        Ok(Outcome::StepFailed {
            step: step.to_owned(),
            code: observation.code,
        })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn validate_execution(plan: &ValidatedPlan, engine: &str) -> Result<(), String> {
    match &plan.status {
        PlanStatus::Complete => {}
        PlanStatus::Incomplete(reasons) => {
            return Err(format!("incomplete plan: {}", reasons.join("; ")));
        }
    }
    if plan.backend != format!("oci:{engine}") {
        return Err(format!(
            "plan backend {} does not match oci:{engine}",
            plan.backend
        ));
    }
    if !matches!(engine, "docker" | "podman") {
        return Err(format!("unsupported OCI engine {engine}"));
    }
    let missing = REQUIRED_CONTROLS
        .iter()
        .copied()
        .filter(|control| !plan.controls.contains(control))
        .map(Control::name)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("OCI plan lacks controls: {}", missing.join(", ")))
    }
}

/// Executes a complete plan in Docker or Podman and returns authenticated evidence.
///
/// # Errors
///
/// Fails closed on plan/source mismatch, unsafe source entries, missing controls,
/// engine failures, or evidence collection failures.
// Keep source verification, materialization, launch, and evidence finalization in
// one auditable transaction boundary.
#[allow(clippy::too_many_lines)]
pub fn execute(plan: &ValidatedPlan, engine: &str, source: &Path) -> Result<RunResult, String> {
    validate_execution(plan, engine)?;
    let source = source.canonicalize().map_err(|error| error.to_string())?;
    let baseline = source_snapshot(&source)?;
    if baseline.manifest.digest != plan.source_digest {
        return Err(format!(
            "source digest mismatch: plan {}, actual {}",
            plan.source_digest, baseline.manifest.digest
        ));
    }
    let scratch = ScratchTree::prepare(&source, baseline)?;
    let source_text = source
        .to_str()
        .ok_or_else(|| "source root is not UTF-8".to_owned())?;
    let scratch_text = scratch
        .path()
        .to_str()
        .ok_or_else(|| "scratch root is not UTF-8".to_owned())?;
    let mut evidence = Evidence::for_plan(plan);
    evidence.append(EvidenceBody::BackendAttested {
        id: plan.backend.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: std::env::consts::OS.to_owned(),
        controls_digest: controls_digest(&plan.controls),
    });
    for control in &plan.controls {
        evidence.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }
    let mut outcome = Outcome::Completed;
    let mut redacted_log = Vec::new();
    let mut wall_time_ms = 0_u64;
    let mut output_bytes = 0_u64;
    let mut observed_processes = 0_u64;
    let secret_values = plan
        .secret_names
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect::<Vec<_>>();
    for step in &plan.steps {
        let arguments = build_arguments(plan, step, source_text, scratch_text);
        let (executable, argv) = step
            .argv
            .split_first()
            .ok_or_else(|| format!("step {} has empty argv", step.id))?;
        evidence.append(EvidenceBody::ProcessStarted {
            executable: executable.clone(),
            argv: argv.to_vec(),
        });
        let observation = run_command(
            Command::new(engine).args(&arguments),
            Duration::from_secs(plan.limits.cpu_seconds),
            plan.limits.output_bytes,
        )?;
        redacted_log.extend_from_slice(&redacted_bytes(&observation.output, &secret_values));
        wall_time_ms = wall_time_ms.saturating_add(observation.wall_time_ms);
        output_bytes = output_bytes.saturating_add(observation.output_bytes);
        observed_processes = observed_processes.saturating_add(1);
        for (name, value) in &secret_values {
            if contains(&observation.output, value.as_bytes()) {
                evidence.append(EvidenceBody::SecretRedacted { name: name.clone() });
            }
        }
        evidence.append(EvidenceBody::ProcessExited {
            code: observation.code.unwrap_or(-1),
        });
        outcome = classify_observation(&step.id, &observation, &secret_values)?;
        if outcome != Outcome::Completed {
            break;
        }
    }
    let final_state = scratch.final_state()?;
    for change in final_state.changes {
        evidence.append(EvidenceBody::FilesystemAccess {
            path: change.path.clone(),
            operation: match change.kind {
                ChangeKind::Added | ChangeKind::Modified => "write".to_owned(),
                ChangeKind::Deleted => "delete".to_owned(),
            },
            allowed: true,
        });
        if change.kind != ChangeKind::Deleted {
            let digest = change
                .digest
                .ok_or_else(|| "non-deleted scratch change has no digest".to_owned())?;
            evidence.append(EvidenceBody::ArtifactRecorded {
                path: change.path,
                digest,
            });
        }
    }
    evidence.append(EvidenceBody::ResourceObserved {
        wall_time_ms,
        cpu_time_ms: 0,
        peak_memory_bytes: 0,
        processes: observed_processes,
        output_bytes,
        scratch_bytes: final_state.bytes,
        scratch_entries: final_state.entries,
    });
    evidence.append(EvidenceBody::LogRecorded {
        digest: format!("sha256:{}", sha256_hex(&redacted_log)),
    });
    evidence.append(EvidenceBody::FilesystemFinal {
        digest: final_state.digest,
    });
    Ok(RunResult { evidence, outcome })
}

fn argument_value(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

/// Process entry point used by the small helper binary.
#[must_use]
pub fn main_entry() -> i32 {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let engine = argument_value(&arguments, "--engine").unwrap_or_else(|| "docker".to_owned());
    if arguments.iter().any(|value| value == "--doctor") {
        let available = Command::new(&engine)
            .arg("version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        let controls = [
            "source_read_only",
            "scratch_overlay",
            "network_deny",
            "process_isolation",
            "resource_limits",
            "secret_redaction",
        ]
        .map(quote_json)
        .join(",");
        let reasons = if available {
            String::new()
        } else {
            quote_json("OCI engine is unavailable or unhealthy")
        };
        println!(
            "{{\"available\":{available},\"controls\":[{controls}],\"id\":{},\"platform\":{},\"reasons\":[{reasons}],\"schema\":{},\"version\":{}}}",
            quote_json(&format!("oci:{engine}")),
            quote_json(std::env::consts::OS),
            quote_json(BACKEND_ATTESTATION_SCHEMA),
            quote_json(env!("CARGO_PKG_VERSION"))
        );
        return 0;
    }
    if !arguments.iter().any(|value| value == "--run") {
        eprintln!(
            "usage: workflow-verifier-oci-helper --doctor|--run --engine ENGINE --source PATH"
        );
        return 2;
    }
    let Some(source) = argument_value(&arguments, "--source") else {
        eprintln!("--source is required");
        return 2;
    };
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read runner plan: {error}");
        return 2;
    }
    let plan = match validate_plan(&input) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("invalid runner plan: {error}");
            return 2;
        }
    };
    if let PlanStatus::Incomplete(reasons) = &plan.status {
        eprintln!("incomplete plan: {}", reasons.join("; "));
        return 3;
    }
    match execute(&plan, &engine, Path::new(&source)) {
        Ok(result) => {
            print!("{}", result.canonical_json());
            if let Err(error) = std::io::stdout().flush() {
                eprintln!("failed to flush evidence: {error}");
                5
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("sandbox infrastructure failure: {error}");
            5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Outcome, ProcessObservation, classify_observation};

    #[test]
    fn engine_start_failure_is_infrastructure_and_redacted() {
        let observation = ProcessObservation {
            code: Some(125),
            timed_out: false,
            output_exceeded: false,
            output: b"daemon rejected token-value".to_vec(),
            output_bytes: 27,
            wall_time_ms: 1,
        };
        let secrets = [("TOKEN".to_owned(), "token-value".to_owned())];
        let error = classify_observation("build", &observation, &secrets)
            .expect_err("engine exit 125 must not look like a workflow failure");
        assert!(error.contains("daemon rejected ***"));
        assert!(!error.contains("token-value"));
    }

    #[test]
    fn ordinary_nonzero_exit_remains_a_step_failure() {
        let observation = ProcessObservation {
            code: Some(9),
            timed_out: false,
            output_exceeded: false,
            output: Vec::new(),
            output_bytes: 0,
            wall_time_ms: 1,
        };
        assert_eq!(
            classify_observation("build", &observation, &[]).expect("classification"),
            Outcome::StepFailed {
                step: "build".to_owned(),
                code: Some(9)
            }
        );
    }
}
