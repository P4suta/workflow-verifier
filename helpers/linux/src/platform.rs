use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use workflow_verifier_helper_runtime::{
    EnvironmentSecrets, NativeSandbox, NativeSandboxRequest, NativeStepRequest, ProcessObservation,
    execute_native_with_exclusions, run_command_with_termination,
};
use workflow_verifier_runner_protocol::{
    Descriptor, LaunchError, Limits, RunResult, ValidatedPlan,
};

use crate::{cgroup, landlock, namespaces, seccomp};

const BROKER_MODE: &str = "--workflow-verifier-linux-broker-v1";
const PROBE_MODE: &str = "--workflow-verifier-linux-probe-v1";
const ENV_CGROUP: &str = "WORKFLOW_VERIFIER_LINUX_CGROUP";
const ENV_READY: &str = "WORKFLOW_VERIFIER_LINUX_READY";
const ENV_WORKING_DIRECTORY: &str = "WORKFLOW_VERIFIER_LINUX_WORKING_DIRECTORY";
const ENV_CGROUP_ROOT: &str = "WORKFLOW_VERIFIER_CGROUP_ROOT";
const READY_PREFIX: &str = "workflow-verifier-linux-ready-";

static PROBE_REASONS: OnceLock<Vec<String>> = OnceLock::new();

struct ReadyFile {
    path: PathBuf,
}

impl ReadyFile {
    fn create() -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("{READY_PREFIX}{}-{nonce}", std::process::id()));
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("create broker readiness file: {error}"))?;
        Ok(Self { path })
    }

    fn is_ready(&self) -> Result<bool, String> {
        std::fs::read(&self.path)
            .map(|value| value == b"ready\n")
            .map_err(|error| format!("read broker readiness file: {error}"))
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn broker_source() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let expected = "workflow-verifier-linux-helper";
    if current.file_name().and_then(std::ffi::OsStr::to_str) == Some(expected) {
        return Ok(current);
    }
    if cfg!(debug_assertions) {
        let candidate = current
            .ancestors()
            .take(8)
            .map(|ancestor| ancestor.join(expected))
            .find(|path| path.is_file());
        if let Some(candidate) = candidate {
            return Ok(candidate);
        }
    }
    Err("the signed workflow-verifier Linux helper cannot locate its broker image".to_owned())
}

fn probe_helper(broker: &Path, capability: &str) -> Result<(), String> {
    let output = Command::new(broker)
        .args([PROBE_MODE, capability])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("start {capability} probe: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(if reason.is_empty() {
            format!("{capability} probe exited with {}", output.status)
        } else {
            reason
        })
    }
}

fn probe_uncached() -> Vec<String> {
    let mut reasons = Vec::new();
    let broker = match broker_source() {
        Ok(path) => Some(path),
        Err(error) => {
            reasons.push(format!("broker probe: {error}"));
            None
        }
    };
    if let Err(error) = landlock::abi() {
        reasons.push(format!("Landlock probe: {error}"));
    }
    if let Some(broker) = broker {
        for capability in ["namespace", "seccomp"] {
            if let Err(error) = probe_helper(&broker, capability) {
                reasons.push(format!("{capability} probe: {error}"));
            }
        }
    }
    let limits = Limits {
        cpu_seconds: 1,
        memory_mb: 64,
        processes: 2,
        output_bytes: 1024,
    };
    if let Err(error) = cgroup::probe(&limits) {
        reasons.push(format!("cgroup v2 probe: {error}"));
    }
    reasons
}

pub(super) fn probe() -> Vec<String> {
    PROBE_REASONS.get_or_init(probe_uncached).clone()
}

struct LinuxSandbox {
    broker: PathBuf,
    cgroup: Option<cgroup::Cgroup>,
}

impl LinuxSandbox {
    fn new() -> Result<Self, String> {
        Ok(Self {
            broker: broker_source()?,
            cgroup: None,
        })
    }
}

impl NativeSandbox for LinuxSandbox {
    fn prepare(&mut self, request: &NativeSandboxRequest<'_>) -> Result<(), String> {
        self.cgroup = Some(cgroup::Cgroup::create(&request.plan.limits)?);
        Ok(())
    }

    fn run(&mut self, request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String> {
        let execution_cgroup = self
            .cgroup
            .as_ref()
            .ok_or_else(|| "Linux sandbox was not prepared".to_owned())?;
        let ready = ReadyFile::create()?;
        let mut environment = request.environment.clone();
        environment
            .entry("PATH".to_owned())
            .or_insert_with(|| "/usr/local/bin:/usr/bin:/bin".to_owned());
        environment.insert(
            "WORKFLOW_VERIFIER_SOURCE".to_owned(),
            request.source_root.to_string_lossy().into_owned(),
        );
        environment.insert(
            "WORKFLOW_VERIFIER_WORKSPACE".to_owned(),
            request.scratch_root.to_string_lossy().into_owned(),
        );
        environment.insert(
            ENV_CGROUP.to_owned(),
            execution_cgroup.path().to_string_lossy().into_owned(),
        );
        environment.insert(
            ENV_READY.to_owned(),
            ready.path.to_string_lossy().into_owned(),
        );
        environment.insert(
            ENV_WORKING_DIRECTORY.to_owned(),
            request.working_directory.to_string_lossy().into_owned(),
        );
        if let Some(root) = std::env::var_os(ENV_CGROUP_ROOT) {
            environment.insert(
                ENV_CGROUP_ROOT.to_owned(),
                root.to_string_lossy().into_owned(),
            );
        }
        let mut command = Command::new(&self.broker);
        command
            .arg(BROKER_MODE)
            .arg("--")
            .args(&request.step.argv)
            .env_clear()
            .envs(environment);
        let observation = run_command_with_termination(
            &mut command,
            Duration::from_secs(request.plan.limits.cpu_seconds),
            request.plan.limits.output_bytes,
            |_child| execution_cgroup.kill(),
        )?;
        if !observation.timed_out && !observation.output_exceeded && !ready.is_ready()? {
            return Err(format!(
                "Linux broker failed before containment was installed: {}",
                String::from_utf8_lossy(&observation.output).trim()
            ));
        }
        Ok(observation)
    }
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("Linux broker environment {name} is missing"))
}

fn validate_ready_path(path: &Path) -> Result<(), String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize broker readiness file: {error}"))?;
    let temporary = std::env::temp_dir()
        .canonicalize()
        .map_err(|error| format!("canonicalize temporary directory: {error}"))?;
    let safe_name = canonical
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.starts_with(READY_PREFIX));
    if safe_name && canonical.parent() == Some(temporary.as_path()) {
        Ok(())
    } else {
        Err(format!(
            "refusing unowned broker readiness path: {}",
            canonical.display()
        ))
    }
}

fn run_broker(arguments: &[String]) -> Result<i32, String> {
    let [mode, separator, command @ ..] = arguments else {
        return Err("invalid Linux broker arguments".to_owned());
    };
    if mode != BROKER_MODE || separator != "--" || command.is_empty() {
        return Err("invalid Linux broker arguments".to_owned());
    }
    let source = required_path("WORKFLOW_VERIFIER_SOURCE")?
        .canonicalize()
        .map_err(|error| format!("canonicalize source: {error}"))?;
    let scratch = required_path("WORKFLOW_VERIFIER_WORKSPACE")?
        .canonicalize()
        .map_err(|error| format!("canonicalize scratch: {error}"))?;
    let working_directory = required_path(ENV_WORKING_DIRECTORY)?
        .canonicalize()
        .map_err(|error| format!("canonicalize working directory: {error}"))?;
    if source == scratch || !working_directory.starts_with(&scratch) {
        return Err("Linux broker received unsafe source/workspace roots".to_owned());
    }
    let cgroup_path = required_path(ENV_CGROUP)?;
    let ready_path = required_path(ENV_READY)?;
    validate_ready_path(&ready_path)?;
    cgroup::attach_current(&cgroup_path)?;
    namespaces::setup(Some(&source))?;
    let policy = landlock::Policy::new(&source, &scratch)?;
    let mut filter = seccomp::Filter::deny_escape_and_network()?;
    let (program, child_arguments) = command
        .split_first()
        .ok_or_else(|| "Linux broker command is empty".to_owned())?;
    let mut child_command = Command::new(program);
    child_command
        .args(child_arguments)
        .current_dir(working_directory)
        .env_remove(ENV_CGROUP)
        .env_remove(ENV_READY)
        .env_remove(ENV_WORKING_DIRECTORY)
        .env_remove(ENV_CGROUP_ROOT)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: the closure performs only raw, async-signal-safe kernel calls;
    // all allocations and policy construction happened before spawn.
    unsafe {
        child_command.pre_exec(move || {
            namespaces::prepare_child()?;
            seccomp::set_no_new_privileges()?;
            policy.enforce()?;
            filter.install()
        });
    }
    let mut child = child_command
        .spawn()
        .map_err(|error| format!("spawn contained workload: {error}"))?;
    std::fs::write(&ready_path, b"ready\n")
        .map_err(|error| format!("attest contained workload: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("wait for contained workload: {error}"))?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGKILL)))
}

fn run_probe(arguments: &[String]) -> Result<(), String> {
    let [mode, capability] = arguments else {
        return Err("invalid Linux capability probe arguments".to_owned());
    };
    if mode != PROBE_MODE {
        return Err("invalid Linux capability probe arguments".to_owned());
    }
    match capability.as_str() {
        "namespace" => namespaces::probe_child(),
        "seccomp" => seccomp::probe_child(),
        _ => Err(format!("unknown Linux capability probe {capability}")),
    }
}

fn broker_exit(result: Result<i32, String>) -> i32 {
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Linux containment failure: {error}");
            126
        }
    }
}

pub(super) fn broker_main(arguments: &[String]) -> Option<i32> {
    match arguments.first().map(String::as_str) {
        Some(BROKER_MODE) => Some(broker_exit(run_broker(arguments))),
        Some(PROBE_MODE) => Some(broker_exit(run_probe(arguments).map(|()| 0))),
        _ => None,
    }
}

pub(super) fn launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    trusted_exclusions: &[String],
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    let mut sandbox = LinuxSandbox::new().map_err(LaunchError::Infrastructure)?;
    execute_native_with_exclusions(
        plan,
        descriptor,
        source_root,
        trusted_exclusions,
        &EnvironmentSecrets,
        &mut sandbox,
    )
}

#[cfg(test)]
mod tests {
    use super::{ReadyFile, validate_ready_path};

    #[test]
    fn readiness_files_are_private_owned_and_removed() {
        let ready = ReadyFile::create().expect("create readiness file");
        let path = ready.path.clone();
        validate_ready_path(&path).expect("validate owned readiness file");
        drop(ready);
        assert!(!path.exists());
    }
}
