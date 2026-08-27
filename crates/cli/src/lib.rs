#![forbid(unsafe_code)]

//! Operating-system adapters and command composition for the public binary.

pub mod auth;
pub mod lsp;
pub mod network;
mod network_profile;
pub mod resolver_transport;

use auth::{AuthService, CredentialKey, ProviderKind, SecretString, SystemCredentialStore};
use network_profile::TrustedNetworkProfile;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as FmtWrite;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use workflow_verifier_domain::{Graph, NodeKind, Provider};
use workflow_verifier_engine::{
    AnalysisEngine, AnalysisRequest, AnalysisResult, CancellationToken, ConfigSnapshot,
    LockSnapshot, SourceSnapshot,
};
use workflow_verifier_foundation::{Budget, JsonValue, content_digest, normalize_slashes};
use workflow_verifier_frontend::{compile_auto, detect, entrypoint};
use workflow_verifier_helper_runtime::{
    SourceSnapshot as RuntimeSourceSnapshot, source_snapshot_with_exclusions,
};
use workflow_verifier_product::{
    BuildInfo, Config, ConfigParseOptions, ConfigTrust, DependencyFetcher, EXIT_CODE_FINDING,
    EXIT_CODE_INCOMPLETE, EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_INVALID_INPUT, EXIT_CODE_PASS,
    EXIT_CODE_SANDBOX_INFRASTRUCTURE, FetchedDependency, FixProposal, GraphKind, Lockfile,
    PolicyExpectation, ResolverOrigin, evaluate_policy, evaluate_policy_fixture,
    graph_to_canonical_json, graph_to_dot, link_local, migrate_config_v1, report_to_sarif,
    resolve_dependencies, semantic_diff,
};
use workflow_verifier_sandbox::{
    Backend as SandboxBackend, Control as SandboxControl, Dependency as SandboxDependency,
    Evidence, Outcome as SandboxOutcome, PlanStatus as SandboxPlanStatus, RunResult as SandboxRun,
    RunnerPlan, RunnerPlanRequest, RunnerPlatform, SandboxAudit, SandboxAuditStatus, Scenario,
    plan_scenario, validate_plan,
};
use workflow_verifier_verifier::{Persona, compose_program};

const HELP: &str = "workflow-verifier 0.1.0

Usage: workflow-verifier COMMAND [OPTIONS]

Commands:
  check       Analyze workflows
  resolve     Resolve dependency identities
  explain     Explain a rule finding
  graph       Render the semantic graph
  diff        Compare two workflow snapshots
  fix         Propose or apply verified fixes
  policy      Test organization policy
  sandbox     Plan, run, replay, verify, or audit a sandbox
  doctor      Inspect local runtime support
  completion  Generate shell completion
  migrate     Migrate product data
  version     Print the version
  lsp         Run the stdio language server
  auth        Manage credentials in the OS credential store
";

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Process-adapter bounds are fixed product contracts: runner output follows
// runner-v2's 16 MiB cap, diagnostics get a separate one MiB channel, and
// doctor probes are short, bounded control requests.
const BYTES_PER_MEBIBYTE: u64 = 1_048_576;
const SANDBOX_HELPER_STDOUT_MEBIBYTES: u64 = 16;
const SANDBOX_HELPER_STDERR_MEBIBYTES: u64 = 1;
const DOCTOR_TIMEOUT_SECONDS: u64 = 5;
const DOCTOR_STREAM_MEBIBYTES: u64 = 1;
const SUPERVISOR_POLL_MILLISECONDS: u64 = 10;
const SECONDS_PER_DAY: u64 = 86_400;
const DETERMINISTIC_WORKER_COUNT: usize = 1;
// IANA's registered default port for HTTPS URL authorities.
const HTTPS_DEFAULT_PORT: u16 = 443;

fn process_exit_code(code: i64) -> i32 {
    i32::try_from(code).expect("the documented public exit-code range fits i32")
}

#[derive(Debug)]
struct CliError {
    code: i32,
    message: String,
}

impl CliError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: process_exit_code(EXIT_CODE_INVALID_INPUT),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: process_exit_code(EXIT_CODE_INTERNAL_FAILURE),
            message: message.into(),
        }
    }

    fn infrastructure(message: impl Into<String>) -> Self {
        Self {
            code: process_exit_code(EXIT_CODE_SANDBOX_INFRASTRUCTURE),
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct CommandOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    fn success(stdout: impl Into<String>) -> Self {
        Self {
            code: process_exit_code(EXIT_CODE_PASS),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct CommonOptions {
    config: Option<PathBuf>,
    policy: Option<PathBuf>,
    trust_repository_config: bool,
    lockfile: Option<PathBuf>,
    persona: Option<Persona>,
    strict: bool,
}

#[derive(Debug)]
struct LoadedWorkspace {
    root: PathBuf,
    sources: BTreeMap<String, String>,
    snapshot: SourceSnapshot,
    authenticated: RuntimeSourceSnapshot,
    roots: Option<BTreeSet<String>>,
}

#[derive(Debug)]
struct AnalyzedWorkspace {
    loaded: LoadedWorkspace,
    result: AnalysisResult,
    config: Config,
}

/// Execute the command from the process environment and write its two output
/// streams exactly once. This is the only public process boundary.
#[must_use]
pub fn run_env() -> i32 {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.len() == 1 && arguments[0] == "lsp" {
        return lsp::run_stdio();
    }
    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "workflow-verifier: {error}");
            return process_exit_code(EXIT_CODE_INTERNAL_FAILURE);
        }
    };
    let output = match utf8_arguments(&arguments).and_then(|values| dispatch(&cwd, &values)) {
        Ok(output) => output,
        Err(error) => CommandOutput {
            code: error.code,
            stdout: String::new(),
            stderr: format!("workflow-verifier: {}\n", error.message),
        },
    };
    let stdout_ok = io::stdout()
        .lock()
        .write_all(output.stdout.as_bytes())
        .is_ok();
    let stderr_ok = io::stderr()
        .lock()
        .write_all(output.stderr.as_bytes())
        .is_ok();
    if stdout_ok && stderr_ok {
        output.code
    } else {
        process_exit_code(EXIT_CODE_INTERNAL_FAILURE)
    }
}

fn utf8_arguments(arguments: &[OsString]) -> Result<Vec<String>, CliError> {
    arguments
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| CliError::invalid("arguments must be valid UTF-8"))
        })
        .collect()
}

fn dispatch(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(CliError::invalid("a command is required; use --help"));
    };
    let rest = &arguments[1..];
    match command {
        "--help" | "-h" | "help" => Ok(CommandOutput::success(HELP)),
        "--version" | "version" => Ok(CommandOutput::success("workflow-verifier 0.1.0\n")),
        "check" => command_check(cwd, rest),
        "graph" => command_graph(cwd, rest),
        "diff" => command_diff(cwd, rest),
        "fix" => command_fix(cwd, rest),
        "resolve" => command_resolve(cwd, rest),
        "explain" => command_explain(cwd, rest),
        "doctor" => command_doctor(rest),
        "policy" => command_policy(cwd, rest),
        "migrate" => command_migrate(cwd, rest),
        "sandbox" => command_sandbox(cwd, rest),
        "completion" => command_completion(rest),
        "auth" => command_auth(rest),
        "lsp" => Err(CliError::invalid(format!(
            "{command} is not available in this internal candidate yet"
        ))),
        value => Err(CliError::invalid(format!("unknown command {value}"))),
    }
}

fn command_sandbox(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return Err(CliError::invalid("sandbox requires a subcommand"));
    };
    match subcommand {
        "replay" => sandbox_replay(cwd, &arguments[1..]),
        "verify" => sandbox_verify(cwd, &arguments[1..]),
        "audit" => sandbox_audit(cwd, &arguments[1..]),
        "plan" => sandbox_plan(cwd, &arguments[1..]),
        "run" => sandbox_run(cwd, &arguments[1..]),
        _ => Err(CliError::invalid(
            "sandbox requires plan, run, replay, verify, or audit",
        )),
    }
}

#[derive(Default)]
struct SandboxPlanOptions {
    backend: Option<String>,
    scenario: Option<PathBuf>,
    job: Option<String>,
    event: Option<String>,
    runner: Option<String>,
    inputs: Vec<String>,
    matrix: Vec<String>,
    variables: Vec<String>,
    secrets: Vec<String>,
    destinations: Vec<String>,
    allow_network: bool,
}

struct PlannedSandbox {
    plan: RunnerPlan,
    source_root: PathBuf,
    trusted_exclusions: Vec<String>,
}

fn sandbox_plan(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let planned = build_sandbox_plan(cwd, arguments)?;
    Ok(CommandOutput::success(planned.plan.to_canonical_json()))
}

#[allow(clippy::too_many_lines)]
fn build_sandbox_plan(cwd: &Path, arguments: &[String]) -> Result<PlannedSandbox, CliError> {
    let mut options = SandboxPlanOptions::default();
    let (common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--backend" => set_once(&mut options.backend, name, required_value(name, value)?),
        "--scenario" => {
            if options
                .scenario
                .replace(PathBuf::from(required_value(name, value)?))
                .is_some()
            {
                return Err(CliError::invalid("--scenario can be supplied only once"));
            }
            Ok(true)
        }
        "--job" => set_once(&mut options.job, name, required_value(name, value)?),
        "--event" => set_once(&mut options.event, name, required_value(name, value)?),
        "--runner" => set_once(&mut options.runner, name, required_value(name, value)?),
        "--input" => push_option(&mut options.inputs, name, value),
        "--matrix" => push_option(&mut options.matrix, name, value),
        "--variable" => push_option(&mut options.variables, name, value),
        "--secret" => push_option(&mut options.secrets, name, value),
        "--network-destination" => push_option(&mut options.destinations, name, value),
        "--allow-workflow-network" => {
            reject_value(name, value)?;
            options.allow_network = true;
            Ok(true)
        }
        _ => Ok(false),
    })?;
    let target = one_target(cwd, &positional)?;
    let analyzed = analyze_target(&target, &common)?;
    let config = &analyzed.config;
    let backend = parse_sandbox_backend(
        options
            .backend
            .as_deref()
            .unwrap_or(&config.sandbox.backend),
    )?;
    let scenario = if let Some(path) = options.scenario.as_ref() {
        Scenario::parse(&read_utf8_file(&absolute(cwd, path))?).map_err(CliError::invalid)?
    } else {
        scenario_from_options(&analyzed.result.report.graphs, &backend, &options)?
    };
    if let Some(name) = options
        .secrets
        .iter()
        .find(|name| !scenario.secret_names.contains(name))
    {
        return Err(CliError::invalid(format!(
            "secret grant is not declared by scenario: {name}"
        )));
    }
    let mut incomplete_reasons: Vec<_> = scenario
        .secret_names
        .iter()
        .filter(|name| !options.secrets.contains(name))
        .map(|name| format!("Incomplete.Missing_secret_grant: {name}"))
        .collect();
    let planned = plan_scenario(
        &scenario,
        &config.sandbox.capsule_digest,
        &analyzed.result.report.graphs,
    )
    .map_err(CliError::invalid)?;
    incomplete_reasons.extend(planned.incomplete_reasons);
    let provider_profile = format!("{}-semantic-v1", scenario.provider.name());
    let plan = RunnerPlan::build(RunnerPlanRequest {
        backend: backend.clone(),
        scenario,
        provider_profile,
        selected_jobs: planned.selected_jobs,
        source_digest: analyzed
            .result
            .report
            .provenance
            .source_manifest_digest
            .clone(),
        lock_digest: analyzed.result.report.provenance.lock_digest.clone(),
        controls: required_sandbox_controls(&backend, options.allow_network),
        network_destinations: options.destinations,
        dependencies: sandbox_dependencies(&analyzed.result.report.graphs),
        steps: planned.steps,
        incomplete_reasons,
        runtime_helper_digest: None,
        runtime_boot_digest: None,
        capability_fingerprint: None,
    })
    .map_err(CliError::invalid)?;
    Ok(PlannedSandbox {
        plan,
        source_root: analyzed.loaded.root,
        trusted_exclusions: analyzed.loaded.authenticated.trusted_exclusions().to_vec(),
    })
}

fn sandbox_run(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let planned = build_sandbox_plan(cwd, arguments)?;
    if let SandboxPlanStatus::Incomplete(reasons) = planned.plan.status() {
        return Ok(CommandOutput {
            code: process_exit_code(EXIT_CODE_INCOMPLETE),
            stdout: String::new(),
            stderr: format!("{}\n", reasons.join("\n")),
        });
    }
    let execution = execute_sandbox_helper(&planned)?;
    execution
        .evidence
        .validate_for_plan(planned.plan.validated())
        .map_err(|error| {
            CliError::infrastructure(format!("sandbox evidence validation failed: {error}"))
        })?;
    let code = match &execution.outcome {
        SandboxOutcome::Completed => process_exit_code(EXIT_CODE_PASS),
        SandboxOutcome::StepFailed { .. }
        | SandboxOutcome::TimedOut { .. }
        | SandboxOutcome::OutputLimitExceeded { .. } => process_exit_code(EXIT_CODE_FINDING),
    };
    Ok(CommandOutput {
        code,
        stdout: execution.canonical_json(),
        stderr: String::new(),
    })
}

fn execute_sandbox_helper(planned: &PlannedSandbox) -> Result<SandboxRun, CliError> {
    let (path, arguments) = sandbox_helper_command(planned)?;
    let environment = helper_environment(&planned.plan.validated().secret_names, |name| {
        std::env::var_os(name)
    });
    let mut command = std::process::Command::new(path);
    command.args(arguments).env_clear().envs(environment);
    let plan = planned.plan.to_canonical_json();
    let observed = supervise_process(
        &mut command,
        Some(plan.as_bytes()),
        Duration::from_secs(planned.plan.validated().limits.cpu_seconds),
        SANDBOX_HELPER_STDOUT_MEBIBYTES * BYTES_PER_MEBIBYTE,
        SANDBOX_HELPER_STDERR_MEBIBYTES * BYTES_PER_MEBIBYTE,
    )
    .map_err(|error| {
        CliError::infrastructure(format!("sandbox helper supervision failed: {error}"))
    })?;
    if observed.timed_out {
        return Err(CliError::infrastructure("sandbox helper timed out"));
    }
    if observed.output_exceeded {
        return Err(CliError::infrastructure(
            "sandbox helper output exceeds its byte limit",
        ));
    }
    if !observed.status.success() {
        let detail = String::from_utf8_lossy(&observed.stderr);
        let detail = detail.trim();
        return Err(CliError::infrastructure(if detail.is_empty() {
            format!(
                "sandbox infrastructure failure: helper exited with {}",
                observed.status
            )
        } else {
            format!("sandbox infrastructure failure: {detail}")
        }));
    }
    let source = std::str::from_utf8(&observed.stdout)
        .map_err(|_| CliError::infrastructure("sandbox helper returned non-UTF-8 protocol data"))?;
    SandboxRun::parse(source).map_err(|error| {
        CliError::infrastructure(format!("sandbox helper returned invalid evidence: {error}"))
    })
}

fn helper_environment(
    secret_names: &[String],
    mut lookup: impl FnMut(&str) -> Option<OsString>,
) -> BTreeMap<OsString, OsString> {
    const RUNTIME_ALLOWLIST: &[&str] = &[
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
        "WORKFLOW_VERIFIER_CGROUP_ROOT",
        "WORKFLOW_VERIFIER_MACOS_VM_BUNDLE",
        "WORKFLOW_VERIFIER_MACOS_VM_MANIFEST_DIGEST",
        "WORKFLOW_VERIFIER_MACOS_VM_SHIM",
    ];
    RUNTIME_ALLOWLIST
        .iter()
        .copied()
        .chain(secret_names.iter().map(String::as_str))
        .filter_map(|name| lookup(name).map(|value| (OsString::from(name), value)))
        .collect()
}

fn sandbox_helper_command(planned: &PlannedSandbox) -> Result<(PathBuf, Vec<String>), CliError> {
    let backend = planned.plan.validated().backend.as_str();
    let source = planned.source_root.to_string_lossy().into_owned();
    let (executable, mut arguments) = if let Some(engine) = backend.strip_prefix("oci:") {
        (
            "workflow-verifier-oci-helper",
            vec![
                "--run".to_owned(),
                "--engine".to_owned(),
                engine.to_owned(),
                "--source".to_owned(),
                source,
            ],
        )
    } else {
        let executable = match backend {
            "linux-native" => "workflow-verifier-linux-helper",
            "windows-native" => "workflow-verifier-windows-helper",
            "macos-vm" => "workflow-verifier-macos-helper",
            _ => {
                return Err(CliError::infrastructure(format!(
                    "sandbox backend is unavailable: {backend}"
                )));
            }
        };
        (
            executable,
            vec!["--run".to_owned(), "--source".to_owned(), source],
        )
    };
    for exclusion in &planned.trusted_exclusions {
        arguments.extend(["--exclude".to_owned(), exclusion.clone()]);
    }
    let path = sibling_executable(executable).ok_or_else(|| {
        CliError::infrastructure(format!("sandbox executor is unavailable: {executable}"))
    })?;
    Ok((path, arguments))
}

fn sibling_executable(name: &str) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let current = std::env::current_exe().ok()?;
    let path = current.parent()?.join(name);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Some(path)
    } else {
        None
    }
}

#[derive(Debug)]
struct SupervisedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    output_exceeded: bool,
}

fn read_bounded(
    mut reader: impl Read,
    limit: u64,
    exceeded: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > limit {
        exceeded.store(true, Ordering::Release);
        output.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    Ok(output)
}

fn supervise_process(
    command: &mut std::process::Command,
    input: Option<&[u8]>,
    timeout: Duration,
    stdout_limit: u64,
    stderr_limit: u64,
) -> Result<SupervisedOutput, String> {
    configure_process_tree(command);
    command
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "missing child stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "missing child stderr".to_owned())?;
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_exceeded = Arc::clone(&exceeded);
    let stdout_reader =
        std::thread::spawn(move || read_bounded(stdout, stdout_limit, stdout_exceeded.as_ref()));
    let stderr_exceeded = Arc::clone(&exceeded);
    let stderr_reader =
        std::thread::spawn(move || read_bounded(stderr, stderr_limit, stderr_exceeded.as_ref()));

    if let Some(input) = input {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| "missing child stdin".to_owned())?
            .write_all(input);
        if let Err(error) = write_result {
            terminate_process_tree(&mut child);
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("cannot write child stdin: {error}"));
        }
    }

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout && !exceeded.load(Ordering::Acquire) => {
                std::thread::sleep(Duration::from_millis(SUPERVISOR_POLL_MILLISECONDS));
            }
            Ok(None) => {
                timed_out = started.elapsed() >= timeout;
                terminate_process_tree(&mut child);
                break child.wait().map_err(|error| error.to_string())?;
            }
            Err(error) => {
                terminate_process_tree(&mut child);
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error.to_string());
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "stdout capture thread panicked".to_owned())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stderr capture thread panicked".to_owned())??;
    Ok(SupervisedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        output_exceeded: exceeded.load(Ordering::Acquire),
    })
}

#[cfg(unix)]
fn configure_process_tree(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_tree(_command: &mut std::process::Command) {}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.id());
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", "--", &process_group])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let executable = std::env::var_os("SystemRoot").map_or_else(
            || PathBuf::from("taskkill.exe"),
            |root| PathBuf::from(root).join("System32").join("taskkill.exe"),
        );
        let _ = std::process::Command::new(executable)
            .args(["/F", "/T", "/PID", &child.id().to_string()])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = child.kill();
}

fn set_once(target: &mut Option<String>, name: &str, value: &str) -> Result<bool, CliError> {
    if target.replace(value.to_owned()).is_some() {
        Err(CliError::invalid(format!(
            "{name} can be supplied only once"
        )))
    } else {
        Ok(true)
    }
}

fn push_option(
    target: &mut Vec<String>,
    name: &str,
    value: Option<&str>,
) -> Result<bool, CliError> {
    target.push(required_value(name, value)?.to_owned());
    Ok(true)
}

fn parse_sandbox_backend(value: &str) -> Result<SandboxBackend, CliError> {
    match value {
        "linux-native" => Ok(SandboxBackend::LinuxNative),
        "windows-native" => Ok(SandboxBackend::WindowsNative),
        "macos-vm" => Ok(SandboxBackend::MacosVm),
        value => {
            let engine = value.strip_prefix("oci:").unwrap_or(value);
            if engine.is_empty()
                || !engine
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
            {
                Err(CliError::invalid("sandbox backend is invalid"))
            } else {
                Ok(SandboxBackend::Oci(engine.to_owned()))
            }
        }
    }
}

fn scenario_from_options(
    graphs: &[Graph],
    backend: &SandboxBackend,
    options: &SandboxPlanOptions,
) -> Result<Scenario, CliError> {
    let job = options
        .job
        .as_deref()
        .ok_or_else(|| CliError::invalid("sandbox plan requires --job or --scenario"))?;
    let matches: Vec<_> = graphs
        .iter()
        .filter(|graph| {
            graph
                .nodes
                .iter()
                .any(|node| node.kind == NodeKind::Job && node.name == job)
        })
        .collect();
    let graph = match matches.as_slice() {
        [] => {
            return Err(CliError::invalid(format!(
                "selected job was not found: {job}"
            )));
        }
        [graph] => *graph,
        _ => {
            return Err(CliError::invalid(format!(
                "selected job is ambiguous; use --scenario: {job}"
            )));
        }
    };
    let runner = if let Some(name) = options.runner.as_deref() {
        RunnerPlatform::parse(name)
            .ok_or_else(|| CliError::invalid(format!("unknown runner platform {name}")))?
    } else {
        default_runner(backend)
    };
    let event = options
        .event
        .clone()
        .unwrap_or_else(|| default_event(graph.provider).to_owned());
    let mut scenario = Scenario::new(graph.provider, &graph.source, job, event, runner)
        .map_err(CliError::invalid)?;
    for assignment in &options.inputs {
        let (name, value) = parse_assignment(assignment)?;
        scenario = scenario
            .with_input(name, value)
            .map_err(CliError::invalid)?;
    }
    for assignment in &options.matrix {
        let (name, value) = parse_assignment(assignment)?;
        scenario = scenario
            .with_matrix(name, JsonValue::String(value))
            .map_err(CliError::invalid)?;
    }
    for assignment in &options.variables {
        let (name, value) = parse_assignment(assignment)?;
        scenario = scenario
            .with_variable(name, value)
            .map_err(CliError::invalid)?;
    }
    for name in &options.secrets {
        scenario = scenario
            .with_secret(name.clone())
            .map_err(CliError::invalid)?;
    }
    Ok(scenario)
}

fn parse_assignment(value: &str) -> Result<(String, String), CliError> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| CliError::invalid("scenario assignments require NAME=VALUE"))?;
    if name.is_empty() {
        return Err(CliError::invalid(
            "scenario assignment name must not be empty",
        ));
    }
    Ok((name.to_owned(), value.to_owned()))
}

fn default_runner(backend: &SandboxBackend) -> RunnerPlatform {
    match backend {
        SandboxBackend::Oci(_) | SandboxBackend::LinuxNative => RunnerPlatform::LinuxX86_64,
        SandboxBackend::WindowsNative => RunnerPlatform::WindowsX86_64,
        SandboxBackend::MacosVm => RunnerPlatform::MacosArm64,
    }
}

fn default_event(provider: Provider) -> &'static str {
    match provider {
        Provider::Github => "workflow_dispatch",
        Provider::Gitlab => "web",
        Provider::Azure => "manual",
        Provider::Circleci => "api",
    }
}

fn sandbox_dependencies(graphs: &[Graph]) -> Vec<SandboxDependency> {
    let mut dependencies = BTreeMap::new();
    for node in graphs
        .iter()
        .flat_map(|graph| &graph.nodes)
        .filter(|node| node.kind == NodeKind::Call && !node.name.starts_with("builtin:"))
    {
        let digest = node
            .attributes
            .get("dependency.digest")
            .and_then(|value| value.constants())
            .and_then(|values| match values {
                [value] if workflow_verifier_foundation::valid_content_digest(value) => {
                    Some(value.clone())
                }
                _ => None,
            });
        dependencies
            .entry(node.name.clone())
            .and_modify(|dependency: &mut SandboxDependency| {
                if dependency.digest.is_none() {
                    dependency.digest.clone_from(&digest);
                    dependency.available = digest.is_some();
                }
            })
            .or_insert_with(|| SandboxDependency {
                reference: node.name.clone(),
                available: digest.is_some(),
                digest,
            });
    }
    dependencies.into_values().collect()
}

fn required_sandbox_controls(backend: &SandboxBackend, allow_network: bool) -> Vec<SandboxControl> {
    let mut controls = vec![
        SandboxControl::SourceReadOnly,
        SandboxControl::ScratchOverlay,
        SandboxControl::ProcessIsolation,
        SandboxControl::ResourceLimits,
        SandboxControl::SecretRedaction,
        if allow_network {
            SandboxControl::EgressBroker
        } else {
            SandboxControl::NetworkDeny
        },
    ];
    controls.extend(match backend {
        SandboxBackend::Oci(_) => Vec::new(),
        SandboxBackend::LinuxNative => vec![
            SandboxControl::Namespace,
            SandboxControl::Seccomp,
            SandboxControl::Landlock,
            SandboxControl::CgroupV2,
        ],
        SandboxBackend::WindowsNative => vec![
            SandboxControl::AppContainer,
            SandboxControl::RestrictedToken,
            SandboxControl::JobObject,
        ],
        SandboxBackend::MacosVm => vec![SandboxControl::VirtualMachine],
    });
    controls
}

fn sandbox_replay(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    if arguments.len() != 1 {
        return Err(CliError::invalid("sandbox replay requires EVIDENCE"));
    }
    let source = read_utf8_file(&absolute(cwd, Path::new(&arguments[0])))?;
    let evidence = Evidence::parse(&source).map_err(CliError::invalid)?;
    Ok(CommandOutput::success(format!(
        "{}\n",
        evidence.canonical_json()
    )))
}

fn sandbox_verify(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    if arguments.len() != 2 {
        return Err(CliError::invalid("sandbox verify requires PLAN EVIDENCE"));
    }
    let plan_source = read_utf8_file(&absolute(cwd, Path::new(&arguments[0])))?;
    let evidence_source = read_utf8_file(&absolute(cwd, Path::new(&arguments[1])))?;
    let plan = validate_plan(&plan_source).map_err(CliError::invalid)?;
    let evidence = Evidence::parse(&evidence_source).map_err(CliError::invalid)?;
    evidence
        .validate_for_plan(&plan)
        .map_err(CliError::invalid)?;
    Ok(CommandOutput::success(format!(
        "{}\n",
        evidence.canonical_json()
    )))
}

fn sandbox_audit(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    if !(2..=3).contains(&arguments.len()) {
        return Err(CliError::invalid(
            "sandbox audit requires PLAN EVIDENCE [TARGET]",
        ));
    }
    let plan_source = read_utf8_file(&absolute(cwd, Path::new(&arguments[0])))?;
    let evidence_source = read_utf8_file(&absolute(cwd, Path::new(&arguments[1])))?;
    let plan = validate_plan(&plan_source).map_err(CliError::invalid)?;
    let evidence = Evidence::parse(&evidence_source).map_err(CliError::invalid)?;
    evidence
        .validate_for_plan(&plan)
        .map_err(CliError::invalid)?;
    if let Some(target) = arguments.get(2) {
        let analyzed = analyze_target(
            &absolute(cwd, Path::new(target)),
            &CommonOptions {
                persona: Some(Persona::Audit),
                ..CommonOptions::default()
            },
        )?;
        if analyzed.result.report.provenance.source_manifest_digest != plan.source_digest {
            return Err(CliError::invalid(
                "audit target source digest does not match the execution plan",
            ));
        }
    }
    let audit = SandboxAudit::evaluate(&plan, &evidence).map_err(CliError::invalid)?;
    let code = if audit.status() == &SandboxAuditStatus::Verified {
        process_exit_code(EXIT_CODE_PASS)
    } else {
        process_exit_code(EXIT_CODE_INCOMPLETE)
    };
    Ok(CommandOutput {
        code,
        stdout: audit.to_canonical_json(),
        stderr: String::new(),
    })
}

fn read_utf8_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)
        .map_err(|error| CliError::invalid(format!("cannot read {}: {error}", path.display())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > Budget::default().max_input_bytes {
        return Err(CliError::invalid(format!(
            "{} exceeds the input byte budget",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|error| CliError::invalid(format!("{} is not UTF-8: {error}", path.display())))
}

fn command_migrate(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let mut owner = None;
    let mut expiry = None;
    let mut output = None;
    let (_common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--suppression-owner" => {
            owner = Some(required_value(name, value)?.to_owned());
            Ok(true)
        }
        "--suppression-expiry" => {
            expiry = Some(required_value(name, value)?.to_owned());
            Ok(true)
        }
        "--output" => {
            output = Some(PathBuf::from(required_value(name, value)?));
            Ok(true)
        }
        _ => Ok(false),
    })?;
    if positional.len() != 1 {
        return Err(CliError::invalid(
            "migrate expects exactly one config-v1 or lock-v1 input path",
        ));
    }
    let input = absolute(cwd, Path::new(&positional[0]));
    let bytes = fs::read(&input)
        .map_err(|error| CliError::invalid(format!("cannot read {}: {error}", input.display())))?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| CliError::invalid(format!("{} is not UTF-8: {error}", input.display())))?;
    let migrated = if source.trim_start().starts_with('{') {
        migrate_legacy_lock(source)?
    } else {
        migrate_config_v1(source, owner.as_deref(), expiry.as_deref(), None)
            .map_err(|errors| CliError::invalid(errors.join("; ")))?
    };
    if let Some(path) = output {
        atomic_write(&absolute(cwd, &path), migrated.as_bytes())?;
        Ok(CommandOutput::success(String::new()))
    } else {
        Ok(CommandOutput::success(migrated))
    }
}

fn migrate_legacy_lock(source: &str) -> Result<String, CliError> {
    let json = JsonValue::parse(source)
        .map_err(|error| CliError::invalid(format!("invalid legacy JSON: {error}")))?;
    let schema = json
        .member("schema")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            CliError::invalid("legacy JSON needs a string schema field; only lock-v1 is migratable")
        })?;
    match schema {
        "lock-v1" => {
            let old = Lockfile::parse(source).map_err(CliError::invalid)?;
            Lockfile::new(old.entries().iter().cloned())
                .map(|lock| lock.to_canonical_json())
                .map_err(CliError::invalid)
        }
        "lock-v2" => Err(CliError::invalid("input is already lock-v2")),
        value => Err(CliError::invalid(format!(
            "{value} is not migratable; only config-v1 and lock-v1 are accepted"
        ))),
    }
}

fn command_policy(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    if arguments.first().map(String::as_str) != Some("test") {
        return Err(CliError::invalid("policy requires the test subcommand"));
    }
    let (common, positional) = parse_options(cwd, &arguments[1..], |_name, _value| Ok(false))?;
    let target = one_target(cwd, &positional)?;
    let canonical = target.canonicalize().map_err(|error| {
        CliError::invalid(format!("cannot open target {}: {error}", target.display()))
    })?;
    let root = if canonical.is_dir() {
        canonical.clone()
    } else {
        canonical
            .parent()
            .ok_or_else(|| CliError::invalid("policy fixture has no parent directory"))?
            .to_path_buf()
    };
    let config = parse_loaded_config(&load_config(&root, &common)?)?;
    let mut sidecars = Vec::new();
    if canonical.is_dir() {
        collect_policy_sidecars(&canonical, &mut sidecars)?;
    } else if policy_sidecar_path(&canonical) {
        sidecars.push(canonical);
    }
    sidecars.sort();
    sidecars.dedup();
    if sidecars.is_empty() {
        return Err(CliError::invalid(
            "policy test found no *.expect.json fixture sidecars",
        ));
    }
    let mut results = Vec::new();
    let mut errors = Vec::new();
    for sidecar in sidecars {
        match evaluate_policy_sidecar(&root, &sidecar, &config) {
            Ok(result) => results.push(result),
            Err(error) => errors.push(error),
        }
    }
    if !errors.is_empty() {
        errors.sort();
        return Err(CliError::invalid(errors.join("\n")));
    }
    results.sort_by(|left, right| left.fixture().cmp(right.fixture()));
    let passed = results
        .iter()
        .all(workflow_verifier_product::PolicyFixtureResult::passed);
    let json = JsonValue::Object(BTreeMap::from([
        (
            "cases".to_owned(),
            JsonValue::Array(
                results
                    .iter()
                    .map(workflow_verifier_product::PolicyFixtureResult::to_json)
                    .collect(),
            ),
        ),
        ("passed".to_owned(), JsonValue::Boolean(passed)),
        (
            "schema".to_owned(),
            JsonValue::String("policy-test-v1".to_owned()),
        ),
    ]));
    Ok(CommandOutput {
        code: process_exit_code(if passed {
            EXIT_CODE_PASS
        } else {
            EXIT_CODE_FINDING
        }),
        stdout: json.canonical_line(),
        stderr: String::new(),
    })
}

fn evaluate_policy_sidecar(
    root: &Path,
    sidecar: &Path,
    config: &Config,
) -> Result<workflow_verifier_product::PolicyFixtureResult, String> {
    const SUFFIX: &str = ".expect.json";
    let sidecar_source = fs::read_to_string(sidecar)
        .map_err(|error| format!("cannot read {}: {error}", sidecar.display()))?;
    let expectation = PolicyExpectation::parse(&sidecar_source)
        .map_err(|error| format!("{}: {error}", sidecar.display()))?;
    let sidecar_text = sidecar.to_string_lossy();
    let workflow_text = sidecar_text
        .strip_suffix(SUFFIX)
        .ok_or_else(|| "policy fixture sidecar has invalid suffix".to_owned())?;
    let workflow = PathBuf::from(workflow_text);
    let source = fs::read_to_string(&workflow)
        .map_err(|error| format!("cannot read {}: {error}", workflow.display()))?;
    let logical = workflow
        .strip_prefix(root)
        .map_or_else(|_| normalize_path(&workflow), normalize_path);
    let compilation = compile_auto(&logical, &source, Budget::default())
        .map_err(|problems| format!("{logical}: {}", frontend_message(&problems)))?;
    let diagnostics: Vec<_> = evaluate_policy(&config.rules, &compilation.graph)
        .into_iter()
        .filter(|diagnostic| !config.suppressed(diagnostic))
        .collect();
    Ok(evaluate_policy_fixture(
        &logical,
        &expectation,
        &diagnostics,
    ))
}

fn collect_policy_sidecars(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .map_err(|error| {
            CliError::invalid(format!(
                "cannot read directory {}: {error}",
                directory.display()
            ))
        })?
        .collect::<Result<_, _>>()
        .map_err(|error| CliError::invalid(format!("cannot read directory entry: {error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            CliError::invalid(format!("cannot inspect {}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if !excluded_directory(&path) {
                collect_policy_sidecars(&path, output)?;
            }
        } else if metadata.is_file() && policy_sidecar_path(&path) {
            output.push(path);
        }
    }
    Ok(())
}

fn policy_sidecar_path(path: &Path) -> bool {
    path.to_string_lossy().ends_with(".expect.json")
}

fn parse_loaded_config(snapshot: &ConfigSnapshot) -> Result<Config, CliError> {
    if snapshot.bytes.is_empty() {
        return Ok(Config::default());
    }
    let source = std::str::from_utf8(&snapshot.bytes)
        .map_err(|error| CliError::invalid(format!("configuration is not UTF-8: {error}")))?;
    let trust = match snapshot.trust.as_str() {
        "built-in" => ConfigTrust::BuiltIn,
        "repository" => ConfigTrust::Repository,
        "trusted" | "trusted-policy" => ConfigTrust::TrustedPolicy,
        value => {
            return Err(CliError::internal(format!(
                "unknown configuration trust {value}"
            )));
        }
    };
    let today = current_utc_date()?;
    Config::parse(
        source,
        ConfigParseOptions {
            origin: snapshot.origin.clone(),
            trust,
            today: Some(today),
        },
    )
    .map_err(|errors| CliError::invalid(errors.join("; ")))
}

fn current_utc_date() -> Result<String, CliError> {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CliError::internal("system clock is before the Unix epoch"))?
        .as_secs()
        / SECONDS_PER_DAY;
    let days = i64::try_from(days)
        .map_err(|_| CliError::internal("system clock date exceeds the supported range"))?;
    Ok(utc_date_from_days(days))
}

fn utc_date_from_days(days_since_epoch: i64) -> String {
    // Integer civil-date conversion by Howard Hinnant. Its era constants are
    // derived from the proleptic Gregorian 400-year cycle, not tuning knobs.
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}")
}

fn command_explain(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let (common, positional) = parse_options(cwd, arguments, |_name, _value| Ok(false))?;
    let Some(rule) = positional.first() else {
        return Err(CliError::invalid("explain requires a rule ID"));
    };
    if positional.len() > 2 {
        return Err(CliError::invalid("explain accepts RULE [TARGET]"));
    }
    let target = positional.get(1).map_or_else(
        || cwd.to_path_buf(),
        |value| absolute(cwd, Path::new(value)),
    );
    let result = analyze_target(&target, &common)?.result;
    let diagnostics: Vec<_> = result
        .report
        .diagnostics()
        .into_iter()
        .filter(|diagnostic| diagnostic.rule_id == *rule)
        .collect();
    if diagnostics.is_empty() {
        return Err(CliError::invalid(format!("no finding for {rule}")));
    }
    let mut output = String::new();
    for diagnostic in diagnostics {
        let _ = writeln!(output, "{}: {}", diagnostic.rule_id, diagnostic.message);
        output.push_str("trace:\n");
        for hop in diagnostic.trace {
            let _ = writeln!(output, "  - {} {}", hop.label, hop.span);
        }
        let capabilities = diagnostic
            .capabilities
            .iter()
            .map(|capability| capability.name())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(output, "capabilities: {capabilities}");
    }
    Ok(CommandOutput::success(output))
}

fn command_doctor(arguments: &[String]) -> Result<CommandOutput, CliError> {
    let mut format = "text";
    let (_common, positional) =
        parse_options(Path::new("."), arguments, |name, value| match name {
            "--format" => {
                format = required_value(name, value)?;
                if !matches!(format, "text" | "json") {
                    return Err(CliError::invalid("--format must be text or json"));
                }
                Ok(true)
            }
            _ => Ok(false),
        })?;
    if !positional.is_empty() {
        return Err(CliError::invalid(
            "doctor does not accept positional arguments",
        ));
    }
    let backends = inspect_backends();
    let rendered = if format == "json" {
        render_doctor_json(backends)
    } else {
        render_doctor_text(&backends)
    };
    Ok(CommandOutput::success(rendered))
}

fn backend_available(backend: &JsonValue) -> bool {
    backend
        .member("available")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

fn render_doctor_json(backends: Vec<JsonValue>) -> String {
    let sandbox_available = backends.iter().any(backend_available);
    JsonValue::Object(BTreeMap::from([
        ("backends".to_owned(), JsonValue::Array(backends)),
        (
            "frontends".to_owned(),
            JsonValue::Array(
                ["github", "gitlab", "azure", "circleci"]
                    .into_iter()
                    .map(|value| JsonValue::String(value.to_owned()))
                    .collect(),
            ),
        ),
        ("platform".to_owned(), JsonValue::String(host_platform())),
        ("resolver_network".to_owned(), JsonValue::Boolean(true)),
        (
            "sandbox_executor".to_owned(),
            JsonValue::Boolean(sandbox_available),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("doctor-v2".to_owned()),
        ),
    ]))
    .canonical_line()
}

fn render_doctor_text(backends: &[JsonValue]) -> String {
    let mut output = format!(
        "frontends: github, gitlab, azure, circleci\nplatform: {}\nresolver network: available\n",
        host_platform()
    );
    let sandbox_available = backends.iter().any(backend_available);
    let _ = writeln!(
        output,
        "sandbox executor: {}",
        if sandbox_available {
            "available"
        } else {
            "unavailable"
        }
    );
    for backend in backends {
        let id = backend
            .member("id")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let available = backend_available(backend);
        let reasons = backend
            .member("reasons")
            .and_then(JsonValue::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(JsonValue::as_str)
            .collect::<Vec<_>>()
            .join("; ");
        let _ = writeln!(
            output,
            "backend {id}: {}{}",
            if available {
                "available"
            } else {
                "unavailable"
            },
            if reasons.is_empty() {
                String::new()
            } else {
                format!(" ({reasons})")
            }
        );
    }
    output
}

fn host_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn inspect_backends() -> Vec<JsonValue> {
    let specifications = [
        (
            "oci:docker",
            "workflow-verifier-oci-helper",
            "linux",
            "docker",
        ),
        (
            "oci:podman",
            "workflow-verifier-oci-helper",
            "linux",
            "podman",
        ),
        (
            "linux-native",
            "workflow-verifier-linux-helper",
            "linux",
            "",
        ),
        (
            "windows-native",
            "workflow-verifier-windows-helper",
            "windows",
            "",
        ),
        ("macos-vm", "workflow-verifier-macos-helper", "macos", ""),
    ];
    specifications
        .into_iter()
        .map(|(id, executable, platform, engine)| inspect_backend(id, executable, platform, engine))
        .collect()
}

fn inspect_backend(id: &str, executable: &str, platform: &str, engine: &str) -> JsonValue {
    let executable = if cfg!(windows) {
        format!("{executable}.exe")
    } else {
        executable.to_owned()
    };
    let path = std::env::current_exe()
        .ok()
        .and_then(|current| current.parent().map(|parent| parent.join(executable)))
        .filter(|candidate| {
            fs::symlink_metadata(candidate)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        });
    let digest = path
        .as_ref()
        .and_then(|candidate| fs::read(candidate).ok())
        .map(content_digest);
    let mut available = false;
    let mut controls = Vec::new();
    let mut reasons = Vec::new();
    let mut reported_platform = platform.to_owned();
    let mut version = "0.1.0".to_owned();
    if let Some(candidate) = &path {
        match probe_backend(candidate, id, engine) {
            Ok(attestation) => {
                available = attestation.available;
                controls = attestation.controls;
                reasons = attestation.reasons;
                reported_platform = attestation.platform;
                version = attestation.version;
            }
            Err(error) => reasons.push(error),
        }
    } else {
        reasons.push("helper executable is absent".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    controls.sort();
    controls.dedup();
    let signature = if digest.is_some() {
        "unverified"
    } else {
        "absent"
    };
    JsonValue::Object(BTreeMap::from([
        ("available".to_owned(), JsonValue::Boolean(available)),
        (
            "capabilities".to_owned(),
            JsonValue::Array(controls.into_iter().map(JsonValue::String).collect()),
        ),
        (
            "digest".to_owned(),
            digest.map_or(JsonValue::Null, JsonValue::String),
        ),
        ("id".to_owned(), JsonValue::String(id.to_owned())),
        (
            "path".to_owned(),
            path.map_or(JsonValue::Null, |value| {
                JsonValue::String(normalize_slashes(&value.to_string_lossy()))
            }),
        ),
        ("platform".to_owned(), JsonValue::String(reported_platform)),
        (
            "protocol".to_owned(),
            JsonValue::String("backend-attestation-v1/runner-v2/evidence-v2".to_owned()),
        ),
        (
            "reasons".to_owned(),
            JsonValue::Array(reasons.into_iter().map(JsonValue::String).collect()),
        ),
        ("required_features".to_owned(), JsonValue::Array(Vec::new())),
        (
            "signature".to_owned(),
            JsonValue::String(signature.to_owned()),
        ),
        ("version".to_owned(), JsonValue::String(version)),
    ]))
}

struct BackendAttestation {
    available: bool,
    controls: Vec<String>,
    platform: String,
    reasons: Vec<String>,
    version: String,
}

fn probe_backend(path: &Path, id: &str, engine: &str) -> Result<BackendAttestation, String> {
    let mut command = std::process::Command::new(path);
    command.arg("--doctor");
    if !engine.is_empty() {
        command.args(["--engine", engine]);
    }
    command
        .env_clear()
        .envs(helper_environment(&[], |name| std::env::var_os(name)));
    let output = supervise_process(
        &mut command,
        None,
        Duration::from_secs(DOCTOR_TIMEOUT_SECONDS),
        DOCTOR_STREAM_MEBIBYTES * BYTES_PER_MEBIBYTE,
        DOCTOR_STREAM_MEBIBYTES * BYTES_PER_MEBIBYTE,
    )
    .map_err(|error| format!("helper doctor failed: {error}"))?;
    if output.timed_out {
        return Err("helper doctor timed out".to_owned());
    }
    if output.output_exceeded {
        return Err("helper doctor output exceeds its byte limit".to_owned());
    }
    if !output.status.success() {
        return Err(format!(
            "helper doctor exited with status {}",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        ));
    }
    parse_backend_attestation(&output.stdout, id)
}

fn parse_backend_attestation(
    source: &[u8],
    expected_id: &str,
) -> Result<BackendAttestation, String> {
    let value = JsonValue::parse_bytes(source).map_err(|error| error.to_string())?;
    let fields = value.exact_object(
        "backend attestation",
        &[
            "available",
            "controls",
            "id",
            "platform",
            "reasons",
            "schema",
            "version",
        ],
    )?;
    let string = |name: &str| {
        fields
            .get(name)
            .and_then(JsonValue::as_str)
            .ok_or_else(|| format!("backend attestation {name} must be a string"))
    };
    if string("schema")? != "backend-attestation-v1" || string("id")? != expected_id {
        return Err("helper returned a mismatched backend attestation".to_owned());
    }
    let strings = |name: &str| -> Result<Vec<String>, String> {
        fields
            .get(name)
            .and_then(JsonValue::as_array)
            .ok_or_else(|| format!("backend attestation {name} must be an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("backend attestation {name} values must be strings"))
            })
            .collect()
    };
    Ok(BackendAttestation {
        available: fields
            .get("available")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "backend attestation available must be a boolean".to_owned())?,
        controls: strings("controls")?,
        platform: string("platform")?.to_owned(),
        reasons: strings("reasons")?,
        version: string("version")?.to_owned(),
    })
}

fn command_auth(arguments: &[String]) -> Result<CommandOutput, CliError> {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return Err(CliError::invalid("auth requires login, status, or logout"));
    };
    let (provider, host) = parse_auth_arguments(&arguments[1..])?;
    let service = AuthService::new(SystemCredentialStore);
    match subcommand {
        "login" => {
            let provider = provider
                .ok_or_else(|| CliError::invalid("auth login requires exactly one provider"))?;
            let key = CredentialKey::new(provider, host.as_deref()).map_err(CliError::invalid)?;
            if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
                return Err(CliError::invalid(
                    "auth login requires an interactive terminal; CI must use resolve --auth-from-env PROVIDER@HOST=ENV_NAME",
                ));
            }
            let secret = acquire_interactive_credential(&key)?;
            service.login(&key, &secret).map_err(CliError::internal)?;
            Ok(CommandOutput::success(format!(
                "credential stored in the OS credential store for {}\n",
                key.identity()
            )))
        }
        "status" => {
            if host.is_some() && provider.is_none() {
                return Err(CliError::invalid("auth status --host requires PROVIDER"));
            }
            let providers = provider.map_or_else(
                || {
                    vec![
                        ProviderKind::Github,
                        ProviderKind::Gitlab,
                        ProviderKind::Azure,
                        ProviderKind::Circleci,
                    ]
                },
                |value| vec![value],
            );
            let mut output = String::new();
            for provider in providers {
                let key =
                    CredentialKey::new(provider, host.as_deref()).map_err(CliError::invalid)?;
                let state = service.status(&key).map_err(CliError::internal)?;
                let _ = writeln!(
                    output,
                    "{}: {}",
                    key.identity(),
                    if state {
                        "authenticated"
                    } else {
                        "not authenticated"
                    }
                );
            }
            Ok(CommandOutput::success(output))
        }
        "logout" => {
            let provider = provider
                .ok_or_else(|| CliError::invalid("auth logout requires exactly one provider"))?;
            let key = CredentialKey::new(provider, host.as_deref()).map_err(CliError::invalid)?;
            let removed = service.logout(&key).map_err(CliError::internal)?;
            Ok(CommandOutput::success(format!(
                "{}: {}\n",
                key.identity(),
                if removed {
                    "removed"
                } else {
                    "not authenticated"
                }
            )))
        }
        _ => Err(CliError::invalid("auth requires login, status, or logout")),
    }
}

fn parse_auth_arguments(
    arguments: &[String],
) -> Result<(Option<ProviderKind>, Option<String>), CliError> {
    let mut provider = None;
    let mut host = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--host" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| CliError::invalid("--host requires a value"))?;
                if host.replace(value.clone()).is_some() {
                    return Err(CliError::invalid("--host can be supplied only once"));
                }
            }
            value if value.starts_with('-') => {
                return Err(CliError::invalid(format!(
                    "unknown auth option {value}; credentials are never accepted on argv"
                )));
            }
            value => {
                if provider.is_some() {
                    return Err(CliError::invalid(
                        "auth accepts at most one provider and never accepts a token argument",
                    ));
                }
                provider = Some(ProviderKind::parse(value).map_err(CliError::invalid)?);
            }
        }
        index += 1;
    }
    Ok((provider, host))
}

fn acquire_interactive_credential(key: &CredentialKey) -> Result<SecretString, CliError> {
    let _ = writeln!(
        io::stderr().lock(),
        "Authentication for {}. Browser/device flow through the official provider CLI is preferred.",
        key.identity()
    );
    if prompt_yes_no("Run the official provider CLI now? [y/N] ")?
        && run_provider_login(key)
        && let Some(secret) = import_provider_credential(key)?
    {
        return Ok(secret);
    }
    masked_token_prompt()
}

fn prompt_yes_no(prompt: &str) -> Result<bool, CliError> {
    io::stderr()
        .lock()
        .write_all(prompt.as_bytes())
        .and_then(|()| io::stderr().lock().flush())
        .map_err(|_| CliError::internal("cannot write authentication prompt"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| CliError::internal("cannot read authentication choice"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn run_provider_login(key: &CredentialKey) -> bool {
    let mut command = match key.provider() {
        ProviderKind::Github => {
            let mut command = std::process::Command::new("gh");
            command.args(["auth", "login", "--hostname", key.host(), "--web"]);
            command
        }
        ProviderKind::Gitlab => {
            let mut command = std::process::Command::new("glab");
            command.args(["auth", "login", "--hostname", key.host(), "--web"]);
            command
        }
        ProviderKind::Azure => {
            let mut command = std::process::Command::new("az");
            command.args(["login", "--use-device-code"]);
            command
        }
        ProviderKind::Circleci => return false,
    };
    command.status().is_ok_and(|status| status.success())
}

fn import_provider_credential(key: &CredentialKey) -> Result<Option<SecretString>, CliError> {
    let mut command = match key.provider() {
        ProviderKind::Github => {
            let mut command = std::process::Command::new("gh");
            command.args(["auth", "token", "--hostname", key.host()]);
            command
        }
        ProviderKind::Gitlab => {
            let mut command = std::process::Command::new("glab");
            command.args(["auth", "token", "--hostname", key.host()]);
            command
        }
        ProviderKind::Azure => {
            let mut command = std::process::Command::new("az");
            command.args([
                "account",
                "get-access-token",
                "--query",
                "accessToken",
                "--output",
                "tsv",
            ]);
            command
        }
        ProviderKind::Circleci => return Ok(None),
    };
    command.stderr(std::process::Stdio::null());
    let Ok(mut output) = command.output() else {
        return Ok(None);
    };
    if !output.status.success() {
        output.stdout.fill(0);
        return Ok(None);
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| CliError::internal("official provider CLI returned invalid credential text"))?
        .trim()
        .to_owned();
    output.stdout.fill(0);
    SecretString::new(value)
        .map(Some)
        .map_err(CliError::internal)
}

#[cfg(unix)]
fn masked_token_prompt() -> Result<SecretString, CliError> {
    struct EchoGuard;
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("stty").arg("echo").status();
            let _ = writeln!(io::stderr().lock());
        }
    }
    let status = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .map_err(|_| CliError::internal("terminal echo control is unavailable"))?;
    if !status.success() {
        return Err(CliError::internal("terminal echo could not be disabled"));
    }
    let _guard = EchoGuard;
    io::stderr()
        .lock()
        .write_all(b"Token (masked): ")
        .and_then(|()| io::stderr().lock().flush())
        .map_err(|_| CliError::internal("cannot write token prompt"))?;
    let mut input = zeroize::Zeroizing::new(String::new());
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| CliError::internal("cannot read masked token"))?;
    SecretString::new(input.trim().to_owned()).map_err(CliError::invalid)
}

#[cfg(not(unix))]
fn masked_token_prompt() -> Result<SecretString, CliError> {
    Err(CliError::internal(
        "masked token input is unavailable on this platform build",
    ))
}

fn command_check(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let mut format = "text";
    let mut output = None;
    let (common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--format" => {
            let selected = required_value(name, value)?;
            if !matches!(selected, "text" | "json" | "sarif") {
                return Err(CliError::invalid(
                    "--format must be one of text, json, or sarif",
                ));
            }
            format = selected;
            Ok(true)
        }
        "--output" => {
            output = Some(PathBuf::from(required_value(name, value)?));
            Ok(true)
        }
        "--cache-mode" => {
            let mode = required_value(name, value)?;
            if !matches!(mode, "off" | "user") {
                return Err(CliError::invalid("--cache-mode must be off or user"));
            }
            Ok(true)
        }
        _ => Ok(false),
    })?;
    let target = one_target(cwd, &positional)?;
    let analyzed = analyze_target(&target, &common)?;
    let rendered = match format {
        "json" => analyzed.result.report.to_canonical_json(),
        "sarif" => report_to_sarif(&analyzed.result.report),
        _ => render_text(&analyzed.result, &analyzed.loaded.sources),
    };
    if let Some(path) = &output {
        atomic_write(&absolute(cwd, path), rendered.as_bytes())?;
    }
    let code = check_exit_code(&analyzed.result);
    Ok(CommandOutput {
        code,
        stdout: if output.is_some() {
            String::new()
        } else {
            rendered
        },
        stderr: String::new(),
    })
}

fn command_graph(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let mut format = "json";
    let mut kind = GraphKind::All;
    let (common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--format" => {
            format = required_value(name, value)?;
            if !matches!(format, "json" | "dot") {
                return Err(CliError::invalid("--format must be json or dot"));
            }
            Ok(true)
        }
        "--kind" => {
            kind = match required_value(name, value)? {
                "all" => GraphKind::All,
                "control" => GraphKind::Control,
                "dataflow" => GraphKind::Dataflow,
                "call" => GraphKind::Call,
                "capability" => GraphKind::Capability,
                _ => {
                    return Err(CliError::invalid(
                        "--kind must be all, control, dataflow, call, or capability",
                    ));
                }
            };
            Ok(true)
        }
        _ => Ok(false),
    })?;
    let target = one_target(cwd, &positional)?;
    let result = analyze_target(&target, &common)?.result;
    let graph = compose_graphs(&result.report.graphs);
    Ok(CommandOutput::success(if format == "dot" {
        graph_to_dot(kind, &graph)
    } else {
        graph_to_canonical_json(kind, &graph)
    }))
}

fn command_diff(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let (common, positional) = parse_options(cwd, arguments, |_name, _value| Ok(false))?;
    if positional.len() != 2 {
        return Err(CliError::invalid("diff requires BASE and HEAD"));
    }
    let base = analyze_target(&absolute(cwd, Path::new(&positional[0])), &common)?;
    let head = analyze_target(&absolute(cwd, Path::new(&positional[1])), &common)?;
    let difference = semantic_diff(
        &compose_graphs(&base.result.report.graphs),
        &compose_graphs(&head.result.report.graphs),
    );
    Ok(CommandOutput::success(difference.to_canonical_json()))
}

fn command_fix(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let mut apply = false;
    let (common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--apply" => {
            reject_value(name, value)?;
            apply = true;
            Ok(true)
        }
        _ => Ok(false),
    })?;
    let target = one_target(cwd, &positional)?;
    let (loaded, _, config) = load_workspace_and_config(&target, &common)?;
    let sources: Vec<(String, String)> = if target.is_file() {
        let (logical, source) = selected_source(&loaded, &target)?;
        vec![(logical.to_owned(), source.to_owned())]
    } else {
        loaded
            .sources
            .iter()
            .filter(|(logical, source)| {
                detect(logical, source).is_some_and(|provider| {
                    config.frontends.contains(&provider) && entrypoint(provider, logical, source)
                })
            })
            .map(|(logical, source)| (logical.clone(), source.clone()))
            .collect()
    };
    let lock = load_lock(
        &loaded.root,
        common.lockfile.as_deref(),
        Some(&loaded.authenticated),
    )?
    .0;
    let mut changes = Vec::new();
    let mut diff = String::new();
    for (logical, source) in sources {
        let compilation = compile_auto(&logical, &source, Budget::default())
            .map_err(|problems| frontend_error(&problems))?;
        let proposals: Vec<_> = compilation
            .dependencies
            .iter()
            .filter_map(|dependency| {
                lock.find(dependency.provider, &dependency.reference)
                    .and_then(|entry| {
                        FixProposal::pin_dependency(
                            &compilation.cst,
                            &dependency.reference,
                            &entry.revision,
                        )
                    })
            })
            .collect();
        if proposals.is_empty() {
            continue;
        }
        let combined = FixProposal::combine(&proposals).map_err(CliError::internal)?;
        let after = combined
            .apply_verified(&compilation.cst, |candidate| {
                compile_auto(&logical, candidate, Budget::default())
                    .map(|_| ())
                    .map_err(|problems| frontend_message(&problems))
            })
            .map_err(CliError::internal)?;
        diff.push_str(&combined.unified_diff(&logical, &source, &after));
        changes.push((logical, after));
    }
    if apply {
        for (logical, after) in changes {
            atomic_write(&loaded.root.join(logical), after.as_bytes())?;
        }
    }
    Ok(CommandOutput::success(diff))
}

#[derive(Debug, Default)]
struct ResolveOptions {
    allow_network: bool,
    update: bool,
    auth_bindings: Vec<String>,
    network_profile: Option<PathBuf>,
}

fn parse_resolve_options(
    cwd: &Path,
    arguments: &[String],
) -> Result<(CommonOptions, Vec<String>, ResolveOptions), CliError> {
    let mut options = ResolveOptions::default();
    let (common, positional) = parse_options(cwd, arguments, |name, value| match name {
        "--allow-network" => {
            reject_value(name, value)?;
            options.allow_network = true;
            Ok(true)
        }
        "--update" => {
            reject_value(name, value)?;
            options.update = true;
            Ok(true)
        }
        "--auth-from-env" => {
            options
                .auth_bindings
                .push(required_value(name, value)?.to_owned());
            Ok(true)
        }
        "--network-profile" => {
            let path = absolute(cwd, Path::new(required_value(name, value)?));
            if options.network_profile.replace(path).is_some() {
                return Err(CliError::invalid(
                    "--network-profile can be supplied only once",
                ));
            }
            Ok(true)
        }
        _ => Ok(false),
    })?;
    if options.update && !options.allow_network {
        return Err(CliError::invalid("--update requires --allow-network"));
    }
    if options.network_profile.is_some() && !options.allow_network {
        return Err(CliError::invalid(
            "--network-profile requires --allow-network",
        ));
    }
    validate_auth_bindings(&options.auth_bindings)?;
    Ok((common, positional, options))
}

fn command_resolve(cwd: &Path, arguments: &[String]) -> Result<CommandOutput, CliError> {
    let (common, positional, options) = parse_resolve_options(cwd, arguments)?;
    let target = one_target(cwd, &positional)?;
    let (loaded, _, config) = load_workspace_and_config(&target, &common)?;
    let (lock, _) = load_lock(
        &loaded.root,
        common.lockfile.as_deref(),
        Some(&loaded.authenticated),
    )?;
    let mut compilations = Vec::new();
    for (path, source) in &loaded.sources {
        let Some(provider) = detect(path, source) else {
            continue;
        };
        let selected_root = loaded
            .roots
            .as_ref()
            .is_some_and(|roots| roots.contains(path));
        if !config.frontends.contains(&provider)
            || loaded
                .roots
                .as_ref()
                .is_some_and(|roots| !roots.contains(path))
            || (!selected_root && !entrypoint(provider, path, source))
        {
            continue;
        }
        let compilation = compile_auto(path, source, Budget::default())
            .map_err(|problems| frontend_error(&problems))?;
        compilations.push(compilation);
    }
    let compilations = link_local(&loaded.sources, compilations, Budget::default())
        .map_err(|errors| CliError::invalid(errors.join("; ")))?;
    let dependencies: Vec<_> = compilations
        .into_iter()
        .flat_map(|compilation| compilation.dependencies)
        .collect();
    let credentials = if options.allow_network {
        load_auth_bindings_with(&options.auth_bindings, |name| std::env::var_os(name))?
    } else {
        BTreeMap::new()
    };
    let trusted_network = options
        .network_profile
        .as_deref()
        .map(|path| TrustedNetworkProfile::load(path, &repository_boundary(cwd, &loaded.root)))
        .transpose()
        .map_err(CliError::invalid)?
        .unwrap_or_default();
    let mut native = if options.allow_network {
        Some(NativeDependencyResolver::new(
            &config,
            credentials,
            &trusted_network,
        )?)
    } else {
        None
    };
    let result = resolve_dependencies(
        &dependencies,
        &lock,
        options.update,
        &config.resolver.allowed_sources,
        native
            .as_mut()
            .map(|resolver| resolver as &mut dyn DependencyFetcher),
    );
    if options.allow_network && result.errors.is_empty() {
        let lock_path = common
            .lockfile
            .clone()
            .unwrap_or_else(|| loaded.root.join("workflow-verifier.lock"));
        atomic_write(&lock_path, result.lockfile.to_canonical_json().as_bytes())?;
    }
    let mut messages = result.errors.clone();
    messages.extend(
        result.unresolved.iter().map(|dependency| {
            format!("Incomplete.Unresolved_dependency: {}", dependency.reference)
        }),
    );
    messages.sort();
    messages.dedup();
    Ok(CommandOutput {
        code: process_exit_code(if messages.is_empty() {
            EXIT_CODE_PASS
        } else {
            EXIT_CODE_INCOMPLETE
        }),
        stdout: result.lockfile.to_canonical_json(),
        stderr: if messages.is_empty() {
            String::new()
        } else {
            format!("{}\n", messages.join("\n"))
        },
    })
}

struct NativeDependencyResolver {
    client: network::SecureHttpClient<network::SystemDnsResolver, network::RustlsTransport>,
    trusted_hosts: Vec<network::TrustedHost>,
    credentials: BTreeMap<CredentialKey, SecretString>,
}

impl NativeDependencyResolver {
    fn new(
        config: &Config,
        mut credentials: BTreeMap<CredentialKey, SecretString>,
        trusted_network: &TrustedNetworkProfile,
    ) -> Result<Self, CliError> {
        load_stored_credentials(&mut credentials, &config.resolver.allowed_origins);
        let transport = network::RustlsTransport::from_native_roots_with_proxy(
            &trusted_network.additional_der_roots,
            trusted_network.proxy.as_ref(),
        )
        .map_err(CliError::infrastructure)?;
        let maximum = usize::try_from(config.analysis.max_resolver_bytes)
            .map_err(|_| CliError::invalid("resolver byte budget exceeds this platform"))?;
        let limits = network::HttpLimits {
            max_response_bytes: maximum,
            ..network::HttpLimits::default()
        };
        Ok(Self {
            client: network::SecureHttpClient::new(network::SystemDnsResolver, transport, limits),
            trusted_hosts: trusted_resolver_hosts(&config.resolver.allowed_origins)
                .map_err(CliError::invalid)?,
            credentials,
        })
    }

    fn get(&self, request: &resolver_transport::ResolverRequest) -> Result<Vec<u8>, String> {
        let credential = resolver_credential(&self.credentials, request)?;
        self.client
            .get_with_headers(
                &request.url,
                credential.map(SecretString::expose),
                &self.trusted_hosts,
                &request.headers,
            )
            .map(|response| response.body)
    }
}

impl DependencyFetcher for NativeDependencyResolver {
    fn fetch(
        &mut self,
        dependency: &workflow_verifier_frontend::Dependency,
    ) -> Result<FetchedDependency, String> {
        let mut get = |request: &resolver_transport::ResolverRequest| self.get(request);
        resolver_transport::resolve_dependency(dependency, &mut get)
    }
}

fn command_completion(arguments: &[String]) -> Result<CommandOutput, CliError> {
    if arguments.len() != 1 {
        return Err(CliError::invalid(
            "completion requires bash, zsh, fish, or powershell",
        ));
    }
    let script = match arguments[0].as_str() {
        "bash" => {
            "complete -W 'check resolve explain graph diff fix policy sandbox doctor completion migrate version lsp auth' workflow-verifier\n"
        }
        "zsh" => {
            "#compdef workflow-verifier\n_arguments '1:command:(check resolve explain graph diff fix policy sandbox doctor completion migrate version lsp auth)'\n"
        }
        "fish" => {
            "complete -c workflow-verifier -f -a 'check resolve explain graph diff fix policy sandbox doctor completion migrate version lsp auth'\n"
        }
        "powershell" => {
            "Register-ArgumentCompleter -Native -CommandName workflow-verifier -ScriptBlock { param($wordToComplete) 'check','resolve','explain','graph','diff','fix','policy','sandbox','doctor','completion','migrate','version','lsp','auth' | Where-Object { $_ -like \"$wordToComplete*\" } }\n"
        }
        _ => {
            return Err(CliError::invalid(
                "completion requires bash, zsh, fish, or powershell",
            ));
        }
    };
    Ok(CommandOutput::success(script))
}

fn parse_options<'a>(
    cwd: &Path,
    arguments: &'a [String],
    mut extension: impl FnMut(&'a str, Option<&'a str>) -> Result<bool, CliError>,
) -> Result<(CommonOptions, Vec<String>), CliError> {
    let mut common = CommonOptions::default();
    let mut positional = Vec::new();
    let mut index = 0;
    let mut options = true;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if options && argument == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && argument.starts_with('-') {
            let takes_value = matches!(
                argument,
                "--config"
                    | "--policy"
                    | "--lockfile"
                    | "--persona"
                    | "--format"
                    | "--output"
                    | "--cache-mode"
                    | "--kind"
                    | "--auth-from-env"
                    | "--network-profile"
                    | "--suppression-owner"
                    | "--suppression-expiry"
                    | "--backend"
                    | "--scenario"
                    | "--job"
                    | "--event"
                    | "--runner"
                    | "--input"
                    | "--matrix"
                    | "--variable"
                    | "--secret"
                    | "--network-destination"
            );
            let value = if takes_value {
                index += 1;
                arguments.get(index).map(String::as_str)
            } else {
                None
            };
            let handled = match argument {
                "--config" => {
                    common.config =
                        Some(absolute(cwd, Path::new(required_value(argument, value)?)));
                    true
                }
                "--policy" => {
                    common.policy =
                        Some(absolute(cwd, Path::new(required_value(argument, value)?)));
                    true
                }
                "--lockfile" => {
                    common.lockfile =
                        Some(absolute(cwd, Path::new(required_value(argument, value)?)));
                    true
                }
                "--persona" => {
                    common.persona = Some(match required_value(argument, value)? {
                        "audit" => Persona::Audit,
                        "gate" => Persona::Gate,
                        "paranoid" => Persona::Paranoid,
                        _ => {
                            return Err(CliError::invalid(
                                "--persona must be audit, gate, or paranoid",
                            ));
                        }
                    });
                    true
                }
                "--trust-repository-config" => {
                    common.trust_repository_config = true;
                    true
                }
                "--strict" => {
                    common.strict = true;
                    true
                }
                _ => extension(argument, value)?,
            };
            if !handled {
                return Err(CliError::invalid(format!("unknown option {argument}")));
            }
        } else {
            positional.push(argument.to_owned());
        }
        index += 1;
    }
    if common.config.is_some() && common.policy.is_some() {
        return Err(CliError::invalid(
            "--config and --policy cannot be used together",
        ));
    }
    Ok((common, positional))
}

fn required_value<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str, CliError> {
    value.ok_or_else(|| CliError::invalid(format!("{name} requires a value")))
}

fn reject_value(name: &str, value: Option<&str>) -> Result<(), CliError> {
    if value.is_some() {
        Err(CliError::invalid(format!("{name} does not take a value")))
    } else {
        Ok(())
    }
}

fn one_target(cwd: &Path, positional: &[String]) -> Result<PathBuf, CliError> {
    if positional.len() > 1 {
        return Err(CliError::invalid("expected at most one workflow target"));
    }
    Ok(positional.first().map_or_else(
        || cwd.to_path_buf(),
        |value| absolute(cwd, Path::new(value)),
    ))
}

fn absolute(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn analyze_target(target: &Path, common: &CommonOptions) -> Result<AnalyzedWorkspace, CliError> {
    let (loaded, config_snapshot, config) = load_workspace_and_config(target, common)?;
    let persona = common.persona.unwrap_or(config.persona);
    let (_, lock_snapshot) = load_lock(
        &loaded.root,
        common.lockfile.as_deref(),
        Some(&loaded.authenticated),
    )?;
    let result = analysis_engine()?
        .analyze(&AnalysisRequest {
            snapshot: loaded.snapshot.clone(),
            overlays: BTreeMap::new(),
            roots: loaded.roots.clone(),
            config: config_snapshot,
            lock: lock_snapshot,
            persona,
            budget: Budget::default(),
            cancellation: CancellationToken::new(),
            worker_count: DETERMINISTIC_WORKER_COUNT,
            strict: common.strict,
        })
        .map_err(|error| CliError::invalid(error.to_string()))?;
    Ok(AnalyzedWorkspace {
        loaded,
        result,
        config,
    })
}

fn analysis_engine() -> Result<AnalysisEngine, CliError> {
    let executable = std::env::current_exe()
        .map_err(|error| CliError::internal(format!("cannot locate analyzer binary: {error}")))?;
    let bytes = fs::read(&executable).map_err(|error| {
        CliError::internal(format!(
            "cannot authenticate analyzer binary {}: {error}",
            executable.display()
        ))
    })?;
    Ok(AnalysisEngine::with_build(BuildInfo {
        implementation: "rust".to_owned(),
        compiler: env!("WORKFLOW_VERIFIER_RUSTC_VERSION").to_owned(),
        target: env!("WORKFLOW_VERIFIER_BUILD_TARGET").to_owned(),
        source_commit: option_env!("WORKFLOW_VERIFIER_SOURCE_COMMIT").map(str::to_owned),
        binary_digest: content_digest(bytes),
    }))
}

fn load_config(root: &Path, common: &CommonOptions) -> Result<ConfigSnapshot, CliError> {
    load_config_from_snapshot(root, common, None)
}

fn load_config_from_snapshot(
    root: &Path,
    common: &CommonOptions,
    captured: Option<&RuntimeSourceSnapshot>,
) -> Result<ConfigSnapshot, CliError> {
    let explicit = common.policy.as_ref().or(common.config.as_ref());
    let automatic = root.join(".workflow-verifier.toml");
    let path = explicit.map(|path| absolute(root, path)).or_else(|| {
        captured
            .map_or_else(
                || automatic.is_file(),
                |snapshot| snapshot.regular_file(".workflow-verifier.toml").is_some(),
            )
            .then_some(automatic)
    });
    let Some(path) = path else {
        return Ok(ConfigSnapshot::default());
    };
    let canonical = path.canonicalize().map_err(|error| {
        CliError::invalid(format!("cannot open config {}: {error}", path.display()))
    })?;
    if common.policy.is_some() && canonical.strip_prefix(root).is_ok() {
        return Err(CliError::invalid(
            "--policy must be outside the analyzed source tree",
        ));
    }
    let relative = canonical.strip_prefix(root).ok().map(normalize_path);
    let bytes = match (captured, relative.as_deref()) {
        (Some(snapshot), Some(relative)) => snapshot
            .regular_file(relative)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                CliError::invalid(format!(
                    "{} is absent from the authenticated source snapshot",
                    canonical.display()
                ))
            })?,
        _ => fs::read(&canonical).map_err(|error| {
            CliError::invalid(format!("cannot read {}: {error}", canonical.display()))
        })?,
    };
    let origin = relative.unwrap_or_else(|| {
        canonical.file_name().map_or_else(
            || "external".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        )
    });
    let trust = if common.policy.is_some() || common.trust_repository_config {
        "trusted"
    } else {
        "repository"
    };
    Ok(ConfigSnapshot {
        origin: format!(
            "{}:{origin}",
            if trust == "trusted" {
                "trusted-policy"
            } else {
                "repository"
            }
        ),
        trust: trust.to_owned(),
        digest: content_digest(&bytes),
        bytes: bytes.into(),
    })
}

fn load_lock(
    root: &Path,
    explicit: Option<&Path>,
    captured: Option<&RuntimeSourceSnapshot>,
) -> Result<(Lockfile, LockSnapshot), CliError> {
    let automatic = root.join("workflow-verifier.lock");
    let path = explicit.map(|path| absolute(root, path)).or_else(|| {
        captured
            .map_or_else(
                || automatic.is_file(),
                |snapshot| snapshot.regular_file("workflow-verifier.lock").is_some(),
            )
            .then_some(automatic)
    });
    let Some(path) = path else {
        let lock = Lockfile::new([]).map_err(CliError::internal)?;
        return Ok((lock, LockSnapshot::default()));
    };
    let canonical = path.canonicalize().map_err(|error| {
        CliError::invalid(format!("cannot open lockfile {}: {error}", path.display()))
    })?;
    let relative = canonical.strip_prefix(root).ok().map(normalize_path);
    let bytes = match (captured, relative.as_deref()) {
        (Some(snapshot), Some(relative)) => snapshot
            .regular_file(relative)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                CliError::invalid(format!(
                    "{} is absent from the authenticated source snapshot",
                    canonical.display()
                ))
            })?,
        _ => fs::read(&canonical).map_err(|error| {
            CliError::invalid(format!("cannot read {}: {error}", canonical.display()))
        })?,
    };
    let source = std::str::from_utf8(&bytes).map_err(|error| {
        CliError::invalid(format!("{} is not UTF-8: {error}", canonical.display()))
    })?;
    let lock = Lockfile::parse(source).map_err(CliError::invalid)?;
    let snapshot = LockSnapshot {
        digest: content_digest(&bytes),
        bytes: bytes.into(),
    };
    Ok((lock, snapshot))
}

fn load_workspace_and_config(
    target: &Path,
    common: &CommonOptions,
) -> Result<(LoadedWorkspace, ConfigSnapshot, Config), CliError> {
    let target = target.canonicalize().map_err(|error| {
        CliError::invalid(format!("cannot open target {}: {error}", target.display()))
    })?;
    let root = workspace_root(&target)?;
    if !target.is_file() && !target.is_dir() {
        return Err(CliError::invalid(
            "target is not a regular file or directory",
        ));
    }
    let preliminary = load_config(&root, common)?;
    let preliminary_config = parse_loaded_config(&preliminary)?;
    let trusted_exclusions = if preliminary_config.provenance.trust == ConfigTrust::TrustedPolicy {
        preliminary_config.source_exclusions.clone()
    } else {
        Vec::new()
    };
    let authenticated = source_snapshot_with_exclusions(&root, &trusted_exclusions)
        .map_err(|error| CliError::invalid(format!("cannot authenticate source tree: {error}")))?;
    let captured = load_config_from_snapshot(&root, common, Some(&authenticated))?;
    if captured.digest != preliminary.digest || captured.trust != preliminary.trust {
        return Err(CliError::invalid(
            "configuration changed while the source snapshot was created",
        ));
    }
    let config = parse_loaded_config(&captured)?;
    let selected = target
        .is_file()
        .then(|| target.strip_prefix(&root).ok().map(normalize_path))
        .flatten();
    let roots = selected.as_ref().map(|path| BTreeSet::from([path.clone()]));
    let mut sources = BTreeMap::new();
    let mut bytes = BTreeMap::new();
    for (logical, contents) in authenticated.regular_files() {
        if !yaml_logical_path(logical)
            || selected
                .as_ref()
                .is_some_and(|selected| selected != logical)
            || (selected.is_none() && analysis_generated(logical))
        {
            continue;
        }
        let source = std::str::from_utf8(contents)
            .map_err(|error| CliError::invalid(format!("{logical} is not valid UTF-8: {error}")))?;
        sources.insert(logical.to_owned(), source.to_owned());
        bytes.insert(logical.to_owned(), contents.to_vec());
    }
    let snapshot = SourceSnapshot::new_authenticated(bytes, authenticated.manifest.digest.clone())
        .map_err(|error| CliError::invalid(error.to_string()))?;
    Ok((
        LoadedWorkspace {
            root,
            sources,
            snapshot,
            authenticated,
            roots,
        },
        captured,
        config,
    ))
}

fn workspace_root(target: &Path) -> Result<PathBuf, CliError> {
    if target.is_dir() {
        return Ok(target.to_path_buf());
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| CliError::invalid("workflow target has no parent directory"))
}

fn repository_boundary(cwd: &Path, analysis_root: &Path) -> PathBuf {
    let invocation_root = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    if analysis_root.starts_with(&invocation_root) {
        invocation_root
    } else {
        analysis_root.to_path_buf()
    }
}

fn yaml_logical_path(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
    })
}

fn analysis_generated(path: &str) -> bool {
    normalize_slashes(path).split('/').any(|component| {
        matches!(
            component.to_ascii_lowercase().as_str(),
            "target" | "_build" | "node_modules"
        )
    })
}

fn excluded_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                ".git" | "target" | "_build" | "node_modules"
            )
        })
}

fn normalize_path(path: &Path) -> String {
    let mut components = Vec::new();
    for component in path.components() {
        if let Component::Normal(value) = component {
            components.push(value.to_string_lossy().into_owned());
        }
    }
    normalize_slashes(&components.join("/"))
}

fn selected_source<'a>(
    loaded: &'a LoadedWorkspace,
    target: &Path,
) -> Result<(&'a str, &'a str), CliError> {
    let canonical = target
        .canonicalize()
        .map_err(|error| CliError::invalid(format!("cannot open {}: {error}", target.display())))?;
    let relative = canonical
        .strip_prefix(&loaded.root)
        .map_err(|_| CliError::invalid("workflow file escapes the workspace root"))?;
    let logical = normalize_path(relative);
    loaded
        .sources
        .get_key_value(&logical)
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .ok_or_else(|| CliError::invalid("workflow file is not a YAML source"))
}

fn compose_graphs(graphs: &[Graph]) -> Graph {
    compose_program(graphs)
}

fn render_text(result: &AnalysisResult, sources: &BTreeMap<String, String>) -> String {
    let diagnostics = result.report.diagnostics();
    if diagnostics.is_empty() {
        return format!(
            "No findings. {} workflow graph(s) analyzed.\n",
            result.report.graphs.len()
        );
    }
    let mut output = String::new();
    for diagnostic in diagnostics {
        let _ = writeln!(
            output,
            "{}[{}]: {}",
            diagnostic.severity.name(),
            diagnostic.rule_id,
            diagnostic.message
        );
        let _ = writeln!(output, " --> {}", diagnostic.span);
        if let Some(source) = sources.get(&diagnostic.span.file)
            && let Some(line) = source
                .lines()
                .nth(diagnostic.span.start.line.saturating_sub(1) as usize)
        {
            let number = diagnostic.span.start.line;
            let marker = " ".repeat(diagnostic.span.start.column.saturating_sub(1) as usize);
            let width = diagnostic
                .span
                .stop
                .byte
                .saturating_sub(diagnostic.span.start.byte)
                .max(1)
                .min(line.len().saturating_sub(marker.len()).max(1));
            let _ = writeln!(
                output,
                "  |\n{number} | {line}\n  | {marker}{}",
                "^".repeat(width)
            );
        }
        let _ = writeln!(output, " confidence: {}", diagnostic.confidence.name());
        if !diagnostic.trace.is_empty() {
            let trace = diagnostic
                .trace
                .iter()
                .map(|hop| hop.label.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            let _ = writeln!(output, " trace: {trace}");
        }
        let next = diagnostic.fix.as_ref().map_or(
            "review the trace and restrict the affected workflow",
            |fix| fix.description.as_str(),
        );
        let _ = writeln!(output, " Next action: {next}\n");
    }
    output
}

fn check_exit_code(result: &AnalysisResult) -> i32 {
    i32::try_from(result.report.provenance.exit_code)
        .unwrap_or_else(|_| process_exit_code(EXIT_CODE_INTERNAL_FAILURE))
}

fn frontend_error(problems: &[workflow_verifier_frontend::FrontendProblem]) -> CliError {
    CliError::invalid(frontend_message(problems))
}

fn frontend_message(problems: &[workflow_verifier_frontend::FrontendProblem]) -> String {
    problems
        .iter()
        .map(|problem| format!("{}: {}", problem.code, problem.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn validate_auth_bindings(bindings: &[String]) -> Result<(), CliError> {
    parse_auth_binding_keys(bindings).map(|_| ())
}

fn parse_auth_binding_keys(bindings: &[String]) -> Result<Vec<(CredentialKey, String)>, CliError> {
    let mut parsed = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for binding in bindings {
        let Some((identity, variable)) = binding.split_once('=') else {
            return Err(CliError::invalid(
                "--auth-from-env requires PROVIDER@HOST=ENV_NAME",
            ));
        };
        let Some((provider, host)) = identity.split_once('@') else {
            return Err(CliError::invalid(
                "--auth-from-env requires PROVIDER@HOST=ENV_NAME",
            ));
        };
        if host.is_empty() || !valid_env_name(variable) {
            return Err(CliError::invalid(
                "--auth-from-env requires PROVIDER@HOST=ENV_NAME",
            ));
        }
        let provider = ProviderKind::parse(provider).map_err(CliError::invalid)?;
        let key = CredentialKey::new(provider, Some(host)).map_err(CliError::invalid)?;
        if !identities.insert(key.clone()) {
            return Err(CliError::invalid(format!(
                "duplicate --auth-from-env identity {}",
                key.identity()
            )));
        }
        parsed.push((key, variable.to_owned()));
    }
    Ok(parsed)
}

fn load_auth_bindings_with(
    bindings: &[String],
    mut lookup: impl FnMut(&str) -> Option<OsString>,
) -> Result<BTreeMap<CredentialKey, SecretString>, CliError> {
    parse_auth_binding_keys(bindings)?
        .into_iter()
        .map(|(key, variable)| {
            let value = lookup(&variable).ok_or_else(|| {
                CliError::invalid(format!(
                    "environment variable {variable} required by --auth-from-env is unset"
                ))
            })?;
            let value = value.into_string().map_err(|_| {
                CliError::invalid(format!(
                    "environment variable {variable} required by --auth-from-env is not UTF-8"
                ))
            })?;
            let secret = SecretString::new(value).map_err(CliError::invalid)?;
            Ok((key, secret))
        })
        .collect()
}

fn trusted_resolver_hosts(
    configured: &[ResolverOrigin],
) -> Result<Vec<network::TrustedHost>, String> {
    const OFFICIAL: &[(&str, &str)] = &[
        ("https://api.github.com", "/repos/"),
        ("https://codeload.github.com", "/"),
        ("https://raw.githubusercontent.com", "/"),
        ("https://github.com", "/"),
        ("https://gitlab.com", "/api/v4/"),
        ("https://circleci.com", "/api/v3/"),
        ("https://dev.azure.com", "/"),
        ("https://auth.docker.io", "/token"),
        ("https://registry-1.docker.io", "/v2/"),
    ];
    let mut hosts = OFFICIAL
        .iter()
        .map(|(origin, prefix)| network::TrustedHost::new(origin, [prefix]))
        .collect::<Result<Vec<_>, _>>()?;
    for origin in configured {
        let prefixes = if origin.path_prefixes.is_empty() {
            vec!["/".to_owned()]
        } else {
            origin.path_prefixes.clone()
        };
        hosts.push(network::TrustedHost::new(&origin.origin, prefixes)?);
    }
    hosts.sort_by(|left, right| {
        (left.origin(), left.path_prefixes()).cmp(&(right.origin(), right.path_prefixes()))
    });
    hosts.dedup();
    Ok(hosts)
}

fn load_stored_credentials(
    credentials: &mut BTreeMap<CredentialKey, SecretString>,
    configured: &[ResolverOrigin],
) {
    let mut keys = std::collections::BTreeSet::new();
    for provider in [
        ProviderKind::Github,
        ProviderKind::Gitlab,
        ProviderKind::Azure,
        ProviderKind::Circleci,
    ] {
        if let Ok(key) = CredentialKey::new(provider, None) {
            keys.insert(key);
        }
        for origin in configured {
            if let Ok(url) = url::Url::parse(&origin.origin)
                && let Some(host) = url.host_str()
                && let Ok(key) = CredentialKey::new(provider, Some(host))
            {
                keys.insert(key);
            }
        }
    }
    let service = AuthService::new(SystemCredentialStore);
    for key in keys {
        if credentials.contains_key(&key) {
            continue;
        }
        if let Ok(Some(secret)) = service.credential(&key) {
            credentials.insert(key, secret);
        }
    }
}

fn resolver_credential<'a>(
    credentials: &'a BTreeMap<CredentialKey, SecretString>,
    request: &resolver_transport::ResolverRequest,
) -> Result<Option<&'a SecretString>, String> {
    let Some(provider) = request.credential_provider else {
        return Ok(None);
    };
    let provider = match provider {
        Provider::Github => ProviderKind::Github,
        Provider::Gitlab => ProviderKind::Gitlab,
        Provider::Azure => ProviderKind::Azure,
        Provider::Circleci => ProviderKind::Circleci,
    };
    let url =
        url::Url::parse(&request.url).map_err(|error| format!("invalid resolver URL: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "resolver URL has no host".to_owned())?;
    let authority = match url.port() {
        Some(port) if port != HTTPS_DEFAULT_PORT => format!("{host}:{port}"),
        _ => host.to_owned(),
    };
    let actual = CredentialKey::new(provider, Some(&authority))?;
    if let Some(secret) = credentials.get(&actual) {
        return Ok(Some(secret));
    }
    let official_alias = match provider {
        ProviderKind::Github => matches!(
            host,
            "github.com" | "api.github.com" | "codeload.github.com" | "raw.githubusercontent.com"
        ),
        ProviderKind::Gitlab => host == "gitlab.com",
        ProviderKind::Azure => host == "dev.azure.com",
        ProviderKind::Circleci => host == "circleci.com",
    };
    if !official_alias {
        return Ok(None);
    }
    let default = CredentialKey::new(provider, None)?;
    Ok(credentials.get(&default))
}

fn valid_env_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|value| value == '_' || value.is_ascii_alphanumeric())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::invalid("output path has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|error| {
        CliError::invalid(format!("cannot create {}: {error}", parent.display()))
    })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError::invalid("output filename must be valid UTF-8"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                CliError::invalid(format!("cannot create {}: {error}", temporary.display()))
            })?;
        file.write_all(bytes).map_err(|error| {
            CliError::invalid(format!("cannot write {}: {error}", temporary.display()))
        })?;
        file.sync_all().map_err(|error| {
            CliError::invalid(format!("cannot sync {}: {error}", temporary.display()))
        })?;
        fs::rename(&temporary, path).map_err(|error| {
            CliError::invalid(format!(
                "cannot replace {} atomically: {error}",
                path.display()
            ))
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        helper_environment, load_auth_bindings_with, parse_auth_binding_keys, supervise_process,
        trusted_resolver_hosts, utc_date_from_days,
    };
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::process::Command;
    use std::time::Duration;
    use workflow_verifier_product::ResolverOrigin;

    fn shell_command(script: &str) -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]);
            command
        }
        #[cfg(not(windows))]
        {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            command
        }
    }

    #[test]
    fn helper_environment_contains_only_runtime_allowlist_and_granted_secrets() {
        let ambient = BTreeMap::from([
            ("PATH", "/usr/bin"),
            ("GRANTED_TOKEN", "granted-value"),
            ("UNRELATED_TOKEN", "must-not-cross-boundary"),
            ("HTTP_PROXY", "http://credential@example.invalid"),
        ]);
        let environment = helper_environment(&["GRANTED_TOKEN".to_owned()], |name| {
            ambient.get(name).map(OsString::from)
        });

        assert_eq!(
            environment.get(&OsString::from("PATH")),
            Some(&OsString::from("/usr/bin"))
        );
        assert_eq!(
            environment.get(&OsString::from("GRANTED_TOKEN")),
            Some(&OsString::from("granted-value"))
        );
        assert!(!environment.contains_key(&OsString::from("UNRELATED_TOKEN")));
        assert!(!environment.contains_key(&OsString::from("HTTP_PROXY")));
    }

    #[test]
    fn utc_calendar_adapter_handles_epoch_and_leap_boundaries() {
        assert_eq!(utc_date_from_days(0), "1970-01-01");
        assert_eq!(utc_date_from_days(11_016), "2000-02-29");
        assert_eq!(utc_date_from_days(20_692), "2026-08-27");
    }

    #[test]
    fn child_supervisor_separates_bounded_stdout_and_stderr() {
        #[cfg(windows)]
        let script = "[Console]::Out.Write('stdout'); [Console]::Error.Write('stderr')";
        #[cfg(not(windows))]
        let script = "printf stdout; printf stderr >&2";
        let observed = supervise_process(
            &mut shell_command(script),
            None,
            Duration::from_secs(2),
            64,
            64,
        )
        .expect("supervise child");

        assert!(observed.status.success());
        assert_eq!(observed.stdout, b"stdout");
        assert_eq!(observed.stderr, b"stderr");
        assert!(!observed.timed_out);
        assert!(!observed.output_exceeded);
    }

    #[test]
    fn child_supervisor_terminates_at_the_wall_timeout() {
        #[cfg(windows)]
        let script = "Start-Sleep -Seconds 10";
        #[cfg(not(windows))]
        let script = "sleep 10";
        let started = std::time::Instant::now();
        let observed = supervise_process(
            &mut shell_command(script),
            None,
            Duration::from_millis(25),
            64,
            64,
        )
        .expect("supervise child");

        assert!(observed.timed_out);
        assert!(!observed.output_exceeded);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "process descendants kept capture pipes open for {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn child_supervisor_terminates_when_output_exceeds_its_cap() {
        #[cfg(windows)]
        let script = "[Console]::Out.Write('0123456789abcdef')";
        #[cfg(not(windows))]
        let script = "printf 0123456789abcdef";
        let observed = supervise_process(
            &mut shell_command(script),
            None,
            Duration::from_secs(2),
            8,
            8,
        )
        .expect("supervise child");

        assert!(observed.output_exceeded);
        assert_eq!(observed.stdout, b"01234567");
        assert!(observed.stderr.is_empty());
    }

    #[test]
    fn environment_auth_bindings_are_typed_canonical_and_secret_safe() {
        let parsed = parse_auth_binding_keys(&[
            "github@GitHub.COM:443=GH_TOKEN".to_owned(),
            "gitlab@gitlab.enterprise.test=GL_TOKEN".to_owned(),
        ])
        .expect("bindings");
        assert_eq!(parsed[0].0.identity(), "github@github.com");
        assert_eq!(parsed[0].1, "GH_TOKEN");
        assert!(
            parse_auth_binding_keys(&[
                "github@github.com=TOKEN".to_owned(),
                "github@GITHUB.COM:443=OTHER".to_owned(),
            ])
            .is_err()
        );

        let secret = "must-not-appear-in-debug";
        let loaded = load_auth_bindings_with(&["github@github.com=GH_TOKEN".to_owned()], |name| {
            (name == "GH_TOKEN").then(|| OsString::from(secret))
        })
        .expect("load binding");
        let credential = loaded.values().next().expect("credential");
        assert_eq!(credential.expose(), secret);
        assert!(!format!("{credential:?}").contains(secret));
    }

    #[test]
    fn resolver_profiles_include_only_official_and_trusted_enterprise_paths() {
        let hosts = trusted_resolver_hosts(&[ResolverOrigin {
            origin: "https://gitlab.enterprise.test".to_owned(),
            path_prefixes: vec!["/api/v4/".to_owned()],
        }])
        .expect("trusted hosts");

        assert!(hosts.iter().any(|host| {
            host.origin() == "https://api.github.com" && host.path_prefixes() == ["/repos/"]
        }));
        assert!(hosts.iter().any(|host| {
            host.origin() == "https://gitlab.enterprise.test"
                && host.path_prefixes() == ["/api/v4/"]
        }));
        assert!(
            !hosts
                .iter()
                .any(|host| host.origin() == "https://127.0.0.1")
        );
    }
}
