use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use workflow_verifier_helper_runtime::{
    EnvironmentSecrets, NativeSandbox, NativeSandboxRequest, NativeStepRequest, ProcessObservation,
    execute_native_with_exclusions, run_command,
};
use workflow_verifier_runner_protocol::vm::Request;
use workflow_verifier_runner_protocol::{
    Descriptor, LaunchError, RunResult, SHA256_HEX_DIGITS, ValidatedPlan,
};

use crate::{VmBundle, VmExecution, VmTransport, execute_vm_step};

const ENV_BUNDLE: &str = "WORKFLOW_VERIFIER_MACOS_VM_BUNDLE";
const ENV_MANIFEST_DIGEST: &str = "WORKFLOW_VERIFIER_MACOS_VM_MANIFEST_DIGEST";
const ENV_SHIM: &str = "WORKFLOW_VERIFIER_MACOS_VM_SHIM";
const PROBE_RESPONSE: &[u8] = b"{\"available\":true,\"schema\":\"vm-shim-probe-v1\"}\n";
const PROBE_PREFIX: &str = "workflow-verifier-vm-probe-";

// Minimal deterministic VM-shim health-check profile. The probe receives only
// enough resources to start `/bin/true`; it is not a workload budget.
const PROBE_CPU_COUNT: u64 = 1;
const PROBE_MEMORY_MIB: u64 = 512;
const PROBE_PROCESS_LIMIT: u64 = 2;
const PROBE_GUEST_TIMEOUT_SECONDS: u64 = 5;
const BYTES_PER_KIBIBYTE: u64 = 1_024;
const PROBE_OUTPUT_KIBIBYTES: u64 = 4;
const PROBE_SHIM_TIMEOUT_SECONDS: u64 = 30;
const PROBE_SHIM_OUTPUT_KIBIBYTES: u64 = 64;
const PROCESS_EXIT_SUCCESS: i32 = 0;
// POSIX permission masks for private probe resources and executable checks.
const OWNER_DIRECTORY_MODE: u32 = 0o700;
const OWNER_FILE_MODE: u32 = 0o600;
const EXECUTABLE_MODE_MASK: u32 = 0o111;

static PROBE_REASONS: OnceLock<Vec<String>> = OnceLock::new();
static NEXT_PROBE: AtomicU64 = AtomicU64::new(0);

fn architecture() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x86_64"),
        value => Err(format!("unsupported macOS VM architecture {value}")),
    }
}

fn configured_bundle() -> Result<VmBundle, String> {
    let root = std::env::var_os(ENV_BUNDLE)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{ENV_BUNDLE} is not configured"))?;
    let digest = std::env::var(ENV_MANIFEST_DIGEST)
        .map_err(|_| format!("{ENV_MANIFEST_DIGEST} is not configured"))?;
    VmBundle::load(&root, &digest, architecture()?)
}

fn configured_shim() -> Result<PathBuf, String> {
    let path = if let Some(configured) = std::env::var_os(ENV_SHIM) {
        PathBuf::from(configured)
    } else {
        std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .ok_or_else(|| "macOS helper has no containing directory".to_owned())?
            .join("workflow-verifier-vm-shim")
    };
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect VM shim {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & EXECUTABLE_MODE_MASK == 0
    {
        return Err(format!(
            "VM shim must be an executable regular non-symlink file: {}",
            path.display()
        ));
    }
    path.canonicalize()
        .map_err(|error| format!("canonicalize VM shim: {error}"))
}

struct ProbeTree {
    root: PathBuf,
    source: PathBuf,
    scratch: PathBuf,
    control: PathBuf,
}

impl ProbeTree {
    fn create() -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "{PROBE_PREFIX}{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let source = root.join("source");
        let scratch = root.join("scratch");
        let control = root.join("control");
        for path in [&root, &source, &scratch, &control] {
            std::fs::create_dir(path).map_err(|error| format!("create VM probe tree: {error}"))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_DIRECTORY_MODE))
                .map_err(|error| format!("protect VM probe tree: {error}"))?;
        }
        Ok(Self {
            root,
            source,
            scratch,
            control,
        })
    }
}

impl Drop for ProbeTree {
    fn drop(&mut self) {
        let safe_name = self
            .root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with(PROBE_PREFIX));
        if safe_name && self.root.parent() == Some(std::env::temp_dir().as_path()) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn probe_request(bundle: &VmBundle, tree: &ProbeTree) -> Result<PathBuf, String> {
    let request = Request {
        plan_digest: format!("sha256:{}", "0".repeat(SHA256_HEX_DIGITS)),
        image: bundle.image(),
        source_root: tree.source.to_string_lossy().into_owned(),
        scratch_root: tree.scratch.to_string_lossy().into_owned(),
        control_root: tree.control.to_string_lossy().into_owned(),
        working_directory: "/workspace".to_owned(),
        argv: vec!["/bin/true".to_owned()],
        environment: std::collections::BTreeMap::new(),
        cpu_count: PROBE_CPU_COUNT,
        memory_mb: PROBE_MEMORY_MIB,
        processes: PROBE_PROCESS_LIMIT,
        timeout_seconds: PROBE_GUEST_TIMEOUT_SECONDS,
        output_bytes: PROBE_OUTPUT_KIBIBYTES * BYTES_PER_KIBIBYTE,
        network: false,
    };
    let path = tree.control.join("probe-request.json");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(OWNER_FILE_MODE)
        .open(&path)
        .and_then(|mut file| {
            use std::io::Write as _;
            file.write_all(request.canonical_json().as_bytes())
        })
        .map_err(|error| format!("write VM probe request: {error}"))?;
    Ok(path)
}

fn probe_uncached() -> Vec<String> {
    let result = (|| {
        let bundle = configured_bundle()?;
        let shim = configured_shim()?;
        let tree = ProbeTree::create()?;
        let request = probe_request(&bundle, &tree)?;
        let mut command = Command::new(shim);
        command.arg("--probe").arg(request).env_clear();
        let observation = run_command(
            &mut command,
            Duration::from_secs(PROBE_SHIM_TIMEOUT_SECONDS),
            PROBE_SHIM_OUTPUT_KIBIBYTES * BYTES_PER_KIBIBYTE,
        )?;
        if observation.code != Some(PROCESS_EXIT_SUCCESS)
            || observation.timed_out
            || observation.output_exceeded
            || observation.output != PROBE_RESPONSE
        {
            return Err(format!(
                "signed VM shim probe failed: {}",
                String::from_utf8_lossy(&observation.output).trim()
            ));
        }
        Ok(())
    })();
    result.err().into_iter().collect()
}

pub(super) fn probe() -> Vec<String> {
    PROBE_REASONS.get_or_init(probe_uncached).clone()
}

struct CommandTransport {
    shim: PathBuf,
}

impl VmTransport for CommandTransport {
    fn invoke(
        &mut self,
        request_path: &Path,
        timeout: Duration,
        output_limit: u64,
    ) -> Result<ProcessObservation, String> {
        let mut command = Command::new(&self.shim);
        command.arg("--run").arg(request_path).env_clear();
        run_command(&mut command, timeout, output_limit)
    }
}

struct MacSandbox {
    bundle: VmBundle,
    transport: CommandTransport,
}

impl MacSandbox {
    fn new() -> Result<Self, String> {
        Ok(Self {
            bundle: configured_bundle()?,
            transport: CommandTransport {
                shim: configured_shim()?,
            },
        })
    }
}

impl NativeSandbox for MacSandbox {
    fn prepare(&mut self, _request: &NativeSandboxRequest<'_>) -> Result<(), String> {
        Ok(())
    }

    fn run(&mut self, request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String> {
        execute_vm_step(
            &VmExecution {
                plan_digest: &request.plan.digest,
                bundle: &self.bundle,
                source_root: request.source_root,
                scratch_root: request.scratch_root,
                working_directory: &request.step.working_directory,
                argv: &request.step.argv,
                environment: &request.environment,
                limits: &request.plan.limits,
            },
            &mut self.transport,
        )
    }
}

pub(super) fn launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    trusted_exclusions: &[String],
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    let mut sandbox = MacSandbox::new().map_err(LaunchError::Infrastructure)?;
    execute_native_with_exclusions(
        plan,
        descriptor,
        source_root,
        trusted_exclusions,
        &EnvironmentSecrets,
        &mut sandbox,
    )
}
