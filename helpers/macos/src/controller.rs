use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use workflow_verifier_helper_runtime::ProcessObservation;
use workflow_verifier_runner_protocol::Limits;
use workflow_verifier_runner_protocol::vm::{Request, parse_observation, parse_request};

use crate::VmBundle;

const CONTROL_PREFIX: &str = "workflow-verifier-vm-control-";
const REQUEST_FILE: &str = "request.json";
const TRANSPORT_OVERHEAD: u64 = 64 * 1024;

static NEXT_CONTROL: AtomicU64 = AtomicU64::new(0);

/// Platform-neutral VM transaction boundary. Production uses the signed Swift
/// shim; tests use an in-memory transport with the identical canonical JSON.
pub trait VmTransport {
    /// Invokes the VM shim with a canonical request file.
    ///
    /// # Errors
    ///
    /// Returns an infrastructure reason when the shim cannot be started,
    /// supervised, terminated, or observed.
    fn invoke(
        &mut self,
        request_path: &Path,
        timeout: Duration,
        output_limit: u64,
    ) -> Result<ProcessObservation, String>;
}

/// Inputs needed to lower one common native step into a VM transaction.
pub struct VmExecution<'a> {
    pub plan_digest: &'a str,
    pub bundle: &'a VmBundle,
    pub source_root: &'a Path,
    pub scratch_root: &'a Path,
    pub working_directory: &'a str,
    pub argv: &'a [String],
    pub environment: &'a BTreeMap<String, String>,
    pub limits: &'a Limits,
}

struct ControlTree {
    path: PathBuf,
}

impl ControlTree {
    fn create() -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let sequence = NEXT_CONTROL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "{CONTROL_PREFIX}{}-{nonce}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .map_err(|error| format!("create VM control directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("protect VM control directory: {error}"))?;
        }
        Ok(Self { path })
    }

    fn request_path(&self) -> PathBuf {
        self.path.join(REQUEST_FILE)
    }
}

impl Drop for ControlTree {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with(CONTROL_PREFIX));
        if safe_name && self.path.parent() == Some(std::env::temp_dir().as_path()) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn canonical_root(path: &Path, name: &str) -> Result<String, String> {
    path.canonicalize()
        .map_err(|error| format!("canonicalize VM {name}: {error}"))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("VM {name} is not UTF-8"))
}

fn request(execution: &VmExecution<'_>, control: &ControlTree) -> Result<Request, String> {
    let value = Request {
        plan_digest: execution.plan_digest.to_owned(),
        image: execution.bundle.image(),
        source_root: canonical_root(execution.source_root, "source root")?,
        scratch_root: canonical_root(execution.scratch_root, "scratch root")?,
        control_root: canonical_root(&control.path, "control root")?,
        working_directory: execution.working_directory.to_owned(),
        argv: execution.argv.to_vec(),
        environment: execution.environment.clone(),
        cpu_count: execution.limits.processes.clamp(1, 8),
        memory_mb: execution.limits.memory_mb,
        processes: execution.limits.processes,
        timeout_seconds: execution.limits.cpu_seconds,
        output_bytes: execution.limits.output_bytes,
        network: false,
    };
    parse_request(&value.canonical_json())?;
    Ok(value)
}

fn decode_transport(
    transport: &ProcessObservation,
    output_limit: u64,
) -> Result<ProcessObservation, String> {
    if transport.timed_out {
        return Ok(ProcessObservation {
            code: None,
            timed_out: true,
            output_exceeded: false,
            output: Vec::new(),
            output_bytes: 0,
            wall_time_ms: transport.wall_time_ms,
        });
    }
    if transport.output_exceeded {
        return Err("VM shim response exceeded its framing limit".to_owned());
    }
    if transport.code != Some(0) {
        return Err(format!(
            "VM shim failed with {:?}: {}",
            transport.code,
            String::from_utf8_lossy(&transport.output).trim()
        ));
    }
    let encoded = std::str::from_utf8(&transport.output)
        .map_err(|error| format!("VM shim response is not UTF-8: {error}"))?;
    let observation = parse_observation(encoded)?;
    if encoded != observation.canonical_json() {
        return Err("VM shim response is not canonical JSON".to_owned());
    }
    if u64::try_from(observation.output.len()).unwrap_or(u64::MAX) > output_limit {
        return Err("VM guest returned output beyond the declared limit".to_owned());
    }
    if observation.timed_out && observation.output_exceeded {
        return Err("VM guest returned conflicting terminal states".to_owned());
    }
    let output_bytes = u64::try_from(observation.output.len()).unwrap_or(u64::MAX);
    Ok(ProcessObservation {
        code: observation.code,
        timed_out: observation.timed_out,
        output_exceeded: observation.output_exceeded,
        output: observation.output,
        output_bytes,
        wall_time_ms: transport.wall_time_ms,
    })
}

/// Executes one VM transaction and validates its canonical guest observation.
///
/// # Errors
///
/// Fails closed for unsafe input roots, malformed/noncanonical protocol,
/// transport failures, framing overflow, or guest output beyond the plan cap.
pub fn execute_vm_step(
    execution: &VmExecution<'_>,
    transport: &mut impl VmTransport,
) -> Result<ProcessObservation, String> {
    let control = ControlTree::create()?;
    let request = request(execution, &control)?;
    let encoded = request.canonical_json();
    let request_path = control.request_path();
    std::fs::write(&request_path, encoded).map_err(|error| format!("write VM request: {error}"))?;
    let transport_limit = execution
        .limits
        .output_bytes
        .saturating_mul(2)
        .saturating_add(TRANSPORT_OVERHEAD);
    let observation = transport.invoke(
        &request_path,
        Duration::from_secs(execution.limits.cpu_seconds),
        transport_limit,
    )?;
    decode_transport(&observation, execution.limits.output_bytes)
}
