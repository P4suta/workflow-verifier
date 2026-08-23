#![forbid(unsafe_code)]

mod native;

pub use native::{
    ClosureSandbox, EnvironmentSecrets, MapSecrets, NativeSandbox, NativeSandboxRequest,
    NativeStepRequest, SecretProvider, execute_native,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use workflow_verifier_runner_protocol::{quote_json, sha256_hex};

const TEMP_RESOURCE_ATTEMPTS: usize = 256;
static NEXT_TEMP_RESOURCE: AtomicU64 = AtomicU64::new(0);

fn validate_temp_name(purpose: &str, suffix: &str) -> Result<(), String> {
    let safe_purpose = !purpose.is_empty()
        && purpose
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    let safe_suffix = suffix.is_empty()
        || (suffix.starts_with('.')
            && !suffix.contains("..")
            && suffix[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')));
    if safe_purpose && safe_suffix {
        Ok(())
    } else {
        Err("temporary resource name contains path syntax".to_owned())
    }
}

fn temp_candidate_in(parent: &Path, purpose: &str, suffix: &str) -> Result<PathBuf, String> {
    validate_temp_name(purpose, suffix)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let sequence = NEXT_TEMP_RESOURCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        "workflow-verifier-{purpose}-{}-{nonce}-{sequence}{suffix}",
        std::process::id()
    )))
}

fn validate_temp_parent(parent: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        Err(format!(
            "temporary resource parent is not a real directory: {}",
            parent.display()
        ))
    } else {
        Ok(())
    }
}

fn reserve_temp_directory_in(parent: &Path, purpose: &str) -> Result<PathBuf, String> {
    validate_temp_parent(parent)?;
    for _ in 0..TEMP_RESOURCE_ATTEMPTS {
        let path = temp_candidate_in(parent, purpose, "")?;
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("could not reserve a unique temporary directory".to_owned())
}

/// Atomically reserves a uniquely named private directory below the process
/// temporary directory.
///
/// # Errors
///
/// Rejects path syntax in `purpose`, or fails if no candidate can be created.
pub fn reserve_temp_directory(purpose: &str) -> Result<PathBuf, String> {
    reserve_temp_directory_in(&std::env::temp_dir(), purpose)
}

/// Atomically reserves a uniquely named private file below the process
/// temporary directory and returns its open handle.
///
/// # Errors
///
/// Rejects path syntax in `purpose` or `suffix`, or fails if no candidate can
/// be created.
pub fn reserve_temp_file(purpose: &str, suffix: &str) -> Result<(PathBuf, File), String> {
    let parent = std::env::temp_dir();
    validate_temp_parent(&parent)?;
    for _ in 0..TEMP_RESOURCE_ATTEMPTS {
        let path = temp_candidate_in(&parent, purpose, suffix)?;
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("could not reserve a unique temporary file".to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceManifest {
    pub canonical_json: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSnapshot {
    pub manifest: SourceManifest,
    files: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    pub digest: Option<String>,
}

fn ignored_component(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git" | ".workflow-verifier-cache" | "_build" | "_opam" | "node_modules" | "target"
    )
}

fn checked_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| format!("non-UTF-8 source path: {}", path.display()))
}

fn visit_files(
    root: &Path,
    current: &Path,
    output: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(current).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "source symlink is not allowed: {}",
            current.display()
        ));
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(current)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if !ignored_component(checked_name(&path)?) {
                visit_files(root, &path, output)?;
            }
        }
    } else if metadata.is_file() {
        let relative = current
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 source path: {}", current.display()))?
            .replace('\\', "/");
        output.insert(
            relative,
            sha256_hex(&fs::read(current).map_err(|error| error.to_string())?),
        );
    } else {
        return Err(format!(
            "unsupported source file type: {}",
            current.display()
        ));
    }
    Ok(())
}

fn manifest(files: &BTreeMap<String, String>) -> SourceManifest {
    let entries = files
        .iter()
        .map(|(path, digest)| {
            format!(
                "{{\"digest\":\"sha256:{digest}\",\"path\":{}}}",
                quote_json(path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let canonical_json = format!("[{entries}]");
    let digest = format!("sha256:{}", sha256_hex(canonical_json.as_bytes()));
    SourceManifest {
        canonical_json,
        digest,
    }
}

/// Reads and hashes every file that may enter a sandbox mount.
///
/// # Errors
///
/// Rejects unreadable paths, symlinks, special files, and non-UTF-8 paths.
pub fn source_snapshot(root: &Path) -> Result<SourceSnapshot, String> {
    let mut files = BTreeMap::new();
    visit_files(root, root, &mut files)?;
    Ok(SourceSnapshot {
        manifest: manifest(&files),
        files,
    })
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "source symlink is not allowed: {}",
            source.display()
        ));
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination).map_err(|error| error.to_string())?;
        let mut entries = fs::read_dir(source)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = checked_name(&path)?.to_owned();
            if !ignored_component(&name) {
                copy_tree(&path, &destination.join(name))?;
            }
        }
    } else if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut input = File::open(source).map_err(|error| error.to_string())?;
        let mut output = File::create(destination).map_err(|error| error.to_string())?;
        std::io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
        fs::set_permissions(destination, metadata.permissions())
            .map_err(|error| error.to_string())?;
    } else {
        return Err(format!(
            "unsupported source file type: {}",
            source.display()
        ));
    }
    Ok(())
}

pub struct ScratchTree {
    path: PathBuf,
    cleanup_parent: PathBuf,
    baseline: SourceSnapshot,
}

pub(crate) struct PrivateSourceTree {
    path: PathBuf,
    cleanup_parent: PathBuf,
}

fn private_copy(
    source: &Path,
    baseline: &SourceSnapshot,
    storage_root: &Path,
    purpose: &str,
) -> Result<PathBuf, String> {
    if source_snapshot(source)? != *baseline {
        return Err("source changed while preparing the sandbox".to_owned());
    }
    let path = reserve_temp_directory_in(storage_root, purpose)?;
    if let Err(error) = copy_tree(source, &path) {
        let _ = fs::remove_dir_all(&path);
        return Err(error);
    }
    let copied = source_snapshot(&path)?;
    if copied.manifest != baseline.manifest {
        let _ = fs::remove_dir_all(&path);
        return Err(format!(
            "private {purpose} copy does not match the source manifest"
        ));
    }
    Ok(path)
}

impl PrivateSourceTree {
    pub(crate) fn prepare_in(
        source: &Path,
        baseline: &SourceSnapshot,
        storage_root: &Path,
    ) -> Result<Self, String> {
        private_copy(source, baseline, storage_root, "source").map(|path| Self {
            path,
            cleanup_parent: storage_root.to_path_buf(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateSourceTree {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("workflow-verifier-source-"));
        if safe_name && self.path.parent() == Some(self.cleanup_parent.as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl ScratchTree {
    /// Creates a private scratch copy after rechecking the source snapshot.
    ///
    /// # Errors
    ///
    /// Fails if the source changed, contains unsafe entries, or cannot be copied.
    pub fn prepare(source: &Path, baseline: SourceSnapshot) -> Result<Self, String> {
        Self::prepare_in(source, baseline, &std::env::temp_dir())
    }

    pub(crate) fn prepare_in(
        source: &Path,
        baseline: SourceSnapshot,
        storage_root: &Path,
    ) -> Result<Self, String> {
        let path = private_copy(source, &baseline, storage_root, "scratch")?;
        Ok(Self {
            path,
            cleanup_parent: storage_root.to_path_buf(),
            baseline,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Computes stable additions, modifications, and deletions.
    ///
    /// # Errors
    ///
    /// Fails if the scratch tree becomes unreadable or gains an unsafe entry.
    pub fn changes(&self) -> Result<Vec<Change>, String> {
        let current = source_snapshot(&self.path)?;
        let paths = self
            .baseline
            .files
            .keys()
            .chain(current.files.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        Ok(paths
            .into_iter()
            .filter_map(
                |path| match (self.baseline.files.get(&path), current.files.get(&path)) {
                    (None, Some(digest)) => Some(Change {
                        path,
                        kind: ChangeKind::Added,
                        digest: Some(format!("sha256:{digest}")),
                    }),
                    (Some(before), Some(after)) if before != after => Some(Change {
                        path,
                        kind: ChangeKind::Modified,
                        digest: Some(format!("sha256:{after}")),
                    }),
                    (Some(before), None) => Some(Change {
                        path,
                        kind: ChangeKind::Deleted,
                        digest: Some(format!("sha256:{before}")),
                    }),
                    _ => None,
                },
            )
            .collect())
    }
}

impl Drop for ScratchTree {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("workflow-verifier-scratch-"));
        if safe_name && self.path.parent() == Some(self.cleanup_parent.as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessObservation {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub output_exceeded: bool,
    pub output: Vec<u8>,
}

fn read_limited<R: Read>(
    mut reader: R,
    total: &AtomicU64,
    exceeded: &AtomicBool,
    limit: u64,
) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(captured);
        }
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        let previous = total.fetch_add(count, Ordering::Relaxed);
        if previous.saturating_add(count) > limit {
            exceeded.store(true, Ordering::Release);
        }
        if previous < limit {
            let remaining = usize::try_from(limit - previous).unwrap_or(usize::MAX);
            captured
                .extend_from_slice(&buffer[..usize::try_from(count).unwrap_or(0).min(remaining)]);
        }
    }
}

/// Runs an already configured process with a wall-clock and combined-output cap.
///
/// # Errors
///
/// Fails if process creation, waiting, termination, or output collection fails.
pub fn run_command(
    command: &mut Command,
    timeout: Duration,
    output_limit: u64,
) -> Result<ProcessObservation, String> {
    run_command_with_termination(command, timeout, output_limit, |child| {
        child.kill().map_err(|error| error.to_string())
    })
}

/// Runs an already configured process and delegates whole-tree termination to
/// the backend before output pipes are joined.
///
/// # Errors
///
/// Fails if process creation, waiting, backend termination, or output
/// collection fails.
pub fn run_command_with_termination<F>(
    command: &mut Command,
    timeout: Duration,
    output_limit: u64,
    mut terminate: F,
) -> Result<ProcessObservation, String>
where
    F: FnMut(&mut Child) -> Result<(), String>,
{
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "missing child stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "missing child stderr".to_owned())?;
    let total = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_total = Arc::clone(&total);
    let stdout_exceeded = Arc::clone(&exceeded);
    let stdout_thread = std::thread::spawn(move || {
        read_limited(stdout, &stdout_total, &stdout_exceeded, output_limit)
    });
    let stderr_total = Arc::clone(&total);
    let stderr_exceeded = Arc::clone(&exceeded);
    let stderr_thread = std::thread::spawn(move || {
        read_limited(stderr, &stderr_total, &stderr_exceeded, output_limit)
    });
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            terminate(&mut child)?;
            break child.wait().map_err(|error| error.to_string())?;
        }
        if exceeded.load(Ordering::Acquire) {
            terminate(&mut child)?;
            break child.wait().map_err(|error| error.to_string())?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut output = stdout_thread
        .join()
        .map_err(|_| "stdout capture thread panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    output.extend(
        stderr_thread
            .join()
            .map_err(|_| "stderr capture thread panicked".to_owned())?
            .map_err(|error| error.to_string())?,
    );
    Ok(ProcessObservation {
        code: status.code(),
        timed_out,
        output_exceeded: exceeded.load(Ordering::Acquire),
        output,
    })
}
