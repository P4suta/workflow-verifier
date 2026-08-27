#![forbid(unsafe_code)]

mod native;

pub use native::{
    ClosureSandbox, EnvironmentSecrets, MapSecrets, NativeSandbox, NativeSandboxRequest,
    NativeStepRequest, NativeStorageParents, SecretProvider, execute_native,
    execute_native_with_exclusions,
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
// Native child supervision polls often enough to observe cancellation without
// busy-spinning; the same cadence is used by the CLI supervisor.
const PROCESS_POLL_MILLISECONDS: u64 = 10;
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
    files: BTreeMap<String, SnapshotEntry>,
    trusted_exclusions: Vec<String>,
}

impl SourceSnapshot {
    /// Returns authenticated bytes for one regular snapshot entry.
    #[must_use]
    pub fn regular_file(&self, path: &str) -> Option<&[u8]> {
        match self.files.get(&path.replace('\\', "/")) {
            Some(SnapshotEntry::Regular { contents, .. }) => Some(contents),
            Some(SnapshotEntry::Symlink { .. }) | None => None,
        }
    }

    /// Iterates over all authenticated regular-file bytes in portable path order.
    pub fn regular_files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files.iter().filter_map(|(path, entry)| match entry {
            SnapshotEntry::Regular { contents, .. } => Some((path.as_str(), contents.as_slice())),
            SnapshotEntry::Symlink { .. } => None,
        })
    }

    /// Returns the normalized trusted policy prefixes authenticated by the manifest.
    #[must_use]
    pub fn trusted_exclusions(&self) -> &[String] {
        &self.trusted_exclusions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotEntry {
    Regular {
        contents: Vec<u8>,
        digest: String,
        executable: bool,
    },
    Symlink {
        digest: String,
        raw_target: String,
        resolved_target: String,
    },
}

impl SnapshotEntry {
    fn digest(&self) -> &str {
        match self {
            Self::Regular { digest, .. } | Self::Symlink { digest, .. } => digest,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Regular { contents, .. } => u64::try_from(contents.len()).unwrap_or(u64::MAX),
            Self::Symlink { raw_target, .. } => u64::try_from(raw_target.len()).unwrap_or(u64::MAX),
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchFinal {
    pub changes: Vec<Change>,
    pub digest: String,
    pub bytes: u64,
    pub entries: u64,
}

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_EXCLUSIONS: [&str; 4] = [
    ".git",
    ".workflow-verifier",
    ".workflow-verifier-cache",
    ".workflow-verifier-output",
];

fn ignored_component(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git" | ".workflow-verifier" | ".workflow-verifier-cache" | ".workflow-verifier-output"
    )
}

fn normalize_trusted_exclusions(values: &[String]) -> Result<Vec<String>, String> {
    let mut exact = BTreeSet::new();
    let mut portable = BTreeSet::new();
    for value in values {
        let normalized = value.replace('\\', "/");
        let components: Vec<_> = normalized.split('/').collect();
        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized.starts_with("//")
            || normalized.as_bytes().get(1) == Some(&b':')
            || normalized.contains('\0')
            || components
                .iter()
                .any(|component| component.is_empty() || matches!(*component, "." | ".."))
        {
            return Err(format!(
                "trusted source exclusion is not a portable relative prefix: {value}"
            ));
        }
        if !portable.insert(normalized.to_ascii_lowercase()) {
            return Err("trusted source exclusions collide under portable case folding".to_owned());
        }
        exact.insert(normalized);
    }
    Ok(exact.into_iter().collect())
}

fn path_below(path: &str, prefix: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let prefix = prefix.to_ascii_lowercase();
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn checked_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| format!("non-UTF-8 source path: {}", path.display()))
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
// The shared API is fallible because the Windows implementation opens a handle.
#[allow(clippy::unnecessary_wraps)]
fn file_identity(_path: &Path, metadata: &fs::Metadata) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(path: &Path, _metadata: &fs::Metadata) -> Result<String, String> {
    use std::hash::{Hash as _, Hasher as _};
    let handle = same_file::Handle::from_path(path).map_err(|error| error.to_string())?;
    let mut first = std::collections::hash_map::DefaultHasher::new();
    0x71_u8.hash(&mut first);
    handle.hash(&mut first);
    let mut second = std::collections::hash_map::DefaultHasher::new();
    0xc3_u8.hash(&mut second);
    handle.hash(&mut second);
    Ok(format!("{:016x}{:016x}", first.finish(), second.finish()))
}

#[cfg(not(any(unix, windows)))]
// Keep the same fallible cross-platform API as the Windows implementation.
#[allow(clippy::unnecessary_wraps)]
fn file_identity(path: &Path, metadata: &fs::Metadata) -> Result<String, String> {
    Ok(format!(
        "{}:{}:{}",
        path.display(),
        metadata.len(),
        metadata.permissions().readonly()
    ))
}

fn normalize_relative_target(path: &str, target: &str) -> Result<String, String> {
    let target = target.replace('\\', "/");
    if target.is_empty()
        || target.starts_with('/')
        || target.starts_with("//")
        || target.as_bytes().get(1) == Some(&b':')
    {
        return Err(format!("absolute or empty source symlink target at {path}"));
    }
    let mut segments = path.rsplit_once('/').map_or_else(Vec::new, |(parent, _)| {
        parent.split('/').map(str::to_owned).collect::<Vec<_>>()
    });
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(format!("source symlink escapes the snapshot root: {path}"));
                }
            }
            value => segments.push(value.to_owned()),
        }
    }
    if segments.is_empty() {
        Err(format!(
            "source symlink resolves to the snapshot root: {path}"
        ))
    } else {
        Ok(segments.join("/"))
    }
}

fn read_regular(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>, String> {
    if before.len() > MAX_FILE_BYTES {
        return Err(format!(
            "Incomplete.Resource_limit: file exceeds 16 MiB: {}",
            path.display()
        ));
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() || file_identity(path, &opened)? != file_identity(path, before)? {
        return Err(format!(
            "source file identity changed while opening: {}",
            path.display()
        ));
    }
    let mut contents = Vec::new();
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|error| error.to_string())?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(format!(
            "Incomplete.Resource_limit: file exceeds 16 MiB: {}",
            path.display()
        ));
    }
    let after = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if after.file_type().is_symlink()
        || file_identity(path, &after)? != file_identity(path, &opened)?
        || after.len() != u64::try_from(contents.len()).unwrap_or(u64::MAX)
    {
        return Err(format!(
            "source file changed while reading: {}",
            path.display()
        ));
    }
    Ok(contents)
}

fn visit_files(
    root: &Path,
    current: &Path,
    output: &mut BTreeMap<String, SnapshotEntry>,
    exclusions: &mut Vec<(String, &'static str)>,
    trusted_exclusions: &[String],
    identities: &mut BTreeSet<String>,
    total_size: &mut u64,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(current).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        let mut entries = fs::read_dir(current)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = checked_name(&path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 source path: {}", path.display()))?
                .replace('\\', "/");
            if ignored_component(name) {
                exclusions.push((relative, "product-default"));
            } else if trusted_exclusions
                .iter()
                .any(|prefix| path_below(&relative, prefix))
            {
                exclusions.push((relative, "trusted-policy"));
            } else {
                visit_files(
                    root,
                    &path,
                    output,
                    exclusions,
                    trusted_exclusions,
                    identities,
                    total_size,
                )?;
            }
        }
        let after = fs::symlink_metadata(current).map_err(|error| error.to_string())?;
        if !after.is_dir() || file_identity(current, &after)? != file_identity(current, &metadata)?
        {
            return Err(format!(
                "source directory changed while reading: {}",
                current.display()
            ));
        }
    } else if metadata.is_file() || metadata.file_type().is_symlink() {
        let relative = current
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 source path: {}", current.display()))?
            .replace('\\', "/");
        let folded = relative.to_ascii_lowercase();
        if output
            .keys()
            .any(|path| path.to_ascii_lowercase() == folded)
        {
            return Err(format!("portable case-fold path collision: {relative}"));
        }
        if output.len() >= MAX_ENTRIES {
            return Err("Incomplete.Resource_limit: source entry budget exceeded".to_owned());
        }
        let identity = file_identity(current, &metadata)?;
        if !identities.insert(identity) {
            return Err(format!("hardlink/file identity collision: {relative}"));
        }
        let snapshot_entry = if metadata.file_type().is_symlink() {
            let target = fs::read_link(current).map_err(|error| error.to_string())?;
            let raw_target = target
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 source symlink target: {}", current.display()))?
                .replace('\\', "/");
            let resolved_target = normalize_relative_target(&relative, &raw_target)?;
            SnapshotEntry::Symlink {
                digest: sha256_hex(raw_target.as_bytes()),
                raw_target,
                resolved_target,
            }
        } else {
            let contents = read_regular(current, &metadata)?;
            SnapshotEntry::Regular {
                digest: sha256_hex(&contents),
                executable: executable(&metadata),
                contents,
            }
        };
        *total_size = total_size
            .checked_add(snapshot_entry.size())
            .ok_or_else(|| "Incomplete.Resource_limit: snapshot size overflow".to_owned())?;
        if *total_size > MAX_SNAPSHOT_BYTES {
            return Err("Incomplete.Resource_limit: snapshot exceeds 4 GiB".to_owned());
        }
        output.insert(relative, snapshot_entry);
    } else {
        return Err(format!(
            "unsupported source file type: {}",
            current.display()
        ));
    }
    Ok(())
}

fn validate_symlink_cycles(files: &BTreeMap<String, SnapshotEntry>) -> Result<(), String> {
    fn visit(
        path: &str,
        files: &BTreeMap<String, SnapshotEntry>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if visiting.contains(path) {
            return Err(format!("source symlink cycle at {path}"));
        }
        if visited.contains(path) {
            return Ok(());
        }
        visiting.insert(path.to_owned());
        if let Some(SnapshotEntry::Symlink {
            resolved_target, ..
        }) = files.get(path)
            && matches!(
                files.get(resolved_target),
                Some(SnapshotEntry::Symlink { .. })
            )
        {
            visit(resolved_target, files, visiting, visited)?;
        }
        visiting.remove(path);
        visited.insert(path.to_owned());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for path in files.keys() {
        visit(path, files, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn manifest(
    files: &BTreeMap<String, SnapshotEntry>,
    exclusions: &[(String, &'static str)],
    trusted_exclusions: &[String],
    total_size: u64,
) -> SourceManifest {
    let entries = files
        .iter()
        .map(|(path, entry)| {
            let (kind, executable, target) = match entry {
                SnapshotEntry::Regular { executable, .. } => ("regular", *executable, "null".to_owned()),
                SnapshotEntry::Symlink { resolved_target, .. } => {
                    ("symlink", false, quote_json(resolved_target))
                }
            };
            format!("{{\"digest\":\"sha256:{}\",\"executable\":{executable},\"kind\":\"{kind}\",\"path\":{},\"size\":{},\"target\":{target}}}", entry.digest(), quote_json(path), entry.size())
        })
        .collect::<Vec<_>>()
        .join(",");
    let exclusions = exclusions
        .iter()
        .map(|(path, reason)| {
            format!(
                "{{\"path\":{},\"reason\":{}}}",
                quote_json(path),
                quote_json(reason)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let default_exclusions = DEFAULT_EXCLUSIONS
        .iter()
        .map(|value| quote_json(value))
        .collect::<Vec<_>>()
        .join(",");
    let trusted_exclusions = trusted_exclusions
        .iter()
        .map(|value| quote_json(value))
        .collect::<Vec<_>>()
        .join(",");
    let policy =
        format!("{{\"default\":[{default_exclusions}],\"trusted\":[{trusted_exclusions}]}}");
    let policy_digest = sha256_hex(policy.as_bytes());
    let unsigned_json = format!(
        "{{\"entries\":[{entries}],\"exclusion_policy_digest\":\"sha256:{policy_digest}\",\"exclusions\":[{exclusions}],\"limits\":{{\"max_entries\":{MAX_ENTRIES},\"max_file_bytes\":{MAX_FILE_BYTES},\"max_snapshot_bytes\":{MAX_SNAPSHOT_BYTES}}},\"schema\":\"source-manifest-v2\",\"total_size\":{total_size}}}"
    );
    let digest = format!("sha256:{}", sha256_hex(unsigned_json.as_bytes()));
    let canonical_json = format!(
        "{{\"digest\":\"{digest}\",{}",
        unsigned_json.trim_start_matches('{')
    );
    SourceManifest {
        canonical_json,
        digest,
    }
}

/// Reads and hashes every file that may enter a sandbox mount.
///
/// # Errors
///
/// Rejects unreadable paths, escaping symlinks, special files, and non-UTF-8 paths.
pub fn source_snapshot(root: &Path) -> Result<SourceSnapshot, String> {
    source_snapshot_with_exclusions(root, &[])
}

/// Reads and hashes a source tree after applying authenticated trusted prefixes.
///
/// # Errors
///
/// Rejects unsafe exclusion prefixes and the same unsafe source states as
/// [`source_snapshot`].
pub fn source_snapshot_with_exclusions(
    root: &Path,
    trusted_exclusions: &[String],
) -> Result<SourceSnapshot, String> {
    let trusted_exclusions = normalize_trusted_exclusions(trusted_exclusions)?;
    let mut files = BTreeMap::new();
    let mut exclusions = Vec::new();
    let mut identities = BTreeSet::new();
    let mut total_size = 0;
    visit_files(
        root,
        root,
        &mut files,
        &mut exclusions,
        &trusted_exclusions,
        &mut identities,
        &mut total_size,
    )?;
    validate_symlink_cycles(&files)?;
    exclusions.sort();
    Ok(SourceSnapshot {
        manifest: manifest(&files, &exclusions, &trusted_exclusions, total_size),
        files,
        trusted_exclusions,
    })
}

#[cfg(unix)]
fn set_executable(path: &Path, value: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)
        .map_err(|error| error.to_string())?
        .permissions();
    let mode = permissions.mode();
    permissions.set_mode(if value { mode | 0o111 } else { mode & !0o111 });
    fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
// Keep the same fallible cross-platform call contract as the Unix implementation.
#[allow(clippy::unnecessary_wraps)]
fn set_executable(_path: &Path, _value: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn create_snapshot_symlink(target: &str, path: &Path, _resolved: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, path).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn create_snapshot_symlink(target: &str, path: &Path, resolved: &Path) -> Result<(), String> {
    if resolved.is_dir() {
        std::os::windows::fs::symlink_dir(target, path).map_err(|error| error.to_string())
    } else {
        std::os::windows::fs::symlink_file(target, path).map_err(|error| error.to_string())
    }
}

#[cfg(not(any(unix, windows)))]
fn create_snapshot_symlink(_target: &str, _path: &Path, _resolved: &Path) -> Result<(), String> {
    Err("source symlink staging is unsupported on this platform".to_owned())
}

fn copy_snapshot(snapshot: &SourceSnapshot, destination: &Path) -> Result<(), String> {
    for (relative, entry) in &snapshot.files {
        if let SnapshotEntry::Regular {
            contents,
            executable,
            ..
        } = entry
        {
            let path = destination.join(relative);
            let parent = path
                .parent()
                .ok_or_else(|| format!("source entry has no parent: {relative}"))?;
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .and_then(|mut file| std::io::Write::write_all(&mut file, contents))
                .map_err(|error| error.to_string())?;
            set_executable(&path, *executable)?;
        }
    }
    for (relative, entry) in &snapshot.files {
        if let SnapshotEntry::Symlink {
            raw_target,
            resolved_target,
            ..
        } = entry
        {
            let path = destination.join(relative);
            let parent = path
                .parent()
                .ok_or_else(|| format!("source symlink has no parent: {relative}"))?;
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            create_snapshot_symlink(raw_target, &path, &destination.join(resolved_target))?;
        }
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
    if source_snapshot_with_exclusions(source, &baseline.trusted_exclusions)? != *baseline {
        return Err("source changed while preparing the sandbox".to_owned());
    }
    let path = reserve_temp_directory_in(storage_root, purpose)?;
    if let Err(error) = copy_snapshot(baseline, &path) {
        let _ = fs::remove_dir_all(&path);
        return Err(error);
    }
    let copied = source_snapshot_with_exclusions(&path, &baseline.trusted_exclusions)?;
    if copied.files != baseline.files {
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
        self.final_state().map(|state| state.changes)
    }

    /// Captures the final tree once and returns both its digest and stable diff.
    ///
    /// # Errors
    ///
    /// Fails if the scratch tree becomes unreadable or gains an unsafe entry.
    pub fn final_state(&self) -> Result<ScratchFinal, String> {
        let current =
            source_snapshot_with_exclusions(&self.path, &self.baseline.trusted_exclusions)?;
        let paths = self
            .baseline
            .files
            .keys()
            .chain(current.files.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let changes = paths
            .into_iter()
            .filter_map(
                |path| match (self.baseline.files.get(&path), current.files.get(&path)) {
                    (None, Some(entry)) => Some(Change {
                        path,
                        kind: ChangeKind::Added,
                        digest: Some(format!("sha256:{}", entry.digest())),
                    }),
                    (Some(before), Some(after)) if before != after => Some(Change {
                        path,
                        kind: ChangeKind::Modified,
                        digest: Some(format!("sha256:{}", after.digest())),
                    }),
                    (Some(before), None) => Some(Change {
                        path,
                        kind: ChangeKind::Deleted,
                        digest: Some(format!("sha256:{}", before.digest())),
                    }),
                    _ => None,
                },
            )
            .collect();
        Ok(ScratchFinal {
            changes,
            digest: current.manifest.digest,
            bytes: current.files.values().map(SnapshotEntry::size).sum(),
            entries: u64::try_from(current.files.len()).unwrap_or(u64::MAX),
        })
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
    pub output_bytes: u64,
    pub wall_time_ms: u64,
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
        std::thread::sleep(Duration::from_millis(PROCESS_POLL_MILLISECONDS));
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
        output_bytes: total.load(Ordering::Acquire),
        wall_time_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}
