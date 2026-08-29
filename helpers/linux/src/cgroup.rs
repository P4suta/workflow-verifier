use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use workflow_verifier_internal::internal::runner_protocol::Limits;

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const DIRECTORY_PREFIX: &str = "workflow-verifier-";
const REQUIRED_CONTROLLERS: &[&str] = &["cpu", "memory", "pids"];

static NEXT_CGROUP: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Cgroup {
    path: PathBuf,
    active: bool,
}

impl Cgroup {
    pub(crate) fn create(limits: &Limits) -> Result<Self, String> {
        let root = delegated_root()?;
        enable_controllers(&root)?;
        let sequence = NEXT_CGROUP.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let path = root.join(format!(
            "{DIRECTORY_PREFIX}{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).map_err(|error| format!("create cgroup: {error}"))?;
        let mut cgroup = Self { path, active: true };
        if let Err(error) = cgroup.configure(limits) {
            let _ = cgroup.cleanup();
            return Err(error);
        }
        Ok(cgroup)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn kill(&self) -> Result<(), String> {
        fs::write(self.path.join("cgroup.kill"), b"1")
            .map_err(|error| format!("kill cgroup: {error}"))
    }

    fn configure(&self, limits: &Limits) -> Result<(), String> {
        for interface in ["cpu.max", "memory.max", "pids.max", "cgroup.kill"] {
            if !self.path.join(interface).exists() {
                return Err(format!("cgroup v2 interface {interface} is unavailable"));
            }
        }
        let memory_bytes = limits
            .memory_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| "memory limit overflows bytes".to_owned())?;
        write_interface(&self.path, "memory.max", &memory_bytes.to_string())?;
        if self.path.join("memory.swap.max").exists() {
            write_interface(&self.path, "memory.swap.max", "0")?;
        }
        if self.path.join("memory.oom.group").exists() {
            write_interface(&self.path, "memory.oom.group", "1")?;
        }
        write_interface(
            &self.path,
            "pids.max",
            &limits.processes.saturating_add(1).max(2).to_string(),
        )?;
        write_interface(&self.path, "cpu.max", "100000 100000")?;
        if self.path.join("cgroup.max.depth").exists() {
            write_interface(&self.path, "cgroup.max.depth", "0")?;
        }
        if self.path.join("cgroup.max.descendants").exists() {
            write_interface(&self.path, "cgroup.max.descendants", "0")?;
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let _ = self.kill();
        for _ in 0..100 {
            if !is_populated(&self.path)? {
                fs::remove_dir(&self.path).map_err(|error| format!("remove cgroup: {error}"))?;
                self.active = false;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("cgroup remained populated after kill".to_owned())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn write_interface(root: &Path, name: &str, value: &str) -> Result<(), String> {
    fs::write(root.join(name), value.as_bytes()).map_err(|error| format!("write {name}: {error}"))
}

fn is_populated(path: &Path) -> Result<bool, String> {
    let events = fs::read_to_string(path.join("cgroup.events"))
        .map_err(|error| format!("read cgroup.events: {error}"))?;
    Ok(events
        .lines()
        .any(|line| line.split_whitespace().eq(["populated", "1"])))
}

fn delegated_root() -> Result<PathBuf, String> {
    let candidate = if let Some(configured) = std::env::var_os("WORKFLOW_VERIFIER_CGROUP_ROOT") {
        PathBuf::from(configured)
    } else {
        let membership = fs::read_to_string("/proc/self/cgroup")
            .map_err(|error| format!("read cgroup membership: {error}"))?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| "unified cgroup v2 membership is unavailable".to_owned())?;
        Path::new(CGROUP_MOUNT).join(relative.trim_start_matches('/'))
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("canonicalize cgroup root: {error}"))?;
    let mount = Path::new(CGROUP_MOUNT)
        .canonicalize()
        .map_err(|error| format!("canonicalize cgroup v2 mount: {error}"))?;
    if !canonical.starts_with(&mount) || !canonical.join("cgroup.controllers").is_file() {
        return Err(format!(
            "cgroup root is not below a unified cgroup v2 mount: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn enable_controllers(root: &Path) -> Result<(), String> {
    let available = fs::read_to_string(root.join("cgroup.controllers"))
        .map_err(|error| format!("read cgroup.controllers: {error}"))?;
    let missing = REQUIRED_CONTROLLERS
        .iter()
        .filter(|controller| {
            !available
                .split_whitespace()
                .any(|item| item == **controller)
        })
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "cgroup v2 controllers are unavailable: {}",
            missing.join(", ")
        ));
    }
    let requested = REQUIRED_CONTROLLERS
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(root.join("cgroup.subtree_control"), requested)
        .map_err(|error| format!("delegate cgroup v2 controllers: {error}"))
}

pub(crate) fn attach_current(path: &Path) -> Result<(), String> {
    let root = delegated_root()?;
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("canonicalize execution cgroup: {error}"))?;
    let safe_name = canonical
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.starts_with(DIRECTORY_PREFIX));
    if !safe_name || canonical.parent() != Some(root.as_path()) {
        return Err(format!(
            "refusing unowned execution cgroup: {}",
            canonical.display()
        ));
    }
    write_interface(&canonical, "cgroup.procs", &std::process::id().to_string())
}

pub(crate) fn probe(limits: &Limits) -> Result<(), String> {
    let mut cgroup = Cgroup::create(limits)?;
    cgroup.cleanup()
}
