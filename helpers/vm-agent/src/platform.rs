use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use workflow_verifier_helper_runtime::run_command_with_termination;
use workflow_verifier_runner_protocol::vm::{Observation, Request, parse_request};

use crate::{guest_working_directory, write_observation};

const SYSROOT: &str = "/sysroot";
const SOURCE: &str = "/source";
const WORKSPACE: &str = "/workspace";
const CONTROL: &str = "/control";
const WORKLOAD_CGROUP: &str = "/sys/fs/cgroup/workload";

fn syscall_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

fn cstring(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("guest path contains NUL: {value:?}"))
}

fn create_directory(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| format!("create {path}: {error}"))
}

fn mount(source: &str, target: &str, filesystem: &str, flags: libc::c_ulong) -> Result<(), String> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    let filesystem = cstring(filesystem)?;
    // SAFETY: every string is NUL-terminated and the data pointer is null.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags,
            std::ptr::null(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(syscall_error(&format!("mount {target:?}")))
    }
}

fn move_mount(source: &str, target: &str) -> Result<(), String> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    // SAFETY: both paths are NUL-terminated mount points and MS_MOVE ignores
    // filesystem/data arguments.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(syscall_error("move guest mount"))
    }
}

fn mount_guest_filesystems() -> Result<Request, String> {
    for path in ["/dev", SYSROOT, SOURCE, WORKSPACE, CONTROL] {
        create_directory(path)?;
    }
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
    )?;
    mount(
        "/dev/vda",
        SYSROOT,
        "ext4",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
    )?;
    mount(
        "workflow_source",
        SOURCE,
        "virtiofs",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
    )?;
    mount(
        "workflow_scratch",
        WORKSPACE,
        "virtiofs",
        libc::MS_NOSUID | libc::MS_NODEV,
    )?;
    mount(
        "workflow_control",
        CONTROL,
        "virtiofs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )?;
    let encoded = std::fs::read_to_string("/control/request.json")
        .map_err(|error| format!("read VM request: {error}"))?;
    parse_request(&encoded)
}

fn enter_rootfs() -> Result<(), String> {
    for relative in ["source", "workspace", "control", "proc", "sys/fs/cgroup"] {
        create_directory(&format!("{SYSROOT}/{relative}"))?;
    }
    move_mount(SOURCE, "/sysroot/source")?;
    move_mount(WORKSPACE, "/sysroot/workspace")?;
    move_mount(CONTROL, "/sysroot/control")?;
    mount(
        "proc",
        "/sysroot/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )?;
    mount(
        "none",
        "/sysroot/sys/fs/cgroup",
        "cgroup2",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )?;
    let root = cstring(SYSROOT)?;
    // SAFETY: the verified read-only rootfs is mounted at this NUL-terminated
    // path and the agent has no untrusted threads.
    if unsafe { libc::chroot(root.as_ptr()) } != 0 {
        return Err(syscall_error("chroot into VM rootfs"));
    }
    std::env::set_current_dir("/").map_err(|error| format!("enter VM rootfs: {error}"))
}

fn write_interface(path: &str, value: &str) -> Result<(), String> {
    std::fs::write(path, value.as_bytes()).map_err(|error| format!("write {path}: {error}"))
}

fn configure_cgroup(request: &Request) -> Result<File, String> {
    create_directory("/sys/fs/cgroup/agent")?;
    write_interface("/sys/fs/cgroup/agent/cgroup.procs", "0")?;
    write_interface(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory +pids",
    )?;
    create_directory(WORKLOAD_CGROUP)?;
    let memory = request
        .memory_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "guest memory limit overflows bytes".to_owned())?;
    write_interface(
        &format!("{WORKLOAD_CGROUP}/memory.max"),
        &memory.to_string(),
    )?;
    if Path::new(&format!("{WORKLOAD_CGROUP}/memory.swap.max")).exists() {
        write_interface(&format!("{WORKLOAD_CGROUP}/memory.swap.max"), "0")?;
    }
    write_interface(
        &format!("{WORKLOAD_CGROUP}/pids.max"),
        &request.processes.to_string(),
    )?;
    write_interface(&format!("{WORKLOAD_CGROUP}/cpu.max"), "100000 100000")?;
    OpenOptions::new()
        .write(true)
        .open(format!("{WORKLOAD_CGROUP}/cgroup.procs"))
        .map_err(|error| format!("open workload cgroup: {error}"))
}

fn kill_workload() -> Result<(), String> {
    write_interface(&format!("{WORKLOAD_CGROUP}/cgroup.kill"), "1")
}

fn command(request: &Request, cgroup_procs: File) -> Result<Command, String> {
    let (program, arguments) = request
        .argv
        .split_first()
        .ok_or_else(|| "VM workload command is empty".to_owned())?;
    let working_directory = guest_working_directory(&request.working_directory)?;
    if !working_directory.is_dir() {
        return Err(format!(
            "VM working directory does not exist: {}",
            working_directory.display()
        ));
    }
    let process_limit = request.processes;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(working_directory)
        .env_clear()
        .envs(&request.environment)
        .env("WORKFLOW_VERIFIER_SOURCE", "/source")
        .env("WORKFLOW_VERIFIER_WORKSPACE", "/workspace")
        .env(
            "PATH",
            request
                .environment
                .get("PATH")
                .map_or("/usr/local/bin:/usr/bin:/bin", String::as_str),
        )
        .env("HOME", "/workspace")
        .env("TMPDIR", "/workspace")
        .stdin(Stdio::null());
    // SAFETY: the closure performs only raw async-signal-safe operations. The
    // cgroup fd remains live until exec and is closed by CLOEXEC afterwards.
    unsafe {
        command.pre_exec(move || {
            if libc::write(cgroup_procs.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let processes = libc::rlimit {
                rlim_cur: process_limit,
                rlim_max: process_limit,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &raw const processes) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn power_off() -> Result<(), String> {
    // SAFETY: the guest agent is PID 1 with privilege over only this VM.
    unsafe {
        libc::sync();
        if libc::reboot(libc::RB_POWER_OFF) == 0 {
            Ok(())
        } else {
            Err(syscall_error("power off VM"))
        }
    }
}

pub(super) fn run() -> Result<(), String> {
    let request = mount_guest_filesystems()?;
    enter_rootfs()?;
    let cgroup_procs = configure_cgroup(&request)?;
    let mut command = command(&request, cgroup_procs)?;
    let observed = run_command_with_termination(
        &mut command,
        Duration::from_secs(request.timeout_seconds),
        request.output_bytes,
        |_child| kill_workload(),
    )?;
    let _ = kill_workload();
    let response = Observation {
        code: observed.code,
        timed_out: observed.timed_out,
        output_exceeded: observed.output_exceeded,
        output: observed.output,
    };
    write_observation(Path::new("/control/response.json"), &response)?;
    power_off()
}
