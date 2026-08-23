use std::ffi::CString;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

fn syscall_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

fn write_mapping(path: &str, value: &str) -> Result<(), String> {
    std::fs::write(path, value.as_bytes()).map_err(|error| format!("write {path}: {error}"))
}

fn mount_private() -> Result<(), String> {
    // SAFETY: all pointers are either null or immutable NUL-terminated strings.
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(syscall_error("make mount propagation private"))
    }
}

fn bind_source_read_only(source: &Path) -> Result<(), String> {
    let encoded = CString::new(source.as_os_str().as_encoded_bytes())
        .map_err(|_| "source path contains NUL".to_owned())?;
    // SAFETY: the source and destination point to the same live NUL-terminated path.
    if unsafe {
        libc::mount(
            encoded.as_ptr(),
            encoded.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(syscall_error("bind private source"));
    }
    // SAFETY: this remount only changes the private mount namespace and uses
    // the same validated mount point as the successful bind above.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            encoded.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(syscall_error("remount private source read-only"))
    }
}

pub(crate) fn setup(source: Option<&Path>) -> Result<(), String> {
    // SAFETY: these accessors have no preconditions or side effects.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: the broker is single-threaded and immediately configures the new
    // user namespace before creating any untrusted process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(syscall_error("unshare user namespace"));
    }
    if Path::new("/proc/self/setgroups").exists() {
        write_mapping("/proc/self/setgroups", "deny")?;
    }
    write_mapping("/proc/self/uid_map", &format!("0 {uid} 1"))?;
    write_mapping("/proc/self/gid_map", &format!("0 {gid} 1"))?;
    let flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWPID;
    // SAFETY: all requested namespace flags are independent and the broker is
    // still single-threaded. Failure aborts before workload creation.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(syscall_error("unshare containment namespaces"));
    }
    mount_private()?;
    if let Some(path) = source {
        bind_source_read_only(path)?;
    }
    // SAFETY: UTS isolation is installed and the static byte slice is valid.
    if unsafe { libc::sethostname(c"workflow-verifier".as_ptr(), 17) } != 0 {
        return Err(syscall_error("set isolated hostname"));
    }
    Ok(())
}

pub(crate) fn prepare_child() -> std::io::Result<()> {
    // SAFETY: this runs in Command::pre_exec after CLONE_NEWPID. The raw calls
    // are async-signal-safe and operate only on the private mount namespace.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) != 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)) {
                return Err(error);
            }
        }
        if libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn probe_child() -> Result<(), String> {
    setup(None)?;
    let mut command = Command::new("/bin/true");
    // SAFETY: prepare_child contains only documented async-signal-safe raw calls.
    unsafe {
        command.pre_exec(prepare_child);
    }
    let status = command
        .status()
        .map_err(|error| format!("spawn PID namespace init: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("PID namespace init exited with {status}"))
    }
}
