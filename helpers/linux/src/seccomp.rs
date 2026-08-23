const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
const BPF_JUMP_EQUAL: u16 = 0x15;
const BPF_JUMP_GREATER_OR_EQUAL: u16 = 0x35;
const BPF_RETURN: u16 = 0x06;
const SECCOMP_DATA_NUMBER_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

pub(crate) struct Filter {
    instructions: Vec<libc::sock_filter>,
}

fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn jump(code: u16, value: u32, on_true: u8, on_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: on_true,
        jf: on_false,
        k: value,
    }
}

fn syscall_number(value: libc::c_long) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("invalid syscall number {value}"))
}

fn forbidden_syscalls() -> Result<Vec<u32>, String> {
    let mut values = [
        libc::SYS_add_key,
        libc::SYS_bpf,
        libc::SYS_chroot,
        libc::SYS_delete_module,
        libc::SYS_finit_module,
        libc::SYS_init_module,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_io_uring_setup,
        libc::SYS_kexec_load,
        libc::SYS_keyctl,
        libc::SYS_mount,
        libc::SYS_move_mount,
        libc::SYS_open_by_handle_at,
        libc::SYS_open_tree,
        libc::SYS_perf_event_open,
        libc::SYS_pivot_root,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_ptrace,
        libc::SYS_reboot,
        libc::SYS_request_key,
        libc::SYS_setns,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_userfaultfd,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_setsockopt,
    ]
    .into_iter()
    .map(syscall_number)
    .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

impl Filter {
    pub(crate) fn deny_escape_and_network() -> Result<Self, String> {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Err(format!(
            "seccomp audit architecture is unsupported on {}",
            std::env::consts::ARCH
        ));

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let denied = libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1);
            let mut instructions = vec![
                statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_DATA_ARCH_OFFSET),
                jump(BPF_JUMP_EQUAL, AUDIT_ARCH, 1, 0),
                statement(BPF_RETURN, libc::SECCOMP_RET_KILL_PROCESS),
                statement(BPF_LOAD_WORD_ABSOLUTE, SECCOMP_DATA_NUMBER_OFFSET),
            ];
            #[cfg(target_arch = "x86_64")]
            instructions.extend([
                jump(BPF_JUMP_GREATER_OR_EQUAL, 0x4000_0000, 0, 1),
                statement(BPF_RETURN, denied),
            ]);
            for number in forbidden_syscalls()? {
                instructions.extend([
                    jump(BPF_JUMP_EQUAL, number, 0, 1),
                    statement(BPF_RETURN, denied),
                ]);
            }
            instructions.push(statement(BPF_RETURN, libc::SECCOMP_RET_ALLOW));
            Ok(Self { instructions })
        }
    }

    pub(crate) fn install(&mut self) -> std::io::Result<()> {
        let length = u16::try_from(self.instructions.len())
            .map_err(|_| std::io::Error::other("seccomp filter is too large"))?;
        let program = libc::sock_fprog {
            len: length,
            filter: self.instructions.as_mut_ptr(),
        };
        // SAFETY: program references the stable instruction buffer for the
        // synchronous prctl call and no_new_privs is set by the caller.
        if unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const program,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

pub(crate) fn set_no_new_privileges() -> std::io::Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS accepts the documented scalar arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn probe_child() -> Result<(), String> {
    set_no_new_privileges().map_err(|error| format!("set no_new_privs: {error}"))?;
    let mut filter = Filter::deny_escape_and_network()?;
    filter
        .install()
        .map_err(|error| format!("install seccomp filter: {error}"))?;
    // SAFETY: flags zero would otherwise be a harmless unshare call; the probe
    // expects the installed filter to reject the syscall with EPERM.
    let result = unsafe { libc::unshare(0) };
    let error = std::io::Error::last_os_error();
    if result == -1 && error.raw_os_error() == Some(libc::EPERM) {
        Ok(())
    } else {
        Err(format!(
            "seccomp did not reject the forbidden unshare syscall: result {result}, {error}"
        ))
    }
}
