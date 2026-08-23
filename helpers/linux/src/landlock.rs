use std::ffi::CString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const MINIMUM_ABI: i32 = 3;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;

const READ_EXECUTE: u64 = EXECUTE | READ_FILE | READ_DIR;
const READ_ONLY: u64 = READ_FILE | READ_DIR;
const FULL_ACCESS: u64 = EXECUTE
    | WRITE_FILE
    | READ_FILE
    | READ_DIR
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_CHAR
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | MAKE_FIFO
    | MAKE_BLOCK
    | MAKE_SYM
    | REFER
    | TRUNCATE;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    reserved: u32,
}

struct Rule {
    path: CString,
    access: u64,
}

pub(crate) struct Policy {
    rules: Vec<Rule>,
}

fn syscall_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

pub(crate) fn abi() -> Result<i32, String> {
    // SAFETY: the version query requires a null attribute and zero size.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0,
            CREATE_RULESET_VERSION,
        )
    };
    let version = i32::try_from(result).map_err(|_| "invalid Landlock ABI response".to_owned())?;
    if version < MINIMUM_ABI {
        Err(if version < 0 {
            syscall_error("query Landlock ABI")
        } else {
            format!("Landlock ABI {version} is older than required ABI {MINIMUM_ABI}")
        })
    } else {
        Ok(version)
    }
}

impl Policy {
    pub(crate) fn new(source: &Path, scratch: &Path) -> Result<Self, String> {
        abi()?;
        let mut policy = Self { rules: Vec::new() };
        for path in ["/bin", "/sbin", "/usr", "/lib", "/lib64"] {
            policy.add_if_present(Path::new(path), READ_EXECUTE)?;
        }
        policy.add_if_present(Path::new("/proc"), READ_ONLY)?;
        for path in [
            "/etc/ld.so.cache",
            "/etc/ld.so.preload",
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/resolv.conf",
        ] {
            policy.add_if_present(Path::new(path), READ_FILE)?;
        }
        policy.add_if_present(Path::new("/dev/null"), READ_FILE | WRITE_FILE)?;
        policy.add_if_present(Path::new("/dev/urandom"), READ_FILE)?;
        policy.add_if_present(Path::new("/dev/random"), READ_FILE)?;
        policy.add(source, READ_EXECUTE)?;
        policy.add(scratch, FULL_ACCESS)?;
        Ok(policy)
    }

    fn add_if_present(&mut self, path: &Path, access: u64) -> Result<(), String> {
        if path.exists() {
            self.add(path, access)?;
        }
        Ok(())
    }

    fn add(&mut self, path: &Path, access: u64) -> Result<(), String> {
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("canonicalize Landlock path {}: {error}", path.display()))?;
        let encoded = CString::new(canonical.as_os_str().as_encoded_bytes())
            .map_err(|_| format!("Landlock path contains NUL: {}", canonical.display()))?;
        if !self
            .rules
            .iter()
            .any(|rule| rule.path == encoded && rule.access == access)
        {
            self.rules.push(Rule {
                path: encoded,
                access,
            });
        }
        Ok(())
    }

    pub(crate) fn enforce(&self) -> std::io::Result<()> {
        let attributes = RulesetAttr {
            handled_access_fs: FULL_ACCESS,
        };
        // SAFETY: attributes has the kernel ABI layout and remains live through
        // the synchronous syscall.
        let raw_ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const attributes,
                std::mem::size_of::<RulesetAttr>(),
                0,
            )
        };
        if raw_ruleset < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ruleset_number = i32::try_from(raw_ruleset)
            .map_err(|_| std::io::Error::other("Landlock ruleset fd does not fit i32"))?;
        // SAFETY: a successful create_ruleset syscall returns a newly owned fd.
        let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset_number) };
        for rule in &self.rules {
            // SAFETY: rule.path is a live NUL-terminated path and flags request
            // a path-only descriptor that is closed by OwnedFd.
            let raw_parent =
                unsafe { libc::open(rule.path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if raw_parent < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: a successful open returns a newly owned fd.
            let parent = unsafe { OwnedFd::from_raw_fd(raw_parent) };
            let path_rule = PathBeneathAttr {
                allowed_access: rule.access,
                parent_fd: parent.as_raw_fd(),
                reserved: 0,
            };
            // SAFETY: both descriptors and path_rule remain live for this call.
            if unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    RULE_PATH_BENEATH,
                    &raw const path_rule,
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: the ruleset is complete, no_new_privs is set by the caller,
        // and flags zero has stable semantics for all supported Landlock ABIs.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}
