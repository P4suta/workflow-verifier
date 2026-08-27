use std::collections::BTreeMap;
use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    LocalFree, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, CreateRestrictedToken, DACL_SECURITY_INFORMATION,
    DISABLE_MAX_PRIVILEGE, FreeSid, GetSecurityDescriptorSacl, GetTokenInformation,
    LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_CAPABILITIES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenIsAppContainer,
    TokenPrivileges,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_CHILD_PROCESS_OVERRIDE;

use workflow_verifier_helper_runtime::{
    EnvironmentSecrets, NativeSandbox, NativeSandboxRequest, NativeStepRequest,
    NativeStorageParents, ProcessObservation, execute_native_with_exclusions,
    reserve_temp_directory, reserve_temp_file,
};
use workflow_verifier_runner_protocol::{Descriptor, LaunchError, RunResult, ValidatedPlan};

const PROFILE_NAME: &str = "OpenAI.workflow-verifier.sandbox.v1";
const PROFILE_LABEL: &str = "workflow-verifier sandbox";
const PROFILE_DESCRIPTION: &str = "Network-denied native workflow verification";
const ERROR_ALREADY_EXISTS_HRESULT: i32 = signed_bits(0x8007_00B7);
const SOURCE_MUTATION_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

static PROFILE_INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();

const fn signed_bits(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}

const fn unsigned_bits(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Result<Vec<u16>, String> {
    let mut encoded = value.as_ref().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err("Windows string contains NUL".to_owned());
    }
    encoded.push(0);
    Ok(encoded)
}

fn windows_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE, context: &str) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(windows_error(context))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetNamedSecurityInfoW allocated this descriptor with LocalAlloc.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

struct LocalWide(*mut u16);

impl Drop for LocalWide {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocated this buffer with LocalAlloc.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

struct CoTaskWide(*mut u16);

impl Drop for CoTaskWide {
    fn drop(&mut self) {
        // SAFETY: GetAppContainerFolderPath allocated this buffer with the COM
        // task allocator.
        unsafe {
            CoTaskMemFree(self.0.cast());
        }
    }
}

struct LocalAcl(*mut ACL);

impl Drop for LocalAcl {
    fn drop(&mut self) {
        // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns a non-null Win32 handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct AppContainerSid(PSID);

impl AppContainerSid {
    fn derive() -> Result<Self, String> {
        let name = wide(PROFILE_NAME)?;
        let mut sid = null_mut();
        // SAFETY: name is NUL-terminated and sid is a valid output pointer.
        let result =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &raw mut sid) };
        if result < 0 || sid.is_null() {
            Err(format!(
                "DeriveAppContainerSidFromAppContainerName failed: HRESULT 0x{:08x}",
                unsigned_bits(result)
            ))
        } else {
            Ok(Self(sid))
        }
    }

    fn create_or_open() -> Result<Self, String> {
        PROFILE_INITIALIZED
            .get_or_init(initialize_profile)
            .clone()?;
        Self::derive()
    }

    fn raw(&self) -> PSID {
        self.0
    }

    fn storage_root(&self) -> Result<PathBuf, String> {
        let mut sid_text = null_mut();
        // SAFETY: this object owns a live SID and sid_text is writable.
        if unsafe { ConvertSidToStringSidW(self.raw(), &raw mut sid_text) } == 0
            || sid_text.is_null()
        {
            return Err(windows_error("ConvertSidToStringSidW"));
        }
        let sid_text = LocalWide(sid_text);
        let mut folder = null_mut();
        // SAFETY: sid_text is a live NUL-terminated SID string and folder is a
        // writable out pointer.
        let result = unsafe { GetAppContainerFolderPath(sid_text.0, &raw mut folder) };
        if result < 0 || folder.is_null() {
            return Err(format!(
                "GetAppContainerFolderPath failed: HRESULT 0x{:08x}",
                unsigned_bits(result)
            ));
        }
        let folder = CoTaskWide(folder);
        let length = (0..32_768)
            .find(|offset| {
                // SAFETY: the API returned a NUL-terminated Windows path. The
                // documented maximum extended path is below this hard bound.
                unsafe { *folder.0.add(*offset) == 0 }
            })
            .ok_or_else(|| "AppContainer storage path is not NUL-terminated".to_owned())?;
        // SAFETY: the preceding bounded scan proved every element through
        // length readable and found the terminator at length.
        let path = PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(folder.0, length)
        }));
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if path.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink() {
            Ok(path)
        } else {
            Err(format!(
                "AppContainer storage is not a real absolute directory: {}",
                path.display()
            ))
        }
    }
}

fn initialize_profile() -> Result<(), String> {
    let name = wide(PROFILE_NAME)?;
    let label = wide(PROFILE_LABEL)?;
    let description = wide(PROFILE_DESCRIPTION)?;
    let mut sid = null_mut();
    // SAFETY: all strings are NUL-terminated, no capabilities are requested,
    // and sid is a valid output pointer.
    let result = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            label.as_ptr(),
            description.as_ptr(),
            null(),
            0,
            &raw mut sid,
        )
    };
    if result == ERROR_ALREADY_EXISTS_HRESULT || unsigned_bits(result) == ERROR_ALREADY_EXISTS {
        Ok(())
    } else if result < 0 || sid.is_null() {
        Err(format!(
            "CreateAppContainerProfile failed: HRESULT 0x{:08x}",
            unsigned_bits(result)
        ))
    } else {
        // SAFETY: a successful profile creation transfers this SID to us;
        // callers derive independently owned SID values after initialization.
        unsafe {
            FreeSid(sid);
        }
        Ok(())
    }
}

impl Drop for AppContainerSid {
    fn drop(&mut self) {
        // SAFETY: userenv returned this SID and transfers ownership to the caller.
        unsafe {
            FreeSid(self.0);
        }
    }
}

fn restricted_token() -> Result<OwnedHandle, String> {
    let mut process_token = null_mut();
    // SAFETY: the pseudo process handle is valid and process_token is writable.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut process_token,
        )
    };
    if opened == 0 {
        return Err(windows_error("OpenProcessToken"));
    }
    let process_token = OwnedHandle::new(process_token, "OpenProcessToken")?;
    let mut restricted = null_mut();
    // SAFETY: the source token is live and every optional SID/privilege array
    // is null with a matching zero count.
    let created = unsafe {
        CreateRestrictedToken(
            process_token.raw(),
            DISABLE_MAX_PRIVILEGE,
            0,
            null(),
            0,
            null(),
            0,
            null(),
            &raw mut restricted,
        )
    };
    if created == 0 {
        Err(windows_error("CreateRestrictedToken"))
    } else {
        OwnedHandle::new(restricted, "CreateRestrictedToken")
    }
}

fn update_path_acl(path: &Path, sid: PSID, permissions: u32, deny: bool) -> Result<(), String> {
    let path = wide(path.as_os_str())?;
    let mut old_acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: output pointers are valid and the path is NUL-terminated.
    let result = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &raw mut old_acl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if result != 0 {
        return Err(format!("GetNamedSecurityInfoW failed with {result}"));
    }
    let _descriptor = SecurityDescriptor(descriptor);
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: permissions,
        grfAccessMode: if deny { DENY_ACCESS } else { GRANT_ACCESS },
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: sid.cast(),
        },
    };
    let mut new_acl: *mut ACL = null_mut();
    // SAFETY: entry and old ACL remain live through the call; new_acl is writable.
    let result = unsafe { SetEntriesInAclW(1, &raw const entry, old_acl, &raw mut new_acl) };
    if result != 0 || new_acl.is_null() {
        return Err(format!("SetEntriesInAclW failed with {result}"));
    }
    let new_acl = LocalAcl(new_acl);
    // SAFETY: the path and ACL remain valid through this synchronous call.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new_acl.0,
            null_mut(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!("SetNamedSecurityInfoW failed with {result}"))
    }
}

fn grant_path(path: &Path, sid: PSID, permissions: u32) -> Result<(), String> {
    update_path_acl(path, sid, permissions, false)
}

fn deny_path(path: &Path, sid: PSID, permissions: u32) -> Result<(), String> {
    update_path_acl(path, sid, permissions, true)
}

fn update_tree_acl(root: &Path, sid: PSID, permissions: u32, deny: bool) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing ACL update through symlink: {}",
            root.display()
        ));
    }
    if deny {
        deny_path(root, sid, permissions)?;
    } else {
        grant_path(root, sid, permissions)?;
    }
    if metadata.is_dir() {
        let mut entries = std::fs::read_dir(root)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            update_tree_acl(&entry.path(), sid, permissions, deny)?;
        }
    }
    Ok(())
}

fn grant_tree(root: &Path, sid: PSID, permissions: u32) -> Result<(), String> {
    update_tree_acl(root, sid, permissions, false)
}

fn deny_tree(root: &Path, sid: PSID, permissions: u32) -> Result<(), String> {
    update_tree_acl(root, sid, permissions, true)
}

fn authorize_source_tree(root: &Path, sid: PSID) -> Result<(), String> {
    grant_tree(root, sid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)?;
    // SetEntriesInAcl canonicalizes a new deny against the existing allow for
    // the same trustee. Reversing these calls lets the later grant weaken it.
    deny_tree(root, sid, SOURCE_MUTATION_RIGHTS)
}

fn set_low_integrity_label(path: &Path, directory: bool) -> Result<(), String> {
    let label = if directory {
        "S:(ML;OICI;NW;;;LW)"
    } else {
        "S:(ML;;NW;;;LW)"
    };
    let label = wide(label)?;
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: label is valid, NUL-terminated SDDL and descriptor is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            label.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(windows_error("create low-integrity security descriptor"));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut label_acl: *mut ACL = null_mut();
    // SAFETY: descriptor is a live security descriptor and all outputs are writable.
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor.0,
            &raw mut present,
            &raw mut label_acl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || label_acl.is_null()
    {
        return Err(windows_error("read low-integrity label ACL"));
    }
    let path = wide(path.as_os_str())?;
    // SAFETY: path and the label ACL remain live for the synchronous call.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            label_acl,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "SetNamedSecurityInfoW integrity label failed with {result}"
        ))
    }
}

fn label_writable_tree(root: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing integrity-label grant through symlink: {}",
            root.display()
        ));
    }
    set_low_integrity_label(root, metadata.is_dir())?;
    if metadata.is_dir() {
        let mut entries = std::fs::read_dir(root)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            label_writable_tree(&entry.path())?;
        }
    }
    Ok(())
}

fn create_job(plan: &ValidatedPlan) -> Result<OwnedHandle, String> {
    // SAFETY: null security attributes and name request an unnamed private job.
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObjectW",
    )?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit =
        u32::try_from(plan.limits.processes).unwrap_or(u32::MAX);
    limits.BasicLimitInformation.PerProcessUserTimeLimit =
        i64::try_from(plan.limits.cpu_seconds.saturating_mul(10_000_000)).unwrap_or(i64::MAX);
    limits.ProcessMemoryLimit =
        usize::try_from(plan.limits.memory_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX);
    // SAFETY: limits has the exact ABI required by JobObjectExtendedLimitInformation.
    let configured = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(std::mem::size_of_val(&limits)).expect("job limits fit u32"),
        )
    };
    if configured == 0 {
        Err(windows_error("SetInformationJobObject"))
    } else {
        Ok(job)
    }
}

struct AttributeList {
    storage: Vec<usize>,
    initialized: bool,
    capabilities: Box<SECURITY_CAPABILITIES>,
    child_process_policy: Box<u32>,
    inherited_handles: Vec<HANDLE>,
}

impl AttributeList {
    fn new(sid: PSID, inherited_handles: Vec<HANDLE>) -> Result<Self, String> {
        if inherited_handles.is_empty() {
            return Err("AppContainer standard handle list cannot be empty".to_owned());
        }
        let mut bytes = 0;
        // SAFETY: the documented sizing call accepts a null list.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 3, 0, &raw mut bytes);
        }
        if bytes == 0 {
            return Err(windows_error("InitializeProcThreadAttributeList sizing"));
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut value = Self {
            storage: vec![0; words],
            initialized: false,
            capabilities: Box::new(SECURITY_CAPABILITIES {
                AppContainerSid: sid,
                Capabilities: null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            }),
            child_process_policy: Box::new(PROCESS_CREATION_CHILD_PROCESS_OVERRIDE),
            inherited_handles,
        };
        // SAFETY: storage is suitably aligned and at least the requested size.
        if unsafe { InitializeProcThreadAttributeList(value.raw(), 3, 0, &raw mut bytes) } == 0 {
            return Err(windows_error("InitializeProcThreadAttributeList"));
        }
        value.initialized = true;
        // SAFETY: the boxed capabilities and SID remain live and at stable
        // addresses for the complete process-creation transaction.
        if unsafe {
            UpdateProcThreadAttribute(
                value.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw const *value.capabilities).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(windows_error("security-capabilities attribute"));
        }
        // SAFETY: the boxed policy remains live and stable for the complete
        // process-creation transaction. Descendants retain the same AppContainer
        // token and remain inside the private Job Object.
        if unsafe {
            UpdateProcThreadAttribute(
                value.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                (&raw const *value.child_process_policy).cast(),
                std::mem::size_of::<u32>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(windows_error("child-process policy attribute"));
        }
        // SAFETY: the vector is not resized after this call, so its handle array
        // remains live and stable through the process-creation transaction.
        if unsafe {
            UpdateProcThreadAttribute(
                value.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                value.inherited_handles.as_ptr().cast(),
                std::mem::size_of_val(value.inherited_handles.as_slice()),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(windows_error("standard handle-list attribute"));
        }
        Ok(value)
    }

    fn raw(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the list was initialized and storage remains live.
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
}

fn quote_crt_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| matches!(character, ' ' | '\t' | '"'))
    {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            } else {
                quoted.push_str(&"\\".repeat(backslashes));
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn is_command_processor_script(arguments: &[String]) -> bool {
    let Some((executable, tail)) = arguments.split_first() else {
        return false;
    };
    let Some(file_name) = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return false;
    };
    let is_command_processor =
        file_name.eq_ignore_ascii_case("cmd.exe") || file_name.eq_ignore_ascii_case("cmd");
    is_command_processor
        && tail.len() >= 2
        && tail[tail.len() - 2].as_str().eq_ignore_ascii_case("/c")
}

fn render_command_line(arguments: &[String]) -> Result<String, String> {
    if arguments.is_empty() {
        return Err("step argv cannot be empty".to_owned());
    }
    if is_command_processor_script(arguments) {
        let (prefix, script) = arguments.split_at(arguments.len() - 1);
        // cmd.exe consumes the text after /C as shell syntax rather than as a
        // CRT argv element. Its outer quotes must therefore preserve embedded
        // quotes verbatim; backslash-escaping them changes the command itself.
        Ok(format!(
            "{} \"{}\"",
            prefix
                .iter()
                .map(|value| quote_crt_argument(value))
                .collect::<Vec<_>>()
                .join(" "),
            script[0]
        ))
    } else {
        Ok(arguments
            .iter()
            .map(|value| quote_crt_argument(value))
            .collect::<Vec<_>>()
            .join(" "))
    }
}

fn command_line(arguments: &[String]) -> Result<Vec<u16>, String> {
    wide(render_command_line(arguments)?)
}

fn environment_block(request: &NativeStepRequest<'_>) -> Result<Vec<u16>, String> {
    let mut environment = BTreeMap::<String, String>::new();
    for name in [
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "PUBLIC",
        "SYSTEMROOT",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    ] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.to_owned(), value);
        }
    }
    for (name, value) in &request.environment {
        if name.is_empty() || name.contains('=') || name.contains('\0') || value.contains('\0') {
            return Err(format!("invalid Windows environment entry {name:?}"));
        }
        environment.insert(name.to_uppercase(), value.clone());
    }
    environment.insert(
        "WORKFLOW_VERIFIER_SOURCE".to_owned(),
        request.source_root.to_string_lossy().into_owned(),
    );
    environment.insert(
        "WORKFLOW_VERIFIER_WORKSPACE".to_owned(),
        request.scratch_root.to_string_lossy().into_owned(),
    );
    environment.insert(
        "TEMP".to_owned(),
        request.scratch_root.to_string_lossy().into_owned(),
    );
    environment.insert(
        "TMP".to_owned(),
        request.scratch_root.to_string_lossy().into_owned(),
    );
    let mut block = Vec::new();
    for (name, value) in environment {
        block.extend(wide(format!("{name}={value}"))?);
    }
    block.push(0);
    Ok(block)
}

struct InheritGuard(HANDLE);

impl InheritGuard {
    fn new(file: &File) -> Result<Self, String> {
        let handle: HANDLE = file.as_raw_handle().cast();
        // SAFETY: the file owns a live kernel handle. The handle list on the
        // matching process creation prevents unrelated inheritable handles from
        // crossing the sandbox boundary.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            Err(windows_error("mark standard handle inheritable"))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for InheritGuard {
    fn drop(&mut self) {
        // SAFETY: the original file still owns this handle. Clearing inheritance
        // narrows the capability immediately after CreateProcessAsUserW returns.
        unsafe {
            SetHandleInformation(self.0, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

struct OutputFile {
    path: PathBuf,
    file: Option<File>,
}

impl OutputFile {
    fn create() -> Result<Self, String> {
        let (path, file) = reserve_temp_file("output", ".log")?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }

    fn length(&self) -> Result<u64, String> {
        self.file
            .as_ref()
            .expect("output file is open while owned")
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(|error| error.to_string())
    }

    fn file(&self) -> &File {
        self.file.as_ref().expect("output file is open while owned")
    }

    fn read(&mut self, limit: u64) -> Result<Vec<u8>, String> {
        let file = self.file.as_mut().expect("output file is open while owned");
        file.seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let mut output = Vec::new();
        std::io::Read::take(file, limit)
            .read_to_end(&mut output)
            .map_err(|error| error.to_string())?;
        Ok(output)
    }
}

impl Drop for OutputFile {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

fn privilege_count(token: HANDLE) -> Result<u32, String> {
    let mut bytes = 0_u32;
    // SAFETY: the documented sizing call accepts a null output buffer.
    unsafe {
        GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &raw mut bytes);
    }
    if bytes < u32::try_from(std::mem::size_of::<u32>()).expect("u32 size fits u32") {
        return Err(windows_error("GetTokenInformation(TokenPrivileges) sizing"));
    }
    let words = usize::try_from(bytes)
        .expect("token buffer size fits usize")
        .div_ceil(std::mem::size_of::<u32>());
    let mut buffer = vec![0_u32; words];
    // SAFETY: the DWORD-aligned buffer has the size returned by the sizing call.
    if unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            bytes,
            &raw mut bytes,
        )
    } == 0
    {
        Err(windows_error("GetTokenInformation(TokenPrivileges)"))
    } else {
        Ok(buffer[0])
    }
}

fn verify_privilege_stripped(token: HANDLE) -> Result<(), String> {
    let privileges = privilege_count(token)?;
    if privileges <= 1 {
        Ok(())
    } else {
        Err(format!(
            "restricted token retained {privileges} privileges; expected at most SeChangeNotifyPrivilege"
        ))
    }
}

fn verify_restricted_appcontainer(process: HANDLE) -> Result<(), String> {
    let mut child_token = null_mut();
    // SAFETY: process is a live process handle and child_token is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut child_token) } == 0 {
        return Err(windows_error("OpenProcessToken(AppContainer)"));
    }
    let child_token = OwnedHandle::new(child_token, "AppContainer token")?;
    verify_privilege_stripped(child_token.raw())?;
    let mut is_app_container = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: output buffer has the documented TokenIsAppContainer size.
    if unsafe {
        GetTokenInformation(
            child_token.raw(),
            TokenIsAppContainer,
            (&raw mut is_app_container).cast(),
            u32::try_from(std::mem::size_of_val(&is_app_container)).expect("token flag fits u32"),
            &raw mut returned,
        )
    } == 0
        || is_app_container == 0
    {
        Err("created process token is not an AppContainer".to_owned())
    } else {
        Ok(())
    }
}

struct SupervisionOutcome {
    timed_out: bool,
    output_exceeded: bool,
}

fn supervise_process(
    job: &OwnedHandle,
    process: &OwnedHandle,
    output: &OutputFile,
    cpu_seconds: u64,
    output_bytes: u64,
) -> Result<SupervisionOutcome, String> {
    let deadline = Instant::now() + Duration::from_secs(cpu_seconds);
    let mut outcome = SupervisionOutcome {
        timed_out: false,
        output_exceeded: false,
    };
    loop {
        // SAFETY: process remains valid for the entire wait loop.
        match unsafe { WaitForSingleObject(process.raw(), 10) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => {}
            other => {
                // SAFETY: fail-closed termination of our private job.
                unsafe {
                    TerminateJobObject(job.raw(), 5);
                }
                return Err(format!("WaitForSingleObject returned {other}"));
            }
        }
        outcome.output_exceeded = output.length()? > output_bytes;
        outcome.timed_out = Instant::now() >= deadline;
        if outcome.timed_out || outcome.output_exceeded {
            // SAFETY: job is private and owns the complete descendant tree.
            if unsafe { TerminateJobObject(job.raw(), 5) } == 0 {
                return Err(windows_error("TerminateJobObject"));
            }
            // SAFETY: process remains valid after job termination.
            unsafe {
                WaitForSingleObject(process.raw(), 5_000);
            }
            break;
        }
    }
    Ok(outcome)
}

fn run_process(
    app_container_sid: PSID,
    token: HANDLE,
    request: &NativeStepRequest<'_>,
) -> Result<ProcessObservation, String> {
    let job = create_job(request.plan)?;
    let mut output = OutputFile::create()?;
    let input = File::open("NUL").map_err(|error| format!("open null standard input: {error}"))?;
    let output_inherit = InheritGuard::new(output.file())?;
    let input_inherit = InheritGuard::new(&input)?;
    let mut attributes = AttributeList::new(
        app_container_sid,
        vec![input_inherit.raw(), output_inherit.raw()],
    )?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb =
        u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).expect("startup info fits u32");
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input_inherit.raw();
    startup.StartupInfo.hStdOutput = output_inherit.raw();
    startup.StartupInfo.hStdError = output_inherit.raw();
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    let mut command_line = command_line(&request.step.argv)?;
    let environment = environment_block(request)?;
    let working_directory = wide(request.working_directory.as_os_str())?;
    // SAFETY: all pointers refer to live mutable buffers for the duration of
    // CreateProcessAsUserW. Only null input and the bounded evidence handle
    // named in PROC_THREAD_ATTRIBUTE_HANDLE_LIST cross the boundary.
    let created = unsafe {
        CreateProcessAsUserW(
            token,
            null(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            working_directory.as_ptr(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    };
    let creation_error = if created == 0 {
        Some(windows_error("CreateProcessAsUserW"))
    } else {
        None
    };
    drop(input_inherit);
    drop(output_inherit);
    if let Some(error) = creation_error {
        return Err(error);
    }
    let process_handle = OwnedHandle::new(process.hProcess, "process handle")?;
    let thread_handle = OwnedHandle::new(process.hThread, "thread handle")?;
    // SAFETY: the new process is still suspended and both handles are live.
    if unsafe { AssignProcessToJobObject(job.raw(), process_handle.raw()) } == 0 {
        // SAFETY: the process is still suspended and not yet owned by the job.
        unsafe {
            TerminateProcess(process_handle.raw(), 5);
        }
        return Err(windows_error("AssignProcessToJobObject"));
    }
    verify_restricted_appcontainer(process_handle.raw())?;
    // SAFETY: the primary thread is suspended exactly once by CREATE_SUSPENDED.
    if unsafe { ResumeThread(thread_handle.raw()) } == u32::MAX {
        // SAFETY: terminating the private job closes the untrusted process tree.
        unsafe {
            TerminateJobObject(job.raw(), 5);
        }
        return Err(windows_error("ResumeThread"));
    }
    let started = Instant::now();
    let supervision = supervise_process(
        &job,
        &process_handle,
        &output,
        request.plan.limits.cpu_seconds,
        request.plan.limits.output_bytes,
    )?;
    let mut code = 0_u32;
    // SAFETY: process has exited and code points to writable storage.
    if unsafe { GetExitCodeProcess(process_handle.raw(), &raw mut code) } == 0 {
        return Err(windows_error("GetExitCodeProcess"));
    }
    let output_bytes = output.length()?;
    let captured = output.read(request.plan.limits.output_bytes)?;
    Ok(ProcessObservation {
        code: i32::try_from(code).ok(),
        timed_out: supervision.timed_out,
        output_exceeded: supervision.output_exceeded,
        output: captured,
        output_bytes,
        wall_time_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

struct WindowsSandbox {
    sid: Option<AppContainerSid>,
    token: Option<OwnedHandle>,
}

impl WindowsSandbox {
    fn new() -> Self {
        Self {
            sid: None,
            token: None,
        }
    }
}

impl NativeSandbox for WindowsSandbox {
    fn storage_parents(&mut self) -> Result<NativeStorageParents, String> {
        if self.sid.is_none() {
            self.sid = Some(AppContainerSid::create_or_open()?);
        }
        let scratch = self
            .sid
            .as_ref()
            .ok_or_else(|| "AppContainer SID was not initialized".to_owned())?
            .storage_root()?;
        Ok(NativeStorageParents {
            source_parent: None,
            scratch_parent: Some(scratch),
        })
    }

    fn prepare(&mut self, request: &NativeSandboxRequest<'_>) -> Result<(), String> {
        if self.sid.is_none() {
            self.sid = Some(AppContainerSid::create_or_open()?);
        }
        let sid = self
            .sid
            .as_ref()
            .ok_or_else(|| "AppContainer SID was not initialized".to_owned())?;
        let token = restricted_token()?;
        verify_privilege_stripped(token.raw())?;
        authorize_source_tree(request.source_root, sid.raw())?;
        label_writable_tree(request.scratch_root)?;
        grant_tree(request.scratch_root, sid.raw(), FILE_ALL_ACCESS)?;
        // Prove Job Object limits can be committed before emitting attestations.
        drop(create_job(request.plan)?);
        self.token = Some(token);
        Ok(())
    }

    fn run(&mut self, request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String> {
        let sid = self
            .sid
            .as_ref()
            .ok_or_else(|| "Windows sandbox was not prepared".to_owned())?;
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| "Windows sandbox was not prepared".to_owned())?;
        run_process(sid.raw(), token.raw(), request)
    }
}

pub(super) fn probe() -> Vec<String> {
    let mut reasons = Vec::new();
    let sid = match AppContainerSid::create_or_open() {
        Ok(sid) => Some(sid),
        Err(error) => {
            reasons.push(format!("AppContainer SID probe: {error}"));
            None
        }
    };
    if let Some(sid) = sid {
        if let Err(error) = sid.storage_root() {
            reasons.push(format!("AppContainer storage probe: {error}"));
        }
        match restricted_token().and_then(|token| verify_privilege_stripped(token.raw())) {
            Ok(()) => {}
            Err(error) => {
                reasons.push(format!("restricted token probe: {error}"));
            }
        }
        let acl_result = reserve_temp_directory("windows-probe").and_then(|root| {
            let result = set_low_integrity_label(&root, true)
                .and_then(|()| grant_path(&root, sid.raw(), FILE_ALL_ACCESS));
            let _ = std::fs::remove_dir(&root);
            result
        });
        if let Err(error) = acl_result {
            reasons.push(format!("AppContainer ACL probe: {error}"));
        }
    }
    let probe_plan = ValidatedPlan {
        digest: String::new(),
        backend: "windows-native".to_owned(),
        scenario_digest: String::new(),
        provider_profile: "probe".to_owned(),
        selected_jobs: vec!["probe".to_owned()],
        controls: Vec::new(),
        status: workflow_verifier_runner_protocol::PlanStatus::Complete,
        source_digest: String::new(),
        lock_digest: String::new(),
        runtime: workflow_verifier_runner_protocol::RuntimeProfile {
            kind: "windows-runtime-profile".to_owned(),
            runner_platform: "windows-x86_64".to_owned(),
            workload_digest: format!("sha256:{}", "0".repeat(64)),
            rootfs_digest: None,
            helper_digest: None,
            boot_digest: None,
            capability_fingerprint: None,
        },
        limits: workflow_verifier_runner_protocol::Limits {
            cpu_seconds: 1,
            memory_mb: 64,
            processes: 2,
            output_bytes: 1024,
        },
        network_destinations: Vec::new(),
        secret_names: Vec::new(),
        dependencies: Vec::new(),
        steps: Vec::new(),
    };
    if let Err(error) = create_job(&probe_plan) {
        reasons.push(format!("Job Object probe: {error}"));
    }
    reasons
}

pub(super) fn launch(
    plan: &ValidatedPlan,
    source_root: &Path,
    trusted_exclusions: &[String],
    descriptor: &Descriptor,
) -> Result<RunResult, LaunchError> {
    let mut sandbox = WindowsSandbox::new();
    execute_native_with_exclusions(
        plan,
        descriptor,
        source_root,
        trusted_exclusions,
        &EnvironmentSecrets,
        &mut sandbox,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AppContainerSid, FILE_GENERIC_READ, OutputFile, SOURCE_MUTATION_RIGHTS, command_line,
        probe, quote_crt_argument,
    };

    #[test]
    fn source_mutation_deny_does_not_overlap_generic_read() {
        assert_eq!(SOURCE_MUTATION_RIGHTS & FILE_GENERIC_READ, 0);
    }

    #[test]
    fn windows_command_line_quotes_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_crt_argument("plain"), "plain");
        assert_eq!(quote_crt_argument(""), "\"\"");
        assert_eq!(quote_crt_argument("two words"), "\"two words\"");
        assert_eq!(quote_crt_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_crt_argument("tail\\"), "tail\\");
        assert!(command_line(&[]).is_err());
    }

    #[test]
    fn cmd_command_line_keeps_switches_unquoted() {
        let encoded = command_line(&[
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "echo artifact>artifact.txt".to_owned(),
        ])
        .expect("encode command line");
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).expect("UTF-16 command line"),
            "cmd.exe /D /S /C \"echo artifact>artifact.txt\""
        );
    }

    #[test]
    fn cmd_command_line_preserves_quotes_inside_the_script() {
        let encoded = command_line(&[
            r"C:\Windows\System32\cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            r#"type "%WORKFLOW_VERIFIER_SOURCE%\input.txt">copied.txt"#.to_owned(),
        ])
        .expect("encode command line");
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).expect("UTF-16 command line"),
            r#"C:\Windows\System32\cmd.exe /D /S /C "type "%WORKFLOW_VERIFIER_SOURCE%\input.txt">copied.txt""#
        );
    }

    #[test]
    fn output_capture_is_closed_before_its_private_file_is_removed() {
        let output = OutputFile::create().expect("create output capture");
        let path = output.path.clone();
        assert!(path.is_file());
        drop(output);
        assert!(!path.exists());
    }

    #[test]
    fn profile_initialization_is_safe_under_parallel_callers() {
        let callers = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    drop(AppContainerSid::create_or_open().expect("initialize profile"));
                })
            })
            .collect::<Vec<_>>();
        for caller in callers {
            caller.join().expect("join profile initializer");
        }
    }

    #[test]
    fn backend_probe_is_safe_under_parallel_callers() {
        let callers = (0..16)
            .map(|_| std::thread::spawn(probe))
            .collect::<Vec<_>>();
        for caller in callers {
            let reasons = caller.join().expect("join backend probe");
            assert!(reasons.is_empty(), "{}", reasons.join("; "));
        }
    }
}
