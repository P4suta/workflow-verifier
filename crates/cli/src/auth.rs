//! Credential identities and OS credential-store boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroize;
use zeroize::Zeroizing;

// DNS wire/text limits and the HTTPS default port are protocol constraints.
const MAX_DNS_HOST_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;
const MAX_TCP_PORT_DIGITS: usize = 5;
const AUTHORITY_SEPARATOR_BYTES: usize = 1;
const MAX_DNS_AUTHORITY_BYTES: usize =
    MAX_DNS_HOST_BYTES + AUTHORITY_SEPARATOR_BYTES + MAX_TCP_PORT_DIGITS;
const HTTPS_DEFAULT_PORT: u16 = 443;

// The v0.1 credential boundary caps provider tokens and OS-store subprocess
// traffic before data enters a platform adapter.
const BYTES_PER_KIBIBYTE: usize = 1_024;
const BYTES_PER_KIBIBYTE_U64: u64 = 1_024;
const MAX_CREDENTIAL_KIBIBYTES: usize = 16;
const CREDENTIAL_COMMAND_TIMEOUT_SECONDS: u64 = 5;
const CREDENTIAL_COMMAND_STDIN_KIBIBYTES: u64 = 32;
const CREDENTIAL_COMMAND_OUTPUT_KIBIBYTES: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderKind {
    Github,
    Gitlab,
    Azure,
    Circleci,
}

impl ProviderKind {
    /// Parse a stable provider identifier.
    ///
    /// # Errors
    /// Rejects providers outside the four v0.1 frontends.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "github" => Ok(Self::Github),
            "gitlab" => Ok(Self::Gitlab),
            "azure" => Ok(Self::Azure),
            "circleci" => Ok(Self::Circleci),
            _ => Err(format!("unknown authentication provider {value}")),
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Azure => "azure",
            Self::Circleci => "circleci",
        }
    }

    #[must_use]
    pub fn default_host(self) -> &'static str {
        match self {
            Self::Github => "github.com",
            Self::Gitlab => "gitlab.com",
            Self::Azure => "dev.azure.com",
            Self::Circleci => "circleci.com",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialKey {
    provider: ProviderKind,
    host: String,
}

impl CredentialKey {
    /// Create a canonical provider/host credential identity.
    ///
    /// # Errors
    /// Rejects URLs, IP literals, localhost, credentials, paths, invalid DNS
    /// labels, and malformed ports.
    pub fn new(provider: ProviderKind, host: Option<&str>) -> Result<Self, String> {
        let host = canonical_host(host.unwrap_or_else(|| provider.default_host()))?;
        Ok(Self { provider, host })
    }

    #[must_use]
    pub fn provider(&self) -> ProviderKind {
        self.provider
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn identity(&self) -> String {
        format!("{}@{}", self.provider.name(), self.host)
    }
}

fn canonical_host(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_DNS_AUTHORITY_BYTES
        || value.contains(['/', '\\', '@', '?', '#', '%'])
        || value.contains("://")
        || value.parse::<std::net::IpAddr>().is_ok()
    {
        return Err("credential host must be a DNS authority without URL syntax".to_owned());
    }
    let lower = value.to_ascii_lowercase();
    let (hostname, port) = match lower.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| "credential host has an invalid port".to_owned())?;
            (host, Some(port))
        }
        None => (lower.as_str(), None),
    };
    if hostname.eq_ignore_ascii_case("localhost")
        || hostname.ends_with(".localhost")
        || hostname.is_empty()
        || hostname.len() > MAX_DNS_HOST_BYTES
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > MAX_DNS_LABEL_BYTES
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("credential host is not a portable DNS authority".to_owned());
    }
    Ok(match port {
        None | Some(HTTPS_DEFAULT_PORT) => hostname.to_owned(),
        Some(port) => format!("{hostname}:{port}"),
    })
}

pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Own a provider credential in zeroizing memory.
    ///
    /// # Errors
    /// Rejects empty, oversized, multiline, control, and non-ASCII values.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_KIBIBYTES * BYTES_PER_KIBIBYTE
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("credential must be a non-empty single-line ASCII token".to_owned());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
const CREDENTIAL_SERVICE: &str = "workflow-verifier";
const SECRET_PAYLOAD_PREFIX: &str = "wv1:";

fn encode_secret_payload(secret: &SecretString) -> Zeroizing<Vec<u8>> {
    let mut payload =
        String::with_capacity(SECRET_PAYLOAD_PREFIX.len() + secret.expose().len() * 2);
    payload.push_str(SECRET_PAYLOAD_PREFIX);
    for byte in secret.expose().bytes() {
        let _ = write!(payload, "{byte:02x}");
    }
    Zeroizing::new(payload.into_bytes())
}

fn decode_secret_payload(payload: &[u8]) -> Result<SecretString, String> {
    let payload = payload
        .strip_suffix(b"\r\n")
        .or_else(|| payload.strip_suffix(b"\n"))
        .unwrap_or(payload);
    let encoded = payload
        .strip_prefix(SECRET_PAYLOAD_PREFIX.as_bytes())
        .ok_or_else(|| "OS credential store returned an unknown payload version".to_owned())?;
    if encoded.is_empty() || encoded.len() % 2 != 0 || !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err("OS credential store returned a malformed protected payload".to_owned());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(encoded.len() / 2));
    let (pairs, remainder) = encoded.as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        let text = std::str::from_utf8(pair)
            .map_err(|_| "OS credential store returned invalid protected text".to_owned())?;
        decoded.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| "OS credential store returned invalid protected text".to_owned())?,
        );
    }
    let value = std::str::from_utf8(&decoded)
        .map_err(|_| "OS credential store returned invalid credential text".to_owned())?
        .to_owned();
    SecretString::new(value)
}

#[cfg(any(target_os = "macos", test))]
fn macos_put_input(key: &CredentialKey, secret: &SecretString) -> Zeroizing<Vec<u8>> {
    let payload = encode_secret_payload(secret);
    Zeroizing::new(
        format!(
            "add-generic-password -U -a {} -s {CREDENTIAL_SERVICE} -w {}\n",
            key.identity(),
            String::from_utf8_lossy(&payload)
        )
        .into_bytes(),
    )
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_PUT_SCRIPT: &str = "$ErrorActionPreference='Stop';try{$vault=[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new();$user=$args[0];@($vault.RetrieveAll()|Where-Object {$_.Resource -eq 'workflow-verifier' -and $_.UserName -eq $user})|ForEach-Object {$vault.Remove($_)};$secret=[Console]::In.ReadToEnd();if([string]::IsNullOrEmpty($secret)){exit 2};$credential=[Windows.Security.Credentials.PasswordCredential,Windows.Security.Credentials,ContentType=WindowsRuntime]::new('workflow-verifier',$user,$secret);$vault.Add($credential)}catch{exit 2}";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_GET_SCRIPT: &str = "$ErrorActionPreference='Stop';try{$vault=[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new();$user=$args[0];$credential=@($vault.RetrieveAll()|Where-Object {$_.Resource -eq 'workflow-verifier' -and $_.UserName -eq $user})|Select-Object -First 1;if($null -eq $credential){exit 1};$credential.RetrievePassword();[Console]::Out.Write($credential.Password)}catch{exit 2}";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_DELETE_SCRIPT: &str = "$ErrorActionPreference='Stop';try{$vault=[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new();$user=$args[0];$credential=@($vault.RetrieveAll()|Where-Object {$_.Resource -eq 'workflow-verifier' -and $_.UserName -eq $user})|Select-Object -First 1;if($null -eq $credential){exit 1};$vault.Remove($credential)}catch{exit 2}";

pub trait CredentialStore {
    /// Store a credential in a platform-protected facility.
    ///
    /// # Errors
    /// Returns an opaque failure which must never contain the secret value.
    fn put(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), String>;

    /// Retrieve a credential without creating a plaintext persistence fallback.
    ///
    /// # Errors
    /// Returns an opaque protected-store failure.
    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, String>;

    /// Delete a credential, returning whether one existed.
    ///
    /// # Errors
    /// Returns an opaque protected-store failure.
    fn delete(&self, key: &CredentialKey) -> Result<bool, String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCredentialStore;

impl CredentialStore for SystemCredentialStore {
    fn put(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
        system_put(key, secret)
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, String> {
        system_get(key)
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, String> {
        system_delete(key)
    }
}

#[cfg(target_os = "linux")]
fn secret_tool(arguments: &[&str]) -> Command {
    let mut command = Command::new("secret-tool");
    command
        .args(arguments)
        .env_clear()
        .envs(credential_store_environment(|name| std::env::var_os(name)));
    command
}

fn credential_store_environment(
    mut lookup: impl FnMut(&str) -> Option<OsString>,
) -> BTreeMap<OsString, OsString> {
    const ALLOWLIST: &[&str] = &[
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "GNOME_KEYRING_CONTROL",
        "HOME",
        "LOCALAPPDATA",
        "PATH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WAYLAND_DISPLAY",
        "WINDIR",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    ];
    ALLOWLIST
        .iter()
        .filter_map(|name| lookup(name).map(|value| (OsString::from(name), value)))
        .collect()
}

fn run_credential_command(
    command: &mut Command,
    input: Option<&[u8]>,
) -> Result<crate::SupervisedOutput, String> {
    crate::supervise_process(
        command,
        input,
        Duration::from_secs(CREDENTIAL_COMMAND_TIMEOUT_SECONDS),
        CREDENTIAL_COMMAND_STDIN_KIBIBYTES * BYTES_PER_KIBIBYTE_U64,
        CREDENTIAL_COMMAND_OUTPUT_KIBIBYTES * BYTES_PER_KIBIBYTE_U64,
    )
    .map_err(|_| "OS credential store is unavailable".to_owned())
}

fn wipe_output(output: &mut crate::SupervisedOutput) {
    output.stdout.zeroize();
    output.stderr.zeroize();
}

#[cfg(target_os = "linux")]
fn run_secret_tool(
    command: &mut Command,
    input: Option<&[u8]>,
) -> Result<crate::SupervisedOutput, String> {
    run_credential_command(command, input)
}

#[cfg(target_os = "linux")]
fn attributes(key: &CredentialKey) -> [&str; 6] {
    [
        "service",
        "workflow-verifier",
        "provider",
        key.provider.name(),
        "host",
        key.host(),
    ]
}

#[cfg(target_os = "linux")]
fn system_put(key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
    let attributes = attributes(key);
    let payload = encode_secret_payload(secret);
    let mut output = run_secret_tool(
        &mut secret_tool(&[
            "store",
            "--label=Workflow Verifier",
            attributes[0],
            attributes[1],
            attributes[2],
            attributes[3],
            attributes[4],
            attributes[5],
        ]),
        Some(&payload),
    )?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.success() {
        Ok(())
    } else {
        Err("OS credential store rejected the credential".to_owned())
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "linux")]
fn system_get(key: &CredentialKey) -> Result<Option<SecretString>, String> {
    let attributes = attributes(key);
    let mut output = run_secret_tool(
        &mut secret_tool(&[
            "lookup",
            attributes[0],
            attributes[1],
            attributes[2],
            attributes[3],
            attributes[4],
            attributes[5],
        ]),
        None,
    )?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.code() == Some(1) {
        Ok(None)
    } else if !output.status.success() {
        Err("OS credential store lookup failed".to_owned())
    } else {
        decode_secret_payload(&output.stdout).map(Some)
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "linux")]
fn system_delete(key: &CredentialKey) -> Result<bool, String> {
    let attributes = attributes(key);
    let output = run_secret_tool(
        &mut secret_tool(&[
            "clear",
            attributes[0],
            attributes[1],
            attributes[2],
            attributes[3],
            attributes[4],
            attributes[5],
        ]),
        None,
    )?;
    if output.timed_out {
        return Err("OS credential store timed out".to_owned());
    }
    if output.output_exceeded {
        return Err("OS credential store output exceeded its limit".to_owned());
    }
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err("OS credential store delete failed".to_owned()),
    }
}

#[cfg(target_os = "macos")]
fn macos_security(arguments: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/security");
    command
        .args(arguments)
        .env_clear()
        .envs(credential_store_environment(|name| std::env::var_os(name)));
    command
}

#[cfg(target_os = "macos")]
fn system_put(key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
    let input = macos_put_input(key, secret);
    let mut output = run_credential_command(&mut macos_security(&["-i"]), Some(&input))?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.success() {
        Ok(())
    } else {
        Err("OS credential store rejected the credential".to_owned())
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "macos")]
fn system_get(key: &CredentialKey) -> Result<Option<SecretString>, String> {
    let identity = key.identity();
    let mut output = run_credential_command(
        &mut macos_security(&[
            "find-generic-password",
            "-a",
            &identity,
            "-s",
            CREDENTIAL_SERVICE,
            "-w",
        ]),
        None,
    )?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.code() == Some(44) {
        Ok(None)
    } else if !output.status.success() {
        Err("OS credential store lookup failed".to_owned())
    } else {
        decode_secret_payload(&output.stdout).map(Some)
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "macos")]
fn system_delete(key: &CredentialKey) -> Result<bool, String> {
    let identity = key.identity();
    let mut output = run_credential_command(
        &mut macos_security(&[
            "delete-generic-password",
            "-a",
            &identity,
            "-s",
            CREDENTIAL_SERVICE,
        ]),
        None,
    )?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else {
        match output.status.code() {
            Some(0) => Ok(true),
            Some(44) => Ok(false),
            _ => Err("OS credential store delete failed".to_owned()),
        }
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "windows")]
fn windows_powershell(script: &str, key: &CredentialKey) -> Result<Command, String> {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .ok_or_else(|| "OS credential store cannot locate Windows PowerShell".to_owned())?;
    let executable = std::path::PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let mut command = Command::new(executable);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .arg(key.identity())
        .env_clear()
        .envs(credential_store_environment(|name| std::env::var_os(name)));
    Ok(command)
}

#[cfg(target_os = "windows")]
fn run_windows_vault(
    script: &str,
    key: &CredentialKey,
    input: Option<&[u8]>,
) -> Result<crate::SupervisedOutput, String> {
    run_credential_command(&mut windows_powershell(script, key)?, input)
}

#[cfg(target_os = "windows")]
fn system_put(key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
    let payload = encode_secret_payload(secret);
    let mut output = run_windows_vault(WINDOWS_PUT_SCRIPT, key, Some(&payload))?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.success() {
        Ok(())
    } else {
        Err("OS credential store rejected the credential".to_owned())
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "windows")]
fn system_get(key: &CredentialKey) -> Result<Option<SecretString>, String> {
    let mut output = run_windows_vault(WINDOWS_GET_SCRIPT, key, None)?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else if output.status.code() == Some(1) {
        Ok(None)
    } else if !output.status.success() {
        Err("OS credential store lookup failed".to_owned())
    } else {
        decode_secret_payload(&output.stdout).map(Some)
    };
    wipe_output(&mut output);
    result
}

#[cfg(target_os = "windows")]
fn system_delete(key: &CredentialKey) -> Result<bool, String> {
    let mut output = run_windows_vault(WINDOWS_DELETE_SCRIPT, key, None)?;
    let result = if output.timed_out {
        Err("OS credential store timed out".to_owned())
    } else if output.output_exceeded {
        Err("OS credential store output exceeded its limit".to_owned())
    } else {
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err("OS credential store delete failed".to_owned()),
        }
    };
    wipe_output(&mut output);
    result
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn system_put(_key: &CredentialKey, _secret: &SecretString) -> Result<(), String> {
    Err("OS credential store adapter is unavailable on this platform build".to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn system_get(_key: &CredentialKey) -> Result<Option<SecretString>, String> {
    Err("OS credential store adapter is unavailable on this platform build".to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn system_delete(_key: &CredentialKey) -> Result<bool, String> {
    Err("OS credential store adapter is unavailable on this platform build".to_owned())
}

#[derive(Debug)]
pub struct AuthService<S> {
    store: S,
}

impl<S: CredentialStore> AuthService<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Store a freshly acquired credential.
    ///
    /// # Errors
    /// Propagates protected-store failures without a plaintext fallback.
    pub fn login(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
        self.store.put(key, secret)
    }

    /// Report whether a protected credential exists.
    ///
    /// # Errors
    /// Propagates protected-store failures.
    pub fn status(&self, key: &CredentialKey) -> Result<bool, String> {
        self.store.get(key).map(|value| value.is_some())
    }

    /// Load a credential for an in-memory resolver request.
    ///
    /// # Errors
    /// Propagates protected-store failures.
    pub fn credential(&self, key: &CredentialKey) -> Result<Option<SecretString>, String> {
        self.store.get(key)
    }

    /// Remove a protected credential.
    ///
    /// # Errors
    /// Propagates protected-store failures.
    pub fn logout(&self, key: &CredentialKey) -> Result<bool, String> {
        self.store.delete(key)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::credential_store_environment;
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    #[test]
    fn credential_store_environment_excludes_unrelated_tokens_and_proxies() {
        let ambient = BTreeMap::from([
            ("PATH", "/usr/bin"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("UNRELATED_TOKEN", "must-not-cross-boundary"),
            ("HTTPS_PROXY", "http://secret@example.invalid"),
        ]);
        let environment =
            credential_store_environment(|name| ambient.get(name).map(OsString::from));

        assert_eq!(
            environment.get(&OsString::from("DBUS_SESSION_BUS_ADDRESS")),
            Some(&OsString::from("unix:path=/run/user/1000/bus"))
        );
        assert!(!environment.contains_key(&OsString::from("UNRELATED_TOKEN")));
        assert!(!environment.contains_key(&OsString::from("HTTPS_PROXY")));
    }
}

#[cfg(test)]
mod protected_backend_contracts {
    use super::{
        CredentialKey, ProviderKind, SecretString, WINDOWS_DELETE_SCRIPT, WINDOWS_GET_SCRIPT,
        WINDOWS_PUT_SCRIPT, decode_secret_payload, encode_secret_payload, macos_put_input,
    };

    #[test]
    fn protected_payload_round_trips_without_embedding_plaintext() {
        let secret = SecretString::new("tok\"$;&`123").expect("secret");
        let payload = encode_secret_payload(&secret);
        assert!(
            !payload
                .windows(secret.expose().len())
                .any(|value| { value == secret.expose().as_bytes() })
        );
        let decoded = decode_secret_payload(&payload).expect("decode payload");
        assert_eq!(decoded.expose(), secret.expose());
    }

    #[test]
    fn macos_batch_and_windows_scripts_keep_plaintext_out_of_argv_code() {
        let key = CredentialKey::new(ProviderKind::Gitlab, Some("gitlab.enterprise.example:8443"))
            .expect("key");
        let secret = SecretString::new("token-$-with-punctuation").expect("secret");
        let batch = macos_put_input(&key, &secret);
        assert!(batch.ends_with(b"\n"));
        assert!(String::from_utf8_lossy(&batch).contains(&key.identity()));
        assert!(!String::from_utf8_lossy(&batch).contains(secret.expose()));
        assert!(!WINDOWS_PUT_SCRIPT.contains(secret.expose()));
        assert!(!WINDOWS_GET_SCRIPT.contains(secret.expose()));
        assert!(!WINDOWS_DELETE_SCRIPT.contains(secret.expose()));
        assert!(WINDOWS_PUT_SCRIPT.contains("PasswordVault"));
        assert!(WINDOWS_GET_SCRIPT.contains("RetrievePassword"));
        assert!(WINDOWS_DELETE_SCRIPT.contains("Remove"));
    }
}
