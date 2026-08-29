use std::fs;
use std::path::Path;
use std::process::Command;

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn packaged_commit(manifest_directory: &Path) -> Option<String> {
    let source = fs::read_to_string(manifest_directory.join(".cargo_vcs_info.json")).ok()?;
    let suffix = source.split_once("\"sha1\"")?.1;
    let value = suffix.split_once(':')?.1.trim_start();
    let value = value.strip_prefix('"')?.split_once('"')?.0;
    valid_commit(value).then(|| value.to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=WORKFLOW_VERIFIER_SOURCE_COMMIT");
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiler = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(
            || "rustc unavailable".to_owned(),
            |value| value.trim().to_owned(),
        );
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_owned());
    println!("cargo:rustc-env=WORKFLOW_VERIFIER_RUSTC_VERSION={compiler}");
    println!("cargo:rustc-env=WORKFLOW_VERIFIER_BUILD_TARGET={target}");
    if let Some(commit) = std::env::var("WORKFLOW_VERIFIER_SOURCE_COMMIT")
        .ok()
        .filter(|value| valid_commit(value))
        .or_else(|| {
            std::env::var_os("CARGO_MANIFEST_DIR")
                .map(std::path::PathBuf::from)
                .as_deref()
                .and_then(packaged_commit)
        })
    {
        println!("cargo:rustc-env=WORKFLOW_VERIFIER_SOURCE_COMMIT={commit}");
    }
}
