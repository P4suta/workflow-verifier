use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=WORKFLOW_VERIFIER_SOURCE_COMMIT");

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
}
