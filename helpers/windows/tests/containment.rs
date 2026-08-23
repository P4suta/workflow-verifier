#![cfg(target_os = "windows")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use workflow_verifier_helper_runtime::source_snapshot;
use workflow_verifier_runner_protocol::{Limits, Outcome, PlanStatus, Step, ValidatedPlan};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn source() -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-windows-containment-test-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale fixture");
    }
    std::fs::create_dir(&root).expect("create fixture");
    std::fs::write(root.join("input.txt"), b"source").expect("write fixture");
    root
}

fn execute(
    root: &Path,
    argv: Vec<String>,
    cpu_seconds: u64,
    output_bytes: u64,
) -> workflow_verifier_runner_protocol::RunResult {
    let descriptor = workflow_verifier_windows_helper::descriptor();
    let source_digest = source_snapshot(root)
        .expect("source snapshot")
        .manifest
        .digest;
    let plan = ValidatedPlan {
        digest: "sha256:windows-test-plan".to_owned(),
        backend: descriptor.id.to_owned(),
        controls: descriptor.controls.clone(),
        status: PlanStatus::Complete,
        source_digest,
        lock_digest: format!("sha256:{}", "1".repeat(64)),
        limits: Limits {
            cpu_seconds,
            memory_mb: 128,
            processes: 4,
            output_bytes,
        },
        secret_names: Vec::new(),
        dependencies: Vec::new(),
        steps: vec![Step {
            id: "contained-step".to_owned(),
            image: format!("sha256:{}", "0".repeat(64)),
            argv,
            environment: BTreeMap::new(),
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
    };
    workflow_verifier_windows_helper::launch(&plan, root.to_str().expect("UTF-8 fixture path"))
        .expect("contained Windows execution")
}

#[test]
fn windows_controls_are_available_as_one_atomic_backend() {
    let descriptor = workflow_verifier_windows_helper::descriptor();
    assert!(descriptor.available, "{}", descriptor.reasons.join("; "));
    assert!(descriptor.reasons.is_empty());
}

#[test]
fn appcontainer_step_records_its_scratch_artifact() {
    let root = source();
    let result = execute(
        &root,
        vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "echo artifact>artifact.txt".to_owned(),
        ],
        5,
        4096,
    );
    assert_eq!(result.outcome, Outcome::Completed);
    assert!(result.canonical_json().contains("artifact.txt"));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn broker_mode_refuses_a_non_appcontainer_caller() {
    let arguments = vec![
        "--workflow-verifier-appcontainer-broker-v1".to_owned(),
        "--".to_owned(),
        "cmd.exe".to_owned(),
        "/C".to_owned(),
        "exit 0".to_owned(),
    ];
    assert_eq!(
        workflow_verifier_windows_helper::broker_main(&arguments),
        Some(126)
    );
}

#[test]
fn appcontainer_cannot_modify_the_private_source_view() {
    let root = source();
    let result = execute(
        &root,
        vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "echo changed>\"%WORKFLOW_VERIFIER_SOURCE%\\input.txt\"".to_owned(),
        ],
        5,
        4096,
    );
    assert!(matches!(result.outcome, Outcome::StepFailed { .. }));
    assert_eq!(
        std::fs::read(root.join("input.txt")).expect("read host source"),
        b"source"
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn job_terminates_a_step_at_the_output_limit() {
    let root = source();
    let result = execute(
        &root,
        vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "for /L %i in (1,1,10000) do @echo 012345678901234567890123456789".to_owned(),
        ],
        5,
        256,
    );
    assert!(matches!(
        result.outcome,
        Outcome::OutputLimitExceeded { .. }
    ));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn job_terminates_a_step_at_the_wall_timeout() {
    let root = source();
    let result = execute(
        &root,
        vec![
            "powershell.exe".to_owned(),
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            "Start-Sleep -Seconds 10".to_owned(),
        ],
        1,
        4096,
    );
    assert!(matches!(result.outcome, Outcome::TimedOut { .. }));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn appcontainer_without_capabilities_cannot_reach_loopback() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local probe");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("listener address").port();
    let connected = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let server_connected = Arc::clone(&connected);
    let server_stop = Arc::clone(&stop);
    let server = std::thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    server_connected.store(true, Ordering::Release);
                    let _ =
                        stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    let root = source();
    let result = execute(
        &root,
        vec![
            "curl.exe".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "2".to_owned(),
            format!("http://127.0.0.1:{port}/"),
        ],
        5,
        4096,
    );
    stop.store(true, Ordering::Release);
    server.join().expect("join local probe");
    assert!(!connected.load(Ordering::Acquire));
    assert!(matches!(result.outcome, Outcome::StepFailed { .. }));
    std::fs::remove_dir_all(root).expect("remove fixture");
}
