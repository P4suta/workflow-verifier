#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use workflow_verifier_internal::internal::helper_runtime::source_snapshot;
use workflow_verifier_internal::internal::runner_protocol::{
    Limits, Outcome, PlanStatus, RuntimeProfile, Step, ValidatedPlan,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-linux-{name}-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale fixture");
    }
    std::fs::create_dir(&root).expect("create fixture");
    root
}

fn source() -> PathBuf {
    let root = fixture("source");
    std::fs::write(root.join("input.txt"), b"source").expect("write fixture");
    root
}

fn execute(
    root: &Path,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    limits: Limits,
) -> workflow_verifier_internal::internal::runner_protocol::RunResult {
    let descriptor = workflow_verifier_linux_helper::descriptor();
    let source_digest = source_snapshot(root)
        .expect("source snapshot")
        .manifest
        .digest;
    let plan = ValidatedPlan {
        digest: "sha256:linux-test-plan".to_owned(),
        backend: descriptor.id.to_owned(),
        scenario_digest: format!("sha256:{}", "2".repeat(64)),
        provider_profile: "github-actions-v1".to_owned(),
        selected_jobs: vec!["contained-step".to_owned()],
        controls: descriptor.controls.clone(),
        status: PlanStatus::Complete,
        source_digest,
        lock_digest: format!("sha256:{}", "1".repeat(64)),
        runtime: RuntimeProfile {
            kind: "linux-capsule".to_owned(),
            runner_platform: "linux-x86_64".to_owned(),
            workload_digest: format!("sha256:{}", "0".repeat(64)),
            rootfs_digest: Some(format!("sha256:{}", "0".repeat(64))),
            helper_digest: None,
            boot_digest: None,
            capability_fingerprint: None,
        },
        limits,
        network_destinations: Vec::new(),
        secret_names: Vec::new(),
        dependencies: Vec::new(),
        steps: vec![Step {
            id: "contained-step".to_owned(),
            image: format!("sha256:{}", "0".repeat(64)),
            argv,
            environment,
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
    };
    workflow_verifier_linux_helper::launch(&plan, root.to_str().expect("UTF-8 fixture path"))
        .expect("contained Linux execution")
}

fn limits() -> Limits {
    Limits {
        cpu_seconds: 5,
        memory_mb: 128,
        processes: 4,
        output_bytes: 4096,
    }
}

fn backend_available() -> bool {
    let descriptor = workflow_verifier_linux_helper::descriptor();
    if descriptor.available {
        true
    } else if std::env::var_os("WORKFLOW_VERIFIER_REQUIRE_NATIVE_TESTS").is_some() {
        panic!(
            "required Linux backend is unavailable: {}",
            descriptor.reasons.join("; ")
        );
    } else {
        eprintln!(
            "skipping Linux containment fixture: {}",
            descriptor.reasons.join("; ")
        );
        false
    }
}

#[test]
fn linux_controls_are_available_as_one_atomic_backend() {
    let descriptor = workflow_verifier_linux_helper::descriptor();
    if std::env::var_os("WORKFLOW_VERIFIER_REQUIRE_NATIVE_TESTS").is_some() {
        assert!(descriptor.available, "{}", descriptor.reasons.join("; "));
        assert!(descriptor.reasons.is_empty());
    } else {
        assert_eq!(descriptor.available, descriptor.reasons.is_empty());
    }
}

#[test]
fn namespace_step_records_its_scratch_artifact() {
    if !backend_available() {
        return;
    }
    let root = source();
    let result = execute(
        &root,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo artifact > artifact.txt".into(),
        ],
        BTreeMap::new(),
        limits(),
    );
    assert_eq!(result.outcome, Outcome::Completed);
    assert!(result.canonical_json().contains("artifact.txt"));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn private_source_is_read_only_and_the_host_source_is_unchanged() {
    if !backend_available() {
        return;
    }
    let root = source();
    let result = execute(
        &root,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo changed > \"$WORKFLOW_VERIFIER_SOURCE/input.txt\"".into(),
        ],
        BTreeMap::new(),
        limits(),
    );
    assert!(matches!(result.outcome, Outcome::StepFailed { .. }));
    assert_eq!(
        std::fs::read(root.join("input.txt")).expect("read host source"),
        b"source"
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn landlock_denies_an_unrelated_readable_host_path() {
    if !backend_available() {
        return;
    }
    let root = source();
    let outside = fixture("outside").join("secret.txt");
    std::fs::write(&outside, b"host secret").expect("write outside fixture");
    let result = execute(
        &root,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "if cat \"$HOST_SECRET\" >/dev/null; then exit 90; else exit 0; fi".into(),
        ],
        BTreeMap::from([(
            "HOST_SECRET".to_owned(),
            outside.to_string_lossy().into_owned(),
        )]),
        limits(),
    );
    assert_eq!(result.outcome, Outcome::Completed);
    std::fs::remove_dir_all(root).expect("remove fixture");
    std::fs::remove_dir_all(outside.parent().expect("outside parent")).expect("remove outside");
}

#[test]
fn workload_is_pid_one_and_cannot_create_an_extra_process_at_the_limit() {
    if !backend_available() {
        return;
    }
    let root = source();
    let mut constrained = limits();
    constrained.processes = 1;
    let pid_one = execute(
        &root,
        vec!["/bin/sh".into(), "-c".into(), "test $$ -eq 1".into()],
        BTreeMap::new(),
        constrained.clone(),
    );
    assert_eq!(pid_one.outcome, Outcome::Completed);
    let fork = execute(
        &root,
        vec![
            "/bin/bash".into(),
            "-c".into(),
            "sleep 1 & child=$!; test -n \"$child\" && wait \"$child\"".into(),
        ],
        BTreeMap::new(),
        constrained,
    );
    assert!(
        matches!(fork.outcome, Outcome::TimedOut { .. }),
        "the shell should be unable to fork and be terminated at the plan limit: {:?}",
        fork.outcome
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn seccomp_denies_namespace_reconfiguration() {
    if !backend_available() {
        return;
    }
    let root = source();
    let result = execute(
        &root,
        vec![
            "/usr/bin/unshare".into(),
            "--mount".into(),
            "/bin/true".into(),
        ],
        BTreeMap::new(),
        limits(),
    );
    assert!(matches!(result.outcome, Outcome::StepFailed { .. }));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn network_namespace_and_seccomp_deny_loopback() {
    if !backend_available() {
        return;
    }
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
                    let _ = stream.write_all(b"unexpected");
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
            "/bin/bash".into(),
            "-c".into(),
            format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
        ],
        BTreeMap::new(),
        limits(),
    );
    stop.store(true, Ordering::Release);
    server.join().expect("join local probe");
    assert!(!connected.load(Ordering::Acquire));
    assert!(matches!(result.outcome, Outcome::StepFailed { .. }));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn cgroup_tree_is_killed_at_time_and_output_limits() {
    if !backend_available() {
        return;
    }
    let root = source();
    let mut time_limited = limits();
    time_limited.cpu_seconds = 1;
    let timed = execute(
        &root,
        vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
        BTreeMap::new(),
        time_limited,
    );
    assert!(matches!(timed.outcome, Outcome::TimedOut { .. }));
    let mut output_limited = limits();
    output_limited.output_bytes = 128;
    let noisy = execute(
        &root,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "yes workflow-verifier".into(),
        ],
        BTreeMap::new(),
        output_limited,
    );
    assert!(matches!(noisy.outcome, Outcome::OutputLimitExceeded { .. }));
    std::fs::remove_dir_all(root).expect("remove fixture");
}
