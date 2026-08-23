use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use workflow_verifier_helper_runtime::{
    ClosureSandbox, MapSecrets, NativeSandbox, NativeSandboxRequest, NativeStepRequest,
    ProcessObservation, execute_native, source_snapshot,
};
use workflow_verifier_runner_protocol::{
    Control, Descriptor, Limits, Outcome, PlanStatus, Step, ValidatedPlan,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn temporary_directory(purpose: &str) -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-{purpose}-test-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale test source");
    }
    std::fs::create_dir(&root).expect("create test directory");
    root
}

fn temporary_source() -> PathBuf {
    let root = temporary_directory("native-execution");
    std::fs::write(root.join("input.txt"), b"immutable").expect("write test source");
    root
}

fn descriptor() -> Descriptor {
    Descriptor {
        id: "linux-native",
        version: "test",
        platform: std::env::consts::OS,
        available: true,
        controls: vec![
            Control::SourceReadOnly,
            Control::ScratchOverlay,
            Control::SecretRedaction,
        ],
        reasons: Vec::new(),
    }
}

fn plan(source_digest: String) -> ValidatedPlan {
    ValidatedPlan {
        digest: "sha256:plan".to_owned(),
        backend: "linux-native".to_owned(),
        controls: descriptor().controls,
        status: PlanStatus::Complete,
        source_digest,
        lock_digest: "sha256:lock".to_owned(),
        limits: Limits {
            cpu_seconds: 1,
            memory_mb: 64,
            processes: 4,
            output_bytes: 1024,
        },
        secret_names: vec!["TOKEN".to_owned()],
        dependencies: Vec::new(),
        steps: vec![Step {
            id: "build".to_owned(),
            image: format!("sha256:{}", "0".repeat(64)),
            argv: vec!["tool".to_owned(), "run".to_owned()],
            environment: BTreeMap::from([("MODE".to_owned(), "test".to_owned())]),
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
    }
}

#[test]
fn native_execution_rejects_a_source_mismatch_before_launch() {
    let root = temporary_source();
    let mut invoked = false;
    let mut sandbox = ClosureSandbox::new(
        |_context: &NativeSandboxRequest<'_>| Ok(()),
        |_request: &NativeStepRequest<'_>| {
            invoked = true;
            unreachable!("source mismatch must stop before launch")
        },
    );
    let result = execute_native(
        &plan("sha256:not-the-source".to_owned()),
        &descriptor(),
        &root,
        &MapSecrets::default(),
        &mut sandbox,
    );
    assert!(result.is_err());
    assert!(!invoked);
    std::fs::remove_dir_all(root).expect("remove test source");
}

#[test]
fn native_execution_emits_common_process_secret_and_artifact_evidence() {
    let root = temporary_source();
    let digest = source_snapshot(&root)
        .expect("source snapshot")
        .manifest
        .digest;
    let secrets = MapSecrets::from([("TOKEN".to_owned(), "do-not-leak".to_owned())]);
    let prepared = Cell::new(false);
    let mut sandbox = ClosureSandbox::new(
        |context: &NativeSandboxRequest<'_>| {
            prepared.set(true);
            assert_ne!(context.source_root, context.scratch_root);
            Ok(())
        },
        |request: &NativeStepRequest<'_>| {
            assert!(
                prepared.get(),
                "controls must be prepared before a step starts"
            );
            assert_ne!(
                request.source_root,
                root.canonicalize().expect("canonical test source"),
                "the sandbox must receive a private source view, never the mutable host tree"
            );
            assert_eq!(
                request.environment.get("MODE").map(String::as_str),
                Some("test")
            );
            assert_eq!(
                request.environment.get("TOKEN").map(String::as_str),
                Some("do-not-leak")
            );
            assert!(request.working_directory.starts_with(request.scratch_root));
            std::fs::write(request.scratch_root.join("artifact.txt"), b"artifact")
                .expect("write artifact");
            Ok(ProcessObservation {
                code: Some(0),
                timed_out: false,
                output_exceeded: false,
                output: b"log do-not-leak".to_vec(),
            })
        },
    );
    let result = execute_native(&plan(digest), &descriptor(), &root, &secrets, &mut sandbox)
        .expect("native execution");
    assert_eq!(result.outcome, Outcome::Completed);
    let json = result.canonical_json();
    assert!(json.contains("\"kind\":\"backend_attested\""));
    assert!(json.contains("\"kind\":\"process_started\""));
    assert!(json.contains("\"kind\":\"secret_redacted\""));
    assert!(json.contains("\"kind\":\"artifact_recorded\""));
    assert!(!json.contains("do-not-leak"));
    std::fs::remove_dir_all(root).expect("remove test source");
}

struct LocatedSandbox {
    storage_root: PathBuf,
    prepared: bool,
}

impl NativeSandbox for LocatedSandbox {
    fn storage_root(&mut self) -> Result<Option<PathBuf>, String> {
        Ok(Some(self.storage_root.clone()))
    }

    fn prepare(&mut self, request: &NativeSandboxRequest<'_>) -> Result<(), String> {
        assert_eq!(request.source_root.parent(), Some(self.storage_root.as_path()));
        assert_eq!(
            request.scratch_root.parent(),
            Some(self.storage_root.as_path())
        );
        self.prepared = true;
        Ok(())
    }

    fn run(&mut self, _request: &NativeStepRequest<'_>) -> Result<ProcessObservation, String> {
        assert!(self.prepared);
        Ok(ProcessObservation {
            code: Some(0),
            timed_out: false,
            output_exceeded: false,
            output: Vec::new(),
        })
    }
}

#[test]
fn native_execution_uses_and_cleans_backend_storage_root() {
    let root = temporary_source();
    let digest = source_snapshot(&root)
        .expect("source snapshot")
        .manifest
        .digest;
    let storage_root = temporary_directory("native-storage");
    let mut sandbox = LocatedSandbox {
        storage_root: storage_root.clone(),
        prepared: false,
    };

    let result = execute_native(
        &plan(digest),
        &descriptor(),
        &root,
        &MapSecrets::default(),
        &mut sandbox,
    )
    .expect("native execution in backend storage");

    assert_eq!(result.outcome, Outcome::Completed);
    assert!(
        std::fs::read_dir(&storage_root)
            .expect("read backend storage")
            .next()
            .is_none(),
        "private source and scratch trees must be removed"
    );
    std::fs::remove_dir_all(root).expect("remove test source");
    std::fs::remove_dir_all(storage_root).expect("remove backend storage");
}
