use workflow_verifier_runner_protocol::{
    Control, Descriptor, Evidence, LaunchError, Limits, Outcome, PlanStatus, RunResult,
    ValidatedPlan, validate_launch, validate_plan,
};

const PLAN: &str = concat!(
    "{\"backend\":\"linux-native\",",
    "\"controls\":[\"source_read_only\",\"network_deny\"],",
    "\"dependencies\":[],\"digest\":\"sha256:placeholder\",",
    "\"limits\":{\"cpu_seconds\":1,\"memory_mb\":64,\"output_bytes\":1024,\"processes\":4},",
    "\"lock_digest\":\"sha256:lock\",\"schema\":\"runner-v1\",",
    "\"secret_names\":[],\"source_digest\":\"sha256:source\",",
    "\"status\":{\"state\":\"complete\"},\"steps\":[]}"
);

const CANONICAL_PLAN: &str =
    include_str!("../../../test/fixtures/protocol/runner-v1-complete.json");
const INVALID_COMPLETE_PLAN: &str =
    include_str!("../../../test/fixtures/protocol/runner-v1-invalid-complete.json");
const CANONICAL_RUN: &str =
    include_str!("../../../test/fixtures/protocol/sandbox-run-v1-complete.json");

fn plan_for(descriptor: &Descriptor, status: PlanStatus) -> ValidatedPlan {
    ValidatedPlan {
        digest: "sha256:test".to_owned(),
        backend: descriptor.id.to_owned(),
        controls: descriptor.controls.clone(),
        status,
        source_digest: "sha256:source".to_owned(),
        lock_digest: "sha256:lock".to_owned(),
        limits: Limits {
            cpu_seconds: 1,
            memory_mb: 64,
            processes: 4,
            output_bytes: 1024,
        },
        secret_names: Vec::new(),
        dependencies: Vec::new(),
        steps: Vec::new(),
    }
}

#[test]
fn malformed_and_tampered_plans_fail_before_launch() {
    assert!(validate_plan("{not-json").is_err());
    assert!(
        validate_plan(PLAN).is_err(),
        "placeholder digest must not validate"
    );
}

#[test]
fn ocaml_and_helpers_share_canonical_runner_fixtures() {
    assert!(validate_plan(CANONICAL_PLAN).is_ok());
    assert!(
        validate_plan(INVALID_COMPLETE_PLAN).is_err(),
        "a self-consistent digest cannot conceal an unresolved dependency"
    );
}

#[test]
fn ocaml_and_helpers_share_canonical_sandbox_run_fixtures() {
    let run = RunResult {
        evidence: Evidence::new(
            "sha256:b8ad3d5133f98eb1a6747bf7360a4e1e3de5bec0bf92724c381121e15e9e8a6f",
        ),
        outcome: Outcome::Completed,
    };
    assert_eq!(run.canonical_json(), CANONICAL_RUN);
}

#[test]
fn every_backend_has_an_exact_identity_and_control_attestation() {
    let descriptors = [
        workflow_verifier_linux_helper::descriptor(),
        workflow_verifier_windows_helper::descriptor(),
        workflow_verifier_macos_helper::descriptor(),
    ];
    assert_eq!(descriptors[0].id, "linux-native");
    assert_eq!(descriptors[1].id, "windows-native");
    assert_eq!(descriptors[2].id, "macos-vm");
    for descriptor in descriptors {
        assert!(
            descriptor
                .canonical_json()
                .contains("\"schema\":\"backend-attestation-v1\"")
        );
        assert!(descriptor.controls.contains(&Control::SourceReadOnly));
        assert!(descriptor.controls.contains(&Control::NetworkDeny));
        assert!(descriptor.controls.contains(&Control::SecretRedaction));
    }
}

#[test]
fn native_availability_and_failure_reasons_are_consistent() {
    let descriptors = [
        workflow_verifier_linux_helper::descriptor(),
        workflow_verifier_windows_helper::descriptor(),
        workflow_verifier_macos_helper::descriptor(),
    ];
    for descriptor in descriptors {
        assert_eq!(
            descriptor.available,
            descriptor.reasons.is_empty(),
            "{} must either atomically attest every control or explain why it cannot",
            descriptor.id
        );
        if descriptor.platform != std::env::consts::OS {
            assert!(!descriptor.available);
            assert!(!descriptor.reasons.is_empty());
        }
    }
}

#[test]
fn platform_mismatch_is_fail_closed() {
    let descriptor = workflow_verifier_linux_helper::descriptor();
    if !cfg!(target_os = "linux") {
        assert!(!descriptor.available);
        assert!(matches!(
            validate_launch(&descriptor, &plan_for(&descriptor, PlanStatus::Complete)),
            Err(LaunchError::UnsupportedPlatform { .. })
        ));
    }
}

#[test]
fn incomplete_plans_are_never_launchable() {
    let status = PlanStatus::Incomplete(vec!["unresolved action".to_owned()]);
    let descriptors = [
        workflow_verifier_linux_helper::descriptor(),
        workflow_verifier_windows_helper::descriptor(),
        workflow_verifier_macos_helper::descriptor(),
    ];
    for descriptor in descriptors {
        let result = validate_launch(&descriptor, &plan_for(&descriptor, status.clone()));
        assert!(matches!(result, Err(LaunchError::IncompletePlan(_))));
    }
}
