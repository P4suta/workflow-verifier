use std::collections::BTreeMap;
use std::path::PathBuf;

use workflow_verifier_oci_helper::{build_arguments, source_manifest};
use workflow_verifier_runner_protocol::{Control, Limits, PlanStatus, Step, ValidatedPlan};

fn plan() -> ValidatedPlan {
    ValidatedPlan {
        digest: "sha256:test".to_owned(),
        backend: "oci:docker".to_owned(),
        controls: vec![
            Control::SourceReadOnly,
            Control::ScratchOverlay,
            Control::NetworkDeny,
            Control::ProcessIsolation,
            Control::ResourceLimits,
            Control::SecretRedaction,
        ],
        status: PlanStatus::Complete,
        source_digest: "sha256:source".to_owned(),
        lock_digest: "sha256:lock".to_owned(),
        limits: Limits {
            cpu_seconds: 5,
            memory_mb: 256,
            processes: 7,
            output_bytes: 4096,
        },
        secret_names: vec!["TOKEN".to_owned()],
        dependencies: Vec::new(),
        steps: Vec::new(),
    }
}

#[test]
fn invocation_is_argv_safe_and_enforces_every_oci_control() {
    let step = Step {
        id: "build".to_owned(),
        image: format!("sha256:{}", "a".repeat(64)),
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo $TOKEN".to_owned(),
        ],
        environment: BTreeMap::new(),
        working_directory: "/workspace".to_owned(),
        supported: true,
    };
    let arguments = build_arguments(&plan(), &step, r"\\?\C:\source", r"\\?\C:\scratch");
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["--network", "none"])
    );
    assert!(arguments.iter().any(|value| value == "--read-only"));
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["--pids-limit", "7"])
    );
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == ["--memory", "256m"])
    );
    assert!(arguments.iter().any(|value| value.contains("readonly")));
    assert!(
        arguments.iter().all(|value| !value.contains(r"\\?\")),
        "Windows extended path prefixes are not valid Docker bind sources"
    );
    assert!(arguments.windows(2).any(|pair| pair == ["--env", "TOKEN"]));
    assert!(!arguments.iter().any(|value| value.contains("secret-value")));
}

#[test]
fn source_manifest_matches_the_shared_ocaml_fixture() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repository.join("test/fixtures/protocol/source-tree");
    let expected =
        std::fs::read_to_string(repository.join("test/fixtures/protocol/source-manifest-v1.json"))
            .expect("shared source manifest fixture")
            .trim()
            .to_owned();
    let manifest = source_manifest(&root).expect("source manifest");
    assert_eq!(manifest.canonical_json, expected);
    assert_eq!(
        manifest.digest,
        "sha256:6d8438471c06fc1f4199de690117a6c60da9bee4c8d9421ad2333a7847033b48"
    );
}
