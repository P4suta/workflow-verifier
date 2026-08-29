use std::collections::BTreeMap;
use workflow_verifier::internal::conformance::domain::Provider;
use workflow_verifier::internal::conformance::foundation::{JsonValue, valid_content_digest};
use workflow_verifier::internal::conformance::sandbox::{
    Backend, Control, Dependency, RunnerPlan, RunnerPlanRequest, RunnerPlatform, SandboxAudit,
    SandboxAuditStatus, Scenario, SourceFile, SourceManifest, Step, plan_scenario,
};
use workflow_verifier::internal::runner_protocol::{
    Evidence, PlanStatus, RunResult, validate_plan,
};

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn scenario(platform: RunnerPlatform) -> Scenario {
    Scenario::new(
        Provider::Github,
        ".github/workflows/ci.yml",
        "build",
        "push",
        platform,
    )
    .expect("valid scenario")
    .with_input("release", "true")
    .expect("portable input")
    .with_secret("TOKEN")
    .expect("portable secret")
}

#[test]
fn source_manifest_is_deterministic_and_excludes_generated_directories() {
    let files = vec![
        SourceFile::regular("src/main.rs", b"fn main() {}\n"),
        SourceFile::regular(".git/config", b"secret"),
        SourceFile::executable("scripts/check.sh", b"#!/bin/sh\ntrue\n"),
    ];
    let first = SourceManifest::create(".", files.clone(), &[]).expect("manifest");
    let second = SourceManifest::create(".", files.into_iter().rev(), &[]).expect("manifest");
    assert_eq!(first, second);
    assert_eq!(first.entries.len(), 2);
    assert_eq!(first.exclusions[0].path, ".git/config");
    assert!(valid_content_digest(&first.digest));
    assert!(first.verify_digest());
    assert!(JsonValue::parse(&first.to_canonical_json()).is_ok());
}

#[test]
fn source_manifest_rejects_portable_collisions_and_escaping_symlinks() {
    let collision = SourceManifest::create(
        ".",
        [
            SourceFile::regular("Readme.md", b"one"),
            SourceFile::regular("README.md", b"two"),
        ],
        &[],
    );
    assert!(collision.is_err());
    assert!(
        SourceManifest::create(".", [SourceFile::symlink("escape", "../outside")], &[]).is_err()
    );
}

#[test]
fn scenario_v1_accepts_linux_arm64_and_authenticates_its_semantics() {
    let scenario = scenario(RunnerPlatform::LinuxArm64);
    assert_eq!(scenario.runner_platform, RunnerPlatform::LinuxArm64);
    assert_eq!(scenario.runner_platform.name(), "linux-arm64");
    assert!(scenario.verify_digest());
    assert_eq!(Scenario::parse(&scenario.to_canonical_json()), Ok(scenario));
}

#[test]
fn runner_plan_is_byte_compatible_with_the_shared_helper_protocol() {
    let scenario = scenario(RunnerPlatform::LinuxArm64);
    let mut environment = BTreeMap::new();
    environment.insert("TOKEN".to_owned(), "must-not-leak".to_owned());
    let request = RunnerPlanRequest {
        backend: Backend::Oci("podman".to_owned()),
        scenario,
        provider_profile: "github-semantic-v1".to_owned(),
        selected_jobs: vec!["build".to_owned()],
        source_digest: digest('a'),
        lock_digest: digest('b'),
        controls: vec![
            Control::SourceReadOnly,
            Control::ScratchOverlay,
            Control::NetworkDeny,
            Control::ProcessIsolation,
            Control::ResourceLimits,
            Control::SecretRedaction,
        ],
        network_destinations: Vec::new(),
        dependencies: vec![Dependency {
            reference: "acme/action@sha".to_owned(),
            digest: Some(digest('c')),
            available: true,
        }],
        steps: vec![Step {
            id: "compile".to_owned(),
            image: digest('d'),
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "make".to_owned()],
            environment,
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
        incomplete_reasons: Vec::new(),
        runtime_helper_digest: None,
        runtime_boot_digest: None,
        capability_fingerprint: None,
    };
    let plan = RunnerPlan::build(request).expect("valid plan");
    assert!(!plan.to_canonical_json().contains("must-not-leak"));
    assert!(plan.to_canonical_json().contains("${SECRET:TOKEN}"));
    let shared = validate_plan(&plan.to_canonical_json()).expect("shared protocol accepts plan");
    assert_eq!(shared.status, PlanStatus::Complete);
    assert_eq!(shared.runtime.runner_platform, "linux-arm64");
}

#[test]
fn unresolved_runtime_is_explicitly_incomplete_never_an_implicit_fallback() {
    let request = RunnerPlanRequest {
        backend: Backend::Oci("podman".to_owned()),
        scenario: scenario(RunnerPlatform::LinuxX86_64),
        provider_profile: "github-semantic-v1".to_owned(),
        selected_jobs: vec!["build".to_owned()],
        source_digest: digest('a'),
        lock_digest: digest('b'),
        controls: vec![Control::NetworkDeny],
        network_destinations: Vec::new(),
        dependencies: Vec::new(),
        steps: vec![Step {
            id: "dynamic".to_owned(),
            image: "ubuntu:latest".to_owned(),
            argv: vec!["/bin/true".to_owned()],
            environment: BTreeMap::new(),
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
        incomplete_reasons: Vec::new(),
        runtime_helper_digest: None,
        runtime_boot_digest: None,
        capability_fingerprint: None,
    };
    let plan = RunnerPlan::build(request).expect("an incomplete plan is still inspectable");
    let shared = validate_plan(&plan.to_canonical_json()).expect("shared protocol accepts it");
    let PlanStatus::Incomplete(reasons) = shared.status else {
        panic!("unresolved work must not produce a runnable plan")
    };
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("Unresolved_capsule"))
    );
}

#[test]
fn complete_persisted_evidence_produces_a_canonical_verified_audit() {
    let plan = validate_plan(include_str!(
        "../test/fixtures/protocol/runner-v2-complete.json"
    ))
    .expect("canonical plan");
    let run = RunResult::parse(include_str!(
        "../test/fixtures/protocol/sandbox-run-v2-complete.json"
    ))
    .expect("canonical run");
    run.evidence
        .validate_for_plan(&plan)
        .expect("bound evidence");
    let audit = SandboxAudit::evaluate(&plan, &run.evidence).expect("audit");
    assert_eq!(audit.status(), &SandboxAuditStatus::Verified);
    assert_eq!(audit.event_count(), 12);
    let json = audit.to_canonical_json();
    let parsed = JsonValue::parse(&json).expect("strict audit JSON");
    assert_eq!(
        parsed.member("schema").and_then(JsonValue::as_str),
        Some("sandbox-audit-v1")
    );
    assert!(json.contains("command_execution"));

    let evidence = Evidence::parse(
        include_str!("../test/fixtures/protocol/sandbox-run-v2-complete.json")
            .strip_prefix("{\"evidence\":")
            .and_then(|value| {
                value
                    .split_once(",\"outcome\":")
                    .map(|(evidence, _)| evidence)
            })
            .unwrap(),
    )
    .expect("evidence projection");
    assert_eq!(evidence.tail_digest(), run.evidence.tail_digest());
}

#[test]
fn scenario_planner_selects_only_the_job_closure_and_concretizes_inputs() {
    let source = r#"on: workflow_dispatch
jobs:
  ignored:
    steps:
      - run: echo ignored
  build:
    steps:
      - run: echo "${{ inputs.release }}"
"#;
    let compilation = workflow_verifier::internal::conformance::frontend::compile_auto(
        ".github/workflows/ci.yml",
        source,
        workflow_verifier::internal::conformance::foundation::Budget::default(),
    )
    .expect("workflow");
    let scenario = Scenario::new(
        Provider::Github,
        ".github/workflows/ci.yml",
        "build",
        "workflow_dispatch",
        RunnerPlatform::LinuxX86_64,
    )
    .unwrap()
    .with_input("release", "true")
    .unwrap();
    let planned = plan_scenario(
        &scenario,
        &digest('a'),
        std::slice::from_ref(&compilation.graph),
    )
    .expect("scenario plan");
    assert_eq!(planned.selected_jobs, ["build"]);
    assert_eq!(planned.steps.len(), 1);
    assert_eq!(
        planned.steps[0].argv.last().map(String::as_str),
        Some("echo \"true\"")
    );
    assert!(planned.incomplete_reasons.is_empty());
}

#[test]
fn scenario_planner_follows_local_composite_action_call_edges() {
    let workflow = workflow_verifier::internal::conformance::frontend::compile_auto(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n",
        workflow_verifier::internal::conformance::foundation::Budget::default(),
    )
    .expect("workflow");
    let action = workflow_verifier::internal::conformance::frontend::compile_auto(
        ".github/actions/demo/action.yml",
        "name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n",
        workflow_verifier::internal::conformance::foundation::Budget::default(),
    )
    .expect("action");
    let scenario = Scenario::new(
        Provider::Github,
        ".github/workflows/ci.yml",
        "build",
        "workflow_dispatch",
        RunnerPlatform::LinuxX86_64,
    )
    .unwrap();
    let planned = plan_scenario(&scenario, &digest('a'), &[workflow.graph, action.graph])
        .expect("scenario plan");

    assert_eq!(planned.selected_jobs, ["build"]);
    assert_eq!(planned.steps.len(), 1);
    assert_eq!(
        planned.steps[0].argv.last().map(String::as_str),
        Some("echo local")
    );
    assert!(planned.incomplete_reasons.is_empty());
}

#[test]
fn scenario_planner_propagates_job_and_step_conditions() {
    let compilation = workflow_verifier::internal::conformance::frontend::compile_auto(
        ".github/workflows/ci.yml",
        r"on: [push, pull_request]
jobs:
  build:
    if: github.event_name == 'push'
    steps:
      - run: echo selected
      - if: github.event_name == 'schedule'
        run: echo skipped
",
        workflow_verifier::internal::conformance::foundation::Budget::default(),
    )
    .expect("workflow");
    let scenario = |event: &str| {
        Scenario::new(
            Provider::Github,
            ".github/workflows/ci.yml",
            "build",
            event,
            RunnerPlatform::LinuxX86_64,
        )
        .unwrap()
    };

    let push = plan_scenario(
        &scenario("push"),
        &digest('a'),
        std::slice::from_ref(&compilation.graph),
    )
    .expect("push plan");
    assert_eq!(push.steps.len(), 1);
    assert_eq!(
        push.steps[0].argv.last().map(String::as_str),
        Some("echo selected")
    );
    assert!(push.incomplete_reasons.is_empty());

    let pull_request = plan_scenario(
        &scenario("pull_request"),
        &digest('a'),
        std::slice::from_ref(&compilation.graph),
    )
    .expect("pull-request plan");
    assert!(pull_request.steps.is_empty());
    assert!(pull_request.incomplete_reasons.is_empty());
}
