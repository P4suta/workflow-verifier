mod support;

use std::collections::BTreeMap;

use support::{digest, valid_request};
use workflow_verifier_foundation::{JsonValue, content_digest};
use workflow_verifier_sandbox::{
    Backend, Control, Dependency, RunnerPlan, Step, portable_limits, validate_plan,
};

fn rejected(mutator: impl FnOnce(&mut workflow_verifier_sandbox::RunnerPlanRequest)) {
    let mut request = valid_request();
    mutator(&mut request);
    assert!(RunnerPlan::build(request).is_err());
}

fn rejected_with(
    expected: &str,
    mutator: impl FnOnce(&mut workflow_verifier_sandbox::RunnerPlanRequest),
) {
    let mut request = valid_request();
    mutator(&mut request);
    assert_eq!(RunnerPlan::build(request).unwrap_err(), expected);
}

#[test]
fn backend_identity_and_platform_are_validated_independently() {
    rejected_with("OCI backend name is invalid", |request| {
        request.backend = Backend::Oci(String::new());
    });
    rejected_with("OCI backend name is invalid", |request| {
        request.backend = Backend::Oci("podman/escape".to_owned());
    });
    rejected(|request| request.backend = Backend::WindowsNative);
}

#[test]
fn every_plan_binding_digest_is_authenticated_independently() {
    let plan_digest_error = "runner-v2 scenario/source/lock digests must be SHA-256";
    rejected_with(plan_digest_error, |request| {
        request.scenario.digest = "invalid".to_owned();
    });
    rejected_with(plan_digest_error, |request| {
        request.source_digest = "invalid".to_owned();
    });
    rejected_with(plan_digest_error, |request| {
        request.lock_digest = "invalid".to_owned();
    });
    let runtime_error = "runtime identities must be SHA-256 content digests";
    rejected_with(runtime_error, |request| {
        request.runtime_helper_digest = Some("invalid".to_owned());
    });
    rejected_with(runtime_error, |request| {
        request.runtime_boot_digest = Some("invalid".to_owned());
    });
    rejected_with(runtime_error, |request| {
        request.capability_fingerprint = Some("invalid".to_owned());
    });
}

#[test]
fn provider_and_selected_job_identity_cannot_be_empty_or_duplicated() {
    let identity_error = "runner-v2 requires a provider profile and selected job";
    rejected_with(identity_error, |request| {
        request.provider_profile = " \t".to_owned();
    });
    rejected_with(identity_error, |request| request.selected_jobs.clear());
    rejected_with(identity_error, |request| {
        request.selected_jobs = vec![" \t".to_owned()];
    });
    rejected(|request| request.selected_jobs = vec!["build".to_owned(), "build".to_owned()]);
    rejected(|request| request.controls = vec![Control::NetworkDeny, Control::NetworkDeny]);
}

#[test]
fn network_policy_is_fail_closed_and_destinations_are_normalized_https() {
    rejected(|request| request.network_destinations = vec!["https://example.com".to_owned()]);
    rejected(|request| request.controls.clear());
    rejected(|request| {
        request.controls.clear();
        request.network_destinations = vec![
            "https://example.com/path".to_owned(),
            "https://example.com/path".to_owned(),
        ];
    });

    for invalid in [
        "http://example.com",
        "https://",
        "https://user@example.com",
        "https://example.com\\path",
        "https://example.com/path?query",
        "https://example.com/path#fragment",
        "https://example.com/../admin",
        "https://example.com/%2e%2e/admin",
        "https://example.com/space here",
        "https://example.com/line\nbreak",
        "https://example.com/nul\0byte",
    ] {
        rejected_with(
            "network destinations must be normalized HTTPS policies",
            |request| {
                request.controls.clear();
                request.network_destinations = vec![invalid.to_owned()];
            },
        );
    }

    let mut allowed = valid_request();
    allowed.controls.clear();
    allowed.network_destinations = vec!["https://example.com/releases".to_owned()];
    assert!(RunnerPlan::build(allowed).is_ok());
}

#[test]
fn dependency_identity_availability_and_digest_are_independent() {
    rejected(|request| {
        request.dependencies.push(Dependency {
            reference: " \t".to_owned(),
            digest: None,
            available: false,
        });
    });
    rejected(|request| {
        let dependency = Dependency {
            reference: "acme/action@v1".to_owned(),
            digest: Some(digest("dependency")),
            available: true,
        };
        request.dependencies = vec![dependency.clone(), dependency];
    });
    rejected(|request| {
        request.dependencies.push(Dependency {
            reference: "acme/action@v1".to_owned(),
            digest: Some("invalid".to_owned()),
            available: true,
        });
    });

    let mut unavailable = valid_request();
    unavailable.dependencies.push(Dependency {
        reference: "acme/action@v1".to_owned(),
        digest: Some(digest("dependency")),
        available: false,
    });
    let plan = RunnerPlan::build(unavailable).expect("unavailable dependency remains inspectable");
    assert!(format!("{:?}", plan.status()).contains("Unresolved_dependency"));
}

#[test]
fn steps_require_each_identity_execution_and_confinement_property() {
    rejected(|request| request.steps[0].id.clear());
    rejected(|request| request.steps[0].argv.clear());
    rejected(|request| request.steps[0].working_directory = "/tmp".to_owned());
    rejected(|request| request.steps[0].working_directory = "/workspace-escape".to_owned());
    rejected(|request| request.steps.push(request.steps[0].clone()));
    rejected(|request| {
        request.steps[0]
            .environment
            .insert("9INVALID".to_owned(), "value".to_owned());
    });

    let mut valid = valid_request();
    valid.steps[0].working_directory = "/workspace/subdirectory".to_owned();
    valid.steps[0]
        .environment
        .insert("_PORTABLE_9".to_owned(), "value".to_owned());
    assert!(RunnerPlan::build(valid).is_ok());
}

#[test]
fn incomplete_causes_are_preserved_and_secret_values_are_never_serialized() {
    let mut request = valid_request();
    request.scenario = request.scenario.with_secret("TOKEN").unwrap();
    request.steps[0]
        .environment
        .insert("TOKEN".to_owned(), "sensitive-value".to_owned());
    request.steps[0].supported = false;
    request.steps[0].image = "mutable-image-tag".to_owned();
    request
        .incomplete_reasons
        .push("dynamic planner input".to_owned());
    let plan = RunnerPlan::build(request).expect("incomplete plan remains inspectable");
    let canonical = plan.to_canonical_json();
    assert!(!canonical.contains("sensitive-value"));
    assert!(canonical.contains("${SECRET:TOKEN}"));
    assert!(canonical.contains("Incomplete.Unsupported_step"));
    assert!(canonical.contains("Incomplete.Unresolved_capsule"));
    assert!(canonical.contains("Incomplete.Planner: dynamic planner input"));
}

#[test]
fn portable_limits_match_the_published_runner_v2_contract() {
    let plan = RunnerPlan::build(valid_request()).expect("valid plan");
    let validated = validate_plan(&plan.to_canonical_json()).expect("shared protocol validation");
    assert_eq!(validated.limits, portable_limits());

    let limits = JsonValue::parse(&plan.to_canonical_json())
        .unwrap()
        .member("limits")
        .cloned()
        .unwrap();
    let fixture = JsonValue::parse(include_str!(
        "../../../test/fixtures/protocol/runner-v2-complete.json"
    ))
    .unwrap();
    assert_eq!(limits, fixture.member("limits").cloned().unwrap());
    assert_eq!(content_digest(b"image"), valid_request().steps[0].image);
}

#[test]
fn multiple_resolved_images_make_runtime_identity_explicitly_incomplete() {
    let mut request = valid_request();
    request.steps.push(Step {
        id: "build:other".to_owned(),
        image: digest("other-image"),
        argv: vec!["/bin/true".to_owned()],
        environment: BTreeMap::new(),
        working_directory: "/workspace".to_owned(),
        supported: true,
    });
    let plan = RunnerPlan::build(request).expect("multi-image plan remains inspectable");
    assert!(
        plan.to_canonical_json()
            .contains("Incomplete.Unresolved_runtime_workload")
    );
}

#[test]
fn resolved_native_runtime_identities_do_not_create_false_incompleteness() {
    let helper_digest = digest("runtime-helper");
    let boot_digest = digest("macos-boot");

    let mut linux = valid_request();
    linux.backend = Backend::LinuxNative;
    linux.runtime_helper_digest = Some(helper_digest.clone());
    let linux = RunnerPlan::build(linux).unwrap().to_canonical_json();
    assert!(!linux.contains("Unresolved_runtime_helper"));

    let mut macos = valid_request();
    macos.backend = Backend::MacosVm;
    macos.scenario = support::scenario(workflow_verifier_sandbox::RunnerPlatform::MacosArm64);
    macos.runtime_helper_digest = Some(helper_digest);
    macos.runtime_boot_digest = Some(boot_digest);
    let macos = RunnerPlan::build(macos).unwrap().to_canonical_json();
    assert!(!macos.contains("Unresolved_runtime_helper"));
    assert!(!macos.contains("Unresolved_macos_boot_bundle"));
}

#[test]
fn missing_native_runtime_identities_are_explicitly_incomplete() {
    let mut linux = valid_request();
    linux.backend = Backend::LinuxNative;
    assert!(
        RunnerPlan::build(linux)
            .unwrap()
            .to_canonical_json()
            .contains("Unresolved_runtime_helper")
    );

    let mut macos = valid_request();
    macos.backend = Backend::MacosVm;
    macos.scenario = support::scenario(workflow_verifier_sandbox::RunnerPlatform::MacosArm64);
    macos.runtime_helper_digest = Some(digest("runtime-helper"));
    assert!(
        RunnerPlan::build(macos)
            .unwrap()
            .to_canonical_json()
            .contains("Unresolved_macos_boot_bundle")
    );
}
