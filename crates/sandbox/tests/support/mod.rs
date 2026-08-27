#![allow(dead_code)]

use std::collections::BTreeMap;

use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::content_digest;
use workflow_verifier_sandbox::{
    Backend, Control, RunnerPlanRequest, RunnerPlatform, Scenario, Step,
};

pub fn digest(label: &str) -> String {
    content_digest(label.as_bytes())
}

pub fn scenario(platform: RunnerPlatform) -> Scenario {
    Scenario::new(
        Provider::Github,
        ".github/workflows/ci.yml",
        "build",
        "push",
        platform,
    )
    .expect("contract scenario is valid")
}

pub fn valid_request() -> RunnerPlanRequest {
    RunnerPlanRequest {
        backend: Backend::Oci("podman".to_owned()),
        scenario: scenario(RunnerPlatform::LinuxX86_64),
        provider_profile: "github-semantic-v1".to_owned(),
        selected_jobs: vec!["build".to_owned()],
        source_digest: digest("source"),
        lock_digest: digest("lock"),
        controls: vec![Control::NetworkDeny],
        network_destinations: Vec::new(),
        dependencies: Vec::new(),
        steps: vec![Step {
            id: "build:step".to_owned(),
            image: digest("image"),
            argv: vec!["/bin/true".to_owned()],
            environment: BTreeMap::new(),
            working_directory: "/workspace".to_owned(),
            supported: true,
        }],
        incomplete_reasons: Vec::new(),
        runtime_helper_digest: None,
        runtime_boot_digest: None,
        capability_fingerprint: None,
    }
}
