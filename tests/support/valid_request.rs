use std::collections::BTreeMap;

use super::digest_support::digest;
use super::scenario_support::scenario;
use workflow_verifier::internal::conformance::sandbox::{
    Backend, Control, RunnerPlanRequest, RunnerPlatform, Step,
};

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
