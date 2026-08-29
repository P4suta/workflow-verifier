use workflow_verifier::internal::conformance::domain::Provider;
use workflow_verifier::internal::conformance::sandbox::{RunnerPlatform, Scenario};

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
