#[path = "support/scenario.rs"]
mod scenario_support;

use std::collections::BTreeMap;

use scenario_support::scenario;
use workflow_verifier::internal::conformance::domain::Provider;
use workflow_verifier::internal::conformance::foundation::JsonValue;
use workflow_verifier::internal::conformance::sandbox::{RunnerPlatform, Scenario};

const PLATFORMS: [RunnerPlatform; 6] = [
    RunnerPlatform::LinuxX86_64,
    RunnerPlatform::LinuxArm64,
    RunnerPlatform::WindowsX86_64,
    RunnerPlatform::WindowsArm64,
    RunnerPlatform::MacosX86_64,
    RunnerPlatform::MacosArm64,
];

#[test]
fn every_published_platform_name_round_trips_with_its_operating_system() {
    let expected = [
        ("linux-x86_64", "linux"),
        ("linux-arm64", "linux"),
        ("windows-x86_64", "windows"),
        ("windows-arm64", "windows"),
        ("macos-x86_64", "macos"),
        ("macos-arm64", "macos"),
    ];
    for (platform, (name, os)) in PLATFORMS.into_iter().zip(expected) {
        assert_eq!(platform.name(), name);
        assert_eq!(platform.os(), os);
        assert_eq!(RunnerPlatform::parse(name), Some(platform));
        let value = scenario(platform);
        assert_eq!(Scenario::parse(&value.to_canonical_json()), Ok(value));
    }
    assert_eq!(RunnerPlatform::parse("linux-riscv64"), None);
}

#[test]
fn constructor_requires_a_safe_entrypoint_and_nonempty_selectors() {
    assert!(
        Scenario::new(
            Provider::Github,
            "../escape.yml",
            "build",
            "push",
            PLATFORMS[0]
        )
        .is_err()
    );
    assert!(
        Scenario::new(
            Provider::Github,
            "/absolute.yml",
            "build",
            "push",
            PLATFORMS[0]
        )
        .is_err()
    );
    assert!(Scenario::new(Provider::Github, "ci.yml", " \t", "push", PLATFORMS[0]).is_err());
    assert!(Scenario::new(Provider::Github, "ci.yml", "build", " \t", PLATFORMS[0]).is_err());

    let normalized = Scenario::new(
        Provider::Github,
        ".github\\workflows\\ci.yml",
        "build",
        "push",
        PLATFORMS[0],
    )
    .unwrap();
    assert_eq!(normalized.workflow_entrypoint, ".github/workflows/ci.yml");
}

#[test]
fn input_and_variable_names_are_portable_and_unique() {
    for invalid in ["", "9name", "with/slash", "with space"] {
        assert!(scenario(PLATFORMS[0]).with_input(invalid, "value").is_err());
        assert!(
            scenario(PLATFORMS[0])
                .with_variable(invalid, "value")
                .is_err()
        );
    }
    let value = scenario(PLATFORMS[0])
        .with_input("_input.name-9", "one")
        .unwrap();
    assert!(value.clone().with_input("_input.name-9", "two").is_err());
    let value = value.with_variable("variable.name-9", "one").unwrap();
    assert!(
        value
            .clone()
            .with_variable("variable.name-9", "two")
            .is_err()
    );
    assert!(value.verify_digest());
}

#[test]
fn matrix_accepts_exactly_the_three_scalar_product_types() {
    let value = scenario(PLATFORMS[0])
        .with_matrix("text", JsonValue::String("value".to_owned()))
        .unwrap()
        .with_matrix("boolean", JsonValue::Boolean(true))
        .unwrap()
        .with_matrix("integer", JsonValue::Integer(-1))
        .unwrap();
    assert!(value.verify_digest());
    assert!(
        value
            .clone()
            .with_matrix("text", JsonValue::String("duplicate".to_owned()))
            .is_err()
    );
    assert!(
        scenario(PLATFORMS[0])
            .with_matrix("array", JsonValue::Array(Vec::new()))
            .is_err()
    );
    assert!(
        scenario(PLATFORMS[0])
            .with_matrix("object", JsonValue::Object(BTreeMap::new()))
            .is_err()
    );
    assert!(
        scenario(PLATFORMS[0])
            .with_matrix("null", JsonValue::Null)
            .is_err()
    );
}

#[test]
fn secret_names_use_environment_identifier_rules_and_are_unique() {
    for invalid in ["", "9TOKEN", "TOKEN-NAME", "TOKEN.NAME", "TOKEN NAME"] {
        assert!(scenario(PLATFORMS[0]).with_secret(invalid).is_err());
    }
    let value = scenario(PLATFORMS[0]).with_secret("_TOKEN_9").unwrap();
    assert!(value.clone().with_secret("_TOKEN_9").is_err());
    assert_eq!(value.secret_names, ["_TOKEN_9"]);
}

#[test]
fn parser_revalidates_names_uniqueness_scalar_types_and_digest() {
    let mut duplicate_secrets = scenario(PLATFORMS[0]);
    duplicate_secrets.secret_names = vec!["TOKEN".to_owned(), "TOKEN".to_owned()];
    assert!(Scenario::parse(&duplicate_secrets.to_canonical_json()).is_err());

    let valid = scenario(PLATFORMS[0])
        .with_input("input", "value")
        .unwrap()
        .with_matrix("matrix", JsonValue::Boolean(false))
        .unwrap();
    let canonical = valid.to_canonical_json();
    assert_eq!(Scenario::parse(&canonical), Ok(valid.clone()));
    assert!(Scenario::parse(&canonical.replace("\"matrix\":false", "\"matrix\":[false]")).is_err());
    assert!(
        Scenario::parse(&canonical.replace("\"input\":\"value\"", "\"9input\":\"value\"")).is_err()
    );
    assert!(Scenario::parse(&canonical.replace("sha256:", "sha256:0")).is_err());

    let mut tampered = valid;
    tampered.event = "pull_request".to_owned();
    assert!(!tampered.verify_digest());
    assert!(Scenario::parse(&tampered.to_canonical_json()).is_err());
}
