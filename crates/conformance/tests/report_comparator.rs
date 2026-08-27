use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use workflow_verifier_conformance::compare_reports;
use workflow_verifier_foundation::{JsonValue, content_digest};

fn object(fields: impl IntoIterator<Item = (&'static str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn semantic_body(schema: &str, rule: &str) -> BTreeMap<String, JsonValue> {
    BTreeMap::from([
        ("completeness".to_owned(), object([])),
        ("configuration".to_owned(), object([])),
        (
            "diagnostics".to_owned(),
            JsonValue::Array(vec![object([(
                "rule_id",
                JsonValue::String(rule.to_owned()),
            )])]),
        ),
        ("gate".to_owned(), object([])),
        ("graphs".to_owned(), JsonValue::Array(Vec::new())),
        ("inputs".to_owned(), JsonValue::Array(Vec::new())),
        ("lock".to_owned(), object([])),
        ("persona".to_owned(), JsonValue::String("gate".to_owned())),
        ("properties".to_owned(), JsonValue::Array(Vec::new())),
        ("provider_profiles".to_owned(), JsonValue::Array(Vec::new())),
        ("schema".to_owned(), JsonValue::String(schema.to_owned())),
        ("snapshot".to_owned(), object([])),
        ("summary".to_owned(), object([])),
    ])
}

fn report_v2(rule: &str) -> String {
    let mut fields = semantic_body("report-v2", rule);
    fields.insert(
        "tool".to_owned(),
        object([
            (
                "binary_digest",
                JsonValue::String(format!("sha256:{}", "a".repeat(64))),
            ),
            (
                "build",
                object([
                    ("dune", JsonValue::String("3.24.2".to_owned())),
                    ("ocaml", JsonValue::String("5.5.0".to_owned())),
                    ("source_commit", JsonValue::Null),
                ]),
            ),
            ("name", JsonValue::String("workflow-verifier".to_owned())),
            ("version", JsonValue::String("0.1.0".to_owned())),
        ]),
    );
    fields.insert("digest".to_owned(), JsonValue::Null);
    let digest = content_digest(JsonValue::Object(fields.clone()).canonical());
    fields.insert("digest".to_owned(), JsonValue::String(digest));
    JsonValue::Object(fields).canonical_line()
}

fn report_v3(rule: &str) -> String {
    let mut semantic = semantic_body("report-v3", rule);
    semantic.insert(
        "tool".to_owned(),
        object([
            ("name", JsonValue::String("workflow-verifier".to_owned())),
            ("version", JsonValue::String("0.1.0".to_owned())),
        ]),
    );
    let semantic_digest = content_digest(JsonValue::Object(semantic.clone()).canonical());
    let mut full = semantic;
    let JsonValue::Object(tool) = full.get_mut("tool").expect("tool") else {
        panic!("tool object")
    };
    tool.insert(
        "build".to_owned(),
        object([
            (
                "binary_digest",
                JsonValue::String(format!("sha256:{}", "b".repeat(64))),
            ),
            ("compiler", JsonValue::String("rustc test".to_owned())),
            ("implementation", JsonValue::String("rust".to_owned())),
            ("source_commit", JsonValue::Null),
            ("target", JsonValue::String("test-target".to_owned())),
        ]),
    );
    full.insert(
        "semantic_digest".to_owned(),
        JsonValue::String(semantic_digest),
    );
    let digest = content_digest(JsonValue::Object(full.clone()).canonical());
    full.insert("digest".to_owned(), JsonValue::String(digest));
    JsonValue::Object(full).canonical_line()
}

#[test]
fn report_v2_and_v3_are_semantically_bijective_across_build_provenance() {
    let comparison = compare_reports(&report_v2("WV-SEC-001"), &report_v3("WV-SEC-001"))
        .expect("authenticated reports");
    assert!(comparison.equivalent());
    assert!(comparison.differences().is_empty());
    assert_eq!(
        JsonValue::parse(&comparison.to_canonical_json())
            .unwrap()
            .member("schema")
            .and_then(JsonValue::as_str),
        Some("report-conformance-v1")
    );
}

#[test]
fn semantic_differences_are_reported_as_stable_json_pointers() {
    let comparison = compare_reports(&report_v2("WV-SEC-001"), &report_v3("WV-SEC-002"))
        .expect("authenticated reports");
    assert!(!comparison.equivalent());
    assert_eq!(
        comparison.differences(),
        &["/diagnostics/0/rule_id".to_owned()]
    );
}

#[test]
fn tampered_or_structurally_extended_reports_fail_closed() {
    let tampered = report_v3("WV-SEC-001").replacen("WV-SEC-001", "WV-SEC-002", 1);
    assert!(compare_reports(&report_v2("WV-SEC-001"), &tampered).is_err());

    let extended = report_v2("WV-SEC-001").replacen('{', "{\"surprise\":true,", 1);
    assert!(compare_reports(&extended, &report_v3("WV-SEC-001")).is_err());
}

#[test]
fn report_v3_manifest_vectors_are_executable_contracts() {
    let valid = include_str!("../../../conformance/vectors/report/report-v3-valid.json");
    let invalid = include_str!("../../../conformance/vectors/report/report-v3-invalid-digest.json");
    let comparison = compare_reports(valid, valid).expect("accepted report-v3 vector");
    assert!(comparison.equivalent());
    let error = compare_reports(valid, invalid).expect_err("tampered report-v3 vector");
    assert!(error.contains("semantic digest mismatch"), "{error}");
}

#[test]
fn compare_command_has_stable_machine_output_and_exit_codes() {
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-conformance-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("temporary comparison directory");
    let v2 = root.join("reference.json");
    let v3 = root.join("candidate.json");
    fs::write(&v2, report_v2("WV-SEC-001")).expect("reference report");
    fs::write(&v3, report_v3("WV-SEC-001")).expect("candidate report");

    let equal = Command::new(env!("CARGO_BIN_EXE_workflow-verifier-conformance"))
        .args(["compare", v2.to_str().unwrap(), v3.to_str().unwrap()])
        .output()
        .expect("invoke comparator");
    assert_eq!(equal.status.code(), Some(0));
    assert!(equal.stderr.is_empty());
    assert_eq!(
        JsonValue::parse(std::str::from_utf8(&equal.stdout).unwrap())
            .unwrap()
            .member("equivalent")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    fs::write(&v3, report_v3("WV-SEC-002")).expect("different candidate report");
    let different = Command::new(env!("CARGO_BIN_EXE_workflow-verifier-conformance"))
        .args(["compare", v2.to_str().unwrap(), v3.to_str().unwrap()])
        .output()
        .expect("invoke comparator");
    assert_eq!(different.status.code(), Some(1));
    assert!(different.stderr.is_empty());

    let invalid = Command::new(env!("CARGO_BIN_EXE_workflow-verifier-conformance"))
        .args(["compare", "missing.json", v3.to_str().unwrap()])
        .current_dir(&root)
        .output()
        .expect("invoke comparator");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!invalid.stderr.is_empty());

    fs::remove_dir_all(root).expect("remove temporary comparison directory");
}
