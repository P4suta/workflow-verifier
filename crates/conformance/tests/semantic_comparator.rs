use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use workflow_verifier_conformance::compare_documents;
use workflow_verifier_internal::internal::conformance::foundation::{JsonValue, content_digest};

fn document(rule: &str) -> String {
    let mut fields = BTreeMap::from([
        (
            "completeness".to_owned(),
            JsonValue::Object(BTreeMap::new()),
        ),
        (
            "diagnostics".to_owned(),
            JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([(
                "rule_id".to_owned(),
                JsonValue::String(rule.to_owned()),
            )]))]),
        ),
        ("digest".to_owned(), JsonValue::Null),
        ("edges".to_owned(), JsonValue::Array(Vec::new())),
        ("entrypoints".to_owned(), JsonValue::Array(Vec::new())),
        ("gate".to_owned(), JsonValue::Object(BTreeMap::new())),
        ("nodes".to_owned(), JsonValue::Array(Vec::new())),
        ("properties".to_owned(), JsonValue::Array(Vec::new())),
        (
            "schema".to_owned(),
            JsonValue::String("semantic-conformance/1".to_owned()),
        ),
        ("sources".to_owned(), JsonValue::Array(Vec::new())),
    ]);
    let digest = content_digest(JsonValue::Object(fields.clone()).canonical());
    fields.insert("digest".to_owned(), JsonValue::String(digest));
    JsonValue::Object(fields).canonical_line()
}

#[test]
fn equivalent_semantic_documents_ignore_no_fields() {
    let comparison = compare_documents(&document("WV-SEC-001"), &document("WV-SEC-001"))
        .expect("authenticated semantic documents");
    assert!(comparison.equivalent());
    assert!(comparison.differences().is_empty());
    assert_eq!(
        JsonValue::parse(&comparison.to_canonical_json())
            .unwrap()
            .member("schema")
            .and_then(JsonValue::as_str),
        Some("semantic-conformance-comparison/1")
    );
}

#[test]
fn differences_and_tampering_fail_closed() {
    let comparison = compare_documents(&document("WV-SEC-001"), &document("WV-SEC-002"))
        .expect("authenticated semantic documents");
    assert_eq!(
        comparison.differences(),
        &["/diagnostics/0/rule_id".to_owned()]
    );
    let tampered = document("WV-SEC-001").replacen("WV-SEC-001", "WV-SEC-002", 1);
    assert!(compare_documents(&document("WV-SEC-001"), &tampered).is_err());
}

#[test]
fn compare_command_has_stable_machine_output_and_exit_codes() {
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-semantic-conformance-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("temporary comparison directory");
    let left = root.join("left.json");
    let right = root.join("right.json");
    fs::write(&left, document("WV-SEC-001")).expect("left document");
    fs::write(&right, document("WV-SEC-001")).expect("right document");

    let equal = Command::new(env!("CARGO_BIN_EXE_workflow-verifier-conformance"))
        .args(["compare", left.to_str().unwrap(), right.to_str().unwrap()])
        .output()
        .expect("invoke comparator");
    assert_eq!(equal.status.code(), Some(0));
    assert!(equal.stderr.is_empty());

    fs::write(&right, document("WV-SEC-002")).expect("different document");
    let different = Command::new(env!("CARGO_BIN_EXE_workflow-verifier-conformance"))
        .args(["compare", left.to_str().unwrap(), right.to_str().unwrap()])
        .output()
        .expect("invoke comparator");
    assert_eq!(different.status.code(), Some(1));
    fs::remove_dir_all(root).expect("remove temporary comparison directory");
}
