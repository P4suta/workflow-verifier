use std::collections::BTreeMap;
use workflow_verifier::internal::conformance::foundation::{
    Budget, BudgetKind, BudgetTracker, JsonValue, PublicPath, content_digest, portable_path_key,
    valid_content_digest,
};

#[test]
fn strict_json_rejects_non_contract_values() {
    let invalid = [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"1.0".as_slice(),
        b"01".as_slice(),
        b"\xef\xbb\xbf{}".as_slice(),
        b"\"\\ud800\"".as_slice(),
    ];
    for source in invalid {
        assert!(
            JsonValue::parse_bytes(source).is_err(),
            "accepted {source:?}"
        );
    }
}

#[test]
fn canonical_json_sorts_and_appends_exactly_one_lf() {
    let parsed = JsonValue::parse("{\"z\":0,\"é\":2,\"a\":1}").expect("fixture is valid");
    assert_eq!(parsed.canonical_line(), "{\"a\":1,\"z\":0,\"é\":2}\n");
}

#[test]
fn canonical_digest_streams_the_exact_canonical_json_bytes() {
    let values = [
        JsonValue::Null,
        JsonValue::String("日本語\n\t\u{0008}\u{000c}\u{001f}\\\"".to_owned()),
        JsonValue::Object(BTreeMap::from([
            (
                "array".to_owned(),
                JsonValue::Array(vec![
                    JsonValue::Boolean(true),
                    JsonValue::Integer(i64::MIN),
                    JsonValue::Object(BTreeMap::from([(
                        "é".to_owned(),
                        JsonValue::String("😀".to_owned()),
                    )])),
                ]),
            ),
            (
                "control".to_owned(),
                JsonValue::String("\0\n\r\t".to_owned()),
            ),
        ])),
    ];

    for value in values {
        assert_eq!(value.canonical_digest(), content_digest(value.canonical()));
    }
}

#[test]
fn content_identity_is_lowercase_only() {
    let digest = content_digest("contract");
    assert!(valid_content_digest(&digest));
    assert!(!valid_content_digest(&digest.to_ascii_uppercase()));
    assert!(!valid_content_digest(&format!("sha256:{}", "A".repeat(64))));
}

#[test]
fn portable_paths_use_normalization_and_full_case_folding() {
    assert_eq!(
        portable_path_key("café/straße.yml"),
        portable_path_key("CAFE\u{301}/STRASSE.YML")
    );
    for invalid in ["", "/root", "C:/root", "a//b", "a/./b", "a/../b", "a\\b"] {
        assert!(PublicPath::new(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn budget_failure_is_typed_and_saturating() {
    let mut budget = BudgetTracker::new(Budget {
        max_entries: 1,
        ..Budget::default()
    });
    assert!(budget.entry().is_ok());
    let error = budget.entry().expect_err("second entry exceeds the budget");
    assert_eq!(error.kind, BudgetKind::Entries);
    assert!(error.to_string().starts_with("Incomplete.Resource_limit:"));
}
