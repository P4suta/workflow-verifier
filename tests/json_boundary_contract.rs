use workflow_verifier::internal::conformance::foundation::{JsonError, JsonLimits, JsonValue};

fn limits_for(source: &str) -> JsonLimits {
    JsonLimits {
        max_bytes: source.len(),
        ..JsonLimits::default()
    }
}

#[test]
fn json_error_display_and_integer_projection_are_exact() {
    let source = "null trailing";
    let error = JsonError {
        offset: "null ".len(),
        message: "trailing JSON input".to_owned(),
    };
    assert_eq!(
        error.to_string(),
        format!("JSON byte {}: trailing JSON input", "null ".len())
    );
    assert_eq!(JsonValue::Integer(i64::MIN).as_i64(), Some(i64::MIN));
    assert_eq!(JsonValue::Null.as_i64(), None);
    assert!(JsonValue::parse(source).is_err());
}

#[test]
fn byte_depth_and_value_limits_accept_the_boundary_only() {
    const ROOT_DEPTH: u32 = 0;
    const NO_VALUES: usize = 0;
    const ONE_ROOT_VALUE: usize = NO_VALUES + 1;

    let scalar = "null";
    assert_eq!(
        JsonValue::parse_with_limits(scalar, limits_for(scalar)),
        Ok(JsonValue::Null)
    );
    let below_input_size = scalar
        .len()
        .checked_sub(1)
        .expect("the scalar fixture is nonempty");
    assert!(
        JsonValue::parse_with_limits(
            scalar,
            JsonLimits {
                max_bytes: below_input_size,
                ..JsonLimits::default()
            }
        )
        .is_err()
    );

    assert_eq!(
        JsonValue::parse_with_limits(
            scalar,
            JsonLimits {
                max_bytes: scalar.len(),
                max_depth: ROOT_DEPTH,
                max_values: ONE_ROOT_VALUE,
            }
        ),
        Ok(JsonValue::Null)
    );
    assert!(
        JsonValue::parse_with_limits(
            scalar,
            JsonLimits {
                max_bytes: scalar.len(),
                max_depth: ROOT_DEPTH,
                max_values: NO_VALUES,
            }
        )
        .is_err()
    );

    for nested in ["[null]", "{\"value\":null}"] {
        assert!(
            JsonValue::parse_with_limits(
                nested,
                JsonLimits {
                    max_bytes: nested.len(),
                    max_depth: ROOT_DEPTH,
                    max_values: JsonLimits::default().max_values,
                }
            )
            .is_err(),
            "accepted a nested value at root-only depth: {nested}"
        );
    }
}

#[test]
fn every_json_string_escape_decodes_and_controls_remain_escaped() {
    let escaped = r#""\\\/\b\f\r\t""#;
    assert_eq!(
        JsonValue::parse(escaped),
        Ok(JsonValue::String("\\/\u{8}\u{c}\r\t".to_owned()))
    );

    let unit_separator = '\u{1f}';
    assert_eq!(
        JsonValue::String(unit_separator.to_string()).canonical(),
        "\"\\u001f\""
    );
    assert!(
        JsonValue::parse(&format!("\"{unit_separator}\"")).is_err(),
        "accepted an unescaped JSON control character"
    );
}

#[test]
fn uppercase_unicode_escape_and_negative_integer_vectors_are_exact() {
    assert_eq!(
        JsonValue::parse(r#""\uABCD""#),
        Ok(JsonValue::String("\u{abcd}".to_owned()))
    );
    assert_eq!(JsonValue::parse("-1"), Ok(JsonValue::Integer(-1)));
}
