use crate::foundation::{JsonValue, content_digest, valid_content_digest};
use std::collections::{BTreeMap, BTreeSet};

const FIELDS: [&str; 10] = [
    "completeness",
    "diagnostics",
    "digest",
    "edges",
    "entrypoints",
    "gate",
    "nodes",
    "properties",
    "schema",
    "sources",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticComparison {
    left_digest: String,
    right_digest: String,
    differences: Vec<String>,
}

impl SemanticComparison {
    #[must_use]
    pub fn equivalent(&self) -> bool {
        self.differences.is_empty()
    }

    #[must_use]
    pub fn differences(&self) -> &[String] {
        &self.differences
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        JsonValue::Object(BTreeMap::from([
            (
                "differences".to_owned(),
                JsonValue::Array(
                    self.differences
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            (
                "equivalent".to_owned(),
                JsonValue::Boolean(self.equivalent()),
            ),
            (
                "left_digest".to_owned(),
                JsonValue::String(self.left_digest.clone()),
            ),
            (
                "right_digest".to_owned(),
                JsonValue::String(self.right_digest.clone()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("semantic-conformance-comparison/1".to_owned()),
            ),
        ]))
        .canonical_line()
    }
}

struct AuthenticatedDocument {
    digest: String,
    semantics: JsonValue,
}

/// Authenticate and compare two test-only `semantic-conformance/1` documents.
///
/// The comparator has no knowledge of any public report generation. Both
/// implementations must independently emit the same normalized semantic
/// document.
///
/// # Errors
/// Rejects non-canonical JSON, extensions, malformed core fields, and digest
/// mismatches before comparison.
pub fn compare_documents(left: &str, right: &str) -> Result<SemanticComparison, String> {
    let left = authenticate_document(left, "left document")?;
    let right = authenticate_document(right, "right document")?;
    let mut differences = Vec::new();
    collect_differences("", &left.semantics, &right.semantics, &mut differences);
    Ok(SemanticComparison {
        left_digest: left.digest,
        right_digest: right.digest,
        differences,
    })
}

fn authenticate_document(source: &str, context: &str) -> Result<AuthenticatedDocument, String> {
    let value = JsonValue::parse(source).map_err(|error| format!("{context}: {error}"))?;
    if value.canonical_line() != source {
        return Err(format!(
            "{context} is not canonical JSON with one trailing newline"
        ));
    }
    let fields = value.exact_object(context, &FIELDS)?;
    if let Some(name) = FIELDS.iter().find(|name| !fields.contains_key(**name)) {
        return Err(format!("{context} needs field {name}"));
    }
    if fields.get("schema").and_then(JsonValue::as_str) != Some("semantic-conformance/1") {
        return Err(format!("{context} has unsupported schema"));
    }
    for name in [
        "diagnostics",
        "edges",
        "entrypoints",
        "nodes",
        "properties",
        "sources",
    ] {
        if fields.get(name).and_then(JsonValue::as_array).is_none() {
            return Err(format!("{context}.{name} must be an array"));
        }
    }
    for name in ["completeness", "gate"] {
        if !matches!(fields.get(name), Some(JsonValue::Object(_))) {
            return Err(format!("{context}.{name} must be an object"));
        }
    }
    let digest = fields
        .get("digest")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("{context}.digest must be a string"))?;
    if !valid_content_digest(digest) {
        return Err(format!(
            "{context}.digest must be a canonical SHA-256 digest"
        ));
    }
    let mut unsigned = fields.clone();
    unsigned.insert("digest".to_owned(), JsonValue::Null);
    if digest != content_digest(JsonValue::Object(unsigned).canonical()) {
        return Err(format!("{context} semantic digest mismatch"));
    }
    let mut semantics = fields.clone();
    semantics.remove("digest");
    Ok(AuthenticatedDocument {
        digest: digest.to_owned(),
        semantics: JsonValue::Object(semantics),
    })
}

fn collect_differences(path: &str, left: &JsonValue, right: &JsonValue, output: &mut Vec<String>) {
    match (left, right) {
        (JsonValue::Object(left), JsonValue::Object(right)) => {
            let keys: BTreeSet<_> = left.keys().chain(right.keys()).collect();
            for key in keys {
                let child = format!("{path}/{}", pointer_segment(key));
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => collect_differences(&child, left, right, output),
                    _ => output.push(child),
                }
            }
        }
        (JsonValue::Array(left), JsonValue::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                let child = format!("{path}/{index}");
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) => collect_differences(&child, left, right, output),
                    _ => output.push(child),
                }
            }
        }
        _ if left != right => output.push(if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        }),
        _ => {}
    }
}

fn pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
