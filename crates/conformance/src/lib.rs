#![forbid(unsafe_code)]

//! Cross-implementation semantic report comparison.

use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, valid_content_digest};

const V2_FIELDS: [&str; 15] = [
    "completeness",
    "configuration",
    "diagnostics",
    "digest",
    "gate",
    "graphs",
    "inputs",
    "lock",
    "persona",
    "properties",
    "provider_profiles",
    "schema",
    "snapshot",
    "summary",
    "tool",
];

const V3_FIELDS: [&str; 16] = [
    "completeness",
    "configuration",
    "diagnostics",
    "digest",
    "gate",
    "graphs",
    "inputs",
    "lock",
    "persona",
    "properties",
    "provider_profiles",
    "schema",
    "semantic_digest",
    "snapshot",
    "summary",
    "tool",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportComparison {
    left_schema: String,
    right_schema: String,
    left_semantic_digest: String,
    right_semantic_digest: String,
    differences: Vec<String>,
}

impl ReportComparison {
    #[must_use]
    pub fn equivalent(&self) -> bool {
        self.differences.is_empty()
    }

    #[must_use]
    pub fn differences(&self) -> &[String] {
        &self.differences
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
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
                "left".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "schema".to_owned(),
                        JsonValue::String(self.left_schema.clone()),
                    ),
                    (
                        "semantic_digest".to_owned(),
                        JsonValue::String(self.left_semantic_digest.clone()),
                    ),
                ])),
            ),
            (
                "right".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "schema".to_owned(),
                        JsonValue::String(self.right_schema.clone()),
                    ),
                    (
                        "semantic_digest".to_owned(),
                        JsonValue::String(self.right_semantic_digest.clone()),
                    ),
                ])),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("report-conformance-v1".to_owned()),
            ),
        ]))
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }
}

struct AuthenticatedReport {
    schema: String,
    semantic: JsonValue,
}

/// Authenticate report-v2/report-v3 inputs and compare their language-neutral
/// semantic projections.
///
/// Build provenance, the report generation digest, and the schema generation
/// number are the only ignored fields. Every other value is compared exactly.
///
/// # Errors
/// Rejects malformed, non-canonical, structurally extended, or self-digest-
/// inconsistent reports before comparing them.
pub fn compare_reports(left: &str, right: &str) -> Result<ReportComparison, String> {
    let left = authenticate_report(left, "left report")?;
    let right = authenticate_report(right, "right report")?;
    let left_semantic_digest = left.semantic.canonical_digest();
    let right_semantic_digest = right.semantic.canonical_digest();
    let mut differences = Vec::new();
    collect_differences("", &left.semantic, &right.semantic, &mut differences);
    Ok(ReportComparison {
        left_schema: left.schema,
        right_schema: right.schema,
        left_semantic_digest,
        right_semantic_digest,
        differences,
    })
}

fn authenticate_report(source: &str, context: &str) -> Result<AuthenticatedReport, String> {
    let value = JsonValue::parse(source).map_err(|error| format!("{context}: {error}"))?;
    if value.canonical_line() != source {
        return Err(format!(
            "{context} is not canonical JSON with one trailing newline"
        ));
    }
    let schema = value
        .member("schema")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("{context} needs string field schema"))?;
    match schema {
        "report-v2" => authenticate_v2(&value, context),
        "report-v3" => authenticate_v3(&value, context),
        other => Err(format!("{context} has unsupported schema {other}")),
    }
}

fn authenticate_v2(value: &JsonValue, context: &str) -> Result<AuthenticatedReport, String> {
    let fields = exact_required_object(value, context, &V2_FIELDS)?;
    validate_v2_tool(required(fields, "tool", context)?, context)?;
    let digest = digest_field(fields, "digest", context)?;
    let mut unsigned = fields.clone();
    unsigned.insert("digest".to_owned(), JsonValue::Null);
    if digest != JsonValue::Object(unsigned).canonical_digest() {
        return Err(format!("{context} report-v2 digest mismatch"));
    }
    Ok(AuthenticatedReport {
        schema: "report-v2".to_owned(),
        semantic: normalize_semantics(fields.clone(), "report-v2")?,
    })
}

fn authenticate_v3(value: &JsonValue, context: &str) -> Result<AuthenticatedReport, String> {
    let fields = exact_required_object(value, context, &V3_FIELDS)?;
    validate_v3_tool(required(fields, "tool", context)?, context)?;
    let digest = digest_field(fields, "digest", context)?;
    let semantic_digest = digest_field(fields, "semantic_digest", context)?;

    let mut semantic = fields.clone();
    semantic.remove("digest");
    semantic.remove("semantic_digest");
    remove_v3_build(&mut semantic)?;
    if semantic_digest != JsonValue::Object(semantic).canonical_digest() {
        return Err(format!("{context} report-v3 semantic digest mismatch"));
    }

    let mut full = fields.clone();
    full.remove("digest");
    if digest != JsonValue::Object(full).canonical_digest() {
        return Err(format!("{context} report-v3 digest mismatch"));
    }
    Ok(AuthenticatedReport {
        schema: "report-v3".to_owned(),
        semantic: normalize_semantics(fields.clone(), "report-v3")?,
    })
}

fn exact_required_object<'a>(
    value: &'a JsonValue,
    context: &str,
    names: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, String> {
    let fields = value.exact_object(context, names)?;
    if let Some(name) = names.iter().find(|name| !fields.contains_key(**name)) {
        return Err(format!("{context} needs field {name}"));
    }
    Ok(fields)
}

fn required<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
    context: &str,
) -> Result<&'a JsonValue, String> {
    fields
        .get(name)
        .ok_or_else(|| format!("{context} needs field {name}"))
}

fn digest_field(
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
    context: &str,
) -> Result<String, String> {
    let digest = required(fields, name, context)?
        .as_str()
        .ok_or_else(|| format!("{context}.{name} must be a string"))?;
    if !valid_content_digest(digest) {
        return Err(format!(
            "{context}.{name} must be a canonical SHA-256 digest"
        ));
    }
    Ok(digest.to_owned())
}

fn validate_v2_tool(value: &JsonValue, context: &str) -> Result<(), String> {
    let tool = exact_required_object(
        value,
        &format!("{context}.tool"),
        &["binary_digest", "build", "name", "version"],
    )?;
    let _ = digest_field(tool, "binary_digest", &format!("{context}.tool"))?;
    validate_tool_identity(tool, context)?;
    let build = exact_required_object(
        required(tool, "build", context)?,
        &format!("{context}.tool.build"),
        &["dune", "ocaml", "source_commit"],
    )?;
    string_field(build, "dune", context)?;
    string_field(build, "ocaml", context)?;
    nullable_string(build, "source_commit", context)
}

fn validate_v3_tool(value: &JsonValue, context: &str) -> Result<(), String> {
    let tool = exact_required_object(
        value,
        &format!("{context}.tool"),
        &["build", "name", "version"],
    )?;
    validate_tool_identity(tool, context)?;
    let build = exact_required_object(
        required(tool, "build", context)?,
        &format!("{context}.tool.build"),
        &[
            "binary_digest",
            "compiler",
            "implementation",
            "source_commit",
            "target",
        ],
    )?;
    let _ = digest_field(build, "binary_digest", &format!("{context}.tool.build"))?;
    string_field(build, "compiler", context)?;
    string_field(build, "implementation", context)?;
    string_field(build, "target", context)?;
    nullable_string(build, "source_commit", context)
}

fn validate_tool_identity(
    fields: &BTreeMap<String, JsonValue>,
    context: &str,
) -> Result<(), String> {
    if string_field(fields, "name", context)? != "workflow-verifier" {
        return Err(format!("{context}.tool.name is not workflow-verifier"));
    }
    if string_field(fields, "version", context)?.is_empty() {
        return Err(format!("{context}.tool.version must not be empty"));
    }
    Ok(())
}

fn string_field<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
    context: &str,
) -> Result<&'a str, String> {
    required(fields, name, context)?
        .as_str()
        .ok_or_else(|| format!("{context}.{name} must be a string"))
}

fn nullable_string(
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
    context: &str,
) -> Result<(), String> {
    match required(fields, name, context)? {
        JsonValue::Null | JsonValue::String(_) => Ok(()),
        _ => Err(format!("{context}.{name} must be a string or null")),
    }
}

fn remove_v3_build(fields: &mut BTreeMap<String, JsonValue>) -> Result<(), String> {
    let Some(JsonValue::Object(tool)) = fields.get_mut("tool") else {
        return Err("report-v3 tool must be an object".to_owned());
    };
    tool.remove("build");
    Ok(())
}

fn normalize_semantics(
    mut fields: BTreeMap<String, JsonValue>,
    schema: &str,
) -> Result<JsonValue, String> {
    fields.remove("digest");
    fields.remove("semantic_digest");
    fields.insert(
        "schema".to_owned(),
        JsonValue::String("report-semantic-v1".to_owned()),
    );
    let Some(JsonValue::Object(tool)) = fields.get_mut("tool") else {
        return Err(format!("{schema} tool must be an object"));
    };
    match schema {
        "report-v2" => {
            tool.remove("binary_digest");
            tool.remove("build");
        }
        "report-v3" => {
            tool.remove("build");
        }
        _ => return Err(format!("unsupported report schema {schema}")),
    }
    Ok(JsonValue::Object(fields))
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
