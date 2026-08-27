use crate::{EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_SANDBOX_INFRASTRUCTURE, Report, TOOL_NAME};
use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, Span, normalize_slashes};
use workflow_verifier_verifier::{Diagnostic, Fix, Severity, TraceHop};

#[must_use]
pub fn report_to_sarif(report: &Report) -> String {
    let diagnostics = report.diagnostics();
    let mut seen = BTreeSet::new();
    let rules = diagnostics
        .iter()
        .filter(|diagnostic| seen.insert(diagnostic.rule_id.clone()))
        .map(rule_descriptor)
        .collect();
    let run = JsonValue::Object(BTreeMap::from([
        (
            "automationDetails".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "id".to_owned(),
                JsonValue::String(report.digest.clone()),
            )])),
        ),
        (
            "invocations".to_owned(),
            JsonValue::Array(vec![invocation(report)]),
        ),
        (
            "results".to_owned(),
            JsonValue::Array(diagnostics.iter().map(result).collect()),
        ),
        ("tool".to_owned(), tool(report, rules)),
    ]));
    JsonValue::Object(BTreeMap::from([
        (
            "$schema".to_owned(),
            JsonValue::String(
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
                    .to_owned(),
            ),
        ),
        ("runs".to_owned(), JsonValue::Array(vec![run])),
        ("version".to_owned(), JsonValue::String("2.1.0".to_owned())),
    ]))
    .canonical_line()
}

fn invocation(report: &Report) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "executionSuccessful".to_owned(),
            JsonValue::Boolean(!matches!(
                report.provenance.exit_code,
                EXIT_CODE_INTERNAL_FAILURE | EXIT_CODE_SANDBOX_INFRASTRUCTURE
            )),
        ),
        (
            "exitCode".to_owned(),
            JsonValue::Integer(report.provenance.exit_code),
        ),
        (
            "exitCodeDescription".to_owned(),
            JsonValue::String(report.provenance.gate_result.name().to_owned()),
        ),
        (
            "properties".to_owned(),
            JsonValue::Object(BTreeMap::from([
                (
                    "reportDigest".to_owned(),
                    JsonValue::String(report.digest.clone()),
                ),
                (
                    "semanticDigest".to_owned(),
                    JsonValue::String(report.semantic_digest.clone()),
                ),
                (
                    "sourceManifestDigest".to_owned(),
                    JsonValue::String(report.provenance.source_manifest_digest.clone()),
                ),
            ])),
        ),
    ]))
}

fn tool(report: &Report, rules: Vec<JsonValue>) -> JsonValue {
    JsonValue::Object(BTreeMap::from([(
        "driver".to_owned(),
        JsonValue::Object(BTreeMap::from([
            (
                "informationUri".to_owned(),
                JsonValue::String("https://github.com/P4suta/workflow-verifier".to_owned()),
            ),
            ("name".to_owned(), JsonValue::String(TOOL_NAME.to_owned())),
            ("rules".to_owned(), JsonValue::Array(rules)),
            (
                "version".to_owned(),
                JsonValue::String(report.tool_version.clone()),
            ),
        ])),
    )]))
}

fn rule_descriptor(diagnostic: &Diagnostic) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "helpUri".to_owned(),
            JsonValue::String(format!(
                "https://workflow-verifier.dev/rules/{}",
                diagnostic.rule_id.to_ascii_lowercase()
            )),
        ),
        (
            "id".to_owned(),
            JsonValue::String(diagnostic.rule_id.clone()),
        ),
        (
            "name".to_owned(),
            JsonValue::String(diagnostic.rule_id.clone()),
        ),
        (
            "shortDescription".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "text".to_owned(),
                JsonValue::String(diagnostic.message.clone()),
            )])),
        ),
    ]))
}

fn result(diagnostic: &Diagnostic) -> JsonValue {
    let mut fields = BTreeMap::from([
        (
            "codeFlows".to_owned(),
            JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([(
                "threadFlows".to_owned(),
                JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([(
                    "locations".to_owned(),
                    JsonValue::Array(
                        diagnostic
                            .trace
                            .iter()
                            .enumerate()
                            .map(|(index, hop)| trace_location(index, hop))
                            .collect(),
                    ),
                )]))]),
            )]))]),
        ),
        (
            "level".to_owned(),
            JsonValue::String(level(diagnostic.severity).to_owned()),
        ),
        (
            "locations".to_owned(),
            JsonValue::Array(vec![location(&diagnostic.span)]),
        ),
        (
            "message".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "text".to_owned(),
                JsonValue::String(diagnostic.message.clone()),
            )])),
        ),
        (
            "partialFingerprints".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "workflowVerifier/v1".to_owned(),
                JsonValue::String(diagnostic.id.clone()),
            )])),
        ),
        ("properties".to_owned(), result_properties(diagnostic)),
        (
            "ruleId".to_owned(),
            JsonValue::String(diagnostic.rule_id.clone()),
        ),
    ]);
    if let Some(fix) = &diagnostic.fix {
        fields.insert("fixes".to_owned(), JsonValue::Array(vec![fix_json(fix)]));
    }
    JsonValue::Object(fields)
}

fn result_properties(diagnostic: &Diagnostic) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "capabilities".to_owned(),
            JsonValue::Array(
                diagnostic
                    .capabilities
                    .iter()
                    .map(|value| JsonValue::String(value.name().to_owned()))
                    .collect(),
            ),
        ),
        (
            "confidence".to_owned(),
            JsonValue::String(diagnostic.confidence.name().to_owned()),
        ),
        (
            "diagnosticId".to_owned(),
            JsonValue::String(diagnostic.id.clone()),
        ),
        (
            "evidence".to_owned(),
            JsonValue::Array(
                diagnostic
                    .evidence
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
    ]))
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => "note",
    }
}

fn region(span: &Span) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "endColumn".to_owned(),
            JsonValue::Integer(i64::from(span.stop.column)),
        ),
        (
            "endLine".to_owned(),
            JsonValue::Integer(i64::from(span.stop.line)),
        ),
        (
            "startColumn".to_owned(),
            JsonValue::Integer(i64::from(span.start.column)),
        ),
        (
            "startLine".to_owned(),
            JsonValue::Integer(i64::from(span.start.line)),
        ),
    ]))
}

fn physical_location(span: &Span) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "artifactLocation".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "uri".to_owned(),
                JsonValue::String(normalize_slashes(&span.file)),
            )])),
        ),
        ("region".to_owned(), region(span)),
    ]))
}

fn location(span: &Span) -> JsonValue {
    JsonValue::Object(BTreeMap::from([(
        "physicalLocation".to_owned(),
        physical_location(span),
    )]))
}

fn trace_location(index: usize, hop: &TraceHop) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "location".to_owned(),
            JsonValue::Object(BTreeMap::from([
                (
                    "message".to_owned(),
                    JsonValue::Object(BTreeMap::from([(
                        "text".to_owned(),
                        JsonValue::String(hop.label.clone()),
                    )])),
                ),
                ("physicalLocation".to_owned(), physical_location(&hop.span)),
            ])),
        ),
        (
            "nestingLevel".to_owned(),
            JsonValue::Integer(i64::try_from(index).unwrap_or(i64::MAX)),
        ),
    ]))
}

fn fix_json(fix: &Fix) -> JsonValue {
    let changes = match (&fix.replacement, &fix.span) {
        (Some(replacement), Some(span)) => vec![JsonValue::Object(BTreeMap::from([
            (
                "artifactLocation".to_owned(),
                JsonValue::Object(BTreeMap::from([(
                    "uri".to_owned(),
                    JsonValue::String(normalize_slashes(&span.file)),
                )])),
            ),
            (
                "replacements".to_owned(),
                JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([
                    ("deletedRegion".to_owned(), region(span)),
                    (
                        "insertedContent".to_owned(),
                        JsonValue::Object(BTreeMap::from([(
                            "text".to_owned(),
                            JsonValue::String(replacement.clone()),
                        )])),
                    ),
                ]))]),
            ),
        ]))],
        _ => Vec::new(),
    };
    JsonValue::Object(BTreeMap::from([
        ("artifactChanges".to_owned(), JsonValue::Array(changes)),
        (
            "description".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "text".to_owned(),
                JsonValue::String(fix.description.clone()),
            )])),
        ),
        (
            "properties".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                "kind".to_owned(),
                JsonValue::String(fix.kind.clone()),
            )])),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BuildInfo, EXIT_CODE_FINDING, EXIT_CODE_INCOMPLETE, EXIT_CODE_INVALID_INPUT,
        EXIT_CODE_PASS, GateResult, ReportProvenance,
    };
    use workflow_verifier_foundation::{Position, content_digest};
    use workflow_verifier_verifier::Persona;

    fn report(exit_code: i64) -> Report {
        Report::new(
            Persona::Gate,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            BuildInfo {
                implementation: "rust".to_owned(),
                compiler: "rustc".to_owned(),
                target: "test-target".to_owned(),
                source_commit: None,
                binary_digest: content_digest("binary"),
            },
            ReportProvenance {
                config_origin: "policy.toml".to_owned(),
                config_trust: "trusted-policy".to_owned(),
                config_digest: content_digest("config"),
                lock_digest: content_digest("lock"),
                source_manifest_digest: content_digest("manifest"),
                provider_profiles: Vec::new(),
                completeness_reasons: Vec::new(),
                gate_result: GateResult::Pass,
                exit_code,
            },
        )
    }

    #[test]
    fn sarif_invocation_success_and_levels_follow_public_protocol() {
        for exit_code in [
            EXIT_CODE_PASS,
            EXIT_CODE_FINDING,
            EXIT_CODE_INVALID_INPUT,
            EXIT_CODE_INCOMPLETE,
        ] {
            assert_eq!(
                invocation(&report(exit_code))
                    .member("executionSuccessful")
                    .and_then(JsonValue::as_bool),
                Some(true)
            );
        }
        for exit_code in [EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_SANDBOX_INFRASTRUCTURE] {
            assert_eq!(
                invocation(&report(exit_code))
                    .member("executionSuccessful")
                    .and_then(JsonValue::as_bool),
                Some(false)
            );
        }
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Error), "error");
        assert_eq!(level(Severity::Warning), "warning");
        assert_eq!(level(Severity::Note), "note");
    }

    #[test]
    fn sarif_fix_requires_both_span_and_replacement() {
        let span = Span::new(
            "workflow.yml",
            Position {
                byte: 0,
                line: 1,
                column: 1,
            },
            Position {
                byte: "old".len(),
                line: 1,
                column: u32::try_from("old".chars().count().saturating_add(1))
                    .expect("fixture column fits u32"),
            },
        );
        let fix = |replacement, span| Fix {
            kind: "replace".to_owned(),
            description: "replace old value".to_owned(),
            replacement,
            span,
        };
        let changes = |fix: &Fix| {
            fix_json(fix)
                .member("artifactChanges")
                .and_then(JsonValue::as_array)
                .map(<[_]>::len)
        };
        assert_eq!(
            changes(&fix(Some("new".to_owned()), Some(span.clone()))),
            Some(1)
        );
        assert_eq!(changes(&fix(None, Some(span))), Some(0));
        assert_eq!(changes(&fix(Some("new".to_owned()), None)), Some(0));
        assert_eq!(changes(&fix(None, None)), Some(0));
    }
}
