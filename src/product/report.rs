use crate::domain::{Program, SourceId};
use crate::foundation::{Digest, JsonValue, normalize_slashes};
use crate::product::serde_views::{DiagnosticView, PropertyView};
use crate::verifier::{Diagnostic, Persona, Property, PropertyState};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::collections::BTreeSet;

pub const TOOL_NAME: &str = "workflow-verifier";
pub const TOOL_VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportInput {
    pub source: SourceId,
    pub path: String,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateResult {
    Pass,
    Finding,
    Incomplete,
}

impl GateResult {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Finding => "finding",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gate {
    pub result: GateResult,
    pub exit_code: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    pub compiler: String,
    pub target: String,
    pub source_commit: Option<String>,
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self {
            compiler: format!(
                "rustc {}",
                option_env!("RUSTC_VERSION").unwrap_or(env!("CARGO_PKG_RUST_VERSION"))
            ),
            target: option_env!("TARGET").unwrap_or("unknown-target").to_owned(),
            source_commit: option_env!("WORKFLOW_VERIFIER_SOURCE_COMMIT").map(str::to_owned),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisProvenance {
    pub config_origin: String,
    pub config_trust: String,
    pub config_digest: Digest,
    pub lock_digest: Digest,
    pub analysis_manifest_digest: Digest,
    pub provider_profiles: Vec<String>,
}

fn public_origin(origin: &str) -> String {
    let normalized = normalize_slashes(origin);
    let drive = normalized.as_bytes().get(1) == Some(&b':');
    let safe = !normalized.starts_with('/')
        && !drive
        && normalized.split('/').all(|segment| segment != "..");
    if safe {
        normalized
    } else {
        let basename = normalized.rsplit('/').next().unwrap_or("external");
        format!("external:{basename}")
    }
}

/// Direct, borrowed serialization view for `workflow-verifier-report/1`.
///
/// The linked program is borrowed only for counts and source identity. Its
/// graph body is never materialized by the check-report path.
#[derive(Clone, Copy)]
pub struct CheckReportView<'a> {
    build: &'a BuildInfo,
    persona: Persona,
    program: &'a Program,
    inputs: &'a [ReportInput],
    diagnostics: &'a [Diagnostic],
    properties: &'a [Property],
    gate: Gate,
    completeness_reasons: &'a [String],
    provenance: &'a AnalysisProvenance,
}

#[derive(Clone, Copy)]
pub struct CheckReportResults<'a> {
    inputs: &'a [ReportInput],
    diagnostics: &'a [Diagnostic],
    properties: &'a [Property],
    gate: Gate,
    completeness_reasons: &'a [String],
    provenance: &'a AnalysisProvenance,
}

impl<'a> CheckReportView<'a> {
    #[must_use]
    pub const fn results(
        inputs: &'a [ReportInput],
        diagnostics: &'a [Diagnostic],
        properties: &'a [Property],
        gate: Gate,
        completeness_reasons: &'a [String],
        provenance: &'a AnalysisProvenance,
    ) -> CheckReportResults<'a> {
        CheckReportResults {
            inputs,
            diagnostics,
            properties,
            gate,
            completeness_reasons,
            provenance,
        }
    }

    #[must_use]
    pub const fn new(
        build: &'a BuildInfo,
        persona: Persona,
        program: &'a Program,
        results: CheckReportResults<'a>,
    ) -> Self {
        let CheckReportResults {
            inputs,
            diagnostics,
            properties,
            gate,
            completeness_reasons,
            provenance,
        } = results;
        Self {
            build,
            persona,
            program,
            inputs,
            diagnostics,
            properties,
            gate,
            completeness_reasons,
            provenance,
        }
    }

    #[must_use]
    /// Computes the tool-independent semantic digest.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in report view violates an
    /// internal invariant.
    pub fn analysis_digest(self) -> Digest {
        let bytes = serde_json::to_vec(&AnalysisProjection(self))
            .expect("serializing an in-memory analysis cannot fail");
        let mut digest = Digest::builder(b"workflow-verifier-report/1/analysis");
        digest.add(bytes);
        digest.finish()
    }

    #[must_use]
    /// Computes the digest of the complete report document.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in report view violates an
    /// internal invariant.
    pub fn digest(self) -> Digest {
        let analysis_digest = self.analysis_digest();
        let bytes = serde_json::to_vec(&ReportProjection {
            view: self,
            analysis_digest,
        })
        .expect("serializing an in-memory report cannot fail");
        let mut digest = Digest::builder(b"workflow-verifier-report/1/document");
        digest.add(bytes);
        digest.finish()
    }

    #[must_use]
    /// Serializes the report using its canonical compact representation.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in report view violates an
    /// internal invariant.
    pub fn to_canonical_json(self) -> String {
        let mut output =
            serde_json::to_string(&self).expect("serializing an in-memory report cannot fail");
        output.push('\n');
        output
    }
}

struct AnalysisProjection<'a>(CheckReportView<'a>);

struct ReportProjection<'a> {
    view: CheckReportView<'a>,
    analysis_digest: Digest,
}

fn serialize_report<S: Serializer>(
    view: CheckReportView<'_>,
    analysis_digest: Option<Digest>,
    digest: Option<Digest>,
    include_tool: bool,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(None)?;
    if let Some(analysis_digest) = analysis_digest {
        map.serialize_entry("analysis_digest", &analysis_digest.to_string())?;
    }
    map.serialize_entry("completeness", &CompletenessView(view.completeness_reasons))?;
    map.serialize_entry("diagnostics", &DiagnosticsView(view.diagnostics))?;
    if let Some(digest) = digest {
        map.serialize_entry("digest", &digest.to_string())?;
    }
    map.serialize_entry("gate", &GateView(view.gate))?;
    map.serialize_entry("inputs", &InputsView(view))?;
    map.serialize_entry("persona", view.persona.name())?;
    map.serialize_entry("properties", &PropertiesView(view.properties))?;
    map.serialize_entry("providers", &view.provenance.provider_profiles)?;
    map.serialize_entry("schema", "workflow-verifier-report/1")?;
    map.serialize_entry("summary", &SummaryView(view))?;
    if include_tool {
        map.serialize_entry("tool", &ToolView(view.build))?;
    }
    map.end()
}

impl Serialize for AnalysisProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_report(self.0, None, None, false, serializer)
    }
}

impl Serialize for ReportProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_report(
            self.view,
            Some(self.analysis_digest),
            None,
            true,
            serializer,
        )
    }
}

impl Serialize for CheckReportView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let analysis_digest = self.analysis_digest();
        serialize_report(
            *self,
            Some(analysis_digest),
            Some(self.digest()),
            true,
            serializer,
        )
    }
}

/// Authenticate a `workflow-verifier-report/1` document.
///
/// # Errors
/// Rejects malformed JSON, another schema, an incomplete/extended top-level
/// object, or a mismatched analysis/document digest.
pub fn authenticate_check_report(source: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "analysis_digest",
        "completeness",
        "diagnostics",
        "digest",
        "gate",
        "inputs",
        "persona",
        "properties",
        "providers",
        "schema",
        "summary",
        "tool",
    ];
    let document = JsonValue::parse(source).map_err(|error| error.to_string())?;
    let fields = document.exact_object("check report", FIELDS)?;
    if fields.len() != FIELDS.len() || FIELDS.iter().any(|name| !fields.contains_key(*name)) {
        return Err("check report has missing fields".to_owned());
    }
    if fields.get("schema").and_then(JsonValue::as_str) != Some("workflow-verifier-report/1") {
        return Err("unsupported check report schema".to_owned());
    }
    let claimed_document = parse_digest_field(fields, "digest")?;
    let claimed_analysis = parse_digest_field(fields, "analysis_digest")?;

    let mut report_projection = fields.clone();
    report_projection.remove("digest");
    let mut document_digest = Digest::builder(b"workflow-verifier-report/1/document");
    document_digest.add(JsonValue::Object(report_projection.clone()).canonical());
    if document_digest.finish() != claimed_document {
        return Err("check report digest mismatch".to_owned());
    }

    report_projection.remove("analysis_digest");
    report_projection.remove("tool");
    let mut analysis_digest = Digest::builder(b"workflow-verifier-report/1/analysis");
    analysis_digest.add(JsonValue::Object(report_projection).canonical());
    if analysis_digest.finish() != claimed_analysis {
        return Err("check report analysis digest mismatch".to_owned());
    }
    Ok(())
}

fn parse_digest_field(
    fields: &std::collections::BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<Digest, String> {
    let value = fields
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("check report needs string field {name}"))?;
    Digest::parse(value).map_err(str::to_owned)
}

struct ToolView<'a>(&'a BuildInfo);

impl Serialize for ToolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("commit", &self.0.source_commit)?;
        map.serialize_entry("compiler", &self.0.compiler)?;
        map.serialize_entry("name", TOOL_NAME)?;
        map.serialize_entry("target", &self.0.target)?;
        map.serialize_entry("version", TOOL_VERSION)?;
        map.end()
    }
}

pub(crate) struct CompletenessView<'a>(pub(crate) &'a [String]);

impl Serialize for CompletenessView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("reasons", self.0)?;
        map.serialize_entry(
            "state",
            if self.0.is_empty() {
                "complete"
            } else {
                "incomplete"
            },
        )?;
        map.end()
    }
}

pub(crate) struct GateView(pub(crate) Gate);

impl Serialize for GateView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("exit_code", &self.0.exit_code)?;
        map.serialize_entry("result", self.0.result.name())?;
        map.end()
    }
}

struct InputsView<'a>(CheckReportView<'a>);

impl Serialize for InputsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let view = self.0;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("config", &ConfigView(view.provenance))?;
        map.serialize_entry("lock", &LockView(view.provenance.lock_digest))?;
        map.serialize_entry(
            "manifest_digest",
            &view.provenance.analysis_manifest_digest.to_string(),
        )?;
        map.serialize_entry("sources", &SourceInputsView(view.inputs))?;
        map.end()
    }
}

struct ConfigView<'a>(&'a AnalysisProvenance);

impl Serialize for ConfigView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("digest", &self.0.config_digest.to_string())?;
        map.serialize_entry("origin", &public_origin(&self.0.config_origin))?;
        map.serialize_entry("trust", &self.0.config_trust)?;
        map.end()
    }
}

struct LockView(Digest);

impl Serialize for LockView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("digest", &self.0.to_string())?;
        map.end()
    }
}

struct SourceInputsView<'a>(&'a [ReportInput]);

impl Serialize for SourceInputsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for input in self.0 {
            sequence.serialize_element(&SourceInputView(input))?;
        }
        sequence.end()
    }
}

struct SourceInputView<'a>(&'a ReportInput);

impl Serialize for SourceInputView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("digest", &self.0.digest.to_string())?;
        map.serialize_entry("id", &self.0.source.0)?;
        map.serialize_entry("path", &normalize_slashes(&self.0.path))?;
        map.end()
    }
}

pub(crate) struct DiagnosticsView<'a>(pub(crate) &'a [Diagnostic]);

impl Serialize for DiagnosticsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for diagnostic in self.0 {
            sequence.serialize_element(&DiagnosticView(diagnostic))?;
        }
        sequence.end()
    }
}

pub(crate) struct PropertiesView<'a>(pub(crate) &'a [Property]);

impl Serialize for PropertiesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for property in self.0 {
            sequence.serialize_element(&PropertyView(property))?;
        }
        sequence.end()
    }
}

struct SummaryView<'a>(CheckReportView<'a>);

impl Serialize for SummaryView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let view = self.0;
        let unknown = view
            .properties
            .iter()
            .filter(|property| matches!(property.state, PropertyState::Unknown(_)))
            .count();
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("diagnostics", &view.diagnostics.len())?;
        map.serialize_entry("edges", &view.program.edges.len())?;
        map.serialize_entry("nodes", &view.program.nodes.len())?;
        map.serialize_entry("properties", &view.properties.len())?;
        map.serialize_entry("sources", &view.inputs.len())?;
        map.serialize_entry("unknown_properties", &unknown)?;
        let violated = view
            .properties
            .iter()
            .filter(|property| property.state == PropertyState::Violated)
            .count();
        map.serialize_entry("violated_properties", &violated)?;
        map.end()
    }
}

#[must_use]
pub fn canonical_provider_profiles(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_names_and_public_origins_are_exact() {
        assert_eq!(
            [
                GateResult::Pass,
                GateResult::Finding,
                GateResult::Incomplete
            ]
            .map(GateResult::name),
            ["pass", "finding", "incomplete"]
        );
        assert_eq!(public_origin("config/policy.toml"), "config/policy.toml");
        assert_eq!(
            public_origin("/private/policy.toml"),
            "external:policy.toml"
        );
    }
}
