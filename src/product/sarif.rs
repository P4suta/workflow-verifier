use crate::domain::Program;
use crate::foundation::{Digest, Span, normalize_slashes};
use crate::product::{
    EXIT_CODE_INTERNAL_FAILURE, EXIT_CODE_SANDBOX_INFRASTRUCTURE, Gate, TOOL_NAME, TOOL_VERSION,
};
use crate::verifier::{Diagnostic, Fix, Severity, TraceHop};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::collections::BTreeSet;

/// Borrowed SARIF 2.1.0 projection over one analysis outcome.
#[derive(Clone, Copy)]
pub struct SarifView<'a> {
    program: &'a Program,
    diagnostics: &'a [Diagnostic],
    gate: Gate,
    report_digest: Digest,
    analysis_digest: Digest,
    manifest_digest: Digest,
}

impl<'a> SarifView<'a> {
    #[must_use]
    pub const fn new(
        program: &'a Program,
        diagnostics: &'a [Diagnostic],
        gate: Gate,
        report_digest: Digest,
        analysis_digest: Digest,
        manifest_digest: Digest,
    ) -> Self {
        Self {
            program,
            diagnostics,
            gate,
            report_digest,
            analysis_digest,
            manifest_digest,
        }
    }

    #[must_use]
    /// Serializes the SARIF projection in canonical compact form.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in SARIF view violates an
    /// internal invariant.
    pub fn to_canonical_json(self) -> String {
        let mut output =
            serde_json::to_string(&self).expect("serializing an in-memory SARIF view cannot fail");
        output.push('\n');
        output
    }
}

impl Serialize for SarifView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(
            "$schema",
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        )?;
        map.serialize_entry("runs", &RunsView(*self))?;
        map.serialize_entry("version", "2.1.0")?;
        map.end()
    }
}

struct RunsView<'a>(SarifView<'a>);

impl Serialize for RunsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&RunView(self.0))?;
        sequence.end()
    }
}

struct RunView<'a>(SarifView<'a>);

impl Serialize for RunView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let view = self.0;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("automationDetails", &AutomationView(view.report_digest))?;
        map.serialize_entry("invocations", &InvocationsView(view))?;
        map.serialize_entry("results", &ResultsView(view))?;
        map.serialize_entry("tool", &ToolView(view.diagnostics))?;
        map.end()
    }
}

struct AutomationView(Digest);

impl Serialize for AutomationView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("id", &self.0.to_string())?;
        map.end()
    }
}

struct InvocationsView<'a>(SarifView<'a>);

impl Serialize for InvocationsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&InvocationView(self.0))?;
        sequence.end()
    }
}

struct InvocationView<'a>(SarifView<'a>);

impl Serialize for InvocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let view = self.0;
        let successful = !matches!(
            view.gate.exit_code,
            EXIT_CODE_INTERNAL_FAILURE | EXIT_CODE_SANDBOX_INFRASTRUCTURE
        );
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("executionSuccessful", &successful)?;
        map.serialize_entry("exitCode", &view.gate.exit_code)?;
        map.serialize_entry("exitCodeDescription", view.gate.result.name())?;
        map.serialize_entry("properties", &InvocationProperties(view))?;
        map.end()
    }
}

struct InvocationProperties<'a>(SarifView<'a>);

impl Serialize for InvocationProperties<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("analysisDigest", &self.0.analysis_digest.to_string())?;
        map.serialize_entry("reportDigest", &self.0.report_digest.to_string())?;
        map.serialize_entry("sourceManifestDigest", &self.0.manifest_digest.to_string())?;
        map.end()
    }
}

struct ToolView<'a>(&'a [Diagnostic]);

impl Serialize for ToolView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("driver", &DriverView(self.0))?;
        map.end()
    }
}

struct DriverView<'a>(&'a [Diagnostic]);

impl Serialize for DriverView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(
            "informationUri",
            "https://github.com/P4suta/workflow-verifier",
        )?;
        map.serialize_entry("name", TOOL_NAME)?;
        map.serialize_entry("rules", &RulesView(self.0))?;
        map.serialize_entry("version", TOOL_VERSION)?;
        map.end()
    }
}

struct RulesView<'a>(&'a [Diagnostic]);

impl Serialize for RulesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let unique: BTreeSet<_> = self.0.iter().map(|value| value.rule_id.as_str()).collect();
        let mut sequence = serializer.serialize_seq(Some(unique.len()))?;
        for rule in unique {
            let diagnostic = self
                .0
                .iter()
                .find(|diagnostic| diagnostic.rule_id == rule)
                .expect("rule identity came from the same diagnostics slice");
            sequence.serialize_element(&RuleView(diagnostic))?;
        }
        sequence.end()
    }
}

struct RuleView<'a>(&'a Diagnostic);

impl Serialize for RuleView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let diagnostic = self.0;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(
            "helpUri",
            &format!(
                "https://workflow-verifier.dev/rules/{}",
                diagnostic.rule_id.to_ascii_lowercase()
            ),
        )?;
        map.serialize_entry("id", &diagnostic.rule_id)?;
        map.serialize_entry("name", &diagnostic.rule_id)?;
        map.serialize_entry("shortDescription", &TextView(&diagnostic.message))?;
        map.end()
    }
}

struct TextView<'a>(&'a str);

impl Serialize for TextView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("text", self.0)?;
        map.end()
    }
}

struct ResultsView<'a>(SarifView<'a>);

impl Serialize for ResultsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.diagnostics.len()))?;
        for diagnostic in self.0.diagnostics {
            sequence.serialize_element(&ResultView {
                program: self.0.program,
                diagnostic,
            })?;
        }
        sequence.end()
    }
}

struct ResultView<'a> {
    program: &'a Program,
    diagnostic: &'a Diagnostic,
}

impl Serialize for ResultView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let diagnostic = self.diagnostic;
        let mut map = serializer.serialize_map(None)?;
        if !diagnostic.trace.is_empty() {
            map.serialize_entry(
                "codeFlows",
                &CodeFlowsView {
                    program: self.program,
                    trace: &diagnostic.trace,
                },
            )?;
        }
        if let Some(fix) = &diagnostic.fix {
            map.serialize_entry(
                "fixes",
                &FixesView {
                    program: self.program,
                    fix,
                },
            )?;
        }
        map.serialize_entry("level", level(diagnostic.severity))?;
        map.serialize_entry(
            "locations",
            &LocationsView {
                program: self.program,
                span: diagnostic.span,
            },
        )?;
        map.serialize_entry("message", &TextView(&diagnostic.message))?;
        map.serialize_entry("partialFingerprints", &FingerprintView(&diagnostic.id))?;
        map.serialize_entry("properties", &ResultPropertiesView(diagnostic))?;
        map.serialize_entry("ruleId", &diagnostic.rule_id)?;
        map.end()
    }
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => "note",
    }
}

struct FingerprintView<'a>(&'a str);

impl Serialize for FingerprintView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("workflowVerifier/v1", self.0)?;
        map.end()
    }
}

struct ResultPropertiesView<'a>(&'a Diagnostic);

impl Serialize for ResultPropertiesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let diagnostic = self.0;
        let capabilities: Vec<_> = diagnostic
            .capabilities
            .iter()
            .map(|value| value.name())
            .collect();
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("capabilities", &capabilities)?;
        map.serialize_entry("confidence", diagnostic.confidence.name())?;
        map.serialize_entry("diagnosticId", &diagnostic.id)?;
        map.serialize_entry("evidence", &diagnostic.evidence)?;
        map.end()
    }
}

struct LocationsView<'a> {
    program: &'a Program,
    span: Span,
}

impl Serialize for LocationsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&LocationView {
            program: self.program,
            span: self.span,
        })?;
        sequence.end()
    }
}

struct LocationView<'a> {
    program: &'a Program,
    span: Span,
}

impl Serialize for LocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(
            "physicalLocation",
            &PhysicalLocationView {
                program: self.program,
                span: self.span,
            },
        )?;
        map.end()
    }
}

struct PhysicalLocationView<'a> {
    program: &'a Program,
    span: Span,
}

impl Serialize for PhysicalLocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let path = self
            .program
            .source_path_for(self.span.source)
            .map_or("<unknown>".to_owned(), normalize_slashes);
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("artifactLocation", &ArtifactLocationView(&path))?;
        map.serialize_entry("region", &RegionView(self.span))?;
        map.end()
    }
}

struct ArtifactLocationView<'a>(&'a str);

impl Serialize for ArtifactLocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("uri", self.0)?;
        map.end()
    }
}

struct RegionView(Span);

impl Serialize for RegionView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let span = self.0;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("endColumn", &span.stop.column)?;
        map.serialize_entry("endLine", &span.stop.line)?;
        map.serialize_entry("startColumn", &span.start.column)?;
        map.serialize_entry("startLine", &span.start.line)?;
        map.end()
    }
}

struct CodeFlowsView<'a> {
    program: &'a Program,
    trace: &'a [TraceHop],
}

impl Serialize for CodeFlowsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&CodeFlowView {
            program: self.program,
            trace: self.trace,
        })?;
        sequence.end()
    }
}

struct CodeFlowView<'a> {
    program: &'a Program,
    trace: &'a [TraceHop],
}

impl Serialize for CodeFlowView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(
            "threadFlows",
            &ThreadFlowsView {
                program: self.program,
                trace: self.trace,
            },
        )?;
        map.end()
    }
}

struct ThreadFlowsView<'a> {
    program: &'a Program,
    trace: &'a [TraceHop],
}

impl Serialize for ThreadFlowsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&ThreadFlowView {
            program: self.program,
            trace: self.trace,
        })?;
        sequence.end()
    }
}

struct ThreadFlowView<'a> {
    program: &'a Program,
    trace: &'a [TraceHop],
}

impl Serialize for ThreadFlowView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(
            "locations",
            &TraceLocationsView {
                program: self.program,
                trace: self.trace,
            },
        )?;
        map.end()
    }
}

struct TraceLocationsView<'a> {
    program: &'a Program,
    trace: &'a [TraceHop],
}

impl Serialize for TraceLocationsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.trace.len()))?;
        for (index, hop) in self.trace.iter().enumerate() {
            sequence.serialize_element(&TraceLocationView {
                program: self.program,
                index,
                hop,
            })?;
        }
        sequence.end()
    }
}

struct TraceLocationView<'a> {
    program: &'a Program,
    index: usize,
    hop: &'a TraceHop,
}

impl Serialize for TraceLocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(
            "location",
            &TraceInnerLocationView {
                program: self.program,
                hop: self.hop,
            },
        )?;
        map.serialize_entry("nestingLevel", &self.index)?;
        map.end()
    }
}

struct TraceInnerLocationView<'a> {
    program: &'a Program,
    hop: &'a TraceHop,
}

impl Serialize for TraceInnerLocationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("message", &TextView(&self.hop.label))?;
        map.serialize_entry(
            "physicalLocation",
            &PhysicalLocationView {
                program: self.program,
                span: self.hop.span,
            },
        )?;
        map.end()
    }
}

struct FixesView<'a> {
    program: &'a Program,
    fix: &'a Fix,
}

impl Serialize for FixesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&FixView {
            program: self.program,
            fix: self.fix,
        })?;
        sequence.end()
    }
}

struct FixView<'a> {
    program: &'a Program,
    fix: &'a Fix,
}

impl Serialize for FixView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(
            "artifactChanges",
            &ArtifactChangesView {
                program: self.program,
                fix: self.fix,
            },
        )?;
        map.serialize_entry("description", &TextView(&self.fix.description))?;
        map.serialize_entry("properties", &FixPropertiesView(&self.fix.kind))?;
        map.end()
    }
}

struct FixPropertiesView<'a>(&'a str);

impl Serialize for FixPropertiesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("kind", self.0)?;
        map.end()
    }
}

struct ArtifactChangesView<'a> {
    program: &'a Program,
    fix: &'a Fix,
}

impl Serialize for ArtifactChangesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let present = self.fix.replacement.is_some() && self.fix.span.is_some();
        let mut sequence = serializer.serialize_seq(Some(usize::from(present)))?;
        if let (Some(replacement), Some(span)) = (&self.fix.replacement, self.fix.span) {
            sequence.serialize_element(&ArtifactChangeView {
                program: self.program,
                replacement,
                span,
            })?;
        }
        sequence.end()
    }
}

struct ArtifactChangeView<'a> {
    program: &'a Program,
    replacement: &'a str,
    span: Span,
}

impl Serialize for ArtifactChangeView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let path = self
            .program
            .source_path_for(self.span.source)
            .map_or("<unknown>".to_owned(), normalize_slashes);
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("artifactLocation", &ArtifactLocationView(&path))?;
        map.serialize_entry(
            "replacements",
            &ReplacementsView {
                replacement: self.replacement,
                span: self.span,
            },
        )?;
        map.end()
    }
}

struct ReplacementsView<'a> {
    replacement: &'a str,
    span: Span,
}

impl Serialize for ReplacementsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        sequence.serialize_element(&ReplacementView {
            replacement: self.replacement,
            span: self.span,
        })?;
        sequence.end()
    }
}

struct ReplacementView<'a> {
    replacement: &'a str,
    span: Span,
}

impl Serialize for ReplacementView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("deletedRegion", &RegionView(self.span))?;
        map.serialize_entry("insertedContent", &TextView(self.replacement))?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_levels_are_stable() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Error), "error");
        assert_eq!(level(Severity::Warning), "warning");
        assert_eq!(level(Severity::Note), "note");
    }
}
