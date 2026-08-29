use crate::domain::Program;
use crate::foundation::content_digest;
use crate::product::graph_output::{
    EdgesView, GraphDocumentView, GraphKind, NodeIdsView, NodesView, SourcesView,
};
use crate::product::report::{CompletenessView, Gate, GateView, PropertiesView};
use crate::product::serde_views::SpanView;
use crate::verifier::{Diagnostic, Property};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

/// Test-only, implementation-neutral projection used by the OCaml oracle.
#[derive(Clone, Copy)]
pub struct SemanticConformanceView<'a> {
    program: &'a Program,
    diagnostics: &'a [Diagnostic],
    properties: &'a [Property],
    gate: Gate,
    completeness_reasons: &'a [String],
}

impl<'a> SemanticConformanceView<'a> {
    #[must_use]
    pub const fn new(
        program: &'a Program,
        diagnostics: &'a [Diagnostic],
        properties: &'a [Property],
        gate: Gate,
        completeness_reasons: &'a [String],
    ) -> Self {
        Self {
            program,
            diagnostics,
            properties,
            gate,
            completeness_reasons,
        }
    }

    #[must_use]
    /// Computes the semantic conformance document digest.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in conformance view violates
    /// an internal invariant.
    pub fn digest(self) -> String {
        let bytes = serde_json::to_vec(&Projection {
            view: self,
            digest: None,
        })
        .expect("serializing semantic conformance cannot fail");
        content_digest(bytes)
    }

    #[must_use]
    /// Serializes the test-only semantic conformance document.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in conformance view violates
    /// an internal invariant.
    pub fn to_canonical_json(self) -> String {
        let mut output =
            serde_json::to_string(&self).expect("serializing semantic conformance cannot fail");
        output.push('\n');
        output
    }
}

struct Projection<'a> {
    view: SemanticConformanceView<'a>,
    digest: Option<&'a str>,
}

fn serialize_document<S: Serializer>(
    view: SemanticConformanceView<'_>,
    digest: Option<&str>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let graph = GraphDocumentView::new(GraphKind::All, view.program);
    let mut map = serializer.serialize_map(Some(10))?;
    map.serialize_entry("completeness", &CompletenessView(view.completeness_reasons))?;
    map.serialize_entry("diagnostics", &SemanticDiagnostics(view.diagnostics))?;
    map.serialize_entry("digest", &digest)?;
    map.serialize_entry("edges", &EdgesView(graph))?;
    map.serialize_entry("entrypoints", &NodeIdsView(&view.program.entrypoints))?;
    map.serialize_entry("gate", &GateView(view.gate))?;
    map.serialize_entry("nodes", &NodesView(view.program))?;
    map.serialize_entry("properties", &PropertiesView(view.properties))?;
    map.serialize_entry("schema", "semantic-conformance/1")?;
    map.serialize_entry("sources", &SourcesView(&view.program.sources))?;
    map.end()
}

struct SemanticDiagnostics<'a>(&'a [Diagnostic]);

impl Serialize for SemanticDiagnostics<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for diagnostic in self.0 {
            sequence.serialize_element(&SemanticDiagnostic(diagnostic))?;
        }
        sequence.end()
    }
}

struct SemanticDiagnostic<'a>(&'a Diagnostic);

impl Serialize for SemanticDiagnostic<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let fields = 5
            + usize::from(!value.capabilities.is_empty())
            + usize::from(!value.evidence.is_empty())
            + usize::from(value.fix.is_some())
            + usize::from(!value.trace.is_empty());
        let mut map = serializer.serialize_map(Some(fields))?;
        if !value.capabilities.is_empty() {
            map.serialize_entry(
                "capabilities",
                &value
                    .capabilities
                    .iter()
                    .map(|capability| capability.name())
                    .collect::<Vec<_>>(),
            )?;
        }
        map.serialize_entry("confidence", value.confidence.name())?;
        if !value.evidence.is_empty() {
            map.serialize_entry("evidence", &value.evidence)?;
        }
        if let Some(fix) = &value.fix {
            map.serialize_entry("fix", &SemanticFix(fix))?;
        }
        map.serialize_entry("message", &value.message)?;
        map.serialize_entry("rule_id", &value.rule_id)?;
        map.serialize_entry("severity", value.severity.name())?;
        map.serialize_entry("span", &SpanView::from(value.span))?;
        if !value.trace.is_empty() {
            map.serialize_entry("trace", &SemanticTrace(&value.trace))?;
        }
        map.end()
    }
}

struct SemanticFix<'a>(&'a crate::verifier::Fix);

impl Serialize for SemanticFix<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("description", &self.0.description)?;
        map.serialize_entry("kind", &self.0.kind)?;
        if let Some(replacement) = &self.0.replacement {
            map.serialize_entry("replacement", replacement)?;
        }
        if let Some(span) = self.0.span {
            map.serialize_entry("span", &SpanView::from(span))?;
        }
        map.end()
    }
}

struct SemanticTrace<'a>(&'a [crate::verifier::TraceHop]);

impl Serialize for SemanticTrace<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for hop in self.0 {
            sequence.serialize_element(&SemanticHop(hop))?;
        }
        sequence.end()
    }
}

struct SemanticHop<'a>(&'a crate::verifier::TraceHop);

impl Serialize for SemanticHop<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("label", &self.0.label)?;
        map.serialize_entry("node", &self.0.node_id.0)?;
        map.serialize_entry("span", &SpanView::from(self.0.span))?;
        map.end()
    }
}

impl Serialize for Projection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_document(self.view, self.digest, serializer)
    }
}

impl Serialize for SemanticConformanceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let digest = self.digest();
        serialize_document(*self, Some(&digest), serializer)
    }
}
