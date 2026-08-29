use crate::domain::{Condition, Edge, EdgeKind, Node, Program, Source};
use crate::foundation::{Digest, JsonValue, normalize_slashes};
use crate::product::serde_views::{AbstractValueView, ConditionView, SpanView, UnknownView};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphKind {
    All,
    Control,
    Dataflow,
    Call,
    Capability,
}

fn keep(kind: GraphKind, edge: EdgeKind) -> bool {
    match kind {
        GraphKind::All => true,
        GraphKind::Control => edge == EdgeKind::Control,
        GraphKind::Dataflow => matches!(
            edge,
            EdgeKind::Data | EdgeKind::Read | EdgeKind::Write | EdgeKind::Persist
        ),
        GraphKind::Call => edge == EdgeKind::Call,
        GraphKind::Capability => edge == EdgeKind::Grant,
    }
}

/// Borrowed projection of a linked analysis program.
///
/// It serializes directly to `workflow-verifier-graph/1`; no mutable graph
/// document or generic JSON tree is constructed.
#[derive(Clone, Copy)]
pub struct GraphDocumentView<'a> {
    kind: GraphKind,
    program: &'a Program,
}

impl<'a> GraphDocumentView<'a> {
    #[must_use]
    pub const fn new(kind: GraphKind, program: &'a Program) -> Self {
        Self { kind, program }
    }

    #[must_use]
    /// Computes the graph document digest.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in graph view violates an
    /// internal invariant.
    pub fn digest(self) -> Digest {
        let bytes = serde_json::to_vec(&GraphProjection(self))
            .expect("serializing an in-memory graph cannot fail");
        let mut digest = Digest::builder(b"workflow-verifier-graph/1");
        digest.add(bytes);
        digest.finish()
    }

    #[must_use]
    /// Serializes the graph document in canonical compact form.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of the built-in graph view violates an
    /// internal invariant.
    pub fn to_canonical_json(self) -> String {
        let mut output =
            serde_json::to_string(&self).expect("serializing an in-memory graph cannot fail");
        output.push('\n');
        output
    }
}

struct GraphProjection<'a>(GraphDocumentView<'a>);

fn serialize_graph<S: Serializer>(
    view: GraphDocumentView<'_>,
    digest: Option<Digest>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(5 + usize::from(digest.is_some())))?;
    if let Some(digest) = digest {
        map.serialize_entry("digest", &digest.to_string())?;
    }
    map.serialize_entry("edges", &EdgesView(view))?;
    map.serialize_entry("entrypoints", &NodeIdsView(&view.program.entrypoints))?;
    map.serialize_entry("nodes", &NodesView(view.program))?;
    map.serialize_entry("schema", "workflow-verifier-graph/1")?;
    map.serialize_entry("sources", &SourcesView(&view.program.sources))?;
    map.end()
}

impl Serialize for GraphProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_graph(self.0, None, serializer)
    }
}

impl Serialize for GraphDocumentView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_graph(*self, Some(self.digest()), serializer)
    }
}

/// Authenticate a `workflow-verifier-graph/1` document.
///
/// # Errors
/// Rejects malformed JSON, another schema, an incomplete/extended top-level
/// object, or a mismatched document digest.
pub fn authenticate_graph_document(source: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "digest",
        "edges",
        "entrypoints",
        "nodes",
        "schema",
        "sources",
    ];
    let document = JsonValue::parse(source).map_err(|error| error.to_string())?;
    let fields = document.exact_object("graph document", FIELDS)?;
    if fields.len() != FIELDS.len() || FIELDS.iter().any(|name| !fields.contains_key(*name)) {
        return Err("graph document has missing fields".to_owned());
    }
    if fields.get("schema").and_then(JsonValue::as_str) != Some("workflow-verifier-graph/1") {
        return Err("unsupported graph document schema".to_owned());
    }
    let claimed = fields
        .get("digest")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "graph document needs string field digest".to_owned())
        .and_then(|value| Digest::parse(value).map_err(str::to_owned))?;
    let mut projection = fields.clone();
    projection.remove("digest");
    let mut digest = Digest::builder(b"workflow-verifier-graph/1");
    digest.add(JsonValue::Object(projection).canonical());
    if digest.finish() != claimed {
        return Err("graph document digest mismatch".to_owned());
    }
    Ok(())
}

pub(crate) struct SourcesView<'a>(pub(crate) &'a [Source]);

impl Serialize for SourcesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for source in self.0 {
            sequence.serialize_element(&SourceView(source))?;
        }
        sequence.end()
    }
}

struct SourceView<'a>(&'a Source);

impl Serialize for SourceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let source = self.0;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("id", &source.id.0)?;
        map.serialize_entry("path", &normalize_slashes(&source.path))?;
        map.serialize_entry("provider", source.provider.name())?;
        map.end()
    }
}

pub(crate) struct NodesView<'a>(pub(crate) &'a Program);

impl Serialize for NodesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.nodes.len()))?;
        for node in &self.0.nodes {
            sequence.serialize_element(&NodeView(node))?;
        }
        sequence.end()
    }
}

struct NodeView<'a>(&'a Node);

impl Serialize for NodeView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let node = self.0;
        let optional = usize::from(!node.attributes.is_empty())
            + usize::from(!node.capabilities.is_empty())
            + usize::from(node.condition != Condition::True)
            + usize::from(!node.effects.is_empty())
            + usize::from(node.unknown.is_some());
        let mut map = serializer.serialize_map(Some(6 + optional))?;
        if !node.attributes.is_empty() {
            map.serialize_entry("attributes", &AttributesView(node))?;
        }
        if !node.capabilities.is_empty() {
            let capabilities: Vec<_> = node
                .capabilities
                .iter()
                .map(|capability| capability.name())
                .collect();
            map.serialize_entry("capabilities", &capabilities)?;
        }
        if node.condition != Condition::True {
            map.serialize_entry("condition", &ConditionView(&node.condition))?;
        }
        if !node.effects.is_empty() {
            let effects: Vec<_> = node.effects.iter().map(|effect| effect.name()).collect();
            map.serialize_entry("effects", &effects)?;
        }
        map.serialize_entry("id", &node.id.0)?;
        map.serialize_entry("kind", node.kind.name())?;
        map.serialize_entry("name", &node.name)?;
        map.serialize_entry("phase", node.phase.name())?;
        map.serialize_entry("source", &node.span.source.0)?;
        map.serialize_entry("span", &SpanView::from(node.span))?;
        if let Some(unknown) = &node.unknown {
            map.serialize_entry("unknown", &UnknownView(unknown))?;
        }
        map.end()
    }
}

struct AttributesView<'a>(&'a Node);

impl Serialize for AttributesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.attributes.len()))?;
        for (name, value) in &self.0.attributes {
            map.serialize_entry(name, &AbstractValueView(value))?;
        }
        map.end()
    }
}

pub(crate) struct EdgesView<'a>(pub(crate) GraphDocumentView<'a>);

impl Serialize for EdgesView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self
            .0
            .program
            .edges
            .iter()
            .filter(|edge| keep(self.0.kind, edge.kind))
            .count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for edge in self
            .0
            .program
            .edges
            .iter()
            .filter(|edge| keep(self.0.kind, edge.kind))
        {
            sequence.serialize_element(&EdgeView(edge))?;
        }
        sequence.end()
    }
}

struct EdgeView<'a>(&'a Edge);

impl Serialize for EdgeView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let edge = self.0;
        let mut map = serializer.serialize_map(None)?;
        if edge.condition != Condition::True {
            map.serialize_entry("condition", &ConditionView(&edge.condition))?;
        }
        map.serialize_entry("from", &edge.from.0)?;
        map.serialize_entry("kind", edge.kind.name())?;
        if let Some(label) = &edge.label {
            map.serialize_entry("label", label)?;
        }
        map.serialize_entry("to", &edge.to.0)?;
        map.end()
    }
}

pub(crate) struct NodeIdsView<'a>(pub(crate) &'a [crate::domain::NodeId]);

impl Serialize for NodeIdsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for id in self.0 {
            sequence.serialize_element(&id.0)?;
        }
        sequence.end()
    }
}

#[must_use]
pub fn graph_to_canonical_json(kind: GraphKind, program: &Program) -> String {
    GraphDocumentView::new(kind, program).to_canonical_json()
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[must_use]
pub fn graph_to_dot(kind: GraphKind, program: &Program) -> String {
    let mut output = "digraph workflow {\n  rankdir=LR;\n".to_owned();
    for node in &program.nodes {
        let _ = writeln!(
            output,
            "  \"{}\" [label=\"{}\\n{}\"];",
            node.id,
            dot_escape(&node.name),
            node.kind.name()
        );
    }
    for edge in program.edges.iter().filter(|edge| keep(kind, edge.kind)) {
        let _ = writeln!(
            output,
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            edge.from,
            edge.to,
            edge.kind.name()
        );
    }
    output.push_str("}\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_filters_classify_every_edge_kind() {
        for edge in [
            EdgeKind::Control,
            EdgeKind::Data,
            EdgeKind::Call,
            EdgeKind::Grant,
            EdgeKind::Persist,
            EdgeKind::Read,
            EdgeKind::Write,
        ] {
            assert!(keep(GraphKind::All, edge));
            assert_eq!(keep(GraphKind::Control, edge), edge == EdgeKind::Control);
            assert_eq!(keep(GraphKind::Call, edge), edge == EdgeKind::Call);
            assert_eq!(keep(GraphKind::Capability, edge), edge == EdgeKind::Grant);
        }
    }

    #[test]
    fn dot_escaping_is_exact() {
        assert_eq!(dot_escape("back\\slash\n\""), "back\\\\slash\\n\\\"");
    }
}
