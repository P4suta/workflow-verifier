use std::collections::BTreeSet;
use workflow_verifier_domain::{EdgeKind, Graph};

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

fn filtered(kind: GraphKind, graph: &Graph) -> Graph {
    if kind == GraphKind::All {
        let mut graph = graph.clone();
        graph.finalize();
        return graph;
    }
    let mut output = Graph::empty(graph.provider, graph.source.clone());
    output.edges = graph
        .edges
        .iter()
        .filter(|edge| keep(kind, edge.kind))
        .cloned()
        .collect();
    let used: BTreeSet<_> = output
        .edges
        .iter()
        .flat_map(|edge| [edge.from.as_str(), edge.to.as_str()])
        .collect();
    output.nodes = graph
        .nodes
        .iter()
        .filter(|node| used.contains(node.id.as_str()))
        .cloned()
        .collect();
    output.entrypoints = graph
        .entrypoints
        .iter()
        .filter(|id| used.contains(id.as_str()))
        .cloned()
        .collect();
    output.finalize();
    output
}

#[must_use]
pub fn graph_to_canonical_json(kind: GraphKind, graph: &Graph) -> String {
    filtered(kind, graph).to_json().canonical_line()
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[must_use]
pub fn graph_to_dot(kind: GraphKind, graph: &Graph) -> String {
    use std::fmt::Write as _;
    let graph = filtered(kind, graph);
    let mut output = "digraph workflow {\n  rankdir=LR;\n".to_owned();
    for node in graph.nodes {
        let _ = writeln!(
            output,
            "  \"{}\" [label=\"{}\\n{}\"];",
            node.id,
            dot_escape(&node.name),
            node.kind.name()
        );
    }
    for edge in graph.edges {
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
