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

#[cfg(test)]
mod tests {
    use super::*;
    use workflow_verifier_domain::{Node, NodeKind, Phase, Provider};
    use workflow_verifier_foundation::Span;

    #[test]
    fn graph_filters_classify_every_edge_kind() {
        let kinds = [
            EdgeKind::Control,
            EdgeKind::Data,
            EdgeKind::Call,
            EdgeKind::Grant,
            EdgeKind::Persist,
            EdgeKind::Read,
            EdgeKind::Write,
        ];
        for edge in kinds {
            assert!(keep(GraphKind::All, edge));
            assert_eq!(keep(GraphKind::Control, edge), edge == EdgeKind::Control);
            assert_eq!(keep(GraphKind::Call, edge), edge == EdgeKind::Call);
            assert_eq!(keep(GraphKind::Capability, edge), edge == EdgeKind::Grant);
            assert_eq!(
                keep(GraphKind::Dataflow, edge),
                matches!(
                    edge,
                    EdgeKind::Data | EdgeKind::Read | EdgeKind::Write | EdgeKind::Persist
                )
            );
        }
    }

    #[test]
    fn dot_escaping_is_exact_and_does_not_change_plain_text() {
        assert_eq!(dot_escape("plain"), "plain");
        assert_eq!(dot_escape("back\\slash"), "back\\\\slash");
        assert_eq!(dot_escape("quoted \"value\""), "quoted \\\"value\\\"");
        assert_eq!(dot_escape("two\nlines"), "two\\nlines");
        assert_eq!(dot_escape("\\\"\n"), "\\\\\\\"\\n");
    }

    #[test]
    fn all_graph_view_retains_isolated_nodes_and_entrypoints() {
        let isolated = Node::simple(
            Provider::Github,
            NodeKind::Workflow,
            "isolated",
            Phase::Source,
            Span::default(),
        );
        let mut graph = Graph::empty(Provider::Github, "workflow.yml");
        graph.add_entrypoint(isolated.id.clone());
        graph.add_node(isolated.clone());
        let all = filtered(GraphKind::All, &graph);
        assert_eq!(all.nodes.as_slice(), std::slice::from_ref(&isolated));
        assert_eq!(all.entrypoints, [isolated.id]);
        assert!(filtered(GraphKind::Control, &graph).nodes.is_empty());
    }
}
