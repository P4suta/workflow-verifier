use std::collections::{BTreeMap, BTreeSet, VecDeque};
use workflow_verifier_domain::{Capability, EdgeKind, Graph, ObservableEffect};
use workflow_verifier_foundation::{DependencyClass, JsonValue, classify_reference};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathChange {
    pub source: String,
    pub sink: String,
    pub path: Vec<String>,
    pub effect: ObservableEffect,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SemanticChange {
    NewReachablePath(PathChange),
    CapabilityAdded(Capability),
    CapabilityRemoved(Capability),
    DependencyBecameMutable(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticDiff {
    pub base_digest: String,
    pub head_digest: String,
    pub changes: Vec<SemanticChange>,
}

impl SemanticDiff {
    fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "base_digest".to_owned(),
                JsonValue::String(self.base_digest.clone()),
            ),
            (
                "changes".to_owned(),
                JsonValue::Array(self.changes.iter().map(change_json).collect()),
            ),
            (
                "head_digest".to_owned(),
                JsonValue::String(self.head_digest.clone()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("semantic-diff-v1".to_owned()),
            ),
        ]))
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }

    #[must_use]
    pub fn verify_digests(&self, base: &Graph, head: &Graph) -> bool {
        self.base_digest == graph_digest(base) && self.head_digest == graph_digest(head)
    }
}

fn graph_digest(graph: &Graph) -> String {
    graph.to_json().canonical_digest()
}

fn capabilities(graph: &Graph) -> BTreeSet<Capability> {
    graph
        .nodes
        .iter()
        .flat_map(|node| node.capabilities.iter().copied())
        .collect()
}

fn mutable_calls(graph: &Graph) -> BTreeSet<String> {
    graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == workflow_verifier_domain::NodeKind::Call
                && classify_reference(&node.name) == DependencyClass::Mutable
        })
        .map(|node| node.name.clone())
        .collect()
}

fn attack_paths(graph: &Graph) -> BTreeSet<PathChange> {
    let sources: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.attributes
                .values()
                .any(workflow_verifier_domain::AbstractValue::is_untrusted)
        })
        .collect();
    let sinks: Vec<_> = graph
        .nodes
        .iter()
        .flat_map(|node| node.effects.iter().map(move |effect| (node, *effect)))
        .collect();
    let mut paths = BTreeSet::new();
    for source in sources {
        for (sink, effect) in &sinks {
            if let Some(path) = shortest_path(graph, &source.id, &sink.id) {
                paths.insert(PathChange {
                    source: source.id.clone(),
                    sink: sink.id.clone(),
                    path,
                    effect: *effect,
                });
            }
        }
    }
    paths
}

fn shortest_path(graph: &Graph, start: &str, goal: &str) -> Option<Vec<String>> {
    let kinds = [
        EdgeKind::Data,
        EdgeKind::Read,
        EdgeKind::Write,
        EdgeKind::Persist,
        EdgeKind::Call,
        EdgeKind::Control,
    ];
    let mut queue = VecDeque::from([start.to_owned()]);
    let mut previous: BTreeMap<String, Option<String>> = BTreeMap::from([(start.to_owned(), None)]);
    while let Some(current) = queue.pop_front() {
        if current == goal {
            let mut path = Vec::new();
            let mut cursor = Some(current);
            while let Some(id) = cursor {
                cursor = previous.get(&id).cloned().flatten();
                path.push(id);
            }
            path.reverse();
            return Some(path);
        }
        let mut successors: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.from == current && kinds.contains(&edge.kind))
            .map(|edge| edge.to.clone())
            .collect();
        successors.sort();
        successors.dedup();
        for successor in successors {
            if !previous.contains_key(&successor) {
                previous.insert(successor.clone(), Some(current.clone()));
                queue.push_back(successor);
            }
        }
    }
    None
}

#[must_use]
pub fn semantic_diff(base: &Graph, head: &Graph) -> SemanticDiff {
    let base_paths = attack_paths(base);
    let head_paths = attack_paths(head);
    let base_caps = capabilities(base);
    let head_caps = capabilities(head);
    let base_mutable = mutable_calls(base);
    let head_mutable = mutable_calls(head);
    let mut changes = Vec::new();
    changes.extend(
        head_paths
            .difference(&base_paths)
            .cloned()
            .map(SemanticChange::NewReachablePath),
    );
    changes.extend(
        head_caps
            .difference(&base_caps)
            .copied()
            .map(SemanticChange::CapabilityAdded),
    );
    changes.extend(
        base_caps
            .difference(&head_caps)
            .copied()
            .map(SemanticChange::CapabilityRemoved),
    );
    changes.extend(
        head_mutable
            .difference(&base_mutable)
            .cloned()
            .map(SemanticChange::DependencyBecameMutable),
    );
    SemanticDiff {
        base_digest: graph_digest(base),
        head_digest: graph_digest(head),
        changes,
    }
}

fn change_json(change: &SemanticChange) -> JsonValue {
    match change {
        SemanticChange::NewReachablePath(path) => JsonValue::Object(BTreeMap::from([
            (
                "effect".to_owned(),
                JsonValue::String(path.effect.name().to_owned()),
            ),
            (
                "kind".to_owned(),
                JsonValue::String("new_reachable_path".to_owned()),
            ),
            (
                "path".to_owned(),
                JsonValue::Array(path.path.iter().cloned().map(JsonValue::String).collect()),
            ),
            ("sink".to_owned(), JsonValue::String(path.sink.clone())),
            ("source".to_owned(), JsonValue::String(path.source.clone())),
        ])),
        SemanticChange::CapabilityAdded(value) => JsonValue::Object(BTreeMap::from([
            (
                "capability".to_owned(),
                JsonValue::String(value.name().to_owned()),
            ),
            (
                "kind".to_owned(),
                JsonValue::String("capability_added".to_owned()),
            ),
        ])),
        SemanticChange::CapabilityRemoved(value) => JsonValue::Object(BTreeMap::from([
            (
                "capability".to_owned(),
                JsonValue::String(value.name().to_owned()),
            ),
            (
                "kind".to_owned(),
                JsonValue::String("capability_removed".to_owned()),
            ),
        ])),
        SemanticChange::DependencyBecameMutable(reference) => JsonValue::Object(BTreeMap::from([
            (
                "kind".to_owned(),
                JsonValue::String("dependency_became_mutable".to_owned()),
            ),
            ("reference".to_owned(), JsonValue::String(reference.clone())),
        ])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use workflow_verifier_domain::{
        AbstractValue, Condition, Edge, Node, NodeKind, Phase, Provider, Secrecy, Trust,
    };
    use workflow_verifier_foundation::Span;

    fn node(kind: NodeKind, name: &str) -> Node {
        Node::simple(Provider::Github, kind, name, Phase::Run, Span::default())
    }

    fn path_graph(with_path: bool) -> (Graph, Node, Node) {
        let mut source = node(NodeKind::Resource, "untrusted source");
        source.attributes = BTreeMap::from([(
            "value".to_owned(),
            AbstractValue::string_constant("input", Trust::Untrusted, Secrecy::Public, Vec::new()),
        )]);
        let middle = node(NodeKind::Step, "middle");
        let mut sink = node(NodeKind::Effect, "deployment");
        sink.effects = vec![ObservableEffect::DeploymentChange];
        let mut graph = Graph::empty(Provider::Github, "workflow.yml");
        graph.add_entrypoint(source.id.clone());
        for item in [&source, &middle, &sink] {
            graph.add_node(item.clone());
        }
        if with_path {
            graph.add_edge(Edge::simple(
                EdgeKind::Data,
                source.id.clone(),
                middle.id.clone(),
            ));
            graph.add_edge(Edge::simple(
                EdgeKind::Control,
                middle.id.clone(),
                sink.id.clone(),
            ));
        } else {
            graph.add_edge(Edge::new(
                EdgeKind::Grant,
                source.id.clone(),
                sink.id.clone(),
                Condition::True,
                None,
            ));
        }
        graph.finalize();
        (graph, source, sink)
    }

    #[test]
    fn attack_path_diff_uses_only_semantic_edges_and_preserves_exact_shortest_path() {
        let (base, _, _) = path_graph(false);
        let (head, source, sink) = path_graph(true);
        assert_eq!(shortest_path(&base, &source.id, &sink.id), None);
        assert_eq!(
            shortest_path(&head, &source.id, &sink.id),
            Some(vec![
                source.id.clone(),
                head.nodes
                    .iter()
                    .find(|node| node.name == "middle")
                    .expect("middle node")
                    .id
                    .clone(),
                sink.id.clone(),
            ])
        );
        assert_eq!(
            shortest_path(&head, &source.id, &source.id),
            Some(vec![source.id.clone()])
        );
        assert_eq!(attack_paths(&base), BTreeSet::new());
        let paths = attack_paths(&head);
        assert_eq!(paths.len(), 1);
        let path = paths.first().expect("attack path");
        assert_eq!(path.source, source.id);
        assert_eq!(path.sink, sink.id);
        assert_eq!(path.effect, ObservableEffect::DeploymentChange);

        let difference = semantic_diff(&base, &head);
        assert!(
            difference
                .changes
                .contains(&SemanticChange::NewReachablePath(path.clone()))
        );
        assert!(difference.verify_digests(&base, &head));
        assert!(!difference.verify_digests(&head, &head));
        assert!(!difference.verify_digests(&base, &base));
        assert!(
            difference
                .to_canonical_json()
                .contains("new_reachable_path")
        );
    }

    #[test]
    fn capability_and_mutability_changes_require_the_right_node_shape() {
        let mut base = Graph::empty(Provider::Github, "base.yml");
        let mut removed = node(NodeKind::Step, "removed capability");
        removed.capabilities = vec![Capability::RepositoryRead];
        base.add_node(removed);
        let mut head = Graph::empty(Provider::Github, "head.yml");
        let mut added = node(NodeKind::Step, "added capability");
        added.capabilities = vec![Capability::RepositoryWrite];
        let mutable_call = node(NodeKind::Call, "owner/action@main");
        let mutable_non_call = node(NodeKind::Step, "owner/not-a-call@main");
        let immutable_call = node(NodeKind::Call, &format!("owner/action@{}", "a".repeat(40)));
        for item in [
            added,
            mutable_call.clone(),
            mutable_non_call,
            immutable_call,
        ] {
            head.add_node(item);
        }
        assert_eq!(
            mutable_calls(&head),
            BTreeSet::from([mutable_call.name.clone()])
        );
        let difference = semantic_diff(&base, &head);
        assert!(
            difference
                .changes
                .contains(&SemanticChange::CapabilityAdded(
                    Capability::RepositoryWrite
                ))
        );
        assert!(
            difference
                .changes
                .contains(&SemanticChange::CapabilityRemoved(
                    Capability::RepositoryRead
                ))
        );
        assert!(
            difference
                .changes
                .contains(&SemanticChange::DependencyBecameMutable(mutable_call.name))
        );
    }
}
