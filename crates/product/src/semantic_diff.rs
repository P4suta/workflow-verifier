use std::collections::{BTreeMap, BTreeSet, VecDeque};
use workflow_verifier_domain::{Capability, EdgeKind, Graph, ObservableEffect};
use workflow_verifier_foundation::{
    DependencyClass, JsonValue, classify_reference, content_digest,
};

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
    content_digest(graph.to_json().canonical())
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
