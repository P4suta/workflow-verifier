use std::collections::BTreeMap;
use workflow_verifier::internal::conformance::domain::{
    Capability, Condition, Edge, EdgeKind, Graph, Node, NodeKind, Phase, Provider,
};
use workflow_verifier::internal::conformance::foundation::{JsonValue, Span};
use workflow_verifier::internal::conformance::product::{
    GraphKind, LockEntry, Lockfile, SemanticChange, graph_to_canonical_json, graph_to_dot,
    semantic_diff,
};

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn graph(capabilities: &[Capability], dependency: &str) -> Graph {
    let mut graph = Graph::empty(Provider::Github, ".github/workflows/ci.yml");
    let job = Node::simple(
        Provider::Github,
        NodeKind::Job,
        "build",
        Phase::Plan,
        Span::default(),
    );
    let call = Node::new(
        Provider::Github,
        NodeKind::Call,
        dependency,
        Phase::Compile,
        Span::default(),
        Node::semantics(
            Condition::True,
            BTreeMap::default(),
            capabilities.iter().copied(),
            [],
            None,
        ),
    );
    graph.add_entrypoint(job.id);
    graph.add_edge(Edge::simple(EdgeKind::Call, job.id, call.id));
    graph.add_node(call);
    graph.add_node(job);
    graph.finalize();
    graph
}

#[test]
fn lock_v2_is_sorted_deduplicated_and_self_authenticating() {
    let github = LockEntry::new(
        Provider::Github,
        "acme/action@main",
        "0123456789abcdef0123456789abcdef01234567",
        digest('a'),
        "https://github.com/acme/action",
    );
    let gitlab = LockEntry::new(
        Provider::Gitlab,
        "acme/template@v1",
        "fedcba9876543210fedcba9876543210fedcba98",
        digest('b'),
        "https://gitlab.com/acme/template",
    );
    let lock = Lockfile::new([gitlab, github.clone(), github]).expect("valid lock");
    assert_eq!(lock.entries().len(), 2);
    assert_eq!(lock.entries()[0].provider, Provider::Github);
    assert!(lock.verify_integrity());
    assert_eq!(Lockfile::parse(&lock.to_canonical_json()), Ok(lock.clone()));
    assert!(lock.to_canonical_json().ends_with('\n'));
}

#[test]
fn lock_v2_rejects_duplicate_fields_unknown_fields_and_digest_tampering() {
    let duplicate = r#"{"entries":[],"integrity":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"lock-v2","schema":"lock-v2"}"#;
    assert!(Lockfile::parse(duplicate).is_err());

    let unknown = format!(
        "{{\"entries\":[],\"integrity\":\"{}\",\"schema\":\"lock-v2\",\"surprise\":true}}",
        digest('a')
    );
    assert!(Lockfile::parse(&unknown).is_err());

    let lock = Lockfile::new([]).expect("empty lock");
    let tampered = lock
        .to_canonical_json()
        .replace(&lock.integrity, &digest('f'));
    assert!(Lockfile::parse(&tampered).is_err());
}

#[test]
fn graph_formats_are_filtered_and_deterministic() {
    let graph = graph(&[Capability::RepositoryRead], "acme/action@main");
    let first = graph_to_canonical_json(GraphKind::All, &graph);
    let second = graph_to_canonical_json(GraphKind::All, &graph);
    assert_eq!(first, second);
    assert!(JsonValue::parse(&first).is_ok());
    let dot = graph_to_dot(GraphKind::Call, &graph);
    assert!(dot.starts_with("digraph workflow {\n  rankdir=LR;\n"));
    assert!(dot.contains("label=\"call\""));
    assert!(dot.ends_with("}\n"));
}

#[test]
fn semantic_diff_reports_capability_and_mutable_dependency_changes() {
    let base = graph(
        &[Capability::RepositoryRead],
        "acme/action@0123456789abcdef0123456789abcdef01234567",
    );
    let head = graph(
        &[Capability::RepositoryRead, Capability::RepositoryWrite],
        "acme/action@main",
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
            .contains(&SemanticChange::DependencyBecameMutable(
                "acme/action@main".to_owned()
            ))
    );
    assert!(difference.verify_digests(&base, &head));
    assert!(JsonValue::parse(&difference.to_canonical_json()).is_ok());
}
