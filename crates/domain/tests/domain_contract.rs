use std::collections::BTreeMap;
use workflow_verifier_domain::{
    AbstractValue, Condition, Edge, EdgeKind, Graph, Node, NodeKind, Phase, Provider, Secrecy,
    Trust, UnknownReason,
};
use workflow_verifier_foundation::{Position, Span};

fn span(start: usize, stop: usize) -> Span {
    Span::new(
        "workflow.yml",
        Position {
            byte: start,
            line: 1,
            column: u32::try_from(start + 1).unwrap_or(u32::MAX),
        },
        Position {
            byte: stop,
            line: 1,
            column: u32::try_from(stop + 1).unwrap_or(u32::MAX),
        },
    )
}

#[test]
fn condition_is_a_canonical_robdd() {
    let a = Condition::atom("a");
    let b = Condition::atom("b");
    let c = Condition::atom("c");
    assert_eq!(a.and(&b).and(&c), c.and(&a).and(&b));
    assert_eq!(a.or(&a.not()), Condition::True);
    assert_eq!(a.and(&a.not()), Condition::False);
}

#[test]
fn unknown_survives_joins() {
    let reason = UnknownReason::ExternalState("remote include".to_owned());
    let unknown = AbstractValue::unknown(reason.clone());
    let concrete =
        AbstractValue::string_constant("main", Trust::Trusted, Secrecy::Public, Vec::new());
    let joined = unknown.join(&concrete);
    assert!(joined.to_json().canonical().contains("external_state"));
    assert!(
        joined
            .to_json()
            .canonical()
            .contains("incompatible value join")
    );
}

#[test]
fn graph_identity_and_serialization_are_insertion_order_independent() {
    let workflow = Node::simple(
        Provider::Github,
        NodeKind::Workflow,
        "ci",
        Phase::Compile,
        span(0, 2),
    );
    let job = Node::new(
        Provider::Github,
        NodeKind::Job,
        "build",
        Phase::Plan,
        span(3, 8),
        Condition::True,
        BTreeMap::new(),
        [],
        [],
        None,
    );
    let edge = Edge::simple(EdgeKind::Control, workflow.id.clone(), job.id.clone());

    let mut first = Graph::empty(Provider::Github, "workflow.yml");
    first.add_node(workflow.clone());
    first.add_node(job.clone());
    first.add_edge(edge.clone());
    first.add_entrypoint(workflow.id.clone());

    let mut second = Graph::empty(Provider::Github, "workflow.yml");
    second.add_edge(edge);
    second.add_node(job);
    second.add_node(workflow.clone());
    second.add_entrypoint(workflow.id);

    assert_eq!(first.to_json().canonical(), second.to_json().canonical());
    assert!(first.validate().is_empty());
}
