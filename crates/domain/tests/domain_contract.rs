use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::abstract_value::{AbstractTruth, StringValue};
use workflow_verifier_domain::{
    AbstractValue, Condition, Edge, EdgeKind, Graph, Node, NodeKind, Phase, Provider, Secrecy,
    Trust, Truth, UnknownReason, Value, ValueType,
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

fn abstract_value(value_type: ValueType, value: Value) -> AbstractValue {
    AbstractValue {
        value_type,
        value,
        trust: Trust::Trusted,
        secrecy: Secrecy::Public,
        provenance: Vec::new(),
    }
}

fn string_value(value: StringValue) -> AbstractValue {
    abstract_value(ValueType::String, Value::String(value))
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
fn condition_evaluation_and_display_preserve_branch_semantics() {
    let approval = Condition::atom("approval");
    assert_eq!(approval.evaluate(&|_| Some(false)), Truth::False);
    assert_eq!(approval.evaluate(&|_| Some(true)), Truth::True);
    assert_eq!(approval.evaluate(&|_| None), Truth::Unknown);
    assert_eq!(approval.to_string(), "approval");

    let platform = Condition::atom("platform");
    assert_eq!(
        approval.and(&platform).to_string(),
        "((not approval and false) or (approval and platform))"
    );

    let redundant_branch = Condition::Branch {
        variable: "redundant".to_owned(),
        low: Box::new(Condition::True),
        high: Box::new(Condition::True),
    };
    assert_eq!(redundant_branch.evaluate(&|_| None), Truth::True);
}

#[test]
fn value_type_names_and_security_predicates_are_stable() {
    let names = [
        (ValueType::Never, "never"),
        (ValueType::Null, "null"),
        (ValueType::Bool, "bool"),
        (ValueType::Number, "number"),
        (ValueType::String, "string"),
        (ValueType::List, "list"),
        (ValueType::Object, "object"),
        (ValueType::Dynamic, "dynamic"),
    ];
    for (value_type, expected) in names {
        assert_eq!(value_type.name(), expected);
    }

    let mut classified = string_value(StringValue::Top);
    assert!(!classified.is_untrusted());
    assert!(!classified.is_secret());
    classified.trust = Trust::Untrusted;
    classified.secrecy = Secrecy::Secret;
    assert!(classified.is_untrusted());
    assert!(classified.is_secret());
}

#[test]
fn abstract_value_join_uses_the_type_lattice() {
    let never_with_value = abstract_value(ValueType::Never, Value::Null);
    let string = string_value(StringValue::Constants(vec!["value".to_owned()]));
    let another_string = string_value(StringValue::Pattern("value-.*".to_owned()));
    let number = abstract_value(
        ValueType::Number,
        Value::Number {
            minimum: None,
            maximum: None,
        },
    );

    assert_eq!(never_with_value.join(&string).value_type, ValueType::String);
    assert_eq!(string.join(&never_with_value).value_type, ValueType::String);
    assert_eq!(string.join(&another_string).value_type, ValueType::String);
    assert_eq!(string.join(&number).value_type, ValueType::Dynamic);
}

#[test]
fn string_join_preserves_constants_affixes_patterns_and_unicode_boundaries() {
    let bottom = string_value(StringValue::Bottom);
    let pattern = string_value(StringValue::Pattern("release-.*".to_owned()));
    assert_eq!(bottom.join(&pattern).value, pattern.value);

    let first = string_value(StringValue::Constants(vec!["beta".to_owned()]));
    let second = string_value(StringValue::Constants(vec!["alpha".to_owned()]));
    assert_eq!(
        first.join(&second).value,
        Value::String(StringValue::Constants(vec![
            "alpha".to_owned(),
            "beta".to_owned(),
        ]))
    );

    let concrete = string_value(StringValue::Constants(vec!["release-α.tar".to_owned()]));
    let affix = string_value(StringValue::Affix {
        prefix: Some("release-β".to_owned()),
        suffix: Some("preview.tar".to_owned()),
    });
    assert_eq!(
        concrete.join(&affix).value,
        Value::String(StringValue::Affix {
            prefix: Some("release-".to_owned()),
            suffix: Some(".tar".to_owned()),
        })
    );

    let shared_prefix = string_value(StringValue::Constants(vec!["shared-value-a".to_owned()]));
    let prefix_only_affix = string_value(StringValue::Affix {
        prefix: Some("shared-".to_owned()),
        suffix: Some("different-b".to_owned()),
    });
    assert_eq!(
        shared_prefix.join(&prefix_only_affix).value,
        Value::String(StringValue::Affix {
            prefix: Some("shared-".to_owned()),
            suffix: None,
        })
    );

    let multiple = string_value(StringValue::Constants(vec![
        "release-main".to_owned(),
        "release-next".to_owned(),
    ]));
    let release_prefix = string_value(StringValue::Affix {
        prefix: Some("release-".to_owned()),
        suffix: None,
    });
    assert_eq!(
        multiple.join(&release_prefix).value,
        Value::String(StringValue::Top)
    );

    let left_affix = string_value(StringValue::Affix {
        prefix: Some("shared-left".to_owned()),
        suffix: Some("left-a".to_owned()),
    });
    let right_affix = string_value(StringValue::Affix {
        prefix: Some("shared-right".to_owned()),
        suffix: Some("right-b".to_owned()),
    });
    assert_eq!(
        left_affix.join(&right_affix).value,
        Value::String(StringValue::Affix {
            prefix: Some("shared-".to_owned()),
            suffix: None,
        })
    );

    let same_pattern = string_value(StringValue::Pattern("release-.*".to_owned()));
    let different_pattern = string_value(StringValue::Pattern("preview-.*".to_owned()));
    assert_eq!(same_pattern.join(&same_pattern).value, same_pattern.value);
    assert_eq!(
        same_pattern.join(&different_pattern).value,
        Value::String(StringValue::Top)
    );
}

#[test]
fn scalar_value_join_preserves_null_boolean_and_number_domains() {
    let null = abstract_value(ValueType::Null, Value::Null);
    assert_eq!(null.join(&null).value, Value::Null);

    let boolean_true = abstract_value(ValueType::Bool, Value::Boolean(AbstractTruth::True));
    let boolean_false = abstract_value(ValueType::Bool, Value::Boolean(AbstractTruth::False));
    assert_eq!(boolean_true.join(&boolean_true).value, boolean_true.value);
    assert_eq!(
        boolean_true.join(&boolean_false).value,
        Value::Boolean(AbstractTruth::Maybe)
    );

    let lower_half = abstract_value(
        ValueType::Number,
        Value::Number {
            minimum: Some(i64::MIN),
            maximum: Some(0),
        },
    );
    let upper_half = abstract_value(
        ValueType::Number,
        Value::Number {
            minimum: Some(0),
            maximum: Some(i64::MAX),
        },
    );
    assert_eq!(
        lower_half.join(&upper_half).value,
        Value::Number {
            minimum: Some(i64::MIN),
            maximum: Some(i64::MAX),
        }
    );
}

#[test]
fn list_value_join_preserves_shape_and_joins_elements() {
    let alpha = string_value(StringValue::Constants(vec!["alpha".to_owned()]));
    let beta = string_value(StringValue::Constants(vec!["beta".to_owned()]));
    let one_element = abstract_value(ValueType::List, Value::List(Some(vec![alpha.clone()])));
    let another_element = abstract_value(ValueType::List, Value::List(Some(vec![beta.clone()])));
    assert_eq!(
        one_element.join(&another_element).value,
        Value::List(Some(vec![string_value(StringValue::Constants(vec![
            "alpha".to_owned(),
            "beta".to_owned(),
        ]))]))
    );
    let empty_list = abstract_value(ValueType::List, Value::List(Some(Vec::new())));
    assert_eq!(one_element.join(&empty_list).value, Value::List(None));
}

#[test]
fn object_value_join_preserves_union_and_unknown_shape() {
    let alpha = string_value(StringValue::Constants(vec!["alpha".to_owned()]));
    let beta = string_value(StringValue::Constants(vec!["beta".to_owned()]));
    let left_object = abstract_value(
        ValueType::Object,
        Value::Object(Some(BTreeMap::from([
            ("left".to_owned(), alpha.clone()),
            ("shared".to_owned(), alpha.clone()),
        ]))),
    );
    let right_object = abstract_value(
        ValueType::Object,
        Value::Object(Some(BTreeMap::from([
            ("right".to_owned(), beta.clone()),
            ("shared".to_owned(), beta.clone()),
        ]))),
    );
    assert_eq!(
        left_object.join(&right_object).value,
        Value::Object(Some(BTreeMap::from([
            ("left".to_owned(), alpha.clone()),
            ("right".to_owned(), beta.clone()),
            (
                "shared".to_owned(),
                string_value(StringValue::Constants(vec![
                    "alpha".to_owned(),
                    "beta".to_owned(),
                ])),
            ),
        ])))
    );
    let unknown_object = abstract_value(ValueType::Object, Value::Object(None));
    assert_eq!(left_object.join(&unknown_object).value, Value::Object(None));
}

#[test]
fn unknown_value_join_deduplicates_reasons_and_records_incompatibility() {
    let external = UnknownReason::ExternalState("remote state".to_owned());
    let evidence = UnknownReason::MissingEvidence("attestation".to_owned());
    let first_unknown = abstract_value(
        ValueType::Dynamic,
        Value::Unknown(vec![external.clone(), external.clone()]),
    );
    let second_unknown = abstract_value(ValueType::Dynamic, Value::Unknown(vec![evidence.clone()]));
    assert_eq!(
        first_unknown.join(&second_unknown).value,
        Value::Unknown(
            BTreeSet::from([external.clone(), evidence])
                .into_iter()
                .collect()
        )
    );
    let null = abstract_value(ValueType::Null, Value::Null);
    assert_eq!(
        first_unknown.join(&null).value,
        Value::Unknown(
            BTreeSet::from([
                external,
                UnknownReason::UnsupportedSyntax("incompatible value join".to_owned()),
            ])
            .into_iter()
            .collect()
        )
    );
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

#[test]
fn graph_navigation_filters_both_endpoint_and_edge_kind() {
    let source = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "source",
        Phase::Run,
        span(0, 0),
    );
    let control_target = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "control-target",
        Phase::Run,
        span(0, 0),
    );
    let data_target = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "data-target",
        Phase::Run,
        span(0, 0),
    );
    let unrelated = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "unrelated",
        Phase::Run,
        span(0, 0),
    );
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    for node in [
        source.clone(),
        control_target.clone(),
        data_target.clone(),
        unrelated.clone(),
    ] {
        graph.add_node(node);
    }
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        source.id.clone(),
        control_target.id.clone(),
    ));
    graph.add_edge(Edge::simple(
        EdgeKind::Data,
        source.id.clone(),
        data_target.id.clone(),
    ));
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        unrelated.id.clone(),
        source.id.clone(),
    ));

    let ids = |nodes: Vec<&Node>| {
        nodes
            .into_iter()
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        ids(graph.successors(&source.id, Some(EdgeKind::Control))),
        BTreeSet::from([control_target.id.clone()])
    );
    assert_eq!(
        ids(graph.successors(&source.id, None)),
        BTreeSet::from([control_target.id.clone(), data_target.id.clone()])
    );
    assert_eq!(
        ids(graph.predecessors(&source.id, Some(EdgeKind::Control))),
        BTreeSet::from([unrelated.id.clone()])
    );
    assert_eq!(
        ids(graph.predecessors(&data_target.id, Some(EdgeKind::Data))),
        BTreeSet::from([source.id])
    );
}

#[test]
fn graph_validation_reports_identity_endpoint_and_phase_failures() {
    let late_source = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "late-source",
        Phase::Run,
        span(0, 0),
    );
    let early_target = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "early-target",
        Phase::Plan,
        span(0, 0),
    );
    let valid_source = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "valid-source",
        Phase::Source,
        span(0, 0),
    );
    let valid_target = Node::simple(
        Provider::Github,
        NodeKind::Step,
        "valid-target",
        Phase::Compile,
        span(0, 0),
    );
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    for node in [
        late_source.clone(),
        early_target.clone(),
        valid_source.clone(),
        valid_target.clone(),
        early_target.clone(),
    ] {
        graph.add_node(node);
    }
    graph.add_edge(Edge::simple(
        EdgeKind::Data,
        late_source.id.clone(),
        early_target.id.clone(),
    ));
    graph.add_edge(Edge::simple(
        EdgeKind::Data,
        valid_source.id.clone(),
        valid_target.id,
    ));
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        valid_source.id,
        "missing-node",
    ));

    let issues = graph.validate();
    assert_eq!(
        issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<Vec<_>>(),
        vec!["IR-DANGLING-EDGE", "IR-DUPLICATE-NODE", "IR-PHASE-ORDER"]
    );
    let phase_issue = issues
        .iter()
        .find(|issue| issue.code == "IR-PHASE-ORDER")
        .expect("phase-order issue must be present");
    assert_eq!(phase_issue.node_ids, vec![late_source.id, early_target.id]);
}

#[test]
fn unknown_reason_display_is_stable_with_and_without_detail() {
    assert_eq!(
        UnknownReason::ExternalState("remote state".to_owned()).to_string(),
        "external_state: remote state"
    );
    assert_eq!(
        UnknownReason::MissingEvidence(String::new()).to_string(),
        "missing_evidence"
    );
}
