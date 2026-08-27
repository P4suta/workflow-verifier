use std::collections::BTreeMap;
use workflow_verifier_domain::{
    AbstractValue, Capability, Condition, Edge, EdgeKind, Graph, Node, NodeKind, ObservableEffect,
    Phase, Provider, Secrecy, Trust, UnknownReason,
};
use workflow_verifier_foundation::{Position, Span};
use workflow_verifier_verifier::{
    Persona, PropertyState, Severity, compose_program, inferred_effects, should_fail, verify,
};

fn span(byte: usize) -> Span {
    Span::new(
        "workflow.yml",
        Position {
            byte,
            line: 1,
            column: u32::try_from(byte + 1).unwrap_or(u32::MAX),
        },
        Position {
            byte: byte + 1,
            line: 1,
            column: u32::try_from(byte + 2).unwrap_or(u32::MAX),
        },
    )
}

fn add_control(graph: &mut Graph, from: &Node, to: &Node) {
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        from.id.clone(),
        to.id.clone(),
    ));
}

#[test]
fn all_twelve_properties_are_always_explicit() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let workflow = Node::simple(
        Provider::Github,
        NodeKind::Workflow,
        "ci",
        Phase::Compile,
        span(0),
    );
    graph.add_node(workflow.clone());
    graph.add_entrypoint(workflow.id);
    let result = verify(Persona::Gate, &graph);
    let ids: Vec<_> = result
        .properties
        .iter()
        .map(|property| property.id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "WV-AI-001",
            "WV-ARTIFACT-001",
            "WV-AUTH-001",
            "WV-CACHE-001",
            "WV-CORRECT-001",
            "WV-CRED-001",
            "WV-PERM-001",
            "WV-SEC-001",
            "WV-SEC-002",
            "WV-SELF-001",
            "WV-SUPPLY-001",
            "WV-TOCTOU-001",
        ]
    );
    assert!(result.complete);
}

#[test]
fn mutable_dependency_has_stable_diagnostic_and_fix() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let call = Node::new(
        Provider::Github,
        NodeKind::Call,
        "actions/checkout@v4",
        Phase::Run,
        span(4),
        Condition::True,
        BTreeMap::new(),
        [Capability::RepositoryRead],
        [ObservableEffect::FileWrite],
        Some(UnknownReason::UnresolvedDependency(
            "actions/checkout@v4".to_owned(),
        )),
    );
    graph.add_node(call);
    let result = verify(Persona::Gate, &graph);
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.rule_id == "WV-SUPPLY-001")
        .expect("supply-chain finding");
    assert!(diagnostic.id.starts_with("diag_"));
    assert_eq!(
        diagnostic.fix.as_ref().map(|fix| fix.kind.as_str()),
        Some("pin-dependency")
    );
    assert!(!should_fail(Persona::Gate, &result));
    assert!(!should_fail(Persona::Audit, &result));
    assert!(should_fail(Persona::Paranoid, &result));
}

#[test]
fn untrusted_command_flow_is_a_gate_failure() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let untrusted = AbstractValue::string_constant(
        "${{ github.event.issue.title }}",
        Trust::Untrusted,
        Secrecy::Public,
        Vec::new(),
    );
    let command = Node::new(
        Provider::Github,
        NodeKind::Command,
        "echo $TITLE",
        Phase::Run,
        span(10),
        Condition::True,
        BTreeMap::from([("command".to_owned(), untrusted)]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(command);
    let result = verify(Persona::Gate, &graph);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "WV-SEC-001")
    );
    assert!(should_fail(Persona::Gate, &result));
}

#[test]
fn injection_trace_starts_at_the_untrusted_resource_and_ends_at_the_command() {
    let mut graph = Graph::empty(Provider::Gitlab, ".gitlab-ci.yml");
    let source = Node::new(
        Provider::Gitlab,
        NodeKind::Resource,
        "CI_COMMIT_BRANCH",
        Phase::Run,
        span(5),
        Condition::True,
        BTreeMap::from([(
            "value".to_owned(),
            AbstractValue::string_constant(
                "CI_COMMIT_BRANCH",
                Trust::Untrusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [],
        [],
        None,
    );
    let command = Node::new(
        Provider::Gitlab,
        NodeKind::Command,
        "echo $CI_COMMIT_BRANCH",
        Phase::Run,
        span(10),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                "echo $CI_COMMIT_BRANCH",
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(source.clone());
    graph.add_node(command.clone());
    graph.add_edge(Edge::simple(
        EdgeKind::Data,
        source.id.clone(),
        command.id.clone(),
    ));
    graph.finalize();

    let result = verify(Persona::Gate, &graph);
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.rule_id == "WV-SEC-001")
        .expect("injection diagnostic");
    assert_eq!(
        diagnostic
            .trace
            .iter()
            .map(|hop| (hop.label.as_str(), hop.node_id.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("untrusted source", source.id.as_str()),
            ("command sink", command.id.as_str()),
        ]
    );
}

#[test]
fn injection_correlates_environment_taint_with_exact_quote_boundaries() {
    fn verify_binding(command_source: &str) -> bool {
        let mut graph = Graph::empty(Provider::Github, "workflow.yml");
        let source = Node::new(
            Provider::Github,
            NodeKind::Resource,
            "inputs.title",
            Phase::Run,
            span(1),
            Condition::True,
            BTreeMap::from([(
                "value".to_owned(),
                AbstractValue::string_constant(
                    "inputs.title",
                    Trust::Untrusted,
                    Secrecy::Public,
                    Vec::new(),
                ),
            )]),
            [],
            [],
            None,
        );
        let binding = Node::simple(
            Provider::Github,
            NodeKind::Resource,
            "env:TITLE",
            Phase::Run,
            span(2),
        );
        let command = Node::new(
            Provider::Github,
            NodeKind::Command,
            command_source,
            Phase::Run,
            span(3),
            Condition::True,
            BTreeMap::from([(
                "command".to_owned(),
                AbstractValue::string_constant(
                    command_source,
                    Trust::Trusted,
                    Secrecy::Public,
                    Vec::new(),
                ),
            )]),
            [Capability::Shell],
            [ObservableEffect::CommandExecution],
            None,
        );
        graph.add_node(source.clone());
        graph.add_node(binding.clone());
        graph.add_node(command.clone());
        graph.add_edge(Edge::simple(EdgeKind::Data, source.id, binding.id.clone()));
        graph.add_edge(Edge::simple(EdgeKind::Data, binding.id, command.id));
        graph.finalize();
        verify(Persona::Gate, &graph)
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "WV-SEC-001")
    }

    assert!(!verify_binding(
        "if [[ \"$TITLE\" =~ ^[a-z]+$ ]]; then value=$(printf ok); printf '%s' \"$TITLE\"; fi"
    ));
    assert!(!verify_binding("printf '%s' $TITLE_SUFFIX"));
    assert!(verify_binding("printf '%s' $TITLE"));
}

#[test]
fn bash_negation_and_quoted_expansions_do_not_create_an_injection_finding() {
    let mut graph = Graph::empty(Provider::Circleci, ".circleci/config.yml");
    let source = Node::new(
        Provider::Circleci,
        NodeKind::Resource,
        "CIRCLE_TAG",
        Phase::Run,
        span(1),
        Condition::True,
        BTreeMap::from([(
            "value".to_owned(),
            AbstractValue::string_constant(
                "CIRCLE_TAG",
                Trust::Untrusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [],
        [],
        None,
    );
    let command_source =
        "if [ ! -z \"$CIRCLE_TAG\" ]; then sed -i \"s/dirty/$CIRCLE_TAG/g\" flash; fi";
    let command = Node::new(
        Provider::Circleci,
        NodeKind::Command,
        command_source,
        Phase::Run,
        span(2),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                command_source,
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(source.clone());
    graph.add_node(command.clone());
    graph.add_edge(Edge::simple(EdgeKind::Data, source.id, command.id));
    graph.finalize();

    assert!(
        verify(Persona::Gate, &graph)
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-SEC-001")
    );
}

#[test]
fn redirecting_a_secret_to_a_private_file_is_not_process_output() {
    let mut graph = Graph::empty(Provider::Circleci, ".circleci/config.yml");
    let secret = Node::new(
        Provider::Circleci,
        NodeKind::Resource,
        "NPM_TOKEN",
        Phase::Run,
        span(1),
        Condition::True,
        BTreeMap::from([(
            "value".to_owned(),
            AbstractValue::string_constant(
                "NPM_TOKEN",
                Trust::Trusted,
                Secrecy::Secret,
                Vec::new(),
            ),
        )]),
        [],
        [],
        None,
    );
    let command_source = "echo \"//registry.npmjs.org/:_authToken=$NPM_TOKEN\" >> ~/.npmrc";
    let command = Node::new(
        Provider::Circleci,
        NodeKind::Command,
        command_source,
        Phase::Run,
        span(2),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                command_source,
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(secret.clone());
    graph.add_node(command.clone());
    graph.add_edge(Edge::simple(EdgeKind::Data, secret.id, command.id));
    graph.finalize();

    assert!(
        verify(Persona::Gate, &graph)
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-SEC-002")
    );
}

#[test]
fn authorization_diagnostic_reports_the_ungated_control_path() {
    let mut graph = Graph::empty(Provider::Gitlab, ".gitlab-ci.yml");
    let workflow = Node::simple(
        Provider::Gitlab,
        NodeKind::Workflow,
        "pipeline",
        Phase::Compile,
        span(0),
    );
    let job = Node::simple(
        Provider::Gitlab,
        NodeKind::Job,
        "release",
        Phase::Plan,
        span(2),
    );
    let step = Node::simple(
        Provider::Gitlab,
        NodeKind::Step,
        "script:1",
        Phase::Run,
        span(4),
    );
    let rule_gate = Node::simple(
        Provider::Gitlab,
        NodeKind::Gate,
        "rule:release",
        Phase::Plan,
        span(5),
    );
    let command = Node::new(
        Provider::Gitlab,
        NodeKind::Command,
        "git push origin HEAD",
        Phase::Run,
        span(6),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                "git push origin HEAD",
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::Shell,
        ],
        [ObservableEffect::CommandExecution],
        None,
    );
    for node in [&workflow, &job, &rule_gate, &step, &command] {
        graph.add_node(node.clone());
    }
    graph.add_entrypoint(workflow.id.clone());
    add_control(&mut graph, &workflow, &job);
    add_control(&mut graph, &job, &rule_gate);
    add_control(&mut graph, &rule_gate, &step);
    add_control(&mut graph, &step, &command);
    graph.finalize();

    let result = verify(Persona::Gate, &graph);
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.rule_id == "WV-AUTH-001")
        .expect("authorization diagnostic");
    assert_eq!(diagnostic.severity, Severity::Error);
    assert_eq!(
        diagnostic.message,
        "a privileged effect is reachable without a dominating authorization gate"
    );
    assert_eq!(
        diagnostic.evidence,
        vec!["dominator set contains no Gate node"]
    );
    assert_eq!(
        diagnostic.capabilities,
        vec![
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::Shell,
        ]
    );
    assert_eq!(
        diagnostic
            .trace
            .iter()
            .map(|hop| (hop.label.as_str(), hop.node_id.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("authorization bypass", workflow.id.as_str()),
            ("authorization bypass", job.id.as_str()),
            ("authorization bypass", rule_gate.id.as_str()),
            ("authorization bypass", step.id.as_str()),
            ("authorization bypass", command.id.as_str()),
        ]
    );
}

#[test]
fn script_effect_inference_covers_reference_deployment_network_and_file_writes() {
    let cases = [
        (
            "terraform apply -auto-approve",
            ObservableEffect::DeploymentChange,
        ),
        (
            "docker login registry.example",
            ObservableEffect::NetworkRequest,
        ),
        ("printf value >> artifact.txt", ObservableEffect::FileWrite),
    ];
    for (source, expected) in cases {
        let command = Node::new(
            Provider::Circleci,
            NodeKind::Command,
            source,
            Phase::Run,
            span(20),
            Condition::True,
            BTreeMap::from([(
                "command".to_owned(),
                AbstractValue::string_constant(source, Trust::Trusted, Secrecy::Public, Vec::new()),
            )]),
            [Capability::Shell],
            [ObservableEffect::CommandExecution],
            None,
        );
        assert!(
            inferred_effects(&command).contains(&expected),
            "{source:?} did not infer {expected:?}"
        );
    }
}

#[test]
fn terraform_apply_without_an_authorization_gate_is_a_violation() {
    let mut graph = Graph::empty(Provider::Circleci, ".circleci/config.yml");
    let command = Node::new(
        Provider::Circleci,
        NodeKind::Command,
        "terraform apply",
        Phase::Run,
        span(30),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                "terraform apply -auto-approve",
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(command);
    let result = verify(Persona::Gate, &graph);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "WV-AUTH-001")
    );
}

#[test]
fn trusted_manual_gate_dominates_a_privileged_effect() {
    let mut graph = Graph::empty(Provider::Gitlab, ".gitlab-ci.yml");
    let manual = Node::new(
        Provider::Gitlab,
        NodeKind::Gate,
        "manual:release",
        Phase::Plan,
        span(0),
        Condition::True,
        BTreeMap::from([(
            "mechanism".to_owned(),
            AbstractValue::string_constant("manual", Trust::Trusted, Secrecy::Public, Vec::new()),
        )]),
        [],
        [],
        None,
    );
    let command = Node::new(
        Provider::Gitlab,
        NodeKind::Command,
        "git push origin HEAD",
        Phase::Run,
        span(2),
        Condition::True,
        BTreeMap::from([(
            "command".to_owned(),
            AbstractValue::string_constant(
                "git push origin HEAD",
                Trust::Trusted,
                Secrecy::Public,
                Vec::new(),
            ),
        )]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(manual.clone());
    graph.add_node(command.clone());
    graph.add_entrypoint(manual.id.clone());
    add_control(&mut graph, &manual, &command);
    graph.finalize();

    let result = verify(Persona::Gate, &graph);
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-AUTH-001")
    );
}

#[test]
fn environment_protection_keeps_authorization_unknown_without_a_false_finding() {
    let mut graph = Graph::empty(Provider::Gitlab, ".gitlab-ci.yml");
    let environment = Node::new(
        Provider::Gitlab,
        NodeKind::Resource,
        "environment:production",
        Phase::Run,
        span(0),
        Condition::True,
        BTreeMap::new(),
        [Capability::Deployment],
        [],
        None,
    );
    let job = Node::new(
        Provider::Gitlab,
        NodeKind::Job,
        "deploy",
        Phase::Plan,
        span(2),
        Condition::True,
        BTreeMap::new(),
        [Capability::Deployment],
        [ObservableEffect::DeploymentChange],
        None,
    );
    graph.add_node(environment.clone());
    graph.add_node(job.clone());
    graph.add_entrypoint(environment.id.clone());
    graph.add_edge(Edge::simple(EdgeKind::Grant, environment.id, job.id));
    graph.finalize();

    let result = verify(Persona::Gate, &graph);
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-AUTH-001")
    );
    let property = result
        .properties
        .iter()
        .find(|property| property.id == "WV-AUTH-001")
        .expect("authorization property");
    assert_eq!(
        property.state,
        PropertyState::Unknown(vec![UnknownReason::ExternalState(
            "protection rules for environment:production".to_owned()
        )])
    );
}

#[test]
fn unrelated_output_does_not_turn_a_secret_reference_into_a_leak() {
    let mut graph = Graph::empty(Provider::Gitlab, ".gitlab-ci.yml");
    let source = "export PASSWORD=$(cat $PASSWORD_FILE)\necho setup complete";
    let command_value =
        AbstractValue::string_constant(source, Trust::Trusted, Secrecy::Public, Vec::new()).join(
            &AbstractValue::string_constant(
                "PASSWORD",
                Trust::Trusted,
                Secrecy::Secret,
                Vec::new(),
            ),
        );
    let command = Node::new(
        Provider::Gitlab,
        NodeKind::Command,
        source,
        Phase::Run,
        span(0),
        Condition::True,
        BTreeMap::from([("command".to_owned(), command_value)]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(command);
    let result = verify(Persona::Gate, &graph);
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-SEC-002")
    );
}

#[test]
fn secret_property_preserves_shell_and_network_sink_uncertainty() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let command = Node::new(
        Provider::Github,
        NodeKind::Command,
        "use $PASSWORD",
        Phase::Run,
        span(0),
        Condition::True,
        BTreeMap::from([
            (
                "command".to_owned(),
                AbstractValue::string_constant(
                    "use $PASSWORD",
                    Trust::Trusted,
                    Secrecy::Secret,
                    Vec::new(),
                ),
            ),
            (
                "shell".to_owned(),
                AbstractValue::string_constant(
                    "default",
                    Trust::Trusted,
                    Secrecy::Public,
                    Vec::new(),
                ),
            ),
        ]),
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
        None,
    );
    let call = Node::new(
        Provider::Github,
        NodeKind::Call,
        "acme/network-action@revision",
        Phase::Run,
        span(2),
        Condition::True,
        BTreeMap::new(),
        [Capability::Network],
        [],
        Some(UnknownReason::UnresolvedDependency(
            "acme/network-action@revision".to_owned(),
        )),
    );
    graph.add_node(command);
    graph.add_node(call);
    let result = verify(Persona::Gate, &graph);
    let property = result
        .properties
        .iter()
        .find(|property| property.id == "WV-SEC-002")
        .expect("secret property");
    assert_eq!(
        property.state,
        PropertyState::Unknown(vec![
            UnknownReason::UnsupportedSyntax("shell default".to_owned()),
            UnknownReason::UnresolvedDependency("acme/network-action@revision".to_owned()),
        ])
    );
}

#[test]
fn graph_cycles_and_unknowns_never_become_proved() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let first = Node::simple(Provider::Github, NodeKind::Job, "a", Phase::Plan, span(0));
    let second = Node::new(
        Provider::Github,
        NodeKind::Opaque,
        "b",
        Phase::Plan,
        span(2),
        Condition::True,
        BTreeMap::new(),
        [],
        [],
        Some(UnknownReason::UnsupportedSyntax("dynamic job".to_owned())),
    );
    graph.add_node(first.clone());
    graph.add_node(second.clone());
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        first.id.clone(),
        second.id.clone(),
    ));
    graph.add_edge(Edge::simple(EdgeKind::Control, second.id, first.id));
    let result = verify(Persona::Paranoid, &graph);
    assert!(!result.complete);
    let correctness = result
        .properties
        .iter()
        .find(|property| property.id == "WV-CORRECT-001")
        .expect("correctness property");
    assert_eq!(correctness.state, PropertyState::Violated);
    assert!(should_fail(Persona::Paranoid, &result));
}

#[test]
fn non_privileged_grants_are_required_even_when_reachable_work_is_unknown() {
    let mut graph = Graph::empty(Provider::Github, "workflow.yml");
    let workflow = Node::new(
        Provider::Github,
        NodeKind::Workflow,
        "ci",
        Phase::Compile,
        span(0),
        Condition::True,
        BTreeMap::new(),
        [Capability::RepositoryRead, Capability::TokenRead],
        [],
        None,
    );
    let call = Node::new(
        Provider::Github,
        NodeKind::Call,
        "actions/checkout@v4",
        Phase::Run,
        span(2),
        Condition::True,
        BTreeMap::new(),
        [Capability::RepositoryRead],
        [ObservableEffect::FileWrite],
        Some(UnknownReason::MissingEvidence(
            "dependency has no semantic summary".to_owned(),
        )),
    );
    graph.add_node(workflow.clone());
    graph.add_node(call.clone());
    graph.add_entrypoint(workflow.id.clone());
    graph.add_edge(Edge::simple(EdgeKind::Control, workflow.id, call.id));
    let result = verify(Persona::Audit, &graph);
    let property = result
        .properties
        .iter()
        .find(|property| property.id == "WV-PERM-001")
        .expect("permission property");
    assert_eq!(property.state, PropertyState::Proved);
}

#[test]
fn whole_program_composition_links_cross_file_resource_writes_to_reads() {
    let file_span = |file: &str, byte: usize| {
        let mut value = span(byte);
        value.file = file.to_owned();
        value
    };
    let mut producer = Graph::empty(Provider::Github, "producer.yml");
    let producer_job = Node::simple(
        Provider::Github,
        NodeKind::Job,
        "producer",
        Phase::Plan,
        file_span("producer.yml", 0),
    );
    let written = Node::simple(
        Provider::Github,
        NodeKind::Resource,
        "artifact:bundle",
        Phase::Post,
        file_span("producer.yml", 2),
    );
    producer.add_node(producer_job.clone());
    producer.add_node(written.clone());
    producer.add_edge(Edge::simple(
        EdgeKind::Write,
        producer_job.id,
        written.id.clone(),
    ));

    let mut consumer = Graph::empty(Provider::Github, "consumer.yml");
    let read = Node::simple(
        Provider::Github,
        NodeKind::Resource,
        "artifact:bundle",
        Phase::Run,
        file_span("consumer.yml", 0),
    );
    let consumer_job = Node::simple(
        Provider::Github,
        NodeKind::Job,
        "consumer",
        Phase::Plan,
        file_span("consumer.yml", 2),
    );
    consumer.add_node(read.clone());
    consumer.add_node(consumer_job.clone());
    consumer.add_edge(Edge::simple(
        EdgeKind::Read,
        read.id.clone(),
        consumer_job.id,
    ));

    let program = compose_program(&[producer, consumer]);
    assert!(program.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Persist
            && edge.from == written.id
            && edge.to == read.id
            && edge.label.as_deref() == Some("cross-file resource")
    }));
    assert!(program.validate().is_empty(), "{:?}", program.validate());
}
