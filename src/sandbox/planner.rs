use crate::domain::{EdgeKind, Graph, Node, NodeId, NodeKind, Phase, Truth};
use crate::foundation::normalize_slashes;
use crate::internal::runner_protocol::Step;
use crate::sandbox::Scenario;
use crate::verifier::compose_program;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioPlan {
    pub steps: Vec<Step>,
    pub selected_jobs: Vec<String>,
    pub incomplete_reasons: Vec<String>,
}

/// Select and concretize the executable job closure for a scenario.
///
/// # Errors
/// Rejects missing/ambiguous entrypoints and jobs. Unsupported dynamic work is
/// preserved as explicit `incomplete_reasons` instead of being omitted.
pub fn plan_scenario(
    scenario: &Scenario,
    image: &str,
    graphs: &[Graph],
) -> Result<ScenarioPlan, String> {
    let candidates: Vec<_> = graphs
        .iter()
        .filter(|graph| {
            graph.provider() == scenario.provider
                && source_matches(&scenario.workflow_entrypoint, graph.source_path())
        })
        .collect();
    let entry = match candidates.as_slice() {
        [] => {
            return Err(format!(
                "scenario workflow entrypoint was not compiled: {}",
                scenario.workflow_entrypoint
            ));
        }
        [entry] => *entry,
        _ => {
            return Err(format!(
                "scenario workflow entrypoint is ambiguous: {}",
                scenario.workflow_entrypoint
            ));
        }
    };
    let jobs: Vec<_> = entry
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Job && node.name == scenario.job)
        .collect();
    let selected = match jobs.as_slice() {
        [] => return Err(format!("scenario job was not found: {}", scenario.job)),
        [job] => *job,
        _ => return Err(format!("scenario job is ambiguous: {}", scenario.job)),
    };
    let program = compose_program(graphs);
    let selected = program
        .nodes
        .iter()
        .find(|node| {
            node.kind == NodeKind::Job
                && node.name == selected.name
                && program
                    .source_path_for(node.span.source)
                    .is_some_and(|path| source_matches(&scenario.workflow_entrypoint, path))
        })
        .ok_or_else(|| "selected job disappeared during program composition".to_owned())?;
    let job_ids = job_closure(&program, selected.id);
    let reachability = descendants(&program, &job_ids, scenario);
    let selected_ids: BTreeSet<_> = reachability
        .iter()
        .filter_map(|(id, truth)| (*truth != Truth::False).then_some(*id))
        .collect();
    let nodes = topological_nodes(&program, &selected_ids);
    let mut steps = Vec::new();
    let mut reasons = Vec::new();
    for node in nodes {
        let truth = reachability.get(&node.id).copied().unwrap_or(Truth::False);
        if truth != Truth::False
            && let Some(reason) = unsupported_reason(node)
        {
            reasons.push(reason);
        }
        match (node.kind, truth) {
            (NodeKind::Command, Truth::True) => {
                let step = shell_step(scenario, image, node);
                if !step.supported {
                    reasons.push(format!(
                        "Incomplete.Unsupported_shell at {}: {}",
                        node.span, node.name
                    ));
                }
                steps.push(step);
            }
            (NodeKind::Command, Truth::Unknown) => {
                reasons.push(format!("Incomplete.Unknown_expression at {}", node.span));
            }
            _ => {}
        }
    }
    let mut selected_jobs: Vec<_> = job_ids
        .iter()
        .filter_map(|id| program.nodes.iter().find(|node| node.id == *id))
        .map(|node| node.name.clone())
        .collect();
    selected_jobs.sort();
    selected_jobs.dedup();
    reasons.sort();
    reasons.dedup();
    Ok(ScenarioPlan {
        steps,
        selected_jobs,
        incomplete_reasons: reasons,
    })
}

fn source_matches(expected: &str, actual: &str) -> bool {
    let expected = normalize_slashes(expected);
    let actual = normalize_slashes(actual);
    actual == expected || actual.ends_with(&format!("/{expected}"))
}

fn job_closure(graph: &Graph, selected: NodeId) -> BTreeSet<NodeId> {
    fn visit(graph: &Graph, id: NodeId, seen: &mut BTreeSet<NodeId>) {
        if !seen.insert(id) {
            return;
        }
        let predecessors: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == EdgeKind::Control && edge.to == id)
            .filter_map(|edge| {
                graph
                    .nodes
                    .iter()
                    .find(|node| node.id == edge.from && node.kind == NodeKind::Job)
            })
            .map(|node| node.id)
            .collect();
        for predecessor in predecessors {
            visit(graph, predecessor, seen);
        }
    }
    let mut seen = BTreeSet::new();
    visit(graph, selected, &mut seen);
    seen
}

fn descendants(
    graph: &Graph,
    jobs: &BTreeSet<NodeId>,
    scenario: &Scenario,
) -> BTreeMap<NodeId, Truth> {
    let mut queue = VecDeque::new();
    for job in jobs {
        let gates: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.kind == EdgeKind::Control
                    && edge.to == *job
                    && edge.label.as_deref() == Some("gate")
            })
            .filter_map(|edge| graph.find_node(edge.from))
            .filter(|node| node.kind == NodeKind::Gate)
            .collect();
        if gates.is_empty() {
            queue.push_back((*job, false, Truth::True));
        } else {
            for gate in gates {
                queue.push_back((gate.id, false, Truth::True));
            }
        }
    }

    let mut states: BTreeMap<(NodeId, bool), Truth> = BTreeMap::new();
    while let Some((id, allow_local_jobs, incoming)) = queue.pop_front() {
        let Some(node) = graph.find_node(id) else {
            continue;
        };
        let node_truth = truth_and(
            incoming,
            node.condition
                .evaluate(&|atom| scenario_fact(scenario, atom)),
        );
        let key = (id, allow_local_jobs);
        let merged = states
            .get(&key)
            .copied()
            .map_or(node_truth, |old| truth_or(old, node_truth));
        if states.get(&key).copied() == Some(merged) {
            continue;
        }
        states.insert(key, merged);
        if merged == Truth::False {
            continue;
        }
        for edge in graph.edges.iter().filter(|edge| {
            edge.from == id && matches!(edge.kind, EdgeKind::Control | EdgeKind::Call)
        }) {
            let allow_local = allow_local_jobs || edge.label.as_deref() == Some("local-unit");
            let Some(target) = graph.find_node(edge.to) else {
                continue;
            };
            if target.kind == NodeKind::Job && !jobs.contains(&target.id) && !allow_local {
                continue;
            }
            let edge_truth = edge
                .condition
                .evaluate(&|atom| scenario_fact(scenario, atom));
            queue.push_back((target.id, allow_local, truth_and(merged, edge_truth)));
        }
    }

    let mut output = BTreeMap::new();
    for ((id, _), truth) in states {
        output
            .entry(id)
            .and_modify(|old| *old = truth_or(*old, truth))
            .or_insert(truth);
    }
    output
}

fn truth_and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn truth_or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn topological_nodes<'a>(graph: &'a Graph, selected: &BTreeSet<NodeId>) -> Vec<&'a Node> {
    let mut remaining: BTreeSet<_> = selected.iter().copied().collect();
    let mut emitted = BTreeSet::new();
    let mut output = Vec::new();
    while !remaining.is_empty() {
        let mut ready_ids: Vec<_> = remaining
            .iter()
            .filter(|id| {
                graph.edges.iter().all(|edge| {
                    !matches!(edge.kind, EdgeKind::Control | EdgeKind::Call)
                        || edge.to != **id
                        || !selected.contains(&edge.from)
                        || emitted.contains(&edge.from)
                })
            })
            .copied()
            .collect();
        if ready_ids.is_empty() {
            // Cycles are emitted in the same total order as acyclic peers. Most
            // importantly, every pass owns IDs from `remaining`, so progress is
            // structural and cannot depend on a node lookup predicate.
            ready_ids.extend(remaining.iter().copied());
        }
        ready_ids.sort_by(|left_id, right_id| {
            let left = graph.find_node(*left_id);
            let right = graph.find_node(*right_id);
            left.map(|node| (&node.span, node.kind, &node.name, &node.id))
                .cmp(&right.map(|node| (&node.span, node.kind, &node.name, &node.id)))
                .then(left_id.cmp(right_id))
        });
        for id in ready_ids {
            remaining.remove(&id);
            emitted.insert(id);
            if let Some(node) = graph.find_node(id) {
                output.push(node);
            }
        }
    }
    output
}

fn scenario_fact(scenario: &Scenario, atom: &str) -> Option<bool> {
    let lower = atom.to_ascii_lowercase();
    if lower.contains("github.event_name") || lower.contains("ci_pipeline_source") {
        for quote in ['\'', '"'] {
            if let Some((_, tail)) = lower.split_once(quote)
                && let Some((expected, _)) = tail.split_once(quote)
            {
                let equal = scenario.event.eq_ignore_ascii_case(expected);
                return Some(if lower.contains("!=") { !equal } else { equal });
            }
        }
    }
    None
}

fn shell_step(scenario: &Scenario, image: &str, node: &Node) -> Step {
    let shell = attribute_constant(node, "shell")
        .unwrap_or("default")
        .to_ascii_lowercase();
    let command = concretize(scenario, &shell, &node.name);
    let unresolved = command.contains("${{") || command.contains("$[[") || command.contains("<<");
    let (argv, supported) = match (scenario.runner_platform.os(), shell.as_str()) {
        ("linux" | "macos", "default" | "bash") => (
            vec![
                "/bin/bash".to_owned(),
                "-euo".to_owned(),
                "pipefail".to_owned(),
                "-c".to_owned(),
                command,
            ],
            true,
        ),
        ("linux" | "macos", "sh" | "posix") => (
            vec![
                "/bin/sh".to_owned(),
                "-eu".to_owned(),
                "-c".to_owned(),
                command,
            ],
            true,
        ),
        ("windows", "default" | "pwsh" | "powershell") => (
            vec![
                "pwsh.exe".to_owned(),
                "-NoLogo".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                command,
            ],
            true,
        ),
        ("windows", "cmd" | "cmd.exe") => (
            vec![
                "cmd.exe".to_owned(),
                "/D".to_owned(),
                "/S".to_owned(),
                "/C".to_owned(),
                command,
            ],
            true,
        ),
        (_, "python" | "python3" | "pwsh" | "powershell") => (
            vec!["<capsule-tool-not-declared>".to_owned(), shell, command],
            false,
        ),
        (_, other) => (
            vec!["<unsupported-shell>".to_owned(), other.to_owned(), command],
            false,
        ),
    };
    let working_directory =
        normalize_slashes(attribute_constant(node, "working_directory").unwrap_or("/workspace"));
    let confined =
        working_directory == "/workspace" || working_directory.starts_with("/workspace/");
    Step {
        id: node.id.to_string(),
        image: image.to_owned(),
        argv,
        environment: scenario.variables.clone(),
        working_directory,
        supported: supported && confined && !unresolved,
    }
}

fn attribute_constant<'a>(node: &'a Node, name: &str) -> Option<&'a str> {
    node.attributes
        .get(name)
        .and_then(|value| value.constants())
        .and_then(|values| match values {
            [value] => Some(value.as_str()),
            _ => None,
        })
}

fn concretize(scenario: &Scenario, shell: &str, source: &str) -> String {
    let mut output = source.to_owned();
    for (name, value) in &scenario.inputs {
        for expression in [
            format!("${{{{ inputs.{name} }}}}"),
            format!("${{{{inputs.{name}}}}}"),
            format!("${{{{ parameters.{name} }}}}"),
            format!("<< pipeline.parameters.{name} >>"),
            format!("<< parameters.{name} >>"),
        ] {
            output = output.replace(&expression, value);
        }
    }
    for (name, value) in &scenario.matrix {
        let value = match value {
            crate::foundation::JsonValue::String(value) => value.clone(),
            crate::foundation::JsonValue::Boolean(value) => value.to_string(),
            crate::foundation::JsonValue::Integer(value) => value.to_string(),
            _ => String::new(),
        };
        for expression in [
            format!("${{{{ matrix.{name} }}}}"),
            format!("${{{{matrix.{name}}}}}"),
        ] {
            output = output.replace(&expression, &value);
        }
    }
    for (name, value) in &scenario.variables {
        for expression in [
            format!("${{{{ vars.{name} }}}}"),
            format!("${{{{ variables.{name} }}}}"),
            format!("$[ variables.{name} ]"),
            format!("${{{{ {name} }}}}"),
            format!("${{{{{name}}}}}"),
        ] {
            output = output.replace(&expression, value);
        }
    }
    for name in &scenario.secret_names {
        let reference = match shell {
            "pwsh" | "powershell" => format!("$env:{name}"),
            "cmd" | "cmd.exe" => format!("%{name}%"),
            _ => format!("\"${{{name}}}\""),
        };
        for expression in [
            format!("${{{{ secrets.{name} }}}}"),
            format!("${{{{secrets.{name}}}}}"),
        ] {
            output = output.replace(&expression, &reference);
        }
    }
    output
}

fn unsupported_reason(node: &Node) -> Option<String> {
    match node.kind {
        NodeKind::Call if node.unknown.is_some() => Some(format!(
            "Incomplete.Unresolved_call at {}: {}",
            node.span, node.name
        )),
        NodeKind::Opaque if node.phase == Phase::Run => Some(format!(
            "Incomplete.Unsupported_feature at {}: {}",
            node.span, node.name
        )),
        NodeKind::Resource
            if ["service", "cache", "artifact", "deployment"]
                .iter()
                .any(|marker| node.name.to_ascii_lowercase().contains(marker)) =>
        {
            Some(format!(
                "Incomplete.Unsupported_feature at {}: {}",
                node.span, node.name
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AbstractValue, Condition, Edge, Secrecy, Trust, UnknownReason};
    use crate::foundation::{JsonValue, Span};

    fn scenario(platform: crate::sandbox::RunnerPlatform) -> Scenario {
        Scenario::new(
            crate::domain::Provider::Github,
            ".github/workflows/ci.yml",
            "build",
            "push",
            platform,
        )
        .unwrap()
    }

    fn node(kind: NodeKind, name: &str, phase: Phase) -> Node {
        Node::simple(
            crate::domain::Provider::Github,
            kind,
            name,
            phase,
            Span::default(),
        )
    }

    fn constant(value: &str) -> AbstractValue {
        AbstractValue::string_constant(value, Trust::Trusted, Secrecy::Public, Vec::new())
    }

    #[test]
    fn truth_operators_cover_the_complete_three_valued_table() {
        let values = [Truth::False, Truth::True, Truth::Unknown];
        let expected_and = [
            [Truth::False, Truth::False, Truth::False],
            [Truth::False, Truth::True, Truth::Unknown],
            [Truth::False, Truth::Unknown, Truth::Unknown],
        ];
        let expected_or = [
            [Truth::False, Truth::True, Truth::Unknown],
            [Truth::True, Truth::True, Truth::True],
            [Truth::Unknown, Truth::True, Truth::Unknown],
        ];
        for (left_index, left) in values.into_iter().enumerate() {
            for (right_index, right) in values.into_iter().enumerate() {
                assert_eq!(
                    truth_and(left, right),
                    expected_and[left_index][right_index]
                );
                assert_eq!(truth_or(left, right), expected_or[left_index][right_index]);
            }
        }
    }

    #[test]
    fn scenario_event_facts_support_equality_inequality_and_unknown_atoms() {
        let scenario = scenario(crate::sandbox::RunnerPlatform::LinuxX86_64);
        assert_eq!(
            scenario_fact(&scenario, "github.event_name == 'push'"),
            Some(true)
        );
        assert_eq!(
            scenario_fact(&scenario, "github.event_name != 'push'"),
            Some(false)
        );
        assert_eq!(
            scenario_fact(&scenario, "github.event_name != \"schedule\""),
            Some(true)
        );
        assert_eq!(
            scenario_fact(&scenario, "CI_PIPELINE_SOURCE == 'push'"),
            Some(true)
        );
        assert_eq!(scenario_fact(&scenario, "github.ref == 'main'"), None);
    }

    #[test]
    fn concretization_covers_all_scalar_matrix_and_platform_secret_forms() {
        let scenario = scenario(crate::sandbox::RunnerPlatform::LinuxX86_64)
            .with_input("input", "input-value")
            .unwrap()
            .with_variable("variable", "variable-value")
            .unwrap()
            .with_matrix("string", JsonValue::String("text".to_owned()))
            .unwrap()
            .with_matrix("boolean", JsonValue::Boolean(true))
            .unwrap()
            .with_matrix("integer", JsonValue::Integer(-1))
            .unwrap()
            .with_secret("TOKEN")
            .unwrap();
        let source = "${{ inputs.input }} ${{ vars.variable }} ${{ matrix.string }} ${{ matrix.boolean }} ${{ matrix.integer }} ${{ secrets.TOKEN }}";
        assert_eq!(
            concretize(&scenario, "bash", source),
            "input-value variable-value text true -1 \"${TOKEN}\""
        );
        assert!(concretize(&scenario, "pwsh", source).ends_with("$env:TOKEN"));
        assert!(concretize(&scenario, "cmd", source).ends_with("%TOKEN%"));
    }

    #[test]
    fn shell_selection_attributes_and_confinement_are_all_semantic() {
        let mut command = node(NodeKind::Command, "echo portable", Phase::Run);
        command
            .attributes
            .insert("shell".to_owned(), constant("sh"));
        command.attributes.insert(
            "working_directory".to_owned(),
            constant("/workspace/subdirectory"),
        );
        assert_eq!(attribute_constant(&command, "shell"), Some("sh"));
        let step = shell_step(
            &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
            "sha256:image",
            &command,
        );
        assert_eq!(step.argv[0], "/bin/sh");
        assert!(step.supported);

        command.attributes.insert(
            "working_directory".to_owned(),
            constant("/workspace-escape"),
        );
        assert!(
            !shell_step(
                &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
                "sha256:image",
                &command
            )
            .supported
        );
        command
            .attributes
            .insert("shell".to_owned(), constant("python"));
        assert!(
            !shell_step(
                &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
                "sha256:image",
                &command
            )
            .supported
        );

        let multiple = constant("bash").join(&constant("sh"));
        command.attributes.insert("shell".to_owned(), multiple);
        assert_eq!(attribute_constant(&command, "shell"), None);

        for unresolved in [
            "echo ${{ unresolved.value }}",
            "echo $[[ unresolved.value ]]",
            "echo << unresolved.value >>",
        ] {
            let unresolved_command = node(NodeKind::Command, unresolved, Phase::Run);
            assert!(
                !shell_step(
                    &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
                    "sha256:image",
                    &unresolved_command,
                )
                .supported
            );
        }
    }

    #[test]
    fn unsupported_nodes_are_classified_by_kind_phase_and_marker() {
        let mut call = node(NodeKind::Call, "external/action@v1", Phase::Run);
        assert_eq!(unsupported_reason(&call), None);
        call.unknown = Some(UnknownReason::UnresolvedDependency("external".to_owned()));
        assert!(
            unsupported_reason(&call)
                .unwrap()
                .contains("Unresolved_call")
        );

        let opaque_plan = node(NodeKind::Opaque, "dynamic", Phase::Plan);
        let opaque_run = node(NodeKind::Opaque, "dynamic", Phase::Run);
        assert_eq!(unsupported_reason(&opaque_plan), None);
        assert!(
            unsupported_reason(&opaque_run)
                .unwrap()
                .contains("Unsupported_feature")
        );

        let resource = node(NodeKind::Resource, "artifact upload", Phase::Run);
        let benign = node(NodeKind::Resource, "workspace", Phase::Run);
        assert!(unsupported_reason(&resource).is_some());
        assert_eq!(unsupported_reason(&benign), None);
    }

    #[test]
    fn job_closure_follows_only_control_edges_from_jobs_and_handles_cycles() {
        let prerequisite = node(NodeKind::Job, "prerequisite", Phase::Run);
        let selected = node(NodeKind::Job, "selected", Phase::Run);
        let command = node(NodeKind::Command, "command", Phase::Run);
        let mut graph = Graph::empty(crate::domain::Provider::Github, "ci.yml");
        graph.nodes = vec![prerequisite.clone(), selected.clone(), command.clone()];
        graph.edges = vec![
            Edge::simple(EdgeKind::Control, prerequisite.id, selected.id),
            Edge::simple(EdgeKind::Control, selected.id, prerequisite.id),
            Edge::simple(EdgeKind::Control, command.id, selected.id),
            Edge::simple(EdgeKind::Data, command.id, selected.id),
        ];
        assert_eq!(
            job_closure(&graph, selected.id),
            BTreeSet::from([prerequisite.id, selected.id])
        );
    }

    #[test]
    fn descendants_respect_gates_edge_kinds_and_local_job_boundaries() {
        let mut gate = node(NodeKind::Gate, "event gate", Phase::Plan);
        gate.condition = Condition::atom("github.event_name == 'push'");
        let selected = node(NodeKind::Job, "selected", Phase::Run);
        let selected_command = node(NodeKind::Command, "selected command", Phase::Run);
        let local_job = node(NodeKind::Job, "local", Phase::Run);
        let local_command = node(NodeKind::Command, "local command", Phase::Run);
        let foreign_job = node(NodeKind::Job, "foreign", Phase::Run);
        let foreign_command = node(NodeKind::Command, "foreign command", Phase::Run);
        let mut graph = Graph::empty(crate::domain::Provider::Github, "ci.yml");
        graph.nodes = vec![
            gate.clone(),
            selected.clone(),
            selected_command.clone(),
            local_job.clone(),
            local_command.clone(),
            foreign_job.clone(),
            foreign_command.clone(),
        ];
        graph.edges = vec![
            Edge::new(
                EdgeKind::Control,
                gate.id,
                selected.id,
                Condition::True,
                Some("gate".to_owned()),
            ),
            Edge::simple(EdgeKind::Control, selected.id, selected_command.id),
            Edge::new(
                EdgeKind::Call,
                selected.id,
                local_job.id,
                Condition::True,
                Some("local-unit".to_owned()),
            ),
            Edge::simple(EdgeKind::Control, local_job.id, local_command.id),
            Edge::simple(EdgeKind::Call, selected.id, foreign_job.id),
            Edge::simple(EdgeKind::Control, foreign_job.id, foreign_command.id),
        ];
        let reachable = descendants(
            &graph,
            &BTreeSet::from([selected.id]),
            &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
        );
        assert_eq!(reachable.get(&selected_command.id), Some(&Truth::True));
        assert_eq!(reachable.get(&local_command.id), Some(&Truth::True));
        assert!(!reachable.contains_key(&foreign_job.id));
        assert!(!reachable.contains_key(&foreign_command.id));
    }

    #[test]
    fn only_a_gate_edge_to_the_selected_job_can_replace_the_job_root() {
        for (target_selected_job, gate_label) in [(false, Some("gate")), (true, Some("not-a-gate"))]
        {
            let mut false_gate = node(NodeKind::Gate, "distractor gate", Phase::Plan);
            false_gate.condition = Condition::False;
            let selected = node(NodeKind::Job, "selected", Phase::Run);
            let other = node(NodeKind::Job, "other", Phase::Run);
            let command = node(NodeKind::Command, "selected command", Phase::Run);
            let gate_target = if target_selected_job {
                selected.id
            } else {
                other.id
            };
            let mut graph = Graph::empty(crate::domain::Provider::Github, "ci.yml");
            graph.nodes = vec![false_gate.clone(), selected.clone(), other, command.clone()];
            graph.edges = vec![
                Edge::new(
                    EdgeKind::Control,
                    false_gate.id,
                    gate_target,
                    Condition::True,
                    gate_label.map(str::to_owned),
                ),
                Edge::simple(EdgeKind::Control, selected.id, command.id),
            ];
            let reachable = descendants(
                &graph,
                &BTreeSet::from([selected.id]),
                &scenario(crate::sandbox::RunnerPlatform::LinuxX86_64),
            );
            assert_eq!(reachable.get(&command.id), Some(&Truth::True));
        }
    }

    #[test]
    fn topological_order_honors_only_selected_control_or_call_dependencies() {
        let target = node(NodeKind::Command, "a-target", Phase::Run);
        let predecessor = node(NodeKind::Command, "z-predecessor", Phase::Run);
        let external = node(NodeKind::Command, "external", Phase::Run);
        let mut graph = Graph::empty(crate::domain::Provider::Github, "ci.yml");
        graph.nodes = vec![target.clone(), predecessor.clone(), external.clone()];
        graph.edges = vec![
            Edge::simple(EdgeKind::Control, predecessor.id, target.id),
            Edge::simple(EdgeKind::Data, target.id, predecessor.id),
            Edge::simple(EdgeKind::Control, external.id, predecessor.id),
        ];
        let selected = BTreeSet::from([target.id, predecessor.id]);
        let ordered: Vec<_> = topological_nodes(&graph, &selected)
            .into_iter()
            .map(|node| node.name.as_str())
            .collect();
        assert_eq!(ordered, ["z-predecessor", "a-target"]);

        graph
            .edges
            .push(Edge::simple(EdgeKind::Call, target.id, predecessor.id));
        let cyclic: Vec<_> = topological_nodes(&graph, &selected)
            .into_iter()
            .map(|node| node.name.as_str())
            .collect();
        assert_eq!(cyclic, ["a-target", "z-predecessor"]);
    }
}
