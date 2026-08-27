use crate::Scenario;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use workflow_verifier_domain::{EdgeKind, Graph, Node, NodeKind, Phase, Truth};
use workflow_verifier_foundation::normalize_slashes;
use workflow_verifier_runner_protocol::Step;
use workflow_verifier_verifier::compose_program;

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
            graph.provider == scenario.provider
                && source_matches(&scenario.workflow_entrypoint, &graph.source)
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
    let job_ids = job_closure(&program, &selected.id);
    let reachability = descendants(&program, &job_ids, scenario);
    let selected_ids: BTreeSet<_> = reachability
        .iter()
        .filter_map(|(id, truth)| (*truth != Truth::False).then_some(id.clone()))
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

fn job_closure(graph: &Graph, selected: &str) -> BTreeSet<String> {
    fn visit(graph: &Graph, id: &str, seen: &mut BTreeSet<String>) {
        if !seen.insert(id.to_owned()) {
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
            .map(|node| node.id.clone())
            .collect();
        for predecessor in predecessors {
            visit(graph, &predecessor, seen);
        }
    }
    let mut seen = BTreeSet::new();
    visit(graph, selected, &mut seen);
    seen
}

fn descendants(
    graph: &Graph,
    jobs: &BTreeSet<String>,
    scenario: &Scenario,
) -> BTreeMap<String, Truth> {
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
            .filter_map(|edge| graph.find_node(&edge.from))
            .filter(|node| node.kind == NodeKind::Gate)
            .collect();
        if gates.is_empty() {
            queue.push_back((job.clone(), false, Truth::True));
        } else {
            for gate in gates {
                queue.push_back((gate.id.clone(), false, Truth::True));
            }
        }
    }

    let mut states: BTreeMap<(String, bool), Truth> = BTreeMap::new();
    while let Some((id, allow_local_jobs, incoming)) = queue.pop_front() {
        let Some(node) = graph.find_node(&id) else {
            continue;
        };
        let node_truth = truth_and(
            incoming,
            node.condition
                .evaluate(&|atom| scenario_fact(scenario, atom)),
        );
        let key = (id.clone(), allow_local_jobs);
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
            let Some(target) = graph.find_node(&edge.to) else {
                continue;
            };
            if target.kind == NodeKind::Job && !jobs.contains(&target.id) && !allow_local {
                continue;
            }
            let edge_truth = edge
                .condition
                .evaluate(&|atom| scenario_fact(scenario, atom));
            queue.push_back((
                target.id.clone(),
                allow_local,
                truth_and(merged, edge_truth),
            ));
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

fn topological_nodes<'a>(graph: &'a Graph, selected: &BTreeSet<String>) -> Vec<&'a Node> {
    let mut remaining: BTreeSet<_> = selected.iter().cloned().collect();
    let mut emitted = BTreeSet::new();
    let mut output = Vec::new();
    while !remaining.is_empty() {
        let mut ready: Vec<_> = remaining
            .iter()
            .filter_map(|id| graph.nodes.iter().find(|node| node.id == *id))
            .filter(|node| {
                graph.edges.iter().all(|edge| {
                    !matches!(edge.kind, EdgeKind::Control | EdgeKind::Call)
                        || edge.to != node.id
                        || !selected.contains(&edge.from)
                        || emitted.contains(&edge.from)
                })
            })
            .collect();
        if ready.is_empty() {
            ready = remaining
                .iter()
                .filter_map(|id| graph.nodes.iter().find(|node| node.id == *id))
                .collect();
        }
        ready.sort_by(|left, right| {
            left.span
                .cmp(&right.span)
                .then(left.kind.cmp(&right.kind))
                .then(left.name.cmp(&right.name))
                .then(left.id.cmp(&right.id))
        });
        for node in ready {
            if remaining.remove(&node.id) {
                emitted.insert(node.id.clone());
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
        id: node.id.clone(),
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
            workflow_verifier_foundation::JsonValue::String(value) => value.clone(),
            workflow_verifier_foundation::JsonValue::Boolean(value) => value.to_string(),
            workflow_verifier_foundation::JsonValue::Integer(value) => value.to_string(),
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
