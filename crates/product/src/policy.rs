use std::collections::{BTreeMap, BTreeSet, VecDeque};
use workflow_verifier_domain::{
    AbstractValue, Capability, EdgeKind, Graph, Node, NodeKind, ObservableEffect, Provider,
    Trust as ValueTrust,
};
use workflow_verifier_foundation::{
    DependencyClass, JsonValue, Span, classify_reference, normalize_slashes, valid_content_digest,
};
use workflow_verifier_frontend::Mutability;
use workflow_verifier_verifier::{Confidence, Diagnostic, Severity, TraceHop};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PolicyTrust {
    Trusted,
    Untrusted,
    Mixed,
    Unknown,
}

impl PolicyTrust {
    fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPredicate {
    Provider(Provider),
    NodeKind(NodeKind),
    PathPrefix(String),
    Trust(PolicyTrust),
    Effect(ObservableEffect),
    Capability(Capability),
    DependencyMutability(Mutability),
    DominatedByGate(bool),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySelector {
    All(Vec<PolicyPredicate>),
    Any(Vec<PolicyPredicate>),
    NoneOf(Vec<PolicyPredicate>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyRuleKind {
    Forbid,
    Require,
    Limit(usize),
    ForbidPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub id: String,
    pub kind: PolicyRuleKind,
    pub selector: PolicySelector,
    pub message: String,
    pub severity: Severity,
}

/// Parse a single config-v2 policy selector assignment.
///
/// # Errors
/// Returns a stable message for unsupported keys and values.
pub fn policy_predicate(key: &str, value: &str) -> Result<PolicyPredicate, String> {
    let lower = value.to_ascii_lowercase();
    match key {
        "provider" => provider(&lower)
            .map(PolicyPredicate::Provider)
            .ok_or_else(|| "unknown provider".to_owned()),
        "kind" | "node_kind" => node_kind(&lower)
            .map(PolicyPredicate::NodeKind)
            .ok_or_else(|| "unknown node kind".to_owned()),
        "path" => Ok(PolicyPredicate::PathPrefix(normalize_slashes(value))),
        "trust" => match lower.as_str() {
            "trusted" => Ok(PolicyPredicate::Trust(PolicyTrust::Trusted)),
            "untrusted" => Ok(PolicyPredicate::Trust(PolicyTrust::Untrusted)),
            "mixed" => Ok(PolicyPredicate::Trust(PolicyTrust::Mixed)),
            "unknown" => Ok(PolicyPredicate::Trust(PolicyTrust::Unknown)),
            _ => Err("unknown trust state".to_owned()),
        },
        "effect" => effect(&lower)
            .map(PolicyPredicate::Effect)
            .ok_or_else(|| "unknown effect".to_owned()),
        "capability" => capability(&lower)
            .map(PolicyPredicate::Capability)
            .ok_or_else(|| "unknown capability".to_owned()),
        "dependency_mutability" | "mutability" => match lower.as_str() {
            "immutable" => Ok(PolicyPredicate::DependencyMutability(Mutability::Immutable)),
            "mutable" => Ok(PolicyPredicate::DependencyMutability(Mutability::Mutable)),
            "local" => Ok(PolicyPredicate::DependencyMutability(Mutability::Local)),
            "unknown" => Ok(PolicyPredicate::DependencyMutability(Mutability::Unknown)),
            _ => Err("unknown dependency mutability".to_owned()),
        },
        "dominance" | "dominated_by_gate" => match lower.as_str() {
            "true" => Ok(PolicyPredicate::DominatedByGate(true)),
            "false" => Ok(PolicyPredicate::DominatedByGate(false)),
            _ => Err("dominance must be true or false".to_owned()),
        },
        _ => Err(format!("unknown selector field: {key}")),
    }
}

#[must_use]
pub fn evaluate_policy(rules: &[PolicyRule], graph: &Graph) -> Vec<Diagnostic> {
    let index = GraphIndex::new(graph);
    let mut nodes: Vec<_> = graph.nodes.iter().collect();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    let mut diagnostics = Vec::new();
    for rule in rules {
        let matches: Vec<_> = nodes
            .iter()
            .copied()
            .filter(|node| selector_matches(&index, node, &rule.selector))
            .collect();
        match rule.kind {
            PolicyRuleKind::Forbid => diagnostics.extend(
                matches
                    .into_iter()
                    .map(|node| diagnostic(rule, node, "policy selector matched")),
            ),
            PolicyRuleKind::Require if matches.is_empty() => diagnostics.push(Diagnostic::new(
                rule.id.clone(),
                rule.severity,
                Confidence::High,
                rule.message.clone(),
                Span::default(),
                Vec::new(),
                [],
                [],
                None,
            )),
            PolicyRuleKind::Limit(maximum) => diagnostics.extend(
                matches
                    .into_iter()
                    .skip(maximum)
                    .map(|node| diagnostic(rule, node, "policy limit exceeded")),
            ),
            PolicyRuleKind::ForbidPath => {
                diagnostics.extend(path_diagnostics(rule, graph, &index, &matches));
            }
            PolicyRuleKind::Require => {}
        }
    }
    diagnostics.sort();
    diagnostics
}

fn diagnostic(rule: &PolicyRule, node: &Node, label: &str) -> Diagnostic {
    Diagnostic::new(
        rule.id.clone(),
        rule.severity,
        Confidence::High,
        rule.message.clone(),
        node.span.clone(),
        vec![TraceHop {
            node_id: node.id.clone(),
            label: label.to_owned(),
            span: node.span.clone(),
        }],
        [],
        [],
        None,
    )
}

fn path_diagnostics(
    rule: &PolicyRule,
    graph: &Graph,
    index: &GraphIndex<'_>,
    sinks: &[&Node],
) -> Vec<Diagnostic> {
    let sources: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| joined_value(node).is_untrusted())
        .collect();
    sinks
        .iter()
        .filter_map(|sink| {
            let mut candidates: Vec<_> = sources
                .iter()
                .filter_map(|source| index.shortest_path(&source.id, &sink.id))
                .collect();
            candidates.sort_by(|left, right| {
                left.len().cmp(&right.len()).then_with(|| {
                    left.iter()
                        .map(|node| node.id.as_str())
                        .cmp(right.iter().map(|node| node.id.as_str()))
                })
            });
            let path = candidates.into_iter().next()?;
            let capabilities: BTreeSet<_> = path
                .iter()
                .flat_map(|node| node.capabilities.iter().copied())
                .collect();
            let last = path.len().saturating_sub(1);
            let trace = path
                .iter()
                .enumerate()
                .map(|(index, node)| TraceHop {
                    node_id: node.id.clone(),
                    label: if index == 0 {
                        "untrusted source"
                    } else if index == last {
                        "policy-selected effect"
                    } else {
                        "reachable semantic path"
                    }
                    .to_owned(),
                    span: node.span.clone(),
                })
                .collect();
            Some(Diagnostic::new(
                rule.id.clone(),
                rule.severity,
                Confidence::High,
                rule.message.clone(),
                sink.span.clone(),
                trace,
                capabilities,
                ["feasible source-to-effect path".to_owned()],
                None,
            ))
        })
        .collect()
}

fn selector_matches(index: &GraphIndex<'_>, node: &Node, selector: &PolicySelector) -> bool {
    match selector {
        PolicySelector::All(predicates) => predicates
            .iter()
            .all(|predicate| predicate_matches(index, node, predicate)),
        PolicySelector::Any(predicates) => predicates
            .iter()
            .any(|predicate| predicate_matches(index, node, predicate)),
        PolicySelector::NoneOf(predicates) => !predicates
            .iter()
            .any(|predicate| predicate_matches(index, node, predicate)),
    }
}

fn predicate_matches(index: &GraphIndex<'_>, node: &Node, predicate: &PolicyPredicate) -> bool {
    match predicate {
        PolicyPredicate::Provider(provider) => node.provider == *provider,
        PolicyPredicate::NodeKind(kind) => node.kind == *kind,
        PolicyPredicate::PathPrefix(prefix) => {
            normalize_slashes(&node.span.file).starts_with(prefix)
        }
        PolicyPredicate::Trust(expected) => matches!(
            (&joined_value(node).trust, expected),
            (ValueTrust::Trusted, PolicyTrust::Trusted)
                | (ValueTrust::Untrusted, PolicyTrust::Untrusted)
                | (ValueTrust::Mixed, PolicyTrust::Mixed)
                | (ValueTrust::Unknown(_), PolicyTrust::Unknown)
        ),
        PolicyPredicate::Effect(effect) => effects(node).contains(effect),
        PolicyPredicate::Capability(capability) => node.capabilities.contains(capability),
        PolicyPredicate::DependencyMutability(expected) => mutability(node) == *expected,
        PolicyPredicate::DominatedByGate(expected) => index.gate_dominates(node) == *expected,
    }
}

fn joined_value(node: &Node) -> AbstractValue {
    node.attributes
        .values()
        .fold(AbstractValue::default(), |value, next| value.join(next))
}

fn mutability(node: &Node) -> Mutability {
    if node.kind != NodeKind::Call {
        return Mutability::Unknown;
    }
    let locked = node
        .attributes
        .get("dependency.digest")
        .and_then(AbstractValue::constants)
        .is_some_and(|values| {
            !values.is_empty() && values.iter().all(|value| valid_content_digest(value))
        });
    if locked {
        return Mutability::Immutable;
    }
    match classify_reference(&node.name) {
        DependencyClass::Immutable => Mutability::Immutable,
        DependencyClass::Mutable => Mutability::Mutable,
        DependencyClass::Local => Mutability::Local,
        DependencyClass::Unknown => Mutability::Unknown,
    }
}

fn effects(node: &Node) -> BTreeSet<ObservableEffect> {
    let mut effects: BTreeSet<_> = node.effects.iter().copied().collect();
    if node.kind == NodeKind::Command {
        effects.insert(ObservableEffect::CommandExecution);
        let source = node
            .attributes
            .get("command")
            .and_then(AbstractValue::constants)
            .and_then(|values| values.iter().max_by_key(|value| value.len()))
            .map_or(node.name.as_str(), String::as_str)
            .to_ascii_lowercase();
        if ["curl ", "wget ", "invoke-webrequest", "fetch(", "requests."]
            .iter()
            .any(|marker| source.contains(marker))
        {
            effects.insert(ObservableEffect::NetworkRequest);
        }
        if source.contains("git push")
            || source.contains("gh pr merge")
            || source.contains("gh release")
        {
            effects.insert(ObservableEffect::RepositoryChange);
        }
    }
    effects
}

struct GraphIndex<'a> {
    graph: &'a Graph,
    nodes: BTreeMap<&'a str, &'a Node>,
    outgoing: BTreeMap<&'a str, Vec<&'a str>>,
}

impl<'a> GraphIndex<'a> {
    fn new(graph: &'a Graph) -> Self {
        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect();
        let mut outgoing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &graph.edges {
            if matches!(
                edge.kind,
                EdgeKind::Control
                    | EdgeKind::Call
                    | EdgeKind::Data
                    | EdgeKind::Read
                    | EdgeKind::Write
                    | EdgeKind::Persist
            ) {
                outgoing.entry(&edge.from).or_default().push(&edge.to);
            }
        }
        for next in outgoing.values_mut() {
            next.sort_unstable();
            next.dedup();
        }
        Self {
            graph,
            nodes,
            outgoing,
        }
    }

    fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<&'a Node>> {
        let mut queue = VecDeque::from([from]);
        let mut previous: BTreeMap<&str, Option<&str>> = BTreeMap::from([(from, None)]);
        while let Some(current) = queue.pop_front() {
            if current == to {
                let mut ids = Vec::new();
                let mut cursor = Some(current);
                while let Some(id) = cursor {
                    ids.push(id);
                    cursor = previous.get(id).copied().flatten();
                }
                ids.reverse();
                return Some(
                    ids.into_iter()
                        .filter_map(|id| self.nodes.get(id).copied())
                        .collect(),
                );
            }
            for next in self.outgoing.get(current).into_iter().flatten() {
                if !previous.contains_key(next) {
                    previous.insert(next, Some(current));
                    queue.push_back(next);
                }
            }
        }
        None
    }

    fn gate_dominates(&self, node: &Node) -> bool {
        self.graph
            .nodes
            .iter()
            .filter(|candidate| candidate.kind == NodeKind::Gate)
            .any(|gate| self.dominates(&gate.id, &node.id))
    }

    fn dominates(&self, dominator: &str, node: &str) -> bool {
        if dominator == node {
            return true;
        }
        let entrypoints: Vec<&str> = if self.graph.entrypoints.is_empty() {
            self.nodes
                .keys()
                .copied()
                .filter(|id| !self.graph.edges.iter().any(|edge| edge.to == *id))
                .collect()
        } else {
            self.graph.entrypoints.iter().map(String::as_str).collect()
        };
        !entrypoints
            .iter()
            .any(|entry| self.path_avoiding(entry, node, dominator))
    }

    fn path_avoiding(&self, from: &str, to: &str, avoided: &str) -> bool {
        if from == avoided {
            return false;
        }
        let mut queue = VecDeque::from([from]);
        let mut seen = BTreeSet::from([from]);
        while let Some(current) = queue.pop_front() {
            if current == to {
                return true;
            }
            for next in self.outgoing.get(current).into_iter().flatten() {
                if *next != avoided && seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        false
    }
}

#[must_use]
pub(crate) fn rule_json(rule: &PolicyRule) -> JsonValue {
    let (selector_name, predicates) = match &rule.selector {
        PolicySelector::All(values) => ("all", values),
        PolicySelector::Any(values) => ("any", values),
        PolicySelector::NoneOf(values) => ("none", values),
    };
    let (kind, limit) = match rule.kind {
        PolicyRuleKind::Forbid => ("forbid", JsonValue::Null),
        PolicyRuleKind::Require => ("require", JsonValue::Null),
        PolicyRuleKind::Limit(value) => (
            "limit",
            JsonValue::Integer(i64::try_from(value).unwrap_or(i64::MAX)),
        ),
        PolicyRuleKind::ForbidPath => ("forbid_path", JsonValue::Null),
    };
    JsonValue::Object(BTreeMap::from([
        ("id".to_owned(), JsonValue::String(rule.id.clone())),
        ("kind".to_owned(), JsonValue::String(kind.to_owned())),
        ("limit".to_owned(), limit),
        (
            "message".to_owned(),
            JsonValue::String(rule.message.clone()),
        ),
        (
            "selector".to_owned(),
            JsonValue::Object(BTreeMap::from([(
                selector_name.to_owned(),
                JsonValue::Array(predicates.iter().map(predicate_json).collect()),
            )])),
        ),
        (
            "severity".to_owned(),
            JsonValue::String(rule.severity.name().to_owned()),
        ),
    ]))
}

fn predicate_json(predicate: &PolicyPredicate) -> JsonValue {
    let (name, value) = match predicate {
        PolicyPredicate::Provider(value) => {
            ("provider", JsonValue::String(value.name().to_owned()))
        }
        PolicyPredicate::NodeKind(value) => ("kind", JsonValue::String(value.name().to_owned())),
        PolicyPredicate::PathPrefix(value) => ("path", JsonValue::String(value.clone())),
        PolicyPredicate::Trust(value) => ("trust", JsonValue::String(value.name().to_owned())),
        PolicyPredicate::Effect(value) => ("effect", JsonValue::String(value.name().to_owned())),
        PolicyPredicate::Capability(value) => {
            ("capability", JsonValue::String(value.name().to_owned()))
        }
        PolicyPredicate::DependencyMutability(value) => (
            "mutability",
            JsonValue::String(
                match value {
                    Mutability::Immutable => "immutable",
                    Mutability::Mutable => "mutable",
                    Mutability::Local => "local",
                    Mutability::Unknown => "unknown",
                }
                .to_owned(),
            ),
        ),
        PolicyPredicate::DominatedByGate(value) => {
            ("dominated_by_gate", JsonValue::Boolean(*value))
        }
    };
    JsonValue::Object(BTreeMap::from([(name.to_owned(), value)]))
}

fn provider(value: &str) -> Option<Provider> {
    Some(match value {
        "github" => Provider::Github,
        "gitlab" => Provider::Gitlab,
        "azure" => Provider::Azure,
        "circleci" => Provider::Circleci,
        _ => return None,
    })
}

fn node_kind(value: &str) -> Option<NodeKind> {
    Some(match value {
        "trigger" => NodeKind::Trigger,
        "parameter" => NodeKind::Parameter,
        "workflow" => NodeKind::Workflow,
        "stage" => NodeKind::Stage,
        "job" => NodeKind::Job,
        "step" => NodeKind::Step,
        "call" => NodeKind::Call,
        "command" => NodeKind::Command,
        "gate" => NodeKind::Gate,
        "resource" => NodeKind::Resource,
        "effect" => NodeKind::Effect,
        "opaque" => NodeKind::Opaque,
        _ => return None,
    })
}

fn effect(value: &str) -> Option<ObservableEffect> {
    Some(match value {
        "repository_change" => ObservableEffect::RepositoryChange,
        "network" | "network_request" => ObservableEffect::NetworkRequest,
        "file_read" => ObservableEffect::FileRead,
        "file_write" => ObservableEffect::FileWrite,
        "command_execution" => ObservableEffect::CommandExecution,
        "artifact_publish" => ObservableEffect::ArtifactPublish,
        "cache_publish" => ObservableEffect::CachePublish,
        "deployment" | "deployment_change" => ObservableEffect::DeploymentChange,
        "credential_use" => ObservableEffect::CredentialUse,
        "workflow_change" => ObservableEffect::WorkflowChange,
        "ai_agent_execution" => ObservableEffect::AiAgentExecution,
        _ => return None,
    })
}

fn capability(value: &str) -> Option<Capability> {
    const VALUES: [Capability; 18] = [
        Capability::RepositoryRead,
        Capability::RepositoryWrite,
        Capability::TokenRead,
        Capability::TokenWrite,
        Capability::Oidc,
        Capability::CloudCredential,
        Capability::SecretAccess,
        Capability::Network,
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::Shell,
        Capability::ArtifactRead,
        Capability::ArtifactWrite,
        Capability::CacheRead,
        Capability::CacheWrite,
        Capability::Deployment,
        Capability::SelfHostedPersistence,
        Capability::AiTool,
    ];
    VALUES
        .into_iter()
        .find(|candidate| candidate.name() == value)
}
