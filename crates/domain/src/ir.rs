use crate::{AbstractValue, Condition, UnknownReason};
use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, Span, sha256_hex};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Provider {
    Github,
    Gitlab,
    Azure,
    Circleci,
}

impl Provider {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Azure => "azure",
            Self::Circleci => "circleci",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Phase {
    Source,
    Compile,
    Plan,
    Run,
    Post,
}

impl Phase {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Compile => "compile",
            Self::Plan => "plan",
            Self::Run => "run",
            Self::Post => "post",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NodeKind {
    Trigger,
    Parameter,
    Workflow,
    Stage,
    Job,
    Step,
    Call,
    Command,
    Gate,
    Resource,
    Effect,
    Opaque,
}

impl NodeKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Parameter => "parameter",
            Self::Workflow => "workflow",
            Self::Stage => "stage",
            Self::Job => "job",
            Self::Step => "step",
            Self::Call => "call",
            Self::Command => "command",
            Self::Gate => "gate",
            Self::Resource => "resource",
            Self::Effect => "effect",
            Self::Opaque => "opaque",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EdgeKind {
    Control,
    Data,
    Call,
    Grant,
    Persist,
    Read,
    Write,
}

impl EdgeKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::Call => "call",
            Self::Grant => "grant",
            Self::Persist => "persist",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    RepositoryRead,
    RepositoryWrite,
    TokenRead,
    TokenWrite,
    Oidc,
    CloudCredential,
    SecretAccess,
    Network,
    FilesystemRead,
    FilesystemWrite,
    Shell,
    ArtifactRead,
    ArtifactWrite,
    CacheRead,
    CacheWrite,
    Deployment,
    SelfHostedPersistence,
    AiTool,
}

impl Capability {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RepositoryRead => "repository_read",
            Self::RepositoryWrite => "repository_write",
            Self::TokenRead => "token_read",
            Self::TokenWrite => "token_write",
            Self::Oidc => "oidc",
            Self::CloudCredential => "cloud_credential",
            Self::SecretAccess => "secret_access",
            Self::Network => "network",
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::Shell => "shell",
            Self::ArtifactRead => "artifact_read",
            Self::ArtifactWrite => "artifact_write",
            Self::CacheRead => "cache_read",
            Self::CacheWrite => "cache_write",
            Self::Deployment => "deployment",
            Self::SelfHostedPersistence => "self_hosted_persistence",
            Self::AiTool => "ai_tool",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservableEffect {
    RepositoryChange,
    NetworkRequest,
    FileRead,
    FileWrite,
    CommandExecution,
    ArtifactPublish,
    CachePublish,
    DeploymentChange,
    CredentialUse,
    WorkflowChange,
    AiAgentExecution,
}

impl ObservableEffect {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RepositoryChange => "repository_change",
            Self::NetworkRequest => "network_request",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::CommandExecution => "command_execution",
            Self::ArtifactPublish => "artifact_publish",
            Self::CachePublish => "cache_publish",
            Self::DeploymentChange => "deployment_change",
            Self::CredentialUse => "credential_use",
            Self::WorkflowChange => "workflow_change",
            Self::AiAgentExecution => "ai_agent_execution",
        }
    }
}

fn identifier(components: &[&str]) -> String {
    let bytes = components.join("\0");
    let digest = sha256_hex(bytes);
    let prefix = digest.get(..20).unwrap_or(&digest);
    format!("wv_{prefix}")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub id: String,
    pub provider: Provider,
    pub kind: NodeKind,
    pub name: String,
    pub phase: Phase,
    pub span: Span,
    pub condition: Condition,
    pub attributes: BTreeMap<String, AbstractValue>,
    pub capabilities: Vec<Capability>,
    pub effects: Vec<ObservableEffect>,
    pub unknown: Option<UnknownReason>,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        provider: Provider,
        kind: NodeKind,
        name: impl Into<String>,
        phase: Phase,
        span: Span,
        condition: Condition,
        attributes: BTreeMap<String, AbstractValue>,
        capabilities: impl IntoIterator<Item = Capability>,
        effects: impl IntoIterator<Item = ObservableEffect>,
        unknown: Option<UnknownReason>,
    ) -> Self {
        let name = name.into();
        let start = span.start.byte.to_string();
        let stop = span.stop.byte.to_string();
        let file = span.file.replace('\\', "/");
        let id = identifier(&[provider.name(), kind.name(), &name, &file, &start, &stop]);
        Self {
            id,
            provider,
            kind,
            name,
            phase,
            span,
            condition,
            attributes,
            capabilities: capabilities
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            effects: effects
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            unknown,
        }
    }

    #[must_use]
    pub fn simple(
        provider: Provider,
        kind: NodeKind,
        name: impl Into<String>,
        phase: Phase,
        span: Span,
    ) -> Self {
        Self::new(
            provider,
            kind,
            name,
            phase,
            span,
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            None,
        )
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "attributes".to_owned(),
                JsonValue::Object(
                    self.attributes
                        .iter()
                        .map(|(key, value)| (key.clone(), value.to_json()))
                        .collect(),
                ),
            ),
            (
                "capabilities".to_owned(),
                JsonValue::Array(
                    self.capabilities
                        .iter()
                        .map(|value| JsonValue::String(value.name().to_owned()))
                        .collect(),
                ),
            ),
            ("condition".to_owned(), self.condition.to_json()),
            (
                "effects".to_owned(),
                JsonValue::Array(
                    self.effects
                        .iter()
                        .map(|value| JsonValue::String(value.name().to_owned()))
                        .collect(),
                ),
            ),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            (
                "kind".to_owned(),
                JsonValue::String(self.kind.name().to_owned()),
            ),
            ("name".to_owned(), JsonValue::String(self.name.clone())),
            (
                "phase".to_owned(),
                JsonValue::String(self.phase.name().to_owned()),
            ),
            (
                "provider".to_owned(),
                JsonValue::String(self.provider.name().to_owned()),
            ),
            ("span".to_owned(), self.span.to_json()),
            (
                "unknown".to_owned(),
                self.unknown
                    .as_ref()
                    .map_or(JsonValue::Null, UnknownReason::to_json),
            ),
        ]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub id: String,
    pub kind: EdgeKind,
    pub from: String,
    pub to: String,
    pub condition: Condition,
    pub label: Option<String>,
}

impl Edge {
    #[must_use]
    pub fn new(
        kind: EdgeKind,
        from: impl Into<String>,
        to: impl Into<String>,
        condition: Condition,
        label: Option<String>,
    ) -> Self {
        let from = from.into();
        let to = to.into();
        let condition_text = condition.to_string();
        let label_text = label.as_deref().unwrap_or_default();
        let id = identifier(&["edge", kind.name(), &from, &to, &condition_text, label_text]);
        Self {
            id,
            kind,
            from,
            to,
            condition,
            label,
        }
    }

    #[must_use]
    pub fn simple(kind: EdgeKind, from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(kind, from, to, Condition::True, None)
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            ("condition".to_owned(), self.condition.to_json()),
            ("from".to_owned(), JsonValue::String(self.from.clone())),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            (
                "kind".to_owned(),
                JsonValue::String(self.kind.name().to_owned()),
            ),
            (
                "label".to_owned(),
                self.label
                    .clone()
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
            ("to".to_owned(), JsonValue::String(self.to.clone())),
        ]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Graph {
    pub provider: Provider,
    pub source: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub entrypoints: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrIssue {
    pub code: String,
    pub message: String,
    pub node_ids: Vec<String>,
}

impl Graph {
    #[must_use]
    pub fn empty(provider: Provider, source: impl Into<String>) -> Self {
        Self {
            provider,
            source: source.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
            entrypoints: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: Edge) {
        self.edges.push(edge);
    }

    pub fn add_entrypoint(&mut self, id: impl Into<String>) {
        self.entrypoints.push(id.into());
    }

    pub fn finalize(&mut self) {
        self.nodes.sort_by(|left, right| left.id.cmp(&right.id));
        self.edges.sort_by(|left, right| left.id.cmp(&right.id));
        self.entrypoints.sort();
        self.entrypoints.dedup();
    }

    #[must_use]
    pub fn find_node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|node| node.id == id)
    }

    #[must_use]
    pub fn successors(&self, id: &str, kind: Option<EdgeKind>) -> Vec<&Node> {
        self.edges
            .iter()
            .filter(|edge| edge.from == id && kind.is_none_or(|wanted| edge.kind == wanted))
            .filter_map(|edge| self.find_node(&edge.to))
            .collect()
    }

    #[must_use]
    pub fn predecessors(&self, id: &str, kind: Option<EdgeKind>) -> Vec<&Node> {
        self.edges
            .iter()
            .filter(|edge| edge.to == id && kind.is_none_or(|wanted| edge.kind == wanted))
            .filter_map(|edge| self.find_node(&edge.from))
            .collect()
    }

    #[must_use]
    pub fn validate(&self) -> Vec<IrIssue> {
        let mut issues = Vec::new();
        let mut seen = BTreeSet::new();
        let nodes: BTreeMap<&str, &Node> = self
            .nodes
            .iter()
            .filter_map(|node| {
                if seen.insert(node.id.as_str()) {
                    Some((node.id.as_str(), node))
                } else {
                    issues.push(IrIssue {
                        code: "IR-DUPLICATE-NODE".to_owned(),
                        message: format!("duplicate node ID {}", node.id),
                        node_ids: vec![node.id.clone()],
                    });
                    None
                }
            })
            .collect();
        for edge in &self.edges {
            match (nodes.get(edge.from.as_str()), nodes.get(edge.to.as_str())) {
                (Some(source), Some(target)) => {
                    if edge.kind == EdgeKind::Data && source.phase > target.phase {
                        issues.push(IrIssue {
                            code: "IR-PHASE-ORDER".to_owned(),
                            message: format!(
                                "{} data is unavailable during {}",
                                source.phase.name(),
                                target.phase.name()
                            ),
                            node_ids: vec![source.id.clone(), target.id.clone()],
                        });
                    }
                }
                _ => issues.push(IrIssue {
                    code: "IR-DANGLING-EDGE".to_owned(),
                    message: format!("edge {} has a missing endpoint", edge.id),
                    node_ids: vec![edge.from.clone(), edge.to.clone()],
                }),
            }
        }
        issues.sort();
        issues
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let mut graph = self.clone();
        graph.finalize();
        JsonValue::Object(BTreeMap::from([
            (
                "edges".to_owned(),
                JsonValue::Array(graph.edges.iter().map(Edge::to_json).collect()),
            ),
            (
                "entrypoints".to_owned(),
                JsonValue::Array(
                    graph
                        .entrypoints
                        .into_iter()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            (
                "nodes".to_owned(),
                JsonValue::Array(graph.nodes.iter().map(Node::to_json).collect()),
            ),
            (
                "provider".to_owned(),
                JsonValue::String(graph.provider.name().to_owned()),
            ),
            (
                "source".to_owned(),
                JsonValue::String(graph.source.replace('\\', "/")),
            ),
        ]))
    }
}
