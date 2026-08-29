use crate::domain::{AbstractValue, Condition, UnknownReason};
use crate::foundation::{SourceId, Span, normalize_slashes};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_PROVISIONAL_NODE_ID: AtomicU32 = AtomicU32::new(0);

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

/// Dense node index in a finalized program.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u32);

impl NodeId {
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    fn provisional() -> Self {
        let id = NEXT_PROVISIONAL_NODE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("provisional node ID space exhausted");
        Self(id)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One interned source. Its ID is always its index in `Program::sources`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Source {
    pub id: SourceId,
    pub path: String,
    pub provider: Provider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub id: NodeId,
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

/// Semantic fields grouped separately from a node's structural identity.
pub struct NodeSemantics<C, E> {
    condition: Condition,
    attributes: BTreeMap<String, AbstractValue>,
    capabilities: C,
    effects: E,
    unknown: Option<UnknownReason>,
}

impl Node {
    /// Rebind this node and all spans embedded in its abstract attributes.
    pub fn remap_sources(&mut self, remap: &HashMap<SourceId, SourceId>) {
        self.span.source = remap
            .get(&self.span.source)
            .copied()
            .unwrap_or(self.span.source);
        for value in self.attributes.values_mut() {
            value.remap_sources(remap);
        }
    }

    #[must_use]
    pub fn semantics<C, E>(
        condition: Condition,
        attributes: BTreeMap<String, AbstractValue>,
        capabilities: C,
        effects: E,
        unknown: Option<UnknownReason>,
    ) -> NodeSemantics<C, E> {
        NodeSemantics {
            condition,
            attributes,
            capabilities,
            effects,
            unknown,
        }
    }

    #[must_use]
    pub fn new<C, E>(
        provider: Provider,
        kind: NodeKind,
        name: impl Into<String>,
        phase: Phase,
        span: Span,
        semantics: NodeSemantics<C, E>,
    ) -> Self
    where
        C: IntoIterator<Item = Capability>,
        E: IntoIterator<Item = ObservableEffect>,
    {
        let NodeSemantics {
            condition,
            attributes,
            capabilities,
            effects,
            unknown,
        } = semantics;
        let name = name.into();
        let id = NodeId::provisional();
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
            Self::semantics(Condition::True, BTreeMap::new(), [], [], None),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub kind: EdgeKind,
    pub from: NodeId,
    pub to: NodeId,
    pub condition: Condition,
    pub label: Option<String>,
}

impl Edge {
    #[must_use]
    pub fn new(
        kind: EdgeKind,
        from: NodeId,
        to: NodeId,
        condition: Condition,
        label: Option<String>,
    ) -> Self {
        Self {
            kind,
            from,
            to,
            condition,
            label,
        }
    }

    #[must_use]
    pub fn simple(kind: EdgeKind, from: NodeId, to: NodeId) -> Self {
        Self::new(kind, from, to, Condition::True, None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub sources: Vec<Source>,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub entrypoints: Vec<NodeId>,
}

/// A frontend fragment is represented by the same dense storage as a linked
/// program. The analyzer exposes `Program`; providers use this alias while
/// lowering one source at a time.
pub type Graph = Program;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrIssue {
    pub code: String,
    pub message: String,
    pub node_ids: Vec<NodeId>,
}

impl Program {
    #[must_use]
    pub fn empty(provider: Provider, source: impl Into<String>) -> Self {
        Self {
            sources: vec![Source {
                id: SourceId(0),
                path: normalize_slashes(&source.into()),
                provider,
            }],
            nodes: Vec::new(),
            edges: Vec::new(),
            entrypoints: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: Edge) {
        if edge.from != edge.to {
            self.edges.push(edge);
        }
    }

    pub fn add_entrypoint(&mut self, id: NodeId) {
        self.entrypoints.push(id);
    }

    #[must_use]
    pub fn source(&self, id: SourceId) -> Option<&Source> {
        self.sources
            .get(id.index())
            .filter(|source| source.id == id)
    }

    #[must_use]
    pub fn source_path(&self) -> &str {
        self.sources
            .first()
            .map_or("<unknown>", |source| source.path.as_str())
    }

    #[must_use]
    pub fn source_path_for(&self, id: SourceId) -> Option<&str> {
        self.source(id).map(|source| source.path.as_str())
    }

    #[must_use]
    pub fn provider(&self) -> Provider {
        self.sources
            .first()
            .map_or(Provider::Github, |source| source.provider)
    }

    /// Canonicalize source order, node order, and endpoints, assigning dense
    /// IDs exactly once for the finalized storage.
    pub fn finalize(&mut self) {
        self.sources.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.provider.cmp(&right.provider))
        });
        let source_remap: HashMap<_, _> = self
            .sources
            .iter_mut()
            .enumerate()
            .map(|(index, source)| {
                let old = source.id;
                source.id = SourceId(u32::try_from(index).unwrap_or(u32::MAX));
                (old, source.id)
            })
            .collect();
        for node in &mut self.nodes {
            node.remap_sources(&source_remap);
        }
        let sources = &self.sources;
        self.nodes.sort_by(|left, right| {
            let left_path = sources
                .get(left.span.source.index())
                .map_or("", |source| source.path.as_str());
            let right_path = sources
                .get(right.span.source.index())
                .map_or("", |source| source.path.as_str());
            left_path
                .cmp(right_path)
                .then(left.span.cmp(&right.span))
                .then(left.provider.cmp(&right.provider))
                .then(left.kind.cmp(&right.kind))
                .then(left.name.cmp(&right.name))
                .then(left.phase.cmp(&right.phase))
        });
        let node_remap: HashMap<_, _> = self
            .nodes
            .iter_mut()
            .enumerate()
            .map(|(index, node)| {
                let old = node.id;
                node.id = NodeId(u32::try_from(index).unwrap_or(u32::MAX));
                (old, node.id)
            })
            .collect();
        for edge in &mut self.edges {
            edge.from = node_remap.get(&edge.from).copied().unwrap_or(edge.from);
            edge.to = node_remap.get(&edge.to).copied().unwrap_or(edge.to);
        }
        for entrypoint in &mut self.entrypoints {
            *entrypoint = node_remap.get(entrypoint).copied().unwrap_or(*entrypoint);
        }
        self.edges.retain(|edge| edge.from != edge.to);
        self.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then(left.to.cmp(&right.to))
                .then(left.kind.cmp(&right.kind))
                .then_with(|| left.condition.to_string().cmp(&right.condition.to_string()))
                .then(left.label.cmp(&right.label))
        });
        self.edges.dedup();
        self.entrypoints.sort();
        self.entrypoints.dedup();
    }

    #[must_use]
    pub fn find_node(&self, id: NodeId) -> Option<&Node> {
        self.nodes
            .get(id.index())
            .filter(|node| node.id == id)
            .or_else(|| self.nodes.iter().find(|node| node.id == id))
    }

    #[must_use]
    pub fn successors(&self, id: NodeId, kind: Option<EdgeKind>) -> Vec<&Node> {
        self.edges
            .iter()
            .filter(|edge| edge.from == id && kind.is_none_or(|wanted| edge.kind == wanted))
            .filter_map(|edge| self.find_node(edge.to))
            .collect()
    }

    #[must_use]
    pub fn predecessors(&self, id: NodeId, kind: Option<EdgeKind>) -> Vec<&Node> {
        self.edges
            .iter()
            .filter(|edge| edge.to == id && kind.is_none_or(|wanted| edge.kind == wanted))
            .filter_map(|edge| self.find_node(edge.from))
            .collect()
    }

    #[must_use]
    pub fn validate(&self) -> Vec<IrIssue> {
        let mut issues = Vec::new();
        let mut seen = BTreeSet::new();
        let nodes: HashMap<NodeId, &Node> = self
            .nodes
            .iter()
            .filter_map(|node| {
                if seen.insert(node.id) {
                    Some((node.id, node))
                } else {
                    issues.push(IrIssue {
                        code: "IR-DUPLICATE-NODE".to_owned(),
                        message: format!("duplicate node ID {}", node.id),
                        node_ids: vec![node.id],
                    });
                    None
                }
            })
            .collect();
        for edge in &self.edges {
            match (nodes.get(&edge.from), nodes.get(&edge.to)) {
                (Some(source), Some(target)) => {
                    if edge.kind == EdgeKind::Data && source.phase > target.phase {
                        issues.push(IrIssue {
                            code: "IR-PHASE-ORDER".to_owned(),
                            message: format!(
                                "{} data is unavailable during {}",
                                source.phase.name(),
                                target.phase.name()
                            ),
                            node_ids: vec![source.id, target.id],
                        });
                    }
                }
                _ => issues.push(IrIssue {
                    code: "IR-DANGLING-EDGE".to_owned(),
                    message: format!(
                        "{} edge {} -> {} has a missing endpoint",
                        edge.kind.name(),
                        edge.from,
                        edge.to
                    ),
                    node_ids: vec![edge.from, edge.to],
                }),
            }
        }
        issues.sort();
        issues
    }
}
