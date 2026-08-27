#![forbid(unsafe_code)]

//! Provider frontends.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use workflow_verifier_domain::{
    AbstractValue, Capability, Condition, Edge, EdgeKind, Graph, Node, NodeKind, ObservableEffect,
    Phase, Provenance, Provider, Secrecy, Trust, UnknownReason,
};
use workflow_verifier_foundation::{
    Budget, DependencyClass, JsonValue, Position, Span, classify_reference,
};
use workflow_verifier_syntax::{MappingEntry, YamlDocument, YamlNode, YamlProblem};

const GITLAB_RESERVED: [&str; 15] = [
    "stages",
    "include",
    "variables",
    "default",
    "workflow",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
    "pages",
    "schedules",
    "spec",
    "types",
    "extends",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PipelinePhase {
    Detected,
    Parsed,
    Expanded,
    Resolved,
    Lowered,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Mutability {
    Immutable,
    Mutable,
    Local,
    Unknown,
}

impl From<DependencyClass> for Mutability {
    fn from(value: DependencyClass) -> Self {
        match value {
            DependencyClass::Immutable => Self::Immutable,
            DependencyClass::Mutable => Self::Mutable,
            DependencyClass::Local => Self::Local,
            DependencyClass::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyKind {
    Action,
    Include,
    Component,
    ContainerImage,
    Task,
    Orb,
    Repository,
    Template,
    Unknown,
}

impl DependencyKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Include => "include",
            Self::Component => "component",
            Self::ContainerImage => "container_image",
            Self::Task => "task",
            Self::Orb => "orb",
            Self::Repository => "repository",
            Self::Template => "template",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyLocator {
    Direct,
    RepositorySource {
        repository: String,
        revision: Option<String>,
        repository_type: Option<String>,
    },
    RepositoryFile {
        repository: String,
        revision: Option<String>,
        path: String,
        repository_type: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyStatus {
    Locked { revision: String, digest: String },
    Unresolved(UnknownReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub provider: Provider,
    pub kind: DependencyKind,
    pub reference: String,
    pub locator: DependencyLocator,
    pub span: Span,
    pub mutability: Mutability,
    pub status: DependencyStatus,
}

impl Dependency {
    #[must_use]
    pub fn unresolved(
        provider: Provider,
        kind: DependencyKind,
        reference: impl Into<String>,
        locator: DependencyLocator,
        span: Span,
    ) -> Self {
        let reference = reference.into();
        Self {
            provider,
            kind,
            mutability: classify_reference(&reference).into(),
            status: DependencyStatus::Unresolved(UnknownReason::UnresolvedDependency(
                reference.clone(),
            )),
            reference,
            locator,
            span,
        }
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let status = match &self.status {
            DependencyStatus::Locked { revision, digest } => JsonValue::Object(BTreeMap::from([
                ("digest".to_owned(), JsonValue::String(digest.clone())),
                ("revision".to_owned(), JsonValue::String(revision.clone())),
                ("state".to_owned(), JsonValue::String("locked".to_owned())),
            ])),
            DependencyStatus::Unresolved(reason) => JsonValue::Object(BTreeMap::from([
                ("reason".to_owned(), reason.to_json()),
                (
                    "state".to_owned(),
                    JsonValue::String("unresolved".to_owned()),
                ),
            ])),
        };
        JsonValue::Object(BTreeMap::from([
            (
                "kind".to_owned(),
                JsonValue::String(self.kind.name().to_owned()),
            ),
            (
                "provider".to_owned(),
                JsonValue::String(self.provider.name().to_owned()),
            ),
            (
                "reference".to_owned(),
                JsonValue::String(self.reference.clone()),
            ),
            ("span".to_owned(), self.span.to_json()),
            ("status".to_owned(), status),
        ]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendProblem {
    pub code: String,
    pub message: String,
    pub span: Span,
}

impl From<&YamlProblem> for FrontendProblem {
    fn from(value: &YamlProblem) -> Self {
        Self {
            code: value.code.clone(),
            message: value.message.clone(),
            span: value.span.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Compilation {
    pub provider: Provider,
    pub phases: Vec<PipelinePhase>,
    pub graph: Graph,
    pub dependencies: Vec<Dependency>,
    pub problems: Vec<FrontendProblem>,
    pub cst: Arc<YamlDocument>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticShape {
    pub workflows: usize,
    pub stages: usize,
    pub jobs: usize,
    pub steps: usize,
    pub calls: usize,
    pub commands: usize,
    pub parameters: usize,
    pub control_edges: usize,
    pub data_edges: usize,
    pub call_edges: usize,
}

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn path_identity(provider: Provider, path: &str) -> bool {
    let path = normalized_path(path);
    match provider {
        Provider::Github => {
            path.starts_with(".github/workflows/")
                || path.contains("/.github/workflows/")
                || matches!(path.as_str(), "action.yml" | "action.yaml")
                || path.ends_with("/action.yml")
                || path.ends_with("/action.yaml")
        }
        Provider::Gitlab => path == ".gitlab-ci.yml" || path.ends_with("/.gitlab-ci.yml"),
        Provider::Azure => {
            matches!(
                path.as_str(),
                "azure-pipelines.yml" | "azure-pipelines.yaml"
            ) || path.ends_with("/azure-pipelines.yml")
                || path.ends_with("/azure-pipelines.yaml")
        }
        Provider::Circleci => {
            path == ".circleci/config.yml"
                || path == ".circleci/config.yaml"
                || path.ends_with("/.circleci/config.yml")
                || path.ends_with("/.circleci/config.yaml")
        }
    }
}

fn has_top_level(source: &str, key: &str) -> bool {
    source.starts_with(&format!("{key}:")) || source.contains(&format!("\n{key}:"))
}

#[must_use]
pub fn detect(path: &str, source: &str) -> Option<Provider> {
    const PROVIDERS: [Provider; 4] = [
        Provider::Github,
        Provider::Gitlab,
        Provider::Azure,
        Provider::Circleci,
    ];
    PROVIDERS
        .into_iter()
        .find(|provider| path_identity(*provider, path))
        .or_else(|| {
            if has_top_level(source, "on") && has_top_level(source, "jobs") {
                Some(Provider::Github)
            } else if has_top_level(source, "workflows") && has_top_level(source, "version") {
                Some(Provider::Circleci)
            } else if has_top_level(source, "stages") && source.contains("script:") {
                Some(Provider::Gitlab)
            } else if has_top_level(source, "trigger")
                && (has_top_level(source, "jobs") || has_top_level(source, "steps"))
            {
                Some(Provider::Azure)
            } else {
                None
            }
        })
}

#[must_use]
pub fn entrypoint(provider: Provider, path: &str, source: &str) -> bool {
    if !path_identity(provider, path) {
        return false;
    }
    let path = normalized_path(path);
    match provider {
        Provider::Github => {
            let Some(name) = path.strip_prefix(".github/workflows/") else {
                return false;
            };
            let yaml_extension = std::path::Path::new(name)
                .extension()
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
                });
            !name.contains('/') && yaml_extension && detect(path.as_str(), source) == Some(provider)
        }
        Provider::Gitlab | Provider::Azure | Provider::Circleci => {
            detect(path.as_str(), source) == Some(provider)
        }
    }
}

/// Compile a provider document through every semantic phase.
///
/// # Errors
/// Returns structured problems for malformed/empty YAML or an unsupported
/// provider identity. Semantic uncertainty inside a valid document stays in
/// the returned graph and does not become a parser error.
pub fn compile_auto(
    path: &str,
    source: &str,
    budget: Budget,
) -> Result<Compilation, Vec<FrontendProblem>> {
    let Some(provider) = detect(path, source) else {
        return Err(vec![FrontendProblem {
            code: "FRONTEND-UNDETECTED".to_owned(),
            message: "the path and document shape do not identify a supported CI provider"
                .to_owned(),
            span: Span::default(),
        }]);
    };
    compile(provider, path, source, budget)
}

/// Compile a source using an already selected provider profile.
///
/// # Errors
/// Returns structured syntax or empty-document problems.
pub fn compile(
    provider: Provider,
    path: &str,
    source: &str,
    budget: Budget,
) -> Result<Compilation, Vec<FrontendProblem>> {
    compile_parsed(
        provider,
        path,
        Arc::new(YamlDocument::parse(path, source, budget)),
    )
}

/// Lower an already parsed document using the selected provider profile.
///
/// This is the cache boundary used by incremental analysis so a content miss
/// is parsed exactly once. The CST remains shared and immutable.
///
/// # Errors
/// Returns the same structured syntax or empty-document problems as
/// [`compile`].
pub fn compile_parsed(
    provider: Provider,
    path: &str,
    cst: Arc<YamlDocument>,
) -> Result<Compilation, Vec<FrontendProblem>> {
    let mut problems: Vec<FrontendProblem> =
        cst.problems().iter().map(FrontendProblem::from).collect();
    if cst.root().is_none()
        || problems
            .iter()
            .any(|problem| problem.code == "YAML-SYNTAX" || problem.code == "YAML-RESOURCE-LIMIT")
    {
        return Err(if problems.is_empty() {
            vec![FrontendProblem {
                code: "FRONTEND-EMPTY".to_owned(),
                message: "workflow document has no root node".to_owned(),
                span: Span::default(),
            }]
        } else {
            problems
        });
    }
    let root = cst.root().cloned().ok_or_else(|| {
        vec![FrontendProblem {
            code: "FRONTEND-EMPTY".to_owned(),
            message: "workflow document has no root node".to_owned(),
            span: Span::default(),
        }]
    })?;
    let mut dependencies = collect_dependencies(provider, &root);
    if matches!(
        provider,
        Provider::Gitlab | Provider::Azure | Provider::Circleci
    ) {
        dependencies.sort_by(|left, right| {
            left.reference
                .cmp(&right.reference)
                .then_with(|| right.span.cmp(&left.span))
        });
        dependencies.dedup_by(|left, right| left.reference == right.reference);
    } else {
        dependencies.sort_by(|left, right| {
            left.reference
                .cmp(&right.reference)
                .then(left.kind.cmp(&right.kind))
                .then(left.span.cmp(&right.span))
        });
        dependencies.dedup_by(|left, right| {
            left.reference == right.reference && left.kind == right.kind && left.span == right.span
        });
    }
    let mut graph = match provider {
        Provider::Github => {
            let (graph, github_problems) = lower_github(path, &root, &dependencies);
            problems.extend(github_problems);
            graph
        }
        Provider::Gitlab => lower_gitlab(path, &root, &dependencies),
        Provider::Azure => {
            let (graph, azure_problems) = lower_azure(path, &root, &dependencies);
            problems.extend(azure_problems);
            graph
        }
        Provider::Circleci => {
            let (graph, circleci_problems) = lower_circleci(path, &root, &dependencies);
            problems.extend(circleci_problems);
            graph
        }
    };
    if provider == Provider::Gitlab {
        problems.extend(gitlab_semantic_problems(&root));
    }
    graph.finalize();
    Ok(Compilation {
        provider,
        phases: vec![
            PipelinePhase::Detected,
            PipelinePhase::Parsed,
            PipelinePhase::Expanded,
            PipelinePhase::Resolved,
            PipelinePhase::Lowered,
        ],
        graph,
        dependencies,
        problems,
        cst,
    })
}

#[must_use]
pub fn semantic_shape(graph: &Graph) -> SemanticShape {
    let count_node = |kind| graph.nodes.iter().filter(|node| node.kind == kind).count();
    let count_edge = |kind| graph.edges.iter().filter(|edge| edge.kind == kind).count();
    SemanticShape {
        workflows: count_node(NodeKind::Workflow),
        stages: count_node(NodeKind::Stage),
        jobs: count_node(NodeKind::Job),
        steps: count_node(NodeKind::Step),
        calls: count_node(NodeKind::Call),
        commands: count_node(NodeKind::Command),
        parameters: count_node(NodeKind::Parameter),
        control_edges: count_edge(EdgeKind::Control),
        data_edges: count_edge(EdgeKind::Data),
        call_edges: count_edge(EdgeKind::Call),
    }
}

fn mapping(node: &YamlNode) -> &[MappingEntry] {
    node.mapping().unwrap_or_default()
}

fn sequence(node: &YamlNode) -> Vec<&YamlNode> {
    node.sequence()
        .map_or_else(|| vec![node], |items| items.iter().collect())
}

fn scalar_values(node: &YamlNode) -> Vec<&str> {
    scalar_nodes(node)
        .into_iter()
        .filter_map(YamlNode::scalar)
        .collect()
}

fn scalar_nodes(node: &YamlNode) -> Vec<&YamlNode> {
    if node.scalar().is_some() {
        vec![node]
    } else {
        node.sequence().map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter(|item| item.scalar().is_some())
                .collect()
        })
    }
}

fn dependency(
    provider: Provider,
    kind: DependencyKind,
    reference: &str,
    span: &Span,
) -> Dependency {
    Dependency::unresolved(
        provider,
        kind,
        reference,
        DependencyLocator::Direct,
        span.clone(),
    )
}

fn collect_dependencies(provider: Provider, root: &YamlNode) -> Vec<Dependency> {
    match provider {
        Provider::Github => {
            let mut output = Vec::new();
            visit(root, &mut |entry| {
                if entry.key == "uses"
                    && let Some(reference) = entry.value.scalar()
                {
                    let kind = if reference.starts_with("docker://") {
                        DependencyKind::ContainerImage
                    } else {
                        DependencyKind::Action
                    };
                    output.push(dependency(provider, kind, reference, entry.value.span()));
                }
            });
            output
        }
        Provider::Gitlab => collect_gitlab_dependencies(root),
        Provider::Azure => collect_azure_dependencies(root),
        Provider::Circleci => {
            let mut output = Vec::new();
            if let Some(orbs) = root.field("orbs") {
                for entry in mapping(orbs) {
                    if let Some(reference) = entry.value.scalar() {
                        output.push(dependency(
                            provider,
                            DependencyKind::Orb,
                            reference,
                            entry.value.span(),
                        ));
                    }
                }
            }
            visit(root, &mut |entry| {
                if entry.key == "image"
                    && let Some(reference) = entry.value.scalar()
                {
                    output.push(dependency(
                        provider,
                        DependencyKind::ContainerImage,
                        reference,
                        entry.value.span(),
                    ));
                }
            });
            output
        }
    }
}

#[derive(Clone)]
struct AzureRepository<'a> {
    alias: String,
    repository: String,
    revision: Option<String>,
    repository_type: Option<String>,
    node: &'a YamlNode,
}

fn azure_repository_specs(root: &YamlNode) -> Vec<AzureRepository<'_>> {
    root.field("resources")
        .and_then(|resources| resources.field("repositories"))
        .map(sequence)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|node| {
            let repository = node.field("name").and_then(YamlNode::scalar)?.to_owned();
            let alias = node
                .field("repository")
                .and_then(YamlNode::scalar)
                .unwrap_or(&repository)
                .to_owned();
            Some(AzureRepository {
                alias,
                repository,
                revision: node
                    .field("ref")
                    .and_then(YamlNode::scalar)
                    .map(str::to_owned),
                repository_type: node
                    .field("type")
                    .and_then(YamlNode::scalar)
                    .map(str::to_owned),
                node,
            })
        })
        .collect()
}

fn azure_template_locator(
    repositories: &[AzureRepository<'_>],
    reference: &str,
) -> DependencyLocator {
    let Some((path, alias)) = reference.rsplit_once('@') else {
        return DependencyLocator::Direct;
    };
    if alias.eq_ignore_ascii_case("self") {
        return DependencyLocator::Direct;
    }
    repositories
        .iter()
        .find(|repository| repository.alias == alias)
        .map_or(DependencyLocator::Direct, |repository| {
            DependencyLocator::RepositoryFile {
                repository: repository.repository.clone(),
                revision: repository.revision.clone(),
                path: path.to_owned(),
                repository_type: repository.repository_type.clone(),
            }
        })
}

fn collect_azure_dependencies(root: &YamlNode) -> Vec<Dependency> {
    let repositories = azure_repository_specs(root);
    let mut output = Vec::new();
    visit(root, &mut |entry| {
        let kind = match entry.key.as_str() {
            "task" => Some(DependencyKind::Task),
            "template" => Some(DependencyKind::Template),
            _ => None,
        };
        if let (Some(kind), Some(reference)) = (kind, entry.value.scalar()) {
            let locator = if kind == DependencyKind::Template {
                azure_template_locator(&repositories, reference)
            } else {
                DependencyLocator::Direct
            };
            output.push(Dependency::unresolved(
                Provider::Azure,
                kind,
                reference,
                locator,
                entry.value.span().clone(),
            ));
        }
    });
    output.extend(repositories.into_iter().map(|repository| {
        let reference = repository.revision.as_deref().map_or_else(
            || repository.repository.clone(),
            |revision| format!("{}@{revision}", repository.repository),
        );
        Dependency::unresolved(
            Provider::Azure,
            DependencyKind::Repository,
            reference,
            DependencyLocator::RepositorySource {
                repository: repository.repository,
                revision: repository.revision,
                repository_type: repository.repository_type,
            },
            repository.node.span().clone(),
        )
    }));
    output
}

fn collect_gitlab_dependencies(root: &YamlNode) -> Vec<Dependency> {
    let mut output = Vec::new();
    if let Some(include) = root.field("include") {
        for item in sequence(include) {
            output.extend(gitlab_include_dependencies(item));
        }
    }
    visit(root, &mut |entry| {
        if entry.key == "trigger"
            && let Some(include) = entry.value.field("include")
        {
            for item in sequence(include) {
                output.extend(gitlab_include_dependencies(item));
            }
        }
        if entry.key == "image"
            && let Some(reference) = entry.value.scalar()
        {
            output.push(dependency(
                Provider::Gitlab,
                DependencyKind::ContainerImage,
                reference,
                entry.value.span(),
            ));
        }
    });
    output
}

fn gitlab_include_dependencies(item: &YamlNode) -> Vec<Dependency> {
    if let Some(reference) = item.scalar() {
        return vec![dependency(
            Provider::Gitlab,
            DependencyKind::Include,
            reference,
            item.span(),
        )];
    }
    if let Some(project) = item.field("project").and_then(YamlNode::scalar) {
        let revision = item
            .field("ref")
            .and_then(YamlNode::scalar)
            .map(str::to_owned);
        let files = item.field("file").map(scalar_values).unwrap_or_default();
        if files.is_empty() {
            let reference = format!(
                "{project}{}",
                revision
                    .as_deref()
                    .map_or_else(String::new, |value| format!("@{value}"))
            );
            return vec![Dependency::unresolved(
                Provider::Gitlab,
                DependencyKind::Repository,
                reference,
                DependencyLocator::RepositorySource {
                    repository: project.to_owned(),
                    revision,
                    repository_type: None,
                },
                item.span().clone(),
            )];
        }
        return files
            .into_iter()
            .map(|path| {
                let reference = format!(
                    "{project}:{path}{}",
                    revision
                        .as_deref()
                        .map_or_else(String::new, |value| format!("@{value}"))
                );
                Dependency::unresolved(
                    Provider::Gitlab,
                    DependencyKind::Repository,
                    reference,
                    DependencyLocator::RepositoryFile {
                        repository: project.to_owned(),
                        revision: revision.clone(),
                        path: path.to_owned(),
                        repository_type: None,
                    },
                    item.span().clone(),
                )
            })
            .collect();
    }
    [
        ("remote", DependencyKind::Include),
        ("component", DependencyKind::Component),
        ("template", DependencyKind::Template),
        ("local", DependencyKind::Include),
    ]
    .into_iter()
    .find_map(|(field, kind)| {
        item.field(field)
            .and_then(YamlNode::scalar)
            .map(|reference| vec![dependency(Provider::Gitlab, kind, reference, item.span())])
    })
    .unwrap_or_default()
}

fn gitlab_semantic_problems(root: &YamlNode) -> Vec<FrontendProblem> {
    let templates: BTreeMap<_, _> = mapping(root)
        .iter()
        .filter(|entry| entry.key.starts_with('.'))
        .map(|entry| (entry.key.as_str(), &entry.value))
        .collect();
    let jobs: Vec<_> = mapping(root)
        .iter()
        .filter(|entry| {
            !GITLAB_RESERVED.contains(&entry.key.as_str())
                && !entry.key.starts_with('.')
                && entry.value.mapping().is_some_and(|items| !items.is_empty())
        })
        .collect();
    let job_names: BTreeSet<_> = jobs.iter().map(|entry| entry.key.as_str()).collect();
    let explicit_stages = root.field("stages").map(scalar_values).unwrap_or_default();
    let known_stages: BTreeSet<_> = if explicit_stages.is_empty() {
        [".pre", "build", "test", "deploy", ".post"]
            .into_iter()
            .chain(jobs.iter().filter_map(|entry| {
                gitlab_effective_field(&templates, "stage", &entry.value).and_then(YamlNode::scalar)
            }))
            .collect()
    } else {
        explicit_stages.into_iter().collect()
    };
    let mut problems = Vec::new();
    for entry in jobs {
        let stage = gitlab_effective_field(&templates, "stage", &entry.value)
            .and_then(YamlNode::scalar)
            .unwrap_or("test");
        if !known_stages.contains(stage) {
            problems.push(FrontendProblem {
                code: "GL-UNKNOWN-STAGE".to_owned(),
                message: format!("{} uses unknown stage {stage}", entry.key),
                span: entry.span.clone(),
            });
        }
        if let Some(needs) = gitlab_effective_field(&templates, "needs", &entry.value) {
            for target in sequence(needs).into_iter().filter_map(|item| {
                item.scalar()
                    .or_else(|| item.field("job").and_then(YamlNode::scalar))
            }) {
                if !job_names.contains(target) {
                    problems.push(FrontendProblem {
                        code: "GL-UNKNOWN-NEEDS".to_owned(),
                        message: format!("{} references unknown {target}", entry.key),
                        span: entry.span.clone(),
                    });
                }
            }
        }
        if let Some(extends) = entry.value.field("extends") {
            for template in scalar_values(extends) {
                if !templates.contains_key(template) {
                    problems.push(FrontendProblem {
                        code: "GL-UNKNOWN-EXTENDS".to_owned(),
                        message: format!("{} extends unknown {template}", entry.key),
                        span: entry.span.clone(),
                    });
                }
            }
        }
    }
    problems
}

fn gitlab_effective_field<'a>(
    templates: &BTreeMap<&'a str, &'a YamlNode>,
    name: &str,
    body: &'a YamlNode,
) -> Option<&'a YamlNode> {
    fn lookup<'a>(
        templates: &BTreeMap<&'a str, &'a YamlNode>,
        name: &str,
        body: &'a YamlNode,
        visited: &mut BTreeSet<&'a str>,
    ) -> Option<&'a YamlNode> {
        if let Some(value) = body.field(name) {
            return Some(value);
        }
        let extends = body.field("extends").map(scalar_values).unwrap_or_default();
        for template in extends.into_iter().rev() {
            if visited.insert(template)
                && let Some(parent) = templates.get(template)
                && let Some(value) = lookup(templates, name, parent, visited)
            {
                return Some(value);
            }
        }
        None
    }
    lookup(templates, name, body, &mut BTreeSet::new())
}

fn visit(node: &YamlNode, callback: &mut impl FnMut(&MappingEntry)) {
    if let Some(entries) = node.mapping() {
        for entry in entries {
            callback(entry);
            visit(&entry.value, callback);
        }
    }
    if let Some(items) = node.sequence() {
        for item in items {
            visit(item, callback);
        }
    }
}

fn workflow_node(provider: Provider, fallback: &str, root: &YamlNode) -> Node {
    let name = root
        .field("name")
        .and_then(YamlNode::scalar)
        .unwrap_or(fallback);
    Node::simple(
        provider,
        NodeKind::Workflow,
        name,
        Phase::Compile,
        root.span().clone(),
    )
}

fn add_control(graph: &mut Graph, from: &Node, to: &Node) {
    graph.add_edge(Edge::simple(
        EdgeKind::Control,
        from.id.clone(),
        to.id.clone(),
    ));
}

fn add_call(graph: &mut Graph, from: &Node, to: &Node) {
    add_control(graph, from, to);
    graph.add_edge(Edge::simple(EdgeKind::Call, from.id.clone(), to.id.clone()));
}

fn insert_gate(graph: &mut Graph, owner: &Node, gate: Node) {
    let mut incoming = Vec::new();
    graph.edges.retain(|edge| {
        if edge.kind == EdgeKind::Control && edge.to == owner.id {
            incoming.push(edge.clone());
            false
        } else {
            true
        }
    });
    for entrypoint in &mut graph.entrypoints {
        if *entrypoint == owner.id {
            entrypoint.clone_from(&gate.id);
        }
    }
    graph.add_node(gate.clone());
    for edge in incoming {
        graph.add_edge(Edge::new(
            EdgeKind::Control,
            edge.from,
            gate.id.clone(),
            edge.condition,
            edge.label,
        ));
    }
    graph.add_edge(Edge::new(
        EdgeKind::Control,
        gate.id.clone(),
        owner.id.clone(),
        gate.condition,
        Some("gate".to_owned()),
    ));
}

fn unquoted_expression_words(value: &str) -> Vec<(usize, &str)> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            if let Some(begin) = start.take() {
                output.push((begin, &value[begin..index]));
            }
            quote = if quote == Some(byte) {
                None
            } else if quote.is_none() {
                Some(byte)
            } else {
                quote
            };
            continue;
        }
        if quote.is_some() {
            continue;
        }
        if expression_identifier_byte(byte) {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            output.push((begin, &value[begin..index]));
        }
    }
    if let Some(begin) = start {
        output.push((begin, &value[begin..]));
    }
    output
}

fn github_gate_references(
    source: &str,
    parent_span: &Span,
    phase: Phase,
) -> Vec<ExpressionReference> {
    let mut references = expression_references(Provider::Github, phase, source, parent_span);
    let trimmed_start = source.len().saturating_sub(source.trim_start().len());
    let trimmed = source.trim();
    let (body, body_offset) = trimmed
        .strip_prefix("${{")
        .and_then(|inner| inner.strip_suffix("}}"))
        .map_or((trimmed, trimmed_start), |inner| {
            let leading = inner.len().saturating_sub(inner.trim_start().len());
            (inner.trim(), trimmed_start + 3 + leading)
        });
    references.extend(
        unquoted_expression_words(body)
            .into_iter()
            .filter(|(_, name)| looks_like_reference(name))
            .map(|(offset, name)| {
                let span = offset_span(parent_span, body_offset + offset, name.len());
                ExpressionReference {
                    name: name.to_owned(),
                    phase,
                    value: reference_value(Provider::Github, name, &span),
                    span,
                }
            }),
    );
    references.sort_by(|left, right| (&left.span, &left.name).cmp(&(&right.span, &right.name)));
    references.dedup_by(|left, right| left.span == right.span && left.name == right.name);
    references
}

fn add_github_gate(
    graph: &mut Graph,
    owner: &Node,
    name: String,
    phase: Phase,
    condition: &YamlNode,
) {
    let scalar_source = condition.scalar();
    let source = scalar_source.unwrap_or("<opaque condition>");
    let references = github_gate_references(source, condition.span(), phase);
    let mut attributes = BTreeMap::from([(
        "expression".to_owned(),
        AbstractValue::string_constant(
            source,
            Trust::Trusted,
            Secrecy::Public,
            vec![Provenance {
                origin: "workflow condition".to_owned(),
                span: condition.span().clone(),
                operation: "gate".to_owned(),
            }],
        ),
    )]);
    for reference in &references {
        let key = format!("reference:{}", reference.name);
        attributes
            .entry(key)
            .and_modify(|value| *value = value.join(&reference.value))
            .or_insert_with(|| reference.value.clone());
    }
    let unknown = if scalar_source.is_none() {
        Some(UnknownReason::UnsupportedSyntax(
            "condition expression".to_owned(),
        ))
    } else {
        references.iter().find_map(|reference| {
            let minimum = minimum_reference_phase(Provider::Github, &reference.name);
            (phase_rank(phase) < phase_rank(minimum)).then(|| {
                UnknownReason::PhaseUnavailable(format!(
                    "{} is unavailable during {}",
                    reference.name,
                    phase.name()
                ))
            })
        })
    };
    let predicate = scalar_source.map_or_else(
        || Condition::atom("github:<opaque condition>"),
        |value| {
            let trimmed = value.trim();
            let body = trimmed
                .strip_prefix("${{")
                .and_then(|inner| inner.strip_suffix("}}"))
                .map_or(trimmed, str::trim);
            gitlab_condition(body)
        },
    );
    let gate = Node::new(
        Provider::Github,
        NodeKind::Gate,
        name,
        phase,
        condition.span().clone(),
        predicate,
        attributes,
        [],
        [],
        unknown,
    );
    insert_gate(graph, owner, gate.clone());
    add_expression_references(graph, Provider::Github, &gate, references);
}

fn unresolved_for(dependencies: &[Dependency], reference: &str) -> Option<UnknownReason> {
    dependencies
        .iter()
        .find(|dependency| dependency.reference == reference)
        .and_then(|dependency| match &dependency.status {
            DependencyStatus::Unresolved(reason) => Some(reason.clone()),
            DependencyStatus::Locked { .. } => None,
        })
}

fn github_call_profile(reference: &str) -> (Vec<Capability>, Vec<ObservableEffect>) {
    let lower = reference.to_ascii_lowercase();
    if reference.starts_with("./") || reference.starts_with("../") {
        (Vec::new(), Vec::new())
    } else if lower.contains("actions/checkout") {
        (
            vec![Capability::RepositoryRead, Capability::FilesystemWrite],
            vec![ObservableEffect::FileWrite],
        )
    } else if lower.contains("actions/attest@") {
        (
            vec![
                Capability::Oidc,
                Capability::ArtifactWrite,
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
                Capability::Network,
            ],
            vec![
                ObservableEffect::CredentialUse,
                ObservableEffect::ArtifactPublish,
                ObservableEffect::FileWrite,
                ObservableEffect::NetworkRequest,
            ],
        )
    } else if lower.contains("upload-artifact") {
        (
            vec![
                Capability::ArtifactWrite,
                Capability::FilesystemRead,
                Capability::Network,
            ],
            vec![
                ObservableEffect::ArtifactPublish,
                ObservableEffect::NetworkRequest,
            ],
        )
    } else if lower.contains("download-artifact") {
        (
            vec![
                Capability::ArtifactRead,
                Capability::FilesystemWrite,
                Capability::Network,
            ],
            vec![
                ObservableEffect::FileWrite,
                ObservableEffect::NetworkRequest,
            ],
        )
    } else if lower.contains("cache") {
        (
            vec![
                Capability::CacheRead,
                Capability::CacheWrite,
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
            ],
            vec![ObservableEffect::CachePublish],
        )
    } else if ["openai", "anthropic", "copilot", "ai-agent", "ai_agent"]
        .into_iter()
        .any(|name| lower.contains(name))
    {
        (
            vec![
                Capability::AiTool,
                Capability::Network,
                Capability::SecretAccess,
                Capability::RepositoryWrite,
            ],
            vec![
                ObservableEffect::AiAgentExecution,
                ObservableEffect::NetworkRequest,
                ObservableEffect::WorkflowChange,
            ],
        )
    } else {
        (vec![Capability::Network], Vec::new())
    }
}

fn github_permissions(body: &YamlNode) -> Vec<Capability> {
    let Some(permissions) = body.field("permissions") else {
        return Vec::new();
    };
    if let Some(value) = permissions.scalar() {
        return match value {
            "write-all" => vec![Capability::RepositoryWrite, Capability::TokenWrite],
            "read-all" => vec![Capability::RepositoryRead, Capability::TokenRead],
            _ => Vec::new(),
        };
    }
    let mut output = BTreeSet::new();
    for entry in mapping(permissions) {
        let access = entry.value.scalar().unwrap_or_default();
        if access == "none" {
            continue;
        }
        if entry.key == "id-token" && access == "write" {
            output.insert(Capability::Oidc);
        } else if entry.key == "models" {
            output.insert(Capability::AiTool);
            output.insert(Capability::Network);
        } else if matches!(entry.key.as_str(), "attestations" | "artifact-metadata") {
            output.insert(if access == "write" {
                Capability::ArtifactWrite
            } else {
                Capability::ArtifactRead
            });
        } else if matches!(entry.key.as_str(), "deployments" | "pages") {
            if access == "write" {
                output.insert(Capability::Deployment);
                output.insert(Capability::TokenWrite);
            } else {
                output.insert(Capability::RepositoryRead);
                output.insert(Capability::TokenRead);
            }
        } else if access == "write" {
            output.insert(Capability::RepositoryWrite);
            output.insert(Capability::TokenWrite);
        } else {
            output.insert(Capability::RepositoryRead);
            output.insert(Capability::TokenRead);
        }
    }
    output.into_iter().collect()
}

fn add_github_matrix_parameters(graph: &mut Graph, job: &Node, matrix: &YamlNode) {
    for entry in mapping(matrix) {
        let values: Vec<_> = sequence(&entry.value)
            .into_iter()
            .filter_map(YamlNode::scalar)
            .collect();
        let value = values.first().map_or_else(
            || AbstractValue::unknown(UnknownReason::DynamicString(entry.key.clone())),
            |first| {
                values.iter().skip(1).fold(
                    AbstractValue::string_constant(
                        *first,
                        Trust::Trusted,
                        Secrecy::Public,
                        Vec::new(),
                    ),
                    |current, value| {
                        current.join(&AbstractValue::string_constant(
                            *value,
                            Trust::Trusted,
                            Secrecy::Public,
                            Vec::new(),
                        ))
                    },
                )
            },
        );
        let parameter = Node::new(
            Provider::Github,
            NodeKind::Parameter,
            format!("matrix.{}", entry.key),
            Phase::Plan,
            entry.span.clone(),
            Condition::True,
            BTreeMap::from([("value".to_owned(), value)]),
            [],
            [],
            None,
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id,
            job.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
    }
}

fn add_github_embedded_references(graph: &mut Graph, target: &Node, container: &YamlNode) {
    if let Some(source) = container.scalar() {
        let references =
            expression_references(Provider::Github, target.phase, source, container.span());
        add_expression_references(graph, Provider::Github, target, references);
        return;
    }
    for entry in mapping(container) {
        add_github_embedded_references(graph, target, &entry.value);
    }
    if let Some(items) = container.sequence() {
        for item in items {
            add_github_embedded_references(graph, target, item);
        }
    }
}

fn add_github_environment_bindings(graph: &mut Graph, target: &Node, environment: &YamlNode) {
    for entry in mapping(environment) {
        let binding = Node::new(
            Provider::Github,
            NodeKind::Resource,
            format!("env:{}", entry.key),
            target.phase,
            entry.span.clone(),
            Condition::True,
            BTreeMap::from([(
                "environment.name".to_owned(),
                AbstractValue::string_constant(
                    &entry.key,
                    Trust::Trusted,
                    Secrecy::Public,
                    Vec::new(),
                ),
            )]),
            [],
            [],
            None,
        );
        graph.add_node(binding.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            binding.id.clone(),
            target.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
        add_github_embedded_references(graph, &binding, &entry.value);
    }
}

fn github_environment(body: &YamlNode) -> Option<(String, Span)> {
    let environment = body.field("environment")?;
    let name = environment
        .scalar()
        .or_else(|| environment.field("name").and_then(YamlNode::scalar))?;
    Some((name.to_owned(), environment.span().clone()))
}

fn add_github_job_resources(graph: &mut Graph, job: &Node, body: &YamlNode) {
    if let Some((name, span)) = github_environment(body) {
        let environment = Node::new(
            Provider::Github,
            NodeKind::Resource,
            format!("environment:{name}"),
            Phase::Run,
            span,
            Condition::True,
            BTreeMap::new(),
            [Capability::Deployment],
            [],
            None,
        );
        graph.add_node(environment.clone());
        graph.add_edge(Edge::simple(
            EdgeKind::Grant,
            environment.id,
            job.id.clone(),
        ));
    }
    if let Some(outputs) = body.field("outputs") {
        for entry in mapping(outputs) {
            let resource = Node::simple(
                Provider::Github,
                NodeKind::Resource,
                format!("output:{}.{}", job.name, entry.key),
                Phase::Post,
                entry.span.clone(),
            );
            graph.add_node(resource.clone());
            graph.add_edge(Edge::simple(
                EdgeKind::Write,
                job.id.clone(),
                resource.id.clone(),
            ));
            add_github_embedded_references(graph, &resource, &entry.value);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn lower_github(
    path: &str,
    root: &YamlNode,
    dependencies: &[Dependency],
) -> (Graph, Vec<FrontendProblem>) {
    let root_permissions = github_permissions(root);
    let mut workflow = workflow_node(Provider::Github, path, root);
    workflow.capabilities.clone_from(&root_permissions);
    if root.field("runs").is_some() {
        return (
            lower_github_action(path, root, dependencies, &workflow),
            Vec::new(),
        );
    }
    let mut graph = Graph::empty(Provider::Github, path);
    let mut problems = Vec::new();
    graph.add_node(workflow.clone());
    graph.add_entrypoint(workflow.id.clone());
    if let Some(on) = root.field("on") {
        let triggers: Vec<(&str, Span)> = if let Some(value) = on.scalar() {
            vec![(value, on.span().clone())]
        } else {
            mapping(on)
                .iter()
                .map(|entry| (entry.key.as_str(), entry.span.clone()))
                .collect()
        };
        for (name, span) in triggers {
            let trigger = Node::simple(
                Provider::Github,
                NodeKind::Trigger,
                name,
                Phase::Source,
                span,
            );
            graph.add_node(trigger.clone());
            add_control(&mut graph, &trigger, &workflow);
        }
    }
    let mut jobs = Vec::new();
    if let Some(job_map) = root.field("jobs") {
        for entry in mapping(job_map) {
            let mut capabilities = if entry.value.field("permissions").is_some() {
                github_permissions(&entry.value)
            } else {
                root_permissions.clone()
            };
            if entry.value.field("runs-on").is_some_and(|node| {
                scalar_values(node)
                    .iter()
                    .any(|value| value.to_ascii_lowercase().contains("self-hosted"))
            }) {
                capabilities.push(Capability::SelfHostedPersistence);
            }
            let has_environment = github_environment(&entry.value).is_some();
            if has_environment {
                capabilities.push(Capability::Deployment);
            }
            let job = Node::new(
                Provider::Github,
                NodeKind::Job,
                &entry.key,
                Phase::Plan,
                entry.span.clone(),
                Condition::True,
                BTreeMap::new(),
                capabilities,
                if has_environment {
                    vec![ObservableEffect::DeploymentChange]
                } else {
                    Vec::new()
                },
                None,
            );
            graph.add_node(job.clone());
            add_control(&mut graph, &workflow, &job);
            jobs.push((entry.key.clone(), entry.value.clone(), job));
        }
    } else {
        problems.push(FrontendProblem {
            code: "GH-SCHEMA-JOBS".to_owned(),
            message: "a GitHub workflow requires a jobs mapping".to_owned(),
            span: root.span().clone(),
        });
    }
    let job_nodes: Vec<_> = jobs.iter().map(|(_, _, job)| job.clone()).collect();
    let job_dependencies: Vec<_> = jobs
        .iter()
        .map(|(name, body, job)| {
            (
                name.clone(),
                body.field("needs")
                    .map(scalar_values)
                    .unwrap_or_default()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                job.span.clone(),
            )
        })
        .collect();
    problems.extend(link_dependencies(
        &mut graph,
        &job_nodes,
        &job_dependencies,
        "GH-UNKNOWN-NEEDS",
        "GH-NEEDS-CYCLE",
        "needs",
    ));
    for (name, body, job) in &jobs {
        if let Some(condition) = body.field("if") {
            add_github_gate(
                &mut graph,
                job,
                format!("if:job:{name}"),
                Phase::Plan,
                condition,
            );
        }
        if let Some(matrix) = body
            .field("strategy")
            .and_then(|strategy| strategy.field("matrix"))
        {
            add_github_matrix_parameters(&mut graph, job, matrix);
        }
        add_github_job_resources(&mut graph, job, body);
        if let Some(reference) = body.field("uses").and_then(YamlNode::scalar) {
            let (capabilities, effects) = github_call_profile(reference);
            let call = Node::new(
                Provider::Github,
                NodeKind::Call,
                reference,
                Phase::Plan,
                body.field("uses")
                    .map_or_else(|| body.span().clone(), |node| node.span().clone()),
                Condition::True,
                BTreeMap::new(),
                capabilities,
                effects,
                unresolved_for(dependencies, reference),
            );
            graph.add_node(call.clone());
            add_call(&mut graph, job, &call);
        }
        add_github_steps(&mut graph, dependencies, job, body, name);
    }
    (graph, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(source: &str) -> YamlDocument {
        YamlDocument::parse("test.yml", source, Budget::default())
    }

    #[test]
    fn github_expression_words_and_gate_spans_exclude_quoted_literals() {
        assert_eq!(
            unquoted_expression_words(
                "github.ref == 'literal.fake' && \"also.fake\" || inputs.flag"
            )
            .into_iter()
            .map(|(_, word)| word)
            .collect::<Vec<_>>(),
            vec!["github.ref", "inputs.flag"]
        );
        assert_eq!(
            unquoted_expression_words(r#"github.ref == "escaped \"fake.ref" && inputs.flag"#)
                .into_iter()
                .map(|(_, word)| word)
                .collect::<Vec<_>>(),
            vec!["github.ref", "inputs.flag"]
        );

        let source = "${{ github.ref == 'literal.fake' && inputs.flag }}";
        let parent = Span::new(
            "test.yml",
            Position::default(),
            Position {
                byte: source.len(),
                column: u32::try_from(source.chars().count().saturating_add(1))
                    .expect("fixture column fits u32"),
                ..Position::default()
            },
        );
        let references = github_gate_references(source, &parent, Phase::Plan);
        assert_eq!(
            references
                .iter()
                .map(|reference| reference.name.as_str())
                .collect::<Vec<_>>(),
            vec!["github.ref", "inputs.flag"]
        );
        for reference in references {
            assert_eq!(
                source.get(reference.span.start.byte..reference.span.stop.byte),
                Some(reference.name.as_str())
            );
        }

        let repeated_source = "${{ github.ref == github.ref }}";
        let repeated_parent = Span::new(
            "test.yml",
            Position::default(),
            Position {
                byte: repeated_source.len(),
                column: u32::try_from(repeated_source.chars().count().saturating_add(1))
                    .expect("fixture column fits u32"),
                ..Position::default()
            },
        );
        let repeated = github_gate_references(repeated_source, &repeated_parent, Phase::Plan);
        assert_eq!(repeated.len(), 2);
        assert!(
            repeated
                .iter()
                .all(|reference| reference.name == "github.ref")
        );
        assert_ne!(repeated[0].span, repeated[1].span);
    }

    #[test]
    fn github_action_profiles_and_permission_spellings_are_exact() {
        let cases = [
            ("./local", Vec::new(), Vec::new()),
            (
                "actions/checkout@main",
                vec![Capability::RepositoryRead, Capability::FilesystemWrite],
                vec![ObservableEffect::FileWrite],
            ),
            (
                "actions/upload-artifact@main",
                vec![
                    Capability::ArtifactWrite,
                    Capability::FilesystemRead,
                    Capability::Network,
                ],
                vec![
                    ObservableEffect::ArtifactPublish,
                    ObservableEffect::NetworkRequest,
                ],
            ),
            (
                "actions/download-artifact@main",
                vec![
                    Capability::ArtifactRead,
                    Capability::FilesystemWrite,
                    Capability::Network,
                ],
                vec![
                    ObservableEffect::FileWrite,
                    ObservableEffect::NetworkRequest,
                ],
            ),
            (
                "actions/cache@main",
                vec![
                    Capability::CacheRead,
                    Capability::CacheWrite,
                    Capability::FilesystemRead,
                    Capability::FilesystemWrite,
                ],
                vec![ObservableEffect::CachePublish],
            ),
        ];
        for (reference, capabilities, effects) in cases {
            assert_eq!(github_call_profile(reference), (capabilities, effects));
        }
        for reference in ["owner/openai-action@main", "owner/ai_agent@main"] {
            let (capabilities, effects) = github_call_profile(reference);
            assert!(capabilities.contains(&Capability::AiTool));
            assert!(capabilities.contains(&Capability::Network));
            assert!(effects.contains(&ObservableEffect::AiAgentExecution));
        }
        assert_eq!(
            github_call_profile("owner/ordinary@main"),
            (vec![Capability::Network], Vec::new())
        );

        let permissions = |source: &str| {
            let document = yaml(source);
            github_permissions(document.root().expect("permissions root"))
        };
        assert_eq!(
            permissions("permissions: write-all\n"),
            vec![Capability::RepositoryWrite, Capability::TokenWrite]
        );
        assert_eq!(
            permissions("permissions: read-all\n"),
            vec![Capability::RepositoryRead, Capability::TokenRead]
        );
        assert_eq!(
            permissions("permissions:\n  id-token: write\n"),
            vec![Capability::Oidc]
        );
        assert_eq!(
            permissions("permissions:\n  models: read\n"),
            vec![Capability::Network, Capability::AiTool]
        );
        assert_eq!(
            permissions("permissions:\n  attestations: write\n"),
            vec![Capability::ArtifactWrite]
        );
        assert_eq!(
            permissions("permissions:\n  artifact-metadata: read\n"),
            vec![Capability::ArtifactRead]
        );
        assert_eq!(
            permissions("permissions:\n  deployments: write\n"),
            vec![Capability::TokenWrite, Capability::Deployment]
        );
        assert_eq!(
            permissions("permissions:\n  pages: read\n"),
            vec![Capability::RepositoryRead, Capability::TokenRead]
        );
        assert_eq!(permissions("permissions:\n  contents: none\n"), Vec::new());
    }

    #[test]
    fn gitlab_condition_parser_respects_quotes_precedence_and_balanced_wrappers() {
        assert_eq!(gitlab_condition("true"), Condition::True);
        assert_eq!(gitlab_condition("false"), Condition::False);
        assert_eq!(gitlab_condition("null"), Condition::False);
        assert_eq!(gitlab_condition("!true"), Condition::False);
        assert_eq!(
            gitlab_condition("$LEFT == 'x'"),
            Condition::atom("(LEFT==\"x\")")
        );
        assert_eq!(
            gitlab_condition("($LEFT == 'x' && ($RIGHT != 'y' || !false))"),
            gitlab_condition("$LEFT == 'x'")
                .and(&gitlab_condition("$RIGHT != 'y'").or(&Condition::True))
        );
        assert_eq!(
            split_condition("call('a || b') || $RIGHT", "||"),
            Some(("call('a || b') ", " $RIGHT"))
        );
        assert_eq!(split_condition("($LEFT || $RIGHT)", "||"), None);
        assert_eq!(trim_wrapping_parentheses("((a && b))"), "a && b");
        assert_eq!(trim_wrapping_parentheses("(a) || b"), "(a) || b");
        assert_eq!(trim_wrapping_parentheses("(')')"), "')'");
    }

    #[test]
    // This is the complete expression lexer/domain cross-product contract.
    #[allow(clippy::too_many_lines)]
    fn expression_reference_lexing_trust_secrecy_and_phase_are_exhaustive() {
        for reference in ["github.ref", "UPPER_CASE", "A1", "123"] {
            assert!(looks_like_reference(reference), "reference {reference:?}");
        }
        for literal in ["", "A", "lower_case", "UPPER-CASE"] {
            assert!(!looks_like_reference(literal), "literal {literal:?}");
        }

        let source = "prefix $(PAREN) $UPPER_2 $lower $9 $() $(unterminated";
        let references = dollar_references(source, Phase::Run);
        assert_eq!(
            references,
            [
                (
                    source.find("PAREN").expect("parenthesized offset"),
                    "PAREN".to_owned(),
                    Phase::Run,
                ),
                (
                    source.find("UPPER_2").expect("uppercase offset"),
                    "UPPER_2".to_owned(),
                    Phase::Run,
                ),
                (
                    source.find("$()").expect("empty parenthesized offset") + "$(".len(),
                    String::new(),
                    Phase::Run,
                ),
            ]
        );

        let unknown_github = Trust::Unknown(vec![UnknownReason::DynamicString(
            "unresolved GitHub dataflow value env.VALUE".to_owned(),
        )]);
        let trust_cases = [
            (
                Provider::Github,
                "github.event.pull_request.title",
                Trust::Untrusted,
            ),
            (Provider::Github, "inputs.name", Trust::Untrusted),
            (Provider::Github, "github.actor", Trust::Untrusted),
            (Provider::Github, "env.VALUE", unknown_github.clone()),
            (
                Provider::Github,
                "needs.build.result",
                Trust::Unknown(vec![UnknownReason::DynamicString(
                    "unresolved GitHub dataflow value needs.build.result".to_owned(),
                )]),
            ),
            (
                Provider::Github,
                "steps.build.outputs.value",
                Trust::Unknown(vec![UnknownReason::DynamicString(
                    "unresolved GitHub dataflow value steps.build.outputs.value".to_owned(),
                )]),
            ),
            (Provider::Github, "steps.build.conclusion", Trust::Trusted),
            (
                Provider::Gitlab,
                "CI_MERGE_REQUEST_DIFF_BASE_SHA",
                Trust::Trusted,
            ),
            (Provider::Gitlab, "CI_MERGE_REQUEST_TITLE", Trust::Untrusted),
            (
                Provider::Gitlab,
                "CI_EXTERNAL_PULL_REQUEST_TITLE",
                Trust::Untrusted,
            ),
            (Provider::Gitlab, "CI_COMMIT_MESSAGE", Trust::Untrusted),
            (Provider::Gitlab, "CI_PROJECT_ID", Trust::Trusted),
            (
                Provider::Azure,
                "System.PullRequest.PullRequestNumber",
                Trust::Trusted,
            ),
            (
                Provider::Azure,
                "System.PullRequest.SourceBranch",
                Trust::Untrusted,
            ),
            (Provider::Azure, "Build.SourceBranch", Trust::Untrusted),
            (Provider::Azure, "Build.BuildId", Trust::Trusted),
            (
                Provider::Circleci,
                "pipeline.parameters.target",
                Trust::Untrusted,
            ),
            (Provider::Circleci, "CIRCLE_BRANCH", Trust::Untrusted),
            (Provider::Circleci, "CIRCLE_BUILD_NUM", Trust::Trusted),
        ];
        for (provider, name, expected) in trust_cases {
            assert_eq!(
                reference_trust(provider, name),
                expected,
                "trust for {name}"
            );
        }

        for secret in [
            "secrets.TOKEN",
            "password",
            "ACCESSKEY",
            "access_token",
            "tokenize",
            "secretary",
        ] {
            assert_eq!(reference_secrecy(secret), Secrecy::Secret);
        }
        for public in ["github.ref", "credential", "key"] {
            assert_eq!(reference_secrecy(public), Secrecy::Public);
        }

        assert_eq!(
            [
                Phase::Source,
                Phase::Compile,
                Phase::Plan,
                Phase::Run,
                Phase::Post
            ]
            .map(phase_rank),
            [0, 1, 2, 3, 4]
        );
        let phase_cases = [
            (Provider::Github, "steps.build.outcome", Phase::Run),
            (Provider::Github, "runner.os", Phase::Run),
            (Provider::Github, "job.status", Phase::Run),
            (Provider::Github, "secrets.TOKEN", Phase::Run),
            (Provider::Github, "needs.build.result", Phase::Plan),
            (Provider::Github, "matrix.os", Phase::Plan),
            (Provider::Github, "strategy.job-total", Phase::Plan),
            (Provider::Github, "github.ref", Phase::Source),
            (Provider::Github, "inputs.name", Phase::Compile),
            (Provider::Gitlab, "CI_COMMIT_SHA", Phase::Plan),
            (Provider::Gitlab, "CUSTOM", Phase::Run),
            (Provider::Azure, "dependencies.build.result", Phase::Run),
            (
                Provider::Azure,
                "stageDependencies.build.result",
                Phase::Run,
            ),
            (Provider::Azure, "parameters.target", Phase::Compile),
            (Provider::Azure, "variables.target", Phase::Plan),
            (
                Provider::Circleci,
                "pipeline.parameters.target",
                Phase::Compile,
            ),
            (Provider::Circleci, "CIRCLE_BRANCH", Phase::Run),
        ];
        for (provider, name, expected) in phase_cases {
            assert_eq!(
                minimum_reference_phase(provider, name),
                expected,
                "phase for {name}"
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn lower_github_action(
    path: &str,
    root: &YamlNode,
    dependencies: &[Dependency],
    workflow: &Node,
) -> Graph {
    let mut graph = Graph::empty(Provider::Github, path);
    graph.add_node(workflow.clone());
    graph.add_entrypoint(workflow.id.clone());

    if let Some(inputs) = root.field("inputs") {
        for entry in mapping(inputs) {
            let parameter = Node::simple(
                Provider::Github,
                NodeKind::Parameter,
                format!("input:{}", entry.key),
                Phase::Compile,
                entry.span.clone(),
            );
            graph.add_node(parameter.clone());
            graph.add_edge(Edge::simple(
                EdgeKind::Data,
                parameter.id,
                workflow.id.clone(),
            ));
        }
    }
    if let Some(outputs) = root.field("outputs") {
        for entry in mapping(outputs) {
            let resource = Node::simple(
                Provider::Github,
                NodeKind::Resource,
                format!("output:action.{}", entry.key),
                Phase::Post,
                entry.span.clone(),
            );
            graph.add_node(resource.clone());
            graph.add_edge(Edge::simple(
                EdgeKind::Write,
                workflow.id.clone(),
                resource.id,
            ));
        }
    }

    let Some(runs) = root.field("runs") else {
        return graph;
    };
    match runs.field("using").and_then(YamlNode::scalar) {
        Some("composite") => {
            let action_job = Node::simple(
                Provider::Github,
                NodeKind::Job,
                "composite action",
                Phase::Plan,
                runs.span().clone(),
            );
            graph.add_node(action_job.clone());
            add_control(&mut graph, workflow, &action_job);
            add_github_steps(
                &mut graph,
                dependencies,
                &action_job,
                runs,
                "composite action",
            );
        }
        Some("docker") => {
            let image = runs
                .field("image")
                .and_then(YamlNode::scalar)
                .unwrap_or("Dockerfile");
            let call = Node::new(
                Provider::Github,
                NodeKind::Call,
                format!("docker:{image}"),
                Phase::Run,
                runs.span().clone(),
                Condition::True,
                BTreeMap::new(),
                [
                    Capability::Shell,
                    Capability::FilesystemRead,
                    Capability::Network,
                ],
                [ObservableEffect::CommandExecution],
                None,
            );
            graph.add_node(call.clone());
            add_call(&mut graph, workflow, &call);
        }
        Some(runtime) => {
            for key in ["main", "pre", "post"] {
                let Some(target) = runs.field(key).and_then(YamlNode::scalar) else {
                    continue;
                };
                let call = Node::new(
                    Provider::Github,
                    NodeKind::Call,
                    format!("{runtime}:{target}"),
                    Phase::Run,
                    runs.span().clone(),
                    Condition::True,
                    BTreeMap::new(),
                    [Capability::Shell, Capability::FilesystemRead],
                    [ObservableEffect::CommandExecution],
                    None,
                );
                graph.add_node(call.clone());
                add_call(&mut graph, workflow, &call);
            }
        }
        None => {}
    }
    graph
}

#[allow(clippy::too_many_lines)]
fn add_github_steps(
    graph: &mut Graph,
    dependencies: &[Dependency],
    job: &Node,
    body: &YamlNode,
    job_name: &str,
) {
    let Some(steps) = body.field("steps").and_then(YamlNode::sequence) else {
        return;
    };
    let mut previous: Option<Node> = None;
    for (index, step_body) in steps.iter().enumerate() {
        let name = step_body
            .field("name")
            .and_then(YamlNode::scalar)
            .or_else(|| step_body.field("id").and_then(YamlNode::scalar))
            .map_or_else(
                || format!("step {}", index.saturating_add(1)),
                str::to_owned,
            );
        let step = Node::simple(
            Provider::Github,
            NodeKind::Step,
            name,
            Phase::Run,
            step_body.span().clone(),
        );
        graph.add_node(step.clone());
        add_control(graph, job, &step);
        if let Some(predecessor) = &previous {
            graph.add_edge(Edge::new(
                EdgeKind::Control,
                predecessor.id.clone(),
                step.id.clone(),
                Condition::True,
                Some("sequence".to_owned()),
            ));
        }
        if let Some(condition) = step_body.field("if") {
            add_github_gate(
                graph,
                &step,
                format!("if:{job_name}:{}", step.name),
                Phase::Run,
                condition,
            );
        }
        if let Some(uses) = step_body.field("uses")
            && let Some(reference) = uses.scalar()
        {
            let (capabilities, effects) = github_call_profile(reference);
            let call = Node::new(
                Provider::Github,
                NodeKind::Call,
                reference,
                Phase::Run,
                uses.span().clone(),
                Condition::True,
                BTreeMap::new(),
                capabilities,
                effects,
                unresolved_for(dependencies, reference),
            );
            graph.add_node(call.clone());
            add_call(graph, &step, &call);
            for field in ["with", "env"] {
                if let Some(values) = step_body.field(field) {
                    add_github_embedded_references(graph, &call, values);
                }
            }
        }
        if let Some(run) = step_body.field("run")
            && let Some(source) = run.scalar()
        {
            let shell = step_body
                .field("shell")
                .and_then(YamlNode::scalar)
                .unwrap_or("default");
            let (command_value, references) = command_value(Provider::Github, source, run.span());
            let attributes = BTreeMap::from([
                ("command".to_owned(), command_value),
                (
                    "shell".to_owned(),
                    AbstractValue::string_constant(
                        shell,
                        Trust::Trusted,
                        Secrecy::Public,
                        Vec::new(),
                    ),
                ),
            ]);
            let command = Node::new(
                Provider::Github,
                NodeKind::Command,
                source,
                Phase::Run,
                run.span().clone(),
                Condition::True,
                attributes,
                [
                    Capability::Shell,
                    Capability::FilesystemRead,
                    Capability::FilesystemWrite,
                ],
                [ObservableEffect::CommandExecution],
                None,
            );
            graph.add_node(command.clone());
            add_control(graph, &step, &command);
            add_expression_references(graph, Provider::Github, &command, references);
            if let Some(environment) = step_body.field("env") {
                add_github_environment_bindings(graph, &command, environment);
            }
        }
        previous = Some(step);
    }
}

#[allow(clippy::too_many_lines)]
fn lower_gitlab(path: &str, root: &YamlNode, dependencies: &[Dependency]) -> Graph {
    let workflow = workflow_node(Provider::Gitlab, "GitLab pipeline", root);
    let mut graph = Graph::empty(Provider::Gitlab, path);
    graph.add_node(workflow.clone());
    graph.add_entrypoint(workflow.id.clone());
    if let Some(variables) = root.field("variables") {
        add_gitlab_variables(&mut graph, &workflow, variables);
    }
    if let Some(workflow_body) = root.field("workflow") {
        add_gitlab_rule_gate(
            &mut graph,
            &workflow,
            &BTreeMap::new(),
            workflow_body,
            "workflow-rule",
        );
    }
    let templates: BTreeMap<_, _> = mapping(root)
        .iter()
        .filter(|entry| entry.key.starts_with('.'))
        .map(|entry| (entry.key.as_str(), &entry.value))
        .collect();
    for (name, body) in &templates {
        graph.add_node(Node::simple(
            Provider::Gitlab,
            NodeKind::Resource,
            format!("template:{name}"),
            Phase::Compile,
            body.span().clone(),
        ));
    }
    let job_entries: Vec<_> = mapping(root)
        .iter()
        .filter(|entry| {
            !GITLAB_RESERVED.contains(&entry.key.as_str())
                && !entry.key.starts_with('.')
                && entry.value.mapping().is_some_and(|items| !items.is_empty())
        })
        .collect();
    let explicit_stages = root.field("stages").map(scalar_values).unwrap_or_default();
    let mut stage_names: BTreeSet<&str> = explicit_stages.iter().copied().collect();
    if stage_names.is_empty() {
        stage_names.extend([".pre", "build", "test", "deploy", ".post"]);
        stage_names.extend(job_entries.iter().filter_map(|entry| {
            gitlab_effective_field(&templates, "stage", &entry.value).and_then(YamlNode::scalar)
        }));
    }
    let stage_span = root.field("stages").unwrap_or(root).span().clone();
    let stage_nodes: Vec<_> = stage_names
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            Node::new(
                Provider::Gitlab,
                NodeKind::Stage,
                name,
                Phase::Plan,
                stage_span.clone(),
                Condition::True,
                BTreeMap::from([(
                    "order".to_owned(),
                    AbstractValue::string_constant(
                        index.to_string(),
                        Trust::Trusted,
                        Secrecy::Public,
                        Vec::new(),
                    ),
                )]),
                [],
                [],
                None,
            )
        })
        .collect();
    let stages: BTreeMap<_, _> = stage_nodes
        .iter()
        .map(|stage| (stage.name.clone(), stage.clone()))
        .collect();
    for stage in &stage_nodes {
        graph.add_node(stage.clone());
    }
    if let Some(first) = stage_nodes.first() {
        add_control(&mut graph, &workflow, first);
    }
    for pair in stage_nodes.windows(2) {
        graph.add_edge(Edge::new(
            EdgeKind::Control,
            pair[0].id.clone(),
            pair[1].id.clone(),
            Condition::True,
            Some("sequence".to_owned()),
        ));
    }
    let mut jobs = Vec::new();
    for entry in job_entries {
        let has_environment =
            gitlab_effective_field(&templates, "environment", &entry.value).is_some();
        let job = Node::new(
            Provider::Gitlab,
            NodeKind::Job,
            &entry.key,
            Phase::Plan,
            entry.span.clone(),
            Condition::True,
            BTreeMap::new(),
            if has_environment {
                vec![Capability::Deployment]
            } else {
                Vec::new()
            },
            if has_environment {
                vec![ObservableEffect::DeploymentChange]
            } else {
                Vec::new()
            },
            None,
        );
        graph.add_node(job.clone());
        let owner = gitlab_effective_field(&templates, "stage", &entry.value)
            .and_then(YamlNode::scalar)
            .and_then(|name| stages.get(name))
            .or_else(|| stages.get("test"));
        if let Some(owner) = owner {
            add_control(&mut graph, owner, &job);
        }
        jobs.push((entry.key.clone(), entry.value.clone(), job));
    }
    for (_, body, job) in &jobs {
        if let Some(needs) = gitlab_effective_field(&templates, "needs", body) {
            for requirement in sequence(needs).into_iter().filter_map(|item| {
                item.scalar()
                    .or_else(|| item.field("job").and_then(YamlNode::scalar))
            }) {
                if let Some((_, _, predecessor)) =
                    jobs.iter().find(|(name, _, _)| name == requirement)
                {
                    graph.add_edge(Edge::new(
                        EdgeKind::Control,
                        predecessor.id.clone(),
                        job.id.clone(),
                        Condition::True,
                        Some("needs".to_owned()),
                    ));
                }
            }
        }
    }
    for (_, body, job) in &jobs {
        add_gitlab_rule_gate(&mut graph, job, &templates, body, "rule");
        add_gitlab_manual_gate(&mut graph, job, &templates, body);
        if let Some(extends) = body.field("extends") {
            for template in scalar_values(extends) {
                let call = Node::simple(
                    Provider::Gitlab,
                    NodeKind::Call,
                    format!("extends:{template}"),
                    Phase::Compile,
                    job.span.clone(),
                );
                graph.add_node(call.clone());
                add_call(&mut graph, job, &call);
            }
        }
        if let Some(trigger) = gitlab_effective_field(&templates, "trigger", body)
            && let Some(reference) = gitlab_child_reference(trigger)
        {
            let call = Node::new(
                Provider::Gitlab,
                NodeKind::Call,
                format!("child:{reference}"),
                Phase::Compile,
                trigger.span().clone(),
                Condition::True,
                BTreeMap::new(),
                [],
                [],
                unresolved_for(dependencies, &reference),
            );
            graph.add_node(call.clone());
            add_call(&mut graph, job, &call);
        }
        add_gitlab_matrix(&mut graph, job, &templates, body);
        add_gitlab_job_resources(&mut graph, job, &templates, body);
        add_gitlab_scripts(&mut graph, job, root, &templates, body);
    }
    for dependency in dependencies {
        let call = Node::new(
            Provider::Gitlab,
            NodeKind::Call,
            &dependency.reference,
            Phase::Compile,
            dependency.span.clone(),
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            unresolved_for(dependencies, &dependency.reference),
        );
        graph.add_node(call.clone());
        add_call(&mut graph, &workflow, &call);
    }
    graph
}

fn gitlab_child_reference(trigger: &YamlNode) -> Option<String> {
    if let Some(reference) = trigger.scalar() {
        return Some(reference.to_owned());
    }
    if let Some(include) = trigger.field("include") {
        for item in sequence(include) {
            if let Some(dependency) = gitlab_include_dependencies(item).into_iter().next() {
                return Some(dependency.reference);
            }
        }
    }
    trigger
        .field("project")
        .and_then(YamlNode::scalar)
        .map(str::to_owned)
}

fn add_gitlab_variables(graph: &mut Graph, owner: &Node, variables: &YamlNode) {
    for entry in mapping(variables) {
        let resource = Node::simple(
            Provider::Gitlab,
            NodeKind::Resource,
            format!("variable:{}", entry.key),
            owner.phase,
            entry.span.clone(),
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            resource.id,
            owner.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
    }
}

fn add_gitlab_manual_gate(
    graph: &mut Graph,
    job: &Node,
    templates: &BTreeMap<&str, &YamlNode>,
    body: &YamlNode,
) {
    let Some(when) = gitlab_effective_field(templates, "when", body) else {
        return;
    };
    if !when
        .scalar()
        .is_some_and(|value| value.eq_ignore_ascii_case("manual"))
    {
        return;
    }
    let mechanism = AbstractValue::string_constant(
        "manual",
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "manual".to_owned(),
            span: when.span().clone(),
            operation: "static gate".to_owned(),
        }],
    );
    let gate = Node::new(
        Provider::Gitlab,
        NodeKind::Gate,
        format!("manual:{}", job.name),
        job.phase,
        when.span().clone(),
        Condition::True,
        BTreeMap::from([("mechanism".to_owned(), mechanism)]),
        [],
        [],
        None,
    );
    insert_gate(graph, job, gate);
}

fn add_gitlab_matrix(
    graph: &mut Graph,
    job: &Node,
    templates: &BTreeMap<&str, &YamlNode>,
    body: &YamlNode,
) {
    fn collect<'a>(node: &'a YamlNode, output: &mut BTreeMap<&'a str, &'a Span>) {
        for entry in mapping(node) {
            output.insert(&entry.key, &entry.span);
            collect(&entry.value, output);
        }
        if let Some(items) = node.sequence() {
            for item in items {
                collect(item, output);
            }
        }
    }

    let Some(matrix) = gitlab_effective_field(templates, "parallel", body)
        .and_then(|parallel| parallel.field("matrix"))
    else {
        return;
    };
    let mut entries = BTreeMap::new();
    collect(matrix, &mut entries);
    for (name, span) in entries {
        let parameter = Node::simple(
            Provider::Gitlab,
            NodeKind::Parameter,
            format!("matrix.{name}"),
            Phase::Plan,
            span.clone(),
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id,
            job.id.clone(),
            Condition::True,
            Some(name.to_owned()),
        ));
    }
}

fn add_gitlab_job_resources(
    graph: &mut Graph,
    job: &Node,
    templates: &BTreeMap<&str, &YamlNode>,
    body: &YamlNode,
) {
    if let Some(variables) = gitlab_effective_field(templates, "variables", body) {
        add_gitlab_variables(graph, job, variables);
    }
    if let Some(environment) = gitlab_effective_field(templates, "environment", body) {
        let name = environment
            .scalar()
            .or_else(|| environment.field("name").and_then(YamlNode::scalar))
            .unwrap_or("dynamic");
        let resource = Node::new(
            Provider::Gitlab,
            NodeKind::Resource,
            format!("environment:{name}"),
            Phase::Run,
            environment.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [Capability::Deployment],
            [],
            None,
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::simple(EdgeKind::Grant, resource.id, job.id.clone()));
    }
    if let Some(cache) = gitlab_effective_field(templates, "cache", body) {
        let resource = Node::new(
            Provider::Gitlab,
            NodeKind::Resource,
            format!("cache:{}", job.name),
            Phase::Run,
            cache.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [Capability::CacheRead, Capability::CacheWrite],
            [ObservableEffect::CachePublish],
            None,
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::simple(
            EdgeKind::Write,
            job.id.clone(),
            resource.id.clone(),
        ));
        graph.add_edge(Edge::simple(EdgeKind::Read, resource.id, job.id.clone()));
    }
    if let Some(artifacts) = gitlab_effective_field(templates, "artifacts", body) {
        let resource = Node::new(
            Provider::Gitlab,
            NodeKind::Resource,
            format!("artifact:{}", job.name),
            Phase::Post,
            artifacts.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [Capability::ArtifactWrite],
            [ObservableEffect::ArtifactPublish],
            None,
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::simple(EdgeKind::Write, job.id.clone(), resource.id));
    }
}

fn add_gitlab_rule_gate(
    graph: &mut Graph,
    job: &Node,
    templates: &BTreeMap<&str, &YamlNode>,
    body: &YamlNode,
    prefix: &str,
) {
    let Some(expression) = gitlab_effective_field(templates, "rules", body)
        .into_iter()
        .flat_map(sequence)
        .find_map(|rule| rule.field("if"))
    else {
        return;
    };
    let scalar_source = expression.scalar();
    let source = scalar_source.unwrap_or("<opaque condition>");
    let references = gitlab_gate_references(source, expression.span(), job.phase);
    let mut attributes = BTreeMap::from([(
        "expression".to_owned(),
        AbstractValue::string_constant(
            source,
            Trust::Trusted,
            Secrecy::Public,
            vec![Provenance {
                origin: "workflow condition".to_owned(),
                span: expression.span().clone(),
                operation: "gate".to_owned(),
            }],
        ),
    )]);
    for reference in &references {
        let key = format!("reference:{}", reference.name);
        attributes
            .entry(key)
            .and_modify(|value| *value = value.join(&reference.value))
            .or_insert_with(|| reference.value.clone());
    }
    let phase_unknown = if scalar_source.is_none() {
        Some(UnknownReason::UnsupportedSyntax(
            "condition expression".to_owned(),
        ))
    } else {
        references.iter().find_map(|reference| {
            let minimum = minimum_reference_phase(Provider::Gitlab, &reference.name);
            (phase_rank(job.phase) < phase_rank(minimum)).then(|| {
                UnknownReason::PhaseUnavailable(format!(
                    "{} is unavailable during {}",
                    reference.name,
                    job.phase.name()
                ))
            })
        })
    };
    let condition = scalar_source.map_or_else(
        || Condition::atom("gitlab:<opaque condition>"),
        gitlab_condition,
    );
    let gate = Node::new(
        Provider::Gitlab,
        NodeKind::Gate,
        format!("{prefix}:{}", job.name),
        job.phase,
        expression.span().clone(),
        condition,
        attributes,
        [],
        [],
        phase_unknown,
    );
    insert_gate(graph, job, gate.clone());
    add_expression_references(graph, Provider::Gitlab, &gate, references);
}

fn gitlab_gate_references(
    source: &str,
    parent_span: &Span,
    phase: Phase,
) -> Vec<ExpressionReference> {
    let mut references = expression_references(Provider::Gitlab, phase, source, parent_span);
    for reference in &mut references {
        let offset = reference
            .span
            .start
            .byte
            .saturating_sub(parent_span.start.byte);
        if offset > 0 && source.as_bytes().get(offset - 1) == Some(&b'$') {
            reference.span = offset_span(parent_span, offset - 1, reference.name.len() + 1);
            reference.value = reference_value(Provider::Gitlab, &reference.name, &reference.span);
        }
    }
    references.sort_by(|left, right| (&left.name, &left.span).cmp(&(&right.name, &right.span)));
    references
}

fn gitlab_condition(source: &str) -> Condition {
    let source = trim_wrapping_parentheses(source.trim());
    if let Some((left, right)) = split_condition(source, "||") {
        return gitlab_condition(left).or(&gitlab_condition(right));
    }
    if let Some((left, right)) = split_condition(source, "&&") {
        return gitlab_condition(left).and(&gitlab_condition(right));
    }
    if let Some(rest) = source.strip_prefix('!')
        && !source.starts_with("!=")
        && !source.starts_with("!~")
    {
        return gitlab_condition(rest).not();
    }
    for operator in ["==", "!=", "<=", ">=", "=~", "!~", "<", ">"] {
        if let Some((left, right)) = split_condition(source, operator) {
            return Condition::atom(format!(
                "({}{}{})",
                render_condition_operand(left),
                operator,
                render_condition_operand(right)
            ));
        }
    }
    match source.to_ascii_lowercase().as_str() {
        "true" => Condition::True,
        "false" | "null" => Condition::False,
        _ => Condition::atom(render_condition_operand(source)),
    }
}

fn split_condition<'a>(source: &'a str, operator: &str) -> Option<(&'a str, &'a str)> {
    let bytes = source.as_bytes();
    let operator_bytes = operator.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quote == Some(b'"') {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            quote = if quote == Some(byte) {
                None
            } else if quote.is_none() {
                Some(byte)
            } else {
                quote
            };
        } else if quote.is_none() {
            match byte {
                b'(' => depth = depth.saturating_add(1),
                b')' => depth = depth.saturating_sub(1),
                _ if depth == 0 && bytes[index..].starts_with(operator_bytes) => {
                    return Some((
                        &source[..index],
                        &source[index.saturating_add(operator.len())..],
                    ));
                }
                _ => {}
            }
        }
    }
    None
}

fn trim_wrapping_parentheses(mut source: &str) -> &str {
    loop {
        let Some(inner) = source
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
        else {
            return source;
        };
        let mut depth = 0usize;
        let mut quote = None;
        let mut closes_early = false;
        for (index, byte) in source.bytes().enumerate() {
            if matches!(byte, b'\'' | b'"') {
                quote = if quote == Some(byte) {
                    None
                } else if quote.is_none() {
                    Some(byte)
                } else {
                    quote
                };
            } else if quote.is_none() && byte == b'(' {
                depth = depth.saturating_add(1);
            } else if quote.is_none() && byte == b')' {
                depth = depth.saturating_sub(1);
                if depth == 0 && index.saturating_add(1) != source.len() {
                    closes_early = true;
                    break;
                }
            }
        }
        if closes_early || depth != 0 {
            return source;
        }
        source = inner.trim();
    }
}

fn render_condition_operand(source: &str) -> String {
    let value = source.trim();
    if let Some(reference) = value.strip_prefix('$') {
        reference.to_owned()
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        format!("{:?}", &value[1..value.len() - 1])
    } else if let Some((name, arguments)) = condition_call(value) {
        format!(
            "{name}({})",
            split_call_arguments(arguments)
                .into_iter()
                .map(render_condition_operand)
                .collect::<Vec<_>>()
                .join(",")
        )
    } else {
        value.to_owned()
    }
}

fn condition_call(value: &str) -> Option<(&str, &str)> {
    let open = value.find('(')?;
    if !value.ends_with(')') || open == 0 {
        return None;
    }
    let name = value.get(..open)?.trim();
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate().skip(open) {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            quote = if quote == Some(byte) {
                None
            } else if quote.is_none() {
                Some(byte)
            } else {
                quote
            };
        } else if quote.is_none() && byte == b'(' {
            depth = depth.saturating_add(1);
        } else if quote.is_none() && byte == b')' {
            depth = depth.saturating_sub(1);
            if depth == 0 && index.saturating_add(1) != value.len() {
                return None;
            }
        }
    }
    (depth == 0 && quote.is_none()).then(|| {
        (
            name,
            value
                .get(open.saturating_add(1)..value.len().saturating_sub(1))
                .unwrap_or_default(),
        )
    })
}

fn split_call_arguments(value: &str) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            quote = if quote == Some(byte) {
                None
            } else if quote.is_none() {
                Some(byte)
            } else {
                quote
            };
        } else if quote.is_none() && byte == b'(' {
            depth = depth.saturating_add(1);
        } else if quote.is_none() && byte == b')' {
            depth = depth.saturating_sub(1);
        } else if quote.is_none() && depth == 0 && byte == b',' {
            output.push(value.get(start..index).unwrap_or_default());
            start = index.saturating_add(1);
        }
    }
    if start < value.len() || !value.trim().is_empty() {
        output.push(value.get(start..).unwrap_or_default());
    }
    output
}

fn add_script_commands(
    graph: &mut Graph,
    provider: Provider,
    owner: &Node,
    script: Option<&YamlNode>,
) {
    let Some(script) = script else { return };
    for script_node in scalar_nodes(script) {
        let Some(source) = script_node.scalar() else {
            continue;
        };
        let (command_value, references) = command_value(provider, source, script_node.span());
        let attributes = BTreeMap::from([("command".to_owned(), command_value)]);
        let command = Node::new(
            provider,
            NodeKind::Command,
            source,
            Phase::Run,
            script_node.span().clone(),
            Condition::True,
            attributes,
            [
                Capability::Shell,
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
            ],
            [ObservableEffect::CommandExecution],
            None,
        );
        graph.add_node(command.clone());
        add_control(graph, owner, &command);
        add_expression_references(graph, provider, &command, references);
    }
}

fn add_gitlab_scripts(
    graph: &mut Graph,
    job: &Node,
    root: &YamlNode,
    templates: &BTreeMap<&str, &YamlNode>,
    body: &YamlNode,
) {
    let defaults = root.field("default");
    let scripts: Vec<_> = ["before_script", "script", "after_script"]
        .into_iter()
        .filter_map(|name| {
            gitlab_effective_field(templates, name, body)
                .or_else(|| defaults.and_then(|value| value.field(name)))
        })
        .flat_map(scalar_nodes)
        .collect();
    let mut previous: Option<Node> = None;
    for (index, script) in scripts.into_iter().enumerate() {
        let step = Node::simple(
            Provider::Gitlab,
            NodeKind::Step,
            format!("script:{}", index.saturating_add(1)),
            Phase::Run,
            script.span().clone(),
        );
        graph.add_node(step.clone());
        add_control(graph, job, &step);
        if let Some(predecessor) = &previous {
            graph.add_edge(Edge::new(
                EdgeKind::Control,
                predecessor.id.clone(),
                step.id.clone(),
                Condition::True,
                Some("sequence".to_owned()),
            ));
        }
        add_script_commands(graph, Provider::Gitlab, &step, Some(script));
        previous = Some(step);
    }
}

#[derive(Clone)]
struct ExpressionReference {
    name: String,
    span: Span,
    phase: Phase,
    value: AbstractValue,
}

fn add_expression_references(
    graph: &mut Graph,
    provider: Provider,
    target: &Node,
    references: Vec<ExpressionReference>,
) {
    for reference in references {
        let resource = Node::new(
            provider,
            NodeKind::Resource,
            &reference.name,
            reference.phase,
            reference.span,
            Condition::True,
            BTreeMap::from([("value".to_owned(), reference.value)]),
            [],
            [],
            None,
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            resource.id,
            target.id.clone(),
            Condition::True,
            Some(reference.name),
        ));
    }
}

fn expression_references(
    provider: Provider,
    default_phase: Phase,
    source: &str,
    parent_span: &Span,
) -> Vec<ExpressionReference> {
    let mut found = match provider {
        Provider::Github => {
            let mut values = delimited_references(source, "${{", "}}", default_phase);
            values.extend(dollar_references(source, default_phase));
            values
        }
        Provider::Gitlab => dollar_references(source, default_phase),
        Provider::Azure => {
            let mut values = delimited_references(source, "${{", "}}", Phase::Compile);
            values.extend(dollar_references(source, default_phase));
            values
        }
        Provider::Circleci => {
            let mut values = delimited_references(source, "<<", ">>", Phase::Compile);
            values.extend(dollar_references(source, default_phase));
            values
        }
    };
    found.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    found.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    found
        .into_iter()
        .map(|(offset, name, phase)| {
            let span = offset_span(parent_span, offset, name.len());
            let value = reference_value(provider, &name, &span);
            ExpressionReference {
                name,
                span,
                phase,
                value,
            }
        })
        .collect()
}

fn reference_value(provider: Provider, name: &str, span: &Span) -> AbstractValue {
    AbstractValue::string_constant(
        name,
        reference_trust(provider, name),
        reference_secrecy(name),
        vec![Provenance {
            origin: name.to_owned(),
            span: span.clone(),
            operation: "expression reference".to_owned(),
        }],
    )
}

fn delimited_references(
    source: &str,
    open: &str,
    close: &str,
    phase: Phase,
) -> Vec<(usize, String, Phase)> {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative_open) = source.get(cursor..).and_then(|rest| rest.find(open)) {
        let body_start = cursor
            .saturating_add(relative_open)
            .saturating_add(open.len());
        let Some(relative_close) = source.get(body_start..).and_then(|rest| rest.find(close))
        else {
            break;
        };
        let body_stop = body_start.saturating_add(relative_close);
        if let Some(body) = source.get(body_start..body_stop) {
            output.extend(
                unquoted_expression_words(body)
                    .into_iter()
                    .filter(|(_, name)| looks_like_reference(name))
                    .map(|(offset, name)| (body_start + offset, name.to_owned(), phase)),
            );
        }
        cursor = body_stop.saturating_add(close.len());
    }
    output
}

fn dollar_references(source: &str, phase: Phase) -> Vec<(usize, String, Phase)> {
    let bytes = source.as_bytes();
    let mut output = Vec::new();
    for (index, _) in source.match_indices('$') {
        let following = index.saturating_add('$'.len_utf8());
        let Some(following_byte) = bytes.get(following).copied() else {
            continue;
        };
        match following_byte {
            b'(' => {
                let name_start = following.saturating_add(1);
                let Some(relative_stop) = bytes[name_start..].iter().position(|byte| *byte == b')')
                else {
                    continue;
                };
                let stop = name_start.saturating_add(relative_stop);
                if let Some(name) = source.get(name_start..stop) {
                    output.push((name_start, name.to_owned(), phase));
                }
            }
            b'A'..=b'Z' | b'_' => {
                let name_start = following;
                let stop = bytes[name_start..]
                    .iter()
                    .position(|byte| !expression_identifier_byte(*byte))
                    .map_or(bytes.len(), |relative| name_start.saturating_add(relative));
                if let Some(name) = source.get(name_start..stop) {
                    output.push((name_start, name.to_owned(), phase));
                }
            }
            _ => {}
        }
    }
    output
}

fn expression_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

fn looks_like_reference(value: &str) -> bool {
    value.contains('.')
        || (value.len() > 1
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'))
}

fn reference_trust(provider: Provider, name: &str) -> Trust {
    let lower = name.to_ascii_lowercase();
    match provider {
        Provider::Github
            if lower.starts_with("github.event.")
                || lower.starts_with("inputs.")
                || [
                    "github.actor",
                    "github.base_ref",
                    "github.head_ref",
                    "github.ref",
                    "github.ref_name",
                    "github.triggering_actor",
                ]
                .contains(&lower.as_str()) =>
        {
            Trust::Untrusted
        }
        Provider::Github
            if lower.starts_with("env.")
                || lower.starts_with("needs.")
                || lower.starts_with("steps.") && lower.contains(".outputs.") =>
        {
            Trust::Unknown(vec![UnknownReason::DynamicString(format!(
                "unresolved GitHub dataflow value {name}"
            ))])
        }
        Provider::Gitlab if lower == "ci_merge_request_diff_base_sha" => Trust::Trusted,
        Provider::Gitlab
            if lower.starts_with("ci_merge_request_")
                || lower.starts_with("ci_external_pull_request_")
                || [
                    "ci_commit_branch",
                    "ci_commit_message",
                    "ci_commit_ref_name",
                    "ci_commit_tag",
                ]
                .contains(&lower.as_str()) =>
        {
            Trust::Untrusted
        }
        Provider::Azure if lower == "system.pullrequest.pullrequestnumber" => Trust::Trusted,
        Provider::Azure
            if lower.starts_with("system.pullrequest.")
                || [
                    "build.sourcebranch",
                    "build.sourcebranchname",
                    "build.sourceversionmessage",
                ]
                .contains(&lower.as_str()) =>
        {
            Trust::Untrusted
        }
        Provider::Circleci
            if lower.starts_with("pipeline.parameters.")
                || ["circle_branch", "circle_pull_request", "circle_tag"]
                    .contains(&lower.as_str()) =>
        {
            Trust::Untrusted
        }
        _ => Trust::Trusted,
    }
}

fn reference_secrecy(name: &str) -> Secrecy {
    let lower = name.to_ascii_lowercase();
    if ["secret", "token", "password", "accesskey", "access_token"]
        .into_iter()
        .any(|fragment| lower.contains(fragment))
    {
        Secrecy::Secret
    } else {
        Secrecy::Public
    }
}

fn phase_rank(phase: Phase) -> u8 {
    match phase {
        Phase::Source => 0,
        Phase::Compile => 1,
        Phase::Plan => 2,
        Phase::Run => 3,
        Phase::Post => 4,
    }
}

fn minimum_reference_phase(provider: Provider, name: &str) -> Phase {
    let lower = name.to_ascii_lowercase();
    match provider {
        Provider::Github
            if ["steps.", "runner.", "job.", "secrets."]
                .into_iter()
                .any(|prefix| lower.starts_with(prefix)) =>
        {
            Phase::Run
        }
        Provider::Github
            if ["needs.", "matrix.", "strategy."]
                .into_iter()
                .any(|prefix| lower.starts_with(prefix)) =>
        {
            Phase::Plan
        }
        Provider::Github if lower.starts_with("github.") => Phase::Source,
        Provider::Github => Phase::Compile,
        Provider::Gitlab if lower.starts_with("ci_") => Phase::Plan,
        Provider::Azure
            if lower.starts_with("dependencies.") || lower.starts_with("stagedependencies.") =>
        {
            Phase::Run
        }
        Provider::Azure if lower.starts_with("parameters.") => Phase::Compile,
        Provider::Azure => Phase::Plan,
        Provider::Circleci if lower.starts_with("pipeline.parameters.") => Phase::Compile,
        Provider::Gitlab | Provider::Circleci => Phase::Run,
    }
}

fn offset_span(parent: &Span, start: usize, length: usize) -> Span {
    let column_offset = u32::try_from(start).unwrap_or(u32::MAX);
    let stop_offset = u32::try_from(start.saturating_add(length)).unwrap_or(u32::MAX);
    Span::new(
        &parent.file,
        Position {
            byte: parent.start.byte.saturating_add(start),
            line: parent.start.line,
            column: parent.start.column.saturating_add(column_offset),
        },
        Position {
            byte: parent
                .start
                .byte
                .saturating_add(start)
                .saturating_add(length),
            line: parent.start.line,
            column: parent.start.column.saturating_add(stop_offset),
        },
    )
}

fn command_value(
    provider: Provider,
    source: &str,
    span: &Span,
) -> (AbstractValue, Vec<ExpressionReference>) {
    let references = expression_references(provider, Phase::Run, source, span);
    let base = AbstractValue::string_constant(
        source,
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "workflow source".to_owned(),
            span: span.clone(),
            operation: "command".to_owned(),
        }],
    );
    let value = references
        .iter()
        .fold(base, |current, reference| current.join(&reference.value));
    (value, references)
}

fn azure_abstract_scalar(node: &YamlNode, phase: Phase) -> AbstractValue {
    let Some(source) = node.scalar() else {
        return AbstractValue::unknown(UnknownReason::DynamicString(
            "non-scalar Azure value".to_owned(),
        ));
    };
    let base = AbstractValue::string_constant(
        source,
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "Azure YAML".to_owned(),
            span: node.span().clone(),
            operation: "value".to_owned(),
        }],
    );
    expression_references(Provider::Azure, phase, source, node.span())
        .iter()
        .fold(base, |value, reference| value.join(&reference.value))
}

fn add_azure_parameters(graph: &mut Graph, owner: &Node, parameters: &YamlNode) {
    for item in sequence(parameters) {
        let name = item
            .field("name")
            .and_then(YamlNode::scalar)
            .unwrap_or("parameter");
        let value = item.field("default").map_or_else(
            || AbstractValue::unknown(UnknownReason::ExternalState(format!("parameter {name}"))),
            |default| azure_abstract_scalar(default, Phase::Compile),
        );
        let parameter = Node::new(
            Provider::Azure,
            NodeKind::Parameter,
            name,
            Phase::Compile,
            item.span().clone(),
            Condition::True,
            BTreeMap::from([("value".to_owned(), value)]),
            [],
            [],
            None,
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id,
            owner.id.clone(),
            Condition::True,
            None,
        ));
    }
}

fn add_azure_variables(graph: &mut Graph, owner: &Node, variables: &YamlNode) {
    let entries: Vec<(String, &YamlNode, Span)> = if mapping(variables).is_empty() {
        sequence(variables)
            .into_iter()
            .filter_map(|item| {
                let name = item.field("name").and_then(YamlNode::scalar)?.to_owned();
                let value = item.field("value").unwrap_or(item);
                Some((name, value, item.span().clone()))
            })
            .collect()
    } else {
        mapping(variables)
            .iter()
            .map(|entry| (entry.key.clone(), &entry.value, entry.span.clone()))
            .collect()
    };
    for (name, value_node, span) in entries {
        let resource = Node::new(
            Provider::Azure,
            NodeKind::Resource,
            format!("variable:{name}"),
            owner.phase,
            span,
            Condition::True,
            BTreeMap::from([(
                "value".to_owned(),
                azure_abstract_scalar(value_node, Phase::Run),
            )]),
            [],
            [],
            None,
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            resource.id,
            owner.id.clone(),
            Condition::True,
            Some(name),
        ));
    }
}

fn add_azure_repository_resources(
    graph: &mut Graph,
    workflow: &Node,
    root: &YamlNode,
    dependencies: &[Dependency],
) {
    for repository in azure_repository_specs(root) {
        let reference = repository.revision.as_deref().map_or_else(
            || repository.repository.clone(),
            |revision| format!("{}@{revision}", repository.repository),
        );
        let resource = Node::new(
            Provider::Azure,
            NodeKind::Resource,
            format!("repository:{}", repository.alias),
            Phase::Compile,
            repository.node.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [Capability::RepositoryRead],
            [],
            None,
        );
        let call = Node::new(
            Provider::Azure,
            NodeKind::Call,
            &reference,
            Phase::Compile,
            repository.node.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [Capability::RepositoryRead, Capability::Network],
            [],
            unresolved_for(dependencies, &reference),
        );
        graph.add_node(resource.clone());
        graph.add_edge(Edge::simple(
            EdgeKind::Read,
            resource.id.clone(),
            workflow.id.clone(),
        ));
        graph.add_node(call.clone());
        add_call(graph, &resource, &call);
    }
}

fn add_azure_template_directives(graph: &mut Graph, owner: &Node, root: &YamlNode) {
    fn walk(graph: &mut Graph, owner: &Node, node: &YamlNode) {
        if let Some(entries) = node.mapping() {
            for entry in entries {
                if entry.key.starts_with("${{") {
                    let opaque = Node::new(
                        Provider::Azure,
                        NodeKind::Opaque,
                        format!("template-directive:{}", entry.key),
                        Phase::Compile,
                        entry.span.clone(),
                        Condition::True,
                        BTreeMap::new(),
                        [],
                        [],
                        Some(UnknownReason::UnsupportedSyntax(format!(
                            "Azure template directive {}",
                            entry.key
                        ))),
                    );
                    graph.add_node(opaque.clone());
                    add_control(graph, owner, &opaque);
                }
                walk(graph, owner, &entry.value);
            }
        }
        if let Some(items) = node.sequence() {
            for item in items {
                walk(graph, owner, item);
            }
        }
    }
    walk(graph, owner, root);
}

fn azure_dependency_names(body: &YamlNode) -> Vec<String> {
    body.field("dependsOn")
        .map(scalar_values)
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn link_dependencies(
    graph: &mut Graph,
    nodes: &[Node],
    dependencies: &[(String, Vec<String>, Span)],
    unknown_code: &str,
    cycle_code: &str,
    label: &str,
) -> Vec<FrontendProblem> {
    fn visit_cycle(
        name: &str,
        dependencies: &[(String, Vec<String>, Span)],
        known: &BTreeSet<String>,
        visiting: &mut Vec<String>,
        visited: &mut BTreeSet<String>,
    ) -> Option<Vec<String>> {
        if visited.contains(name) {
            return None;
        }
        if visiting.iter().any(|item| item == name) {
            let mut path = vec![name.to_owned()];
            path.extend(visiting.iter().rev().cloned());
            return Some(path);
        }
        visiting.push(name.to_owned());
        let targets = dependencies
            .iter()
            .find(|(owner, _, _)| owner == name)
            .map(|(_, targets, _)| targets.as_slice())
            .unwrap_or_default();
        for target in targets.iter().filter(|target| known.contains(*target)) {
            if let Some(path) = visit_cycle(target, dependencies, known, visiting, visited) {
                return Some(path);
            }
        }
        let _ = visiting.pop();
        visited.insert(name.to_owned());
        None
    }

    let mut problems = Vec::new();
    for (owner_name, targets, span) in dependencies {
        let Some(owner) = nodes.iter().find(|node| node.name == *owner_name) else {
            continue;
        };
        for target_name in targets {
            if let Some(target) = nodes.iter().find(|node| node.name == *target_name) {
                graph.add_edge(Edge::new(
                    EdgeKind::Control,
                    target.id.clone(),
                    owner.id.clone(),
                    Condition::True,
                    Some(label.to_owned()),
                ));
            } else {
                problems.push(FrontendProblem {
                    code: unknown_code.to_owned(),
                    message: format!("{owner_name} references unknown {target_name}"),
                    span: span.clone(),
                });
            }
        }
    }

    let known: BTreeSet<_> = nodes.iter().map(|node| node.name.clone()).collect();
    let mut visiting = Vec::new();
    let mut visited = BTreeSet::new();
    let cycle = nodes.iter().find_map(|node| {
        visit_cycle(
            &node.name,
            dependencies,
            &known,
            &mut visiting,
            &mut visited,
        )
    });
    if let Some(path) = cycle {
        let span = path
            .iter()
            .find_map(|name| nodes.iter().find(|node| node.name == *name))
            .map_or_else(Span::default, |node| node.span.clone());
        problems.push(FrontendProblem {
            code: cycle_code.to_owned(),
            message: format!("dependency cycle: {}", path.join(" -> ")),
            span,
        });
    }
    problems
}

fn azure_gate_references(
    source: &str,
    parent_span: &Span,
    phase: Phase,
) -> Vec<ExpressionReference> {
    let trimmed_start = source.len().saturating_sub(source.trim_start().len());
    let trimmed = source.trim();
    let (body, body_offset) = trimmed
        .strip_prefix("${{")
        .and_then(|inner| inner.strip_suffix("}}"))
        .map_or((trimmed, trimmed_start), |inner| {
            let leading = inner.len().saturating_sub(inner.trim_start().len());
            (inner.trim(), trimmed_start + 3 + leading)
        });
    let mut references: Vec<_> = unquoted_expression_words(body)
        .into_iter()
        .filter(|(_, name)| looks_like_reference(name))
        .map(|(offset, name)| {
            let span = offset_span(parent_span, body_offset + offset, name.len());
            ExpressionReference {
                name: name.to_owned(),
                span: span.clone(),
                phase,
                value: reference_value(Provider::Azure, name, &span),
            }
        })
        .collect();
    references.sort_by(|left, right| (&left.name, &left.span).cmp(&(&right.name, &right.span)));
    references.dedup_by(|left, right| left.name == right.name && left.span == right.span);
    references
}

fn add_azure_gate(graph: &mut Graph, owner: &Node, name: String, condition: &YamlNode) {
    let scalar_source = condition.scalar();
    let source = scalar_source.unwrap_or("<opaque condition>");
    let references = scalar_source.map_or_else(Vec::new, |source| {
        azure_gate_references(source, condition.span(), owner.phase)
    });
    let mut attributes = BTreeMap::from([(
        "expression".to_owned(),
        AbstractValue::string_constant(
            source,
            Trust::Trusted,
            Secrecy::Public,
            vec![Provenance {
                origin: "workflow condition".to_owned(),
                span: condition.span().clone(),
                operation: "gate".to_owned(),
            }],
        ),
    )]);
    for reference in &references {
        let key = format!("reference:{}", reference.name);
        attributes
            .entry(key)
            .and_modify(|value| *value = value.join(&reference.value))
            .or_insert_with(|| reference.value.clone());
    }
    let unknown = if scalar_source.is_none() {
        Some(UnknownReason::UnsupportedSyntax(
            "condition expression".to_owned(),
        ))
    } else {
        references.iter().find_map(|reference| {
            let minimum = minimum_reference_phase(Provider::Azure, &reference.name);
            (phase_rank(owner.phase) < phase_rank(minimum)).then(|| {
                UnknownReason::PhaseUnavailable(format!(
                    "{} is unavailable during {}",
                    reference.name,
                    owner.phase.name()
                ))
            })
        })
    };
    let predicate = scalar_source.map_or_else(
        || Condition::atom("azure:<opaque condition>"),
        |source| {
            let trimmed = source.trim();
            let body = trimmed
                .strip_prefix("${{")
                .and_then(|inner| inner.strip_suffix("}}"))
                .map_or(trimmed, str::trim);
            gitlab_condition(body)
        },
    );
    let gate = Node::new(
        Provider::Azure,
        NodeKind::Gate,
        name,
        owner.phase,
        condition.span().clone(),
        predicate,
        attributes,
        [],
        [],
        unknown,
    );
    insert_gate(graph, owner, gate.clone());
    add_expression_references(graph, Provider::Azure, &gate, references);
}

fn add_azure_matrix(graph: &mut Graph, job: &Node, body: &YamlNode) {
    let Some(matrix) = body
        .field("strategy")
        .and_then(|strategy| strategy.field("matrix"))
    else {
        return;
    };
    for entry in mapping(matrix) {
        let parameter = Node::simple(
            Provider::Azure,
            NodeKind::Parameter,
            format!("matrix.{}", entry.key),
            Phase::Plan,
            entry.span.clone(),
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id,
            job.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
    }
}

fn azure_task_profile(reference: &str) -> (Vec<Capability>, Vec<ObservableEffect>) {
    let lower = reference.to_ascii_lowercase();
    if lower.contains("publish") {
        (
            vec![Capability::ArtifactWrite, Capability::Network],
            vec![ObservableEffect::ArtifactPublish],
        )
    } else if lower.contains("download") {
        (
            vec![Capability::ArtifactRead, Capability::Network],
            vec![ObservableEffect::FileWrite],
        )
    } else if lower.contains("cache") {
        (
            vec![Capability::CacheRead, Capability::CacheWrite],
            vec![ObservableEffect::CachePublish],
        )
    } else if ["azurecli", "aws", "gcloud"]
        .into_iter()
        .any(|name| lower.contains(name))
    {
        (
            vec![
                Capability::CloudCredential,
                Capability::Network,
                Capability::Shell,
            ],
            vec![
                ObservableEffect::CredentialUse,
                ObservableEffect::NetworkRequest,
                ObservableEffect::CommandExecution,
            ],
        )
    } else {
        (
            vec![Capability::Shell],
            vec![ObservableEffect::CommandExecution],
        )
    }
}

fn add_azure_environment(graph: &mut Graph, job: &Node, body: &YamlNode) {
    let Some(environment) = body.field("environment") else {
        return;
    };
    let name = environment
        .scalar()
        .or_else(|| environment.field("name").and_then(YamlNode::scalar))
        .unwrap_or("dynamic");
    let resource = Node::new(
        Provider::Azure,
        NodeKind::Resource,
        format!("environment:{name}"),
        Phase::Run,
        environment.span().clone(),
        Condition::True,
        BTreeMap::new(),
        [Capability::Deployment],
        [],
        None,
    );
    graph.add_node(resource.clone());
    graph.add_edge(Edge::simple(EdgeKind::Grant, resource.id, job.id.clone()));
}

fn add_azure_command(graph: &mut Graph, step: &Node, shell: &str, source: &YamlNode) {
    let Some(command_source) = source.scalar() else {
        return;
    };
    let (command_value, references) = command_value(Provider::Azure, command_source, source.span());
    let command = Node::new(
        Provider::Azure,
        NodeKind::Command,
        command_source,
        Phase::Run,
        source.span().clone(),
        Condition::True,
        BTreeMap::from([
            ("command".to_owned(), command_value),
            (
                "shell".to_owned(),
                AbstractValue::string_constant(shell, Trust::Trusted, Secrecy::Public, Vec::new()),
            ),
        ]),
        [
            Capability::Shell,
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
        ],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(command.clone());
    add_control(graph, step, &command);
    add_expression_references(graph, Provider::Azure, &command, references);
}

#[allow(clippy::too_many_lines)]
fn add_azure_steps(graph: &mut Graph, dependencies: &[Dependency], job: &Node, body: &YamlNode) {
    let Some(steps) = body.field("steps") else {
        return;
    };
    let records: Vec<_> = sequence(steps)
        .into_iter()
        .enumerate()
        .map(|(index, body)| {
            let name = body
                .field("displayName")
                .and_then(YamlNode::scalar)
                .map_or_else(
                    || format!("step {}", index.saturating_add(1)),
                    str::to_owned,
                );
            let step = Node::simple(
                Provider::Azure,
                NodeKind::Step,
                name,
                Phase::Run,
                body.span().clone(),
            );
            (body, step)
        })
        .collect();
    for (_, step) in &records {
        graph.add_node(step.clone());
        add_control(graph, job, step);
    }
    for pair in records.windows(2) {
        graph.add_edge(Edge::new(
            EdgeKind::Control,
            pair[0].1.id.clone(),
            pair[1].1.id.clone(),
            Condition::True,
            Some("sequence".to_owned()),
        ));
    }
    for (body, step) in records {
        if let Some(condition) = body.field("condition") {
            add_azure_gate(
                graph,
                &step,
                format!("condition:{}:{}", job.name, step.name),
                condition,
            );
        }
        if let Some(checkout) = body.field("checkout") {
            if let Some(reference) = checkout.scalar() {
                let call = Node::new(
                    Provider::Azure,
                    NodeKind::Call,
                    format!("checkout:{reference}"),
                    Phase::Run,
                    checkout.span().clone(),
                    Condition::True,
                    BTreeMap::new(),
                    [Capability::RepositoryRead, Capability::FilesystemWrite],
                    [ObservableEffect::FileWrite],
                    None,
                );
                graph.add_node(call.clone());
                add_call(graph, &step, &call);
            }
        } else if let Some(template) = body.field("template") {
            if let Some(reference) = template.scalar() {
                let call = Node::new(
                    Provider::Azure,
                    NodeKind::Call,
                    reference,
                    Phase::Compile,
                    template.span().clone(),
                    Condition::True,
                    BTreeMap::new(),
                    [],
                    [],
                    unresolved_for(dependencies, reference),
                );
                graph.add_node(call.clone());
                add_call(graph, &step, &call);
            }
        } else if let Some(task) = body.field("task") {
            if let Some(reference) = task.scalar() {
                let (capabilities, effects) = azure_task_profile(reference);
                let call = Node::new(
                    Provider::Azure,
                    NodeKind::Call,
                    reference,
                    Phase::Run,
                    task.span().clone(),
                    Condition::True,
                    BTreeMap::new(),
                    capabilities,
                    effects,
                    unresolved_for(dependencies, reference),
                );
                graph.add_node(call.clone());
                add_call(graph, &step, &call);
            }
        } else if let Some((shell, command)) = ["script", "bash", "pwsh", "powershell"]
            .into_iter()
            .find_map(|key| body.field(key).map(|node| (key, node)))
        {
            add_azure_command(graph, &step, shell, command);
        } else {
            let opaque = Node::new(
                Provider::Azure,
                NodeKind::Opaque,
                format!("unsupported Azure step {}", step.name),
                Phase::Run,
                step.span.clone(),
                Condition::True,
                BTreeMap::new(),
                [],
                [],
                Some(UnknownReason::UnsupportedSyntax(
                    "Azure step kind".to_owned(),
                )),
            );
            graph.add_node(opaque.clone());
            add_control(graph, &step, &opaque);
        }
    }
}

struct AzureJob<'a> {
    body: &'a YamlNode,
    job: Node,
    parent: Node,
    owns_variables: bool,
}

fn collect_azure_jobs<'a>(parent: &Node, jobs: &'a YamlNode) -> Vec<AzureJob<'a>> {
    sequence(jobs)
        .into_iter()
        .filter_map(|body| {
            let name = body
                .field("job")
                .and_then(YamlNode::scalar)
                .or_else(|| body.field("deployment").and_then(YamlNode::scalar))?;
            let deployment =
                body.field("deployment").is_some() || body.field("environment").is_some();
            Some(AzureJob {
                body,
                job: Node::new(
                    Provider::Azure,
                    NodeKind::Job,
                    name,
                    Phase::Plan,
                    body.span().clone(),
                    Condition::True,
                    BTreeMap::new(),
                    deployment.then_some(Capability::Deployment),
                    deployment.then_some(ObservableEffect::DeploymentChange),
                    None,
                ),
                parent: parent.clone(),
                owns_variables: true,
            })
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn lower_azure(
    path: &str,
    root: &YamlNode,
    dependencies: &[Dependency],
) -> (Graph, Vec<FrontendProblem>) {
    let workflow = workflow_node(Provider::Azure, "Azure pipeline", root);
    let mut graph = Graph::empty(Provider::Azure, path);
    graph.add_node(workflow.clone());
    graph.add_entrypoint(workflow.id.clone());
    for name in ["trigger", "pr", "schedules"] {
        if let Some(trigger) = root.field(name) {
            let node = Node::simple(
                Provider::Azure,
                NodeKind::Trigger,
                name,
                Phase::Source,
                trigger.span().clone(),
            );
            graph.add_node(node.clone());
            add_control(&mut graph, &node, &workflow);
        }
    }
    if let Some(parameters) = root.field("parameters") {
        add_azure_parameters(&mut graph, &workflow, parameters);
    }
    if let Some(variables) = root.field("variables") {
        add_azure_variables(&mut graph, &workflow, variables);
    }
    add_azure_repository_resources(&mut graph, &workflow, root, dependencies);
    add_azure_template_directives(&mut graph, &workflow, root);

    let stages: Vec<_> = root
        .field("stages")
        .map(sequence)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|body| {
            let name = body.field("stage").and_then(YamlNode::scalar)?;
            Some((
                body,
                Node::simple(
                    Provider::Azure,
                    NodeKind::Stage,
                    name,
                    Phase::Plan,
                    body.span().clone(),
                ),
            ))
        })
        .collect();
    for (_, stage) in &stages {
        graph.add_node(stage.clone());
        add_control(&mut graph, &workflow, stage);
    }
    let stage_nodes: Vec<_> = stages.iter().map(|(_, stage)| stage.clone()).collect();
    let stage_dependencies: Vec<_> = stages
        .iter()
        .map(|(body, stage)| {
            (
                stage.name.clone(),
                azure_dependency_names(body),
                body.span().clone(),
            )
        })
        .collect();
    let mut problems = link_dependencies(
        &mut graph,
        &stage_nodes,
        &stage_dependencies,
        "AZ-UNKNOWN-DEPENDENCY",
        "AZ-DEPENDENCY-CYCLE",
        "dependsOn",
    );
    for (body, stage) in &stages {
        if let Some(condition) = body.field("condition") {
            add_azure_gate(
                &mut graph,
                stage,
                format!("condition:stage:{}", stage.name),
                condition,
            );
        }
    }

    let mut jobs = Vec::new();
    for (body, stage) in &stages {
        if let Some(job_values) = body.field("jobs") {
            jobs.extend(collect_azure_jobs(stage, job_values));
        }
    }
    if stages.is_empty() {
        if let Some(job_values) = root.field("jobs") {
            jobs = collect_azure_jobs(&workflow, job_values);
        } else {
            jobs.push(AzureJob {
                body: root,
                job: Node::simple(
                    Provider::Azure,
                    NodeKind::Job,
                    "pipeline",
                    Phase::Plan,
                    root.span().clone(),
                ),
                parent: workflow.clone(),
                owns_variables: false,
            });
        }
    }
    for lowered in &jobs {
        graph.add_node(lowered.job.clone());
        add_control(&mut graph, &lowered.parent, &lowered.job);
    }
    let job_nodes: Vec<_> = jobs.iter().map(|lowered| lowered.job.clone()).collect();
    let job_dependencies: Vec<_> = jobs
        .iter()
        .map(|lowered| {
            (
                lowered.job.name.clone(),
                azure_dependency_names(lowered.body),
                lowered.body.span().clone(),
            )
        })
        .collect();
    problems.extend(link_dependencies(
        &mut graph,
        &job_nodes,
        &job_dependencies,
        "AZ-UNKNOWN-JOB-DEPENDENCY",
        "AZ-JOB-DEPENDENCY-CYCLE",
        "dependsOn",
    ));
    for lowered in &jobs {
        if let Some(condition) = lowered.body.field("condition") {
            add_azure_gate(
                &mut graph,
                &lowered.job,
                format!("condition:job:{}", lowered.job.name),
                condition,
            );
        }
        if lowered.owns_variables
            && let Some(variables) = lowered.body.field("variables")
        {
            add_azure_variables(&mut graph, &lowered.job, variables);
        }
        add_azure_matrix(&mut graph, &lowered.job, lowered.body);
        add_azure_environment(&mut graph, &lowered.job, lowered.body);
        add_azure_steps(&mut graph, dependencies, &lowered.job, lowered.body);
    }
    (graph, problems)
}

type CircleciParameters = BTreeMap<String, Node>;

#[derive(Clone)]
struct CircleciCommand<'a> {
    body: &'a YamlNode,
    resource: Node,
    parameters: CircleciParameters,
}

#[derive(Clone)]
struct CircleciOrb {
    reference: String,
    target: Node,
}

struct CircleciInvocation<'a> {
    alias: String,
    aliases: Vec<String>,
    target: Node,
    body: &'a YamlNode,
    requires: Vec<String>,
    span: Span,
}

fn add_circleci_parameters(
    graph: &mut Graph,
    owner: &Node,
    prefix: &str,
    parameters: &YamlNode,
) -> CircleciParameters {
    let mut bindings = BTreeMap::new();
    for entry in mapping(parameters) {
        let value = entry
            .value
            .field("default")
            .and_then(YamlNode::scalar)
            .map_or_else(
                || {
                    AbstractValue::unknown(UnknownReason::ExternalState(format!(
                        "{prefix} parameter {}",
                        entry.key
                    )))
                },
                |default| {
                    AbstractValue::string_constant(
                        default,
                        if prefix == "pipeline" {
                            Trust::Untrusted
                        } else {
                            Trust::Trusted
                        },
                        Secrecy::Public,
                        vec![Provenance {
                            origin: format!("{prefix} parameter"),
                            span: entry.span.clone(),
                            operation: "default".to_owned(),
                        }],
                    )
                },
            );
        let parameter = Node::new(
            Provider::Circleci,
            NodeKind::Parameter,
            format!("{prefix}.{}", entry.key),
            Phase::Compile,
            entry.span.clone(),
            Condition::True,
            BTreeMap::from([("value".to_owned(), value)]),
            [],
            [],
            None,
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id.clone(),
            owner.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
        bindings.insert(entry.key.clone(), parameter);
    }
    bindings
}

fn circleci_local_parameter_name(reference: &str) -> Option<&str> {
    let prefix = "parameters.";
    reference
        .get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        .then(|| reference.get(prefix.len()..))
        .flatten()
}

fn circleci_argument_value(node: &YamlNode) -> AbstractValue {
    let Some(source) = node.scalar() else {
        return AbstractValue::unknown(UnknownReason::DynamicString(
            "CircleCI argument".to_owned(),
        ));
    };
    let base = AbstractValue::string_constant(
        source,
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "CircleCI invocation argument".to_owned(),
            span: node.span().clone(),
            operation: "bind".to_owned(),
        }],
    );
    expression_references(Provider::Circleci, Phase::Compile, source, node.span())
        .iter()
        .fold(base, |value, reference| value.join(&reference.value))
}

fn bind_circleci_arguments(
    graph: &mut Graph,
    scope: &str,
    bindings: &CircleciParameters,
    body: &YamlNode,
) {
    for entry in mapping(body) {
        let Some(parameter) = bindings.get(&entry.key) else {
            continue;
        };
        let argument = Node::new(
            Provider::Circleci,
            NodeKind::Parameter,
            format!("argument:{scope}.{}", entry.key),
            Phase::Compile,
            entry.span.clone(),
            Condition::True,
            BTreeMap::from([("value".to_owned(), circleci_argument_value(&entry.value))]),
            [],
            [],
            None,
        );
        graph.add_node(argument.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            argument.id,
            parameter.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
    }
}

fn circleci_builtin_profile(name: &str) -> (Vec<Capability>, Vec<ObservableEffect>, EdgeKind) {
    match name.to_ascii_lowercase().as_str() {
        "checkout" => (
            vec![Capability::RepositoryRead, Capability::FilesystemWrite],
            vec![ObservableEffect::FileWrite],
            EdgeKind::Read,
        ),
        "save_cache" => (
            vec![Capability::CacheWrite, Capability::FilesystemRead],
            vec![ObservableEffect::CachePublish],
            EdgeKind::Write,
        ),
        "restore_cache" => (
            vec![Capability::CacheRead, Capability::FilesystemWrite],
            vec![ObservableEffect::FileWrite],
            EdgeKind::Read,
        ),
        "store_artifacts" | "store_test_results" => (
            vec![Capability::ArtifactWrite, Capability::FilesystemRead],
            vec![ObservableEffect::ArtifactPublish],
            EdgeKind::Write,
        ),
        "persist_to_workspace" => (
            vec![Capability::ArtifactWrite, Capability::FilesystemRead],
            vec![ObservableEffect::ArtifactPublish],
            EdgeKind::Persist,
        ),
        "attach_workspace" => (
            vec![Capability::ArtifactRead, Capability::FilesystemWrite],
            vec![ObservableEffect::FileWrite],
            EdgeKind::Read,
        ),
        _ => (Vec::new(), Vec::new(), EdgeKind::Call),
    }
}

fn circleci_mapping_head(node: &YamlNode) -> Option<(&str, &YamlNode)> {
    mapping(node)
        .first()
        .map(|entry| (entry.key.as_str(), &entry.value))
}

fn circleci_orb_target<'a>(
    orbs: &'a BTreeMap<String, CircleciOrb>,
    name: &str,
) -> Option<&'a CircleciOrb> {
    name.split_once('/').and_then(|(alias, _)| orbs.get(alias))
}

fn circleci_orb_attributes(
    span: &Span,
    target: Option<&CircleciOrb>,
) -> BTreeMap<String, AbstractValue> {
    target.map_or_else(BTreeMap::new, |orb| {
        BTreeMap::from([(
            "dependency.reference".to_owned(),
            AbstractValue::string_constant(
                &orb.reference,
                Trust::Trusted,
                Secrecy::Public,
                vec![Provenance {
                    origin: "CircleCI orb alias".to_owned(),
                    span: span.clone(),
                    operation: "resolve immutable dependency identity".to_owned(),
                }],
            ),
        )])
    })
}

fn add_circleci_run(
    graph: &mut Graph,
    parent: &Node,
    run: &YamlNode,
    parameters: &CircleciParameters,
) {
    let command_node = run.field("command").unwrap_or(run);
    let name = if run.scalar().is_some() {
        run.scalar().unwrap_or("run")
    } else {
        run.field("name")
            .and_then(YamlNode::scalar)
            .unwrap_or("run")
    };
    let Some(source) = command_node.scalar() else {
        return;
    };
    let (mut value, references) = command_value(Provider::Circleci, source, command_node.span());
    for reference in &references {
        if let Some(local) = circleci_local_parameter_name(&reference.name)
            && !parameters.contains_key(local)
        {
            value = value.join(&AbstractValue::unknown(UnknownReason::ExternalState(
                format!("CircleCI parameter {local}"),
            )));
        }
    }
    let command = Node::new(
        Provider::Circleci,
        NodeKind::Command,
        name,
        Phase::Run,
        command_node.span().clone(),
        Condition::True,
        BTreeMap::from([("command".to_owned(), value)]),
        [
            Capability::Shell,
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
        ],
        [ObservableEffect::CommandExecution],
        None,
    );
    graph.add_node(command.clone());
    add_control(graph, parent, &command);
    add_expression_references(graph, Provider::Circleci, &command, references.clone());
    for reference in references {
        if let Some(parameter) =
            circleci_local_parameter_name(&reference.name).and_then(|name| parameters.get(name))
        {
            graph.add_edge(Edge::new(
                EdgeKind::Data,
                parameter.id.clone(),
                command.id.clone(),
                Condition::True,
                Some(reference.name),
            ));
        }
    }
}

fn add_circleci_step(
    graph: &mut Graph,
    commands: &BTreeMap<String, CircleciCommand<'_>>,
    orbs: &BTreeMap<String, CircleciOrb>,
    parameters: &CircleciParameters,
    step_body: &YamlNode,
    step: &Node,
) {
    if let Some(builtin) = step_body.scalar() {
        let orb_target = circleci_orb_target(orbs, builtin);
        let (capabilities, effects, edge_kind) = circleci_builtin_profile(builtin);
        let call = Node::new(
            Provider::Circleci,
            NodeKind::Call,
            format!(
                "{}:{builtin}",
                if orb_target.is_some() {
                    "orb"
                } else {
                    "builtin"
                }
            ),
            Phase::Run,
            step_body.span().clone(),
            Condition::True,
            circleci_orb_attributes(step_body.span(), orb_target),
            capabilities,
            effects,
            orb_target.and_then(|orb| orb.target.unknown.clone()),
        );
        graph.add_node(call.clone());
        graph.add_edge(Edge::simple(edge_kind, step.id.clone(), call.id.clone()));
        add_control(graph, step, &call);
        if let Some(orb) = orb_target {
            graph.add_edge(Edge::simple(EdgeKind::Call, call.id, orb.target.id.clone()));
        }
        return;
    }
    if let Some(run) = step_body.field("run") {
        add_circleci_run(graph, step, run, parameters);
        return;
    }
    let Some((name, arguments)) = circleci_mapping_head(step_body) else {
        return;
    };
    let local_definition = commands.get(name);
    let orb_target = circleci_orb_target(orbs, name);
    let (capabilities, effects, _) = circleci_builtin_profile(name);
    let call_name = if local_definition.is_some() {
        format!("command:{name}")
    } else if orb_target.is_some() {
        format!("orb:{name}")
    } else {
        format!("builtin:{name}")
    };
    let call = Node::new(
        Provider::Circleci,
        NodeKind::Call,
        call_name,
        Phase::Run,
        step_body.span().clone(),
        Condition::True,
        circleci_orb_attributes(step_body.span(), orb_target),
        capabilities,
        effects,
        orb_target.and_then(|orb| orb.target.unknown.clone()),
    );
    graph.add_node(call.clone());
    add_call(graph, step, &call);
    if let Some(definition) = local_definition {
        graph.add_edge(Edge::simple(
            EdgeKind::Call,
            call.id.clone(),
            definition.resource.id.clone(),
        ));
        bind_circleci_arguments(graph, &call.name, &definition.parameters, arguments);
    } else if let Some(orb) = orb_target {
        graph.add_edge(Edge::simple(
            EdgeKind::Call,
            call.id.clone(),
            orb.target.id.clone(),
        ));
    }
    for entry in mapping(arguments) {
        let Some(source) = entry.value.scalar() else {
            continue;
        };
        let references =
            expression_references(Provider::Circleci, Phase::Run, source, entry.value.span());
        add_expression_references(graph, Provider::Circleci, &call, references);
    }
}

fn add_circleci_steps(
    graph: &mut Graph,
    commands: &BTreeMap<String, CircleciCommand<'_>>,
    orbs: &BTreeMap<String, CircleciOrb>,
    parameters: &CircleciParameters,
    owner: &Node,
    body: &YamlNode,
) {
    let Some(steps) = body.field("steps") else {
        return;
    };
    let records: Vec<_> = sequence(steps)
        .into_iter()
        .enumerate()
        .map(|(index, step_body)| {
            let name = step_body
                .scalar()
                .or_else(|| circleci_mapping_head(step_body).map(|(name, _)| name))
                .map_or_else(
                    || format!("step {}", index.saturating_add(1)),
                    str::to_owned,
                );
            let step = Node::simple(
                Provider::Circleci,
                NodeKind::Step,
                name,
                Phase::Run,
                step_body.span().clone(),
            );
            (step_body, step)
        })
        .collect();
    for (_, step) in &records {
        graph.add_node(step.clone());
        add_control(graph, owner, step);
    }
    for pair in records.windows(2) {
        graph.add_edge(Edge::new(
            EdgeKind::Control,
            pair[0].1.id.clone(),
            pair[1].1.id.clone(),
            Condition::True,
            Some("sequence".to_owned()),
        ));
    }
    for (step_body, step) in records {
        add_circleci_step(graph, commands, orbs, parameters, step_body, &step);
    }
}

fn add_circleci_executors(
    graph: &mut Graph,
    config: &Node,
    root: &YamlNode,
) -> BTreeMap<String, Node> {
    let mut executors = BTreeMap::new();
    if let Some(definitions) = root.field("executors") {
        for entry in mapping(definitions) {
            let resource = Node::new(
                Provider::Circleci,
                NodeKind::Resource,
                format!("executor:{}", entry.key),
                Phase::Compile,
                entry.span.clone(),
                Condition::True,
                BTreeMap::new(),
                [Capability::FilesystemRead, Capability::FilesystemWrite],
                [],
                None,
            );
            graph.add_node(resource.clone());
            add_control(graph, config, &resource);
            executors.insert(entry.key.clone(), resource);
        }
    }
    executors
}

fn add_circleci_command_definitions<'a>(
    graph: &mut Graph,
    config: &Node,
    root: &'a YamlNode,
) -> BTreeMap<String, CircleciCommand<'a>> {
    let mut commands = BTreeMap::new();
    if let Some(definitions) = root.field("commands") {
        for entry in mapping(definitions) {
            let resource = Node::simple(
                Provider::Circleci,
                NodeKind::Resource,
                format!("command-definition:{}", entry.key),
                Phase::Compile,
                entry.span.clone(),
            );
            graph.add_node(resource.clone());
            add_control(graph, config, &resource);
            let parameters = entry
                .value
                .field("parameters")
                .map_or_else(BTreeMap::new, |values| {
                    add_circleci_parameters(graph, &resource, &entry.key, values)
                });
            commands.insert(
                entry.key.clone(),
                CircleciCommand {
                    body: &entry.value,
                    resource,
                    parameters,
                },
            );
        }
    }
    commands
}

fn add_circleci_job_executor(
    graph: &mut Graph,
    executors: &BTreeMap<String, Node>,
    job: &Node,
    body: &YamlNode,
) {
    if let Some(resource) = body
        .field("executor")
        .and_then(YamlNode::scalar)
        .and_then(|name| executors.get(name))
    {
        graph.add_edge(Edge::simple(
            EdgeKind::Read,
            resource.id.clone(),
            job.id.clone(),
        ));
    }
}

fn add_circleci_gate(
    graph: &mut Graph,
    owner: &Node,
    name: String,
    phase: Phase,
    expression: &YamlNode,
) {
    let scalar_source = expression.scalar();
    let source = scalar_source.unwrap_or("<opaque condition>");
    let references = expression_references(Provider::Circleci, phase, source, expression.span());
    let mut attributes = BTreeMap::from([(
        "expression".to_owned(),
        AbstractValue::string_constant(
            source,
            Trust::Trusted,
            Secrecy::Public,
            vec![Provenance {
                origin: "workflow condition".to_owned(),
                span: expression.span().clone(),
                operation: "gate".to_owned(),
            }],
        ),
    )]);
    for reference in &references {
        let key = format!("reference:{}", reference.name);
        attributes
            .entry(key)
            .and_modify(|value| *value = value.join(&reference.value))
            .or_insert_with(|| reference.value.clone());
    }
    let phase_unknown = if scalar_source.is_none() {
        Some(UnknownReason::UnsupportedSyntax(
            "condition expression".to_owned(),
        ))
    } else {
        references.iter().find_map(|reference| {
            let minimum = minimum_reference_phase(Provider::Circleci, &reference.name);
            (phase_rank(phase) < phase_rank(minimum)).then(|| {
                UnknownReason::PhaseUnavailable(format!(
                    "{} is unavailable during {}",
                    reference.name,
                    phase.name()
                ))
            })
        })
    };
    let condition = scalar_source.map_or_else(
        || Condition::atom("circleci:<opaque condition>"),
        |value| {
            let trimmed = value.trim();
            let body = trimmed
                .strip_prefix("<<")
                .and_then(|inner| inner.strip_suffix(">>"))
                .map_or(trimmed, str::trim);
            gitlab_condition(body)
        },
    );
    let gate = Node::new(
        Provider::Circleci,
        NodeKind::Gate,
        name,
        phase,
        expression.span().clone(),
        condition,
        attributes,
        [],
        [],
        phase_unknown,
    );
    insert_gate(graph, owner, gate.clone());
    add_expression_references(graph, Provider::Circleci, &gate, references);
}

fn add_circleci_matrix(graph: &mut Graph, job: &Node, invocation: &YamlNode) {
    let Some(parameters) = invocation
        .field("matrix")
        .and_then(|matrix| matrix.field("parameters"))
    else {
        return;
    };
    for entry in mapping(parameters) {
        let parameter = Node::simple(
            Provider::Circleci,
            NodeKind::Parameter,
            format!("matrix.{}", entry.key),
            Phase::Plan,
            entry.span.clone(),
        );
        graph.add_node(parameter.clone());
        graph.add_edge(Edge::new(
            EdgeKind::Data,
            parameter.id,
            job.id.clone(),
            Condition::True,
            Some(entry.key.clone()),
        ));
    }
}

fn circleci_invocation_aliases(reference: &str, alias: &str, body: &YamlNode) -> Vec<String> {
    let matrix_alias = body.field("matrix").map(|matrix| {
        matrix
            .field("alias")
            .and_then(YamlNode::scalar)
            .unwrap_or(reference)
    });
    let mut aliases = vec![alias.to_owned()];
    if let Some(matrix_alias) = matrix_alias {
        aliases.push(matrix_alias.to_owned());
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

fn link_circleci_invocations(
    invocations: &[CircleciInvocation<'_>],
    graph: &mut Graph,
) -> Vec<FrontendProblem> {
    fn visit_cycle(
        name: &str,
        invocations: &[CircleciInvocation<'_>],
        visiting: &mut Vec<String>,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if visiting.iter().any(|candidate| candidate == name) {
            return true;
        }
        if visited.contains(name) {
            return false;
        }
        visiting.push(name.to_owned());
        if let Some(invocation) = invocations
            .iter()
            .find(|candidate| candidate.aliases.iter().any(|alias| alias == name))
        {
            for requirement in &invocation.requires {
                if visit_cycle(requirement, invocations, visiting, visited) {
                    return true;
                }
            }
        }
        let _ = visiting.pop();
        visited.insert(name.to_owned());
        false
    }

    let mut problems = Vec::new();
    for invocation in invocations {
        for requirement in &invocation.requires {
            if let Some(predecessor) = invocations
                .iter()
                .find(|candidate| candidate.aliases.contains(requirement))
            {
                graph.add_edge(Edge::new(
                    EdgeKind::Control,
                    predecessor.target.id.clone(),
                    invocation.target.id.clone(),
                    Condition::True,
                    Some("requires".to_owned()),
                ));
            } else {
                problems.push(FrontendProblem {
                    code: "CC-UNKNOWN-REQUIREMENT".to_owned(),
                    message: format!("{} requires unknown {requirement}", invocation.alias),
                    span: invocation.span.clone(),
                });
            }
        }
    }
    let mut visiting = Vec::new();
    let mut visited = BTreeSet::new();
    if invocations
        .iter()
        .any(|invocation| visit_cycle(&invocation.alias, invocations, &mut visiting, &mut visited))
    {
        problems.push(FrontendProblem {
            code: "CC-REQUIRES-CYCLE".to_owned(),
            message: "CircleCI workflow requirements contain a cycle".to_owned(),
            span: invocations
                .first()
                .map_or_else(Span::default, |invocation| invocation.span.clone()),
        });
    }
    problems
}

#[allow(clippy::too_many_lines)]
fn lower_circleci(
    path: &str,
    root: &YamlNode,
    dependencies: &[Dependency],
) -> (Graph, Vec<FrontendProblem>) {
    let config = workflow_node(Provider::Circleci, "CircleCI config", root);
    let mut graph = Graph::empty(Provider::Circleci, path);
    let mut problems = Vec::new();
    graph.add_node(config.clone());
    graph.add_entrypoint(config.id.clone());

    let mut dependency_calls = BTreeMap::new();
    for dependency in dependencies {
        let call = Node::new(
            Provider::Circleci,
            NodeKind::Call,
            &dependency.reference,
            Phase::Compile,
            dependency.span.clone(),
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            unresolved_for(dependencies, &dependency.reference),
        );
        graph.add_node(call.clone());
        add_call(&mut graph, &config, &call);
        dependency_calls.insert(dependency.reference.clone(), call);
    }

    if root
        .field("setup")
        .and_then(YamlNode::scalar)
        .is_some_and(|value| value == "true")
    {
        let setup = root.field("setup").expect("checked setup field");
        let effect = Node::new(
            Provider::Circleci,
            NodeKind::Effect,
            "dynamic config",
            Phase::Compile,
            setup.span().clone(),
            Condition::True,
            BTreeMap::new(),
            [],
            [ObservableEffect::WorkflowChange],
            None,
        );
        graph.add_node(effect.clone());
        add_control(&mut graph, &config, &effect);
    }
    if let Some(parameters) = root.field("parameters") {
        add_circleci_parameters(&mut graph, &config, "pipeline", parameters);
    }
    let executors = add_circleci_executors(&mut graph, &config, root);
    let commands = add_circleci_command_definitions(&mut graph, &config, root);
    let orbs: BTreeMap<_, _> = root
        .field("orbs")
        .into_iter()
        .flat_map(mapping)
        .filter_map(|entry| {
            let reference = entry.value.scalar()?;
            let target = dependency_calls.get(reference)?.clone();
            Some((
                entry.key.clone(),
                CircleciOrb {
                    reference: reference.to_owned(),
                    target,
                },
            ))
        })
        .collect();
    for definition in commands.values() {
        add_circleci_steps(
            &mut graph,
            &commands,
            &orbs,
            &definition.parameters,
            &definition.resource,
            definition.body,
        );
    }

    let mut jobs: BTreeMap<String, (Node, CircleciParameters)> = BTreeMap::new();
    if let Some(job_map) = root.field("jobs") {
        for entry in mapping(job_map) {
            let job = Node::simple(
                Provider::Circleci,
                NodeKind::Job,
                &entry.key,
                Phase::Plan,
                entry.span.clone(),
            );
            graph.add_node(job.clone());
            add_circleci_job_executor(&mut graph, &executors, &job, &entry.value);
            let parameters = entry
                .value
                .field("parameters")
                .map_or_else(BTreeMap::new, |declarations| {
                    add_circleci_parameters(&mut graph, &job, &entry.key, declarations)
                });
            add_circleci_steps(
                &mut graph,
                &commands,
                &orbs,
                &parameters,
                &job,
                &entry.value,
            );
            jobs.insert(entry.key.clone(), (job, parameters));
        }
    }

    if let Some(workflows) = root.field("workflows") {
        for entry in mapping(workflows)
            .iter()
            .filter(|entry| entry.key != "version")
        {
            let workflow = Node::simple(
                Provider::Circleci,
                NodeKind::Workflow,
                &entry.key,
                Phase::Plan,
                entry.span.clone(),
            );
            graph.add_node(workflow.clone());
            add_control(&mut graph, &config, &workflow);
            if let Some(when) = entry.value.field("when") {
                add_circleci_gate(
                    &mut graph,
                    &workflow,
                    format!("when:{}", workflow.name),
                    Phase::Plan,
                    when,
                );
            }
            let mut invocations = Vec::new();
            if let Some(workflow_jobs) = entry.value.field("jobs") {
                for item in sequence(workflow_jobs) {
                    let (reference, invocation_body) = item.scalar().map_or_else(
                        || circleci_mapping_head(item).unwrap_or(("<unknown>", item)),
                        |name| (name, item),
                    );
                    let alias = invocation_body
                        .field("name")
                        .and_then(YamlNode::scalar)
                        .unwrap_or(reference)
                        .to_owned();
                    let aliases = circleci_invocation_aliases(reference, &alias, invocation_body);
                    let requires = invocation_body
                        .field("requires")
                        .map(scalar_values)
                        .unwrap_or_default()
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let (target, parameters) = if invocation_body
                        .field("type")
                        .and_then(YamlNode::scalar)
                        == Some("approval")
                    {
                        (
                            Node::new(
                                Provider::Circleci,
                                NodeKind::Gate,
                                format!("approval:{alias}"),
                                Phase::Plan,
                                item.span().clone(),
                                Condition::atom(format!("circleci:approval:{alias}")),
                                BTreeMap::new(),
                                [],
                                [],
                                None,
                            ),
                            BTreeMap::new(),
                        )
                    } else if let Some((job, parameters)) = jobs.get(reference) {
                        (job.clone(), parameters.clone())
                    } else {
                        problems.push(FrontendProblem {
                            code: "CC-UNKNOWN-JOB".to_owned(),
                            message: format!("{} invokes unknown job {reference}", workflow.name),
                            span: item.span().clone(),
                        });
                        (
                            Node::new(
                                Provider::Circleci,
                                NodeKind::Opaque,
                                format!("unknown-job:{reference}"),
                                Phase::Plan,
                                item.span().clone(),
                                Condition::True,
                                BTreeMap::new(),
                                [],
                                [],
                                Some(UnknownReason::UnresolvedDependency(reference.to_owned())),
                            ),
                            BTreeMap::new(),
                        )
                    };
                    if graph.find_node(&target.id).is_none() {
                        graph.add_node(target.clone());
                    }
                    add_control(&mut graph, &workflow, &target);
                    add_circleci_matrix(&mut graph, &target, invocation_body);
                    bind_circleci_arguments(&mut graph, &alias, &parameters, invocation_body);
                    invocations.push(CircleciInvocation {
                        alias,
                        aliases,
                        target,
                        body: invocation_body,
                        requires,
                        span: item.span().clone(),
                    });
                }
            }
            problems.extend(link_circleci_invocations(&invocations, &mut graph));
            for invocation in invocations.iter().rev() {
                if let Some(filters) = invocation.body.field("filters") {
                    add_circleci_gate(
                        &mut graph,
                        &invocation.target,
                        format!("filter:{}:{}", workflow.name, invocation.alias),
                        Phase::Plan,
                        filters,
                    );
                }
            }
        }
    }
    (graph, problems)
}

#[cfg(test)]
mod circleci_tests {
    use super::*;

    fn yaml(source: &str) -> YamlDocument {
        YamlDocument::parse(".circleci/config.yml", source, Budget::default())
    }

    #[test]
    fn local_parameter_names_and_argument_values_preserve_exact_dataflow() {
        assert_eq!(
            circleci_local_parameter_name("parameters.name"),
            Some("name")
        );
        assert_eq!(
            circleci_local_parameter_name("PARAMETERS.Name"),
            Some("Name")
        );
        assert_eq!(circleci_local_parameter_name("parameters."), Some(""));
        assert_eq!(
            circleci_local_parameter_name("pipeline.parameters.name"),
            None
        );
        assert_eq!(circleci_local_parameter_name("parameter.name"), None);

        let scalar = yaml("value: literal\n");
        let scalar_value = circleci_argument_value(
            scalar
                .root()
                .and_then(|root| root.field("value"))
                .expect("scalar"),
        );
        assert_eq!(scalar_value.constants(), Some(&["literal".to_owned()][..]));
        assert_eq!(scalar_value.trust, Trust::Trusted);
        assert_eq!(scalar_value.provenance.len(), 1);
        assert_eq!(scalar_value.provenance[0].operation, "bind");

        let expression = yaml("value: << pipeline.parameters.branch >>\n");
        let expression_value = circleci_argument_value(
            expression
                .root()
                .and_then(|root| root.field("value"))
                .expect("expression"),
        );
        assert_eq!(expression_value.trust, Trust::Untrusted);
        let mapping = yaml("value: {nested: data}\n");
        assert!(matches!(
            circleci_argument_value(
                mapping
                    .root()
                    .and_then(|root| root.field("value"))
                    .expect("mapping")
            )
            .trust,
            Trust::Unknown(_)
        ));
    }

    #[test]
    fn argument_binding_ignores_unknown_keys_and_targets_the_declared_parameter() {
        let parameter = Node::simple(
            Provider::Circleci,
            NodeKind::Parameter,
            "command.subject",
            Phase::Compile,
            Span::default(),
        );
        let bindings = BTreeMap::from([("subject".to_owned(), parameter.clone())]);
        let body = yaml("subject: world\nunknown: ignored\n");
        let mut graph = Graph::empty(Provider::Circleci, ".circleci/config.yml");
        graph.add_node(parameter.clone());
        bind_circleci_arguments(
            &mut graph,
            "greet",
            &bindings,
            body.root().expect("argument mapping"),
        );
        let argument = graph
            .nodes
            .iter()
            .find(|node| node.name == "argument:greet.subject")
            .expect("bound argument");
        assert!(
            graph
                .nodes
                .iter()
                .all(|node| node.name != "argument:greet.unknown")
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Data
                && edge.from == argument.id
                && edge.to == parameter.id
                && edge.label.as_deref() == Some("subject")
        }));
    }

    #[test]
    fn builtin_profiles_cover_every_circleci_storage_operation() {
        let cases = [
            (
                "checkout",
                vec![Capability::RepositoryRead, Capability::FilesystemWrite],
                vec![ObservableEffect::FileWrite],
                EdgeKind::Read,
            ),
            (
                "save_cache",
                vec![Capability::CacheWrite, Capability::FilesystemRead],
                vec![ObservableEffect::CachePublish],
                EdgeKind::Write,
            ),
            (
                "restore_cache",
                vec![Capability::CacheRead, Capability::FilesystemWrite],
                vec![ObservableEffect::FileWrite],
                EdgeKind::Read,
            ),
            (
                "store_artifacts",
                vec![Capability::ArtifactWrite, Capability::FilesystemRead],
                vec![ObservableEffect::ArtifactPublish],
                EdgeKind::Write,
            ),
            (
                "store_test_results",
                vec![Capability::ArtifactWrite, Capability::FilesystemRead],
                vec![ObservableEffect::ArtifactPublish],
                EdgeKind::Write,
            ),
            (
                "persist_to_workspace",
                vec![Capability::ArtifactWrite, Capability::FilesystemRead],
                vec![ObservableEffect::ArtifactPublish],
                EdgeKind::Persist,
            ),
            (
                "attach_workspace",
                vec![Capability::ArtifactRead, Capability::FilesystemWrite],
                vec![ObservableEffect::FileWrite],
                EdgeKind::Read,
            ),
            ("unknown", Vec::new(), Vec::new(), EdgeKind::Call),
        ];
        for (name, capabilities, effects, edge) in cases {
            assert_eq!(
                circleci_builtin_profile(name),
                (capabilities, effects, edge)
            );
        }
        assert_eq!(
            circleci_builtin_profile("CHECKOUT"),
            circleci_builtin_profile("checkout")
        );
    }
}
