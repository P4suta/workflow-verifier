#![forbid(unsafe_code)]

//! Provider-neutral semantic verification.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use workflow_verifier_domain::{
    AbstractValue, Capability, Condition, Edge, EdgeKind, Graph, Node, NodeKind, ObservableEffect,
    Provider, Secrecy, Trust, UnknownReason, Value,
};
use workflow_verifier_foundation::{
    DependencyClass, JsonValue, Span, classify_reference, normalize_slashes, sha256_hex,
    valid_content_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Note,
}

impl Severity {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceHop {
    pub node_id: String,
    pub label: String,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fix {
    pub kind: String,
    pub description: String,
    pub replacement: Option<String>,
    pub span: Option<Span>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub span: Span,
    pub trace: Vec<TraceHop>,
    pub capabilities: Vec<Capability>,
    pub evidence: Vec<String>,
    pub fix: Option<Fix>,
}

impl Diagnostic {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        message: impl Into<String>,
        span: Span,
        trace: Vec<TraceHop>,
        capabilities: impl IntoIterator<Item = Capability>,
        evidence: impl IntoIterator<Item = String>,
        fix: Option<Fix>,
    ) -> Self {
        let rule_id = rule_id.into();
        let message = message.into();
        let start = span.start.byte.to_string();
        let identity = [
            rule_id.as_str(),
            span.file.as_str(),
            start.as_str(),
            message.as_str(),
        ]
        .join("\0");
        let digest = sha256_hex(identity);
        let id = format!("diag_{}", digest.get(..20).unwrap_or(&digest));
        Self {
            id,
            rule_id,
            severity,
            confidence,
            message,
            span,
            trace,
            capabilities: capabilities
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            evidence: evidence
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            fix,
        }
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let trace = self
            .trace
            .iter()
            .map(|hop| {
                JsonValue::Object(BTreeMap::from([
                    ("label".to_owned(), JsonValue::String(hop.label.clone())),
                    ("node_id".to_owned(), JsonValue::String(hop.node_id.clone())),
                    ("span".to_owned(), hop.span.to_json()),
                ]))
            })
            .collect();
        let fix = self.fix.as_ref().map_or(JsonValue::Null, |fix| {
            JsonValue::Object(BTreeMap::from([
                (
                    "description".to_owned(),
                    JsonValue::String(fix.description.clone()),
                ),
                ("kind".to_owned(), JsonValue::String(fix.kind.clone())),
                (
                    "replacement".to_owned(),
                    fix.replacement
                        .clone()
                        .map_or(JsonValue::Null, JsonValue::String),
                ),
                (
                    "span".to_owned(),
                    fix.span.as_ref().map_or(JsonValue::Null, Span::to_json),
                ),
            ]))
        });
        JsonValue::Object(BTreeMap::from([
            (
                "capabilities".to_owned(),
                JsonValue::Array(
                    self.capabilities
                        .iter()
                        .map(|capability| JsonValue::String(capability.name().to_owned()))
                        .collect(),
                ),
            ),
            (
                "confidence".to_owned(),
                JsonValue::String(self.confidence.name().to_owned()),
            ),
            (
                "evidence".to_owned(),
                JsonValue::Array(
                    self.evidence
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            ("fix".to_owned(), fix),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            (
                "message".to_owned(),
                JsonValue::String(self.message.clone()),
            ),
            (
                "rule_id".to_owned(),
                JsonValue::String(self.rule_id.clone()),
            ),
            (
                "severity".to_owned(),
                JsonValue::String(self.severity.name().to_owned()),
            ),
            ("span".to_owned(), self.span.to_json()),
            ("trace".to_owned(), JsonValue::Array(trace)),
        ]))
    }
}

impl Ord for Diagnostic {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.span
            .cmp(&other.span)
            .then(self.rule_id.cmp(&other.rule_id))
            .then(self.id.cmp(&other.id))
    }
}

impl PartialOrd for Diagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PropertyState {
    Proved,
    Violated,
    Unknown(Vec<UnknownReason>),
    NotApplicable,
}

impl PropertyState {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Proved => "Proved",
            Self::Violated => "Violated",
            Self::Unknown(_) => "Unknown",
            Self::NotApplicable => "NotApplicable",
        }
    }

    #[must_use]
    pub fn combine(states: impl IntoIterator<Item = Self>) -> Self {
        let states: Vec<_> = states.into_iter().collect();
        if states.contains(&Self::Violated) {
            return Self::Violated;
        }
        let unknowns: BTreeSet<_> = states
            .iter()
            .filter_map(|state| match state {
                Self::Unknown(reasons) => Some(reasons.as_slice()),
                _ => None,
            })
            .flatten()
            .cloned()
            .collect();
        if !unknowns.is_empty() {
            Self::Unknown(unknowns.into_iter().collect())
        } else if states.contains(&Self::Proved) {
            Self::Proved
        } else {
            Self::NotApplicable
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Property {
    pub id: String,
    pub state: PropertyState,
    pub subject: Option<String>,
    pub explanation: String,
}

impl Property {
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let reasons = match &self.state {
            PropertyState::Unknown(reasons) => {
                JsonValue::Array(reasons.iter().map(UnknownReason::to_json).collect())
            }
            _ => JsonValue::Array(Vec::new()),
        };
        JsonValue::Object(BTreeMap::from([
            (
                "explanation".to_owned(),
                JsonValue::String(self.explanation.clone()),
            ),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            ("reasons".to_owned(), reasons),
            (
                "state".to_owned(),
                JsonValue::String(self.state.name().to_owned()),
            ),
            (
                "subject".to_owned(),
                self.subject
                    .clone()
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
        ]))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Persona {
    #[default]
    Gate,
    Audit,
    Paranoid,
}

impl Persona {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Gate => "gate",
            Self::Audit => "audit",
            Self::Paranoid => "paranoid",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub properties: Vec<Property>,
    pub diagnostics: Vec<Diagnostic>,
    pub complete: bool,
    pub analyzed_nodes: usize,
    pub analyzed_edges: usize,
}

impl VerificationResult {
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "analyzed_edges".to_owned(),
                JsonValue::Integer(i64::try_from(self.analyzed_edges).unwrap_or(i64::MAX)),
            ),
            (
                "analyzed_nodes".to_owned(),
                JsonValue::Integer(i64::try_from(self.analyzed_nodes).unwrap_or(i64::MAX)),
            ),
            ("complete".to_owned(), JsonValue::Boolean(self.complete)),
            (
                "diagnostics".to_owned(),
                JsonValue::Array(self.diagnostics.iter().map(Diagnostic::to_json).collect()),
            ),
            (
                "properties".to_owned(),
                JsonValue::Array(self.properties.iter().map(Property::to_json).collect()),
            ),
        ]))
    }
}

#[derive(Clone)]
struct GraphIndex<'a> {
    graph: &'a Graph,
    nodes: BTreeMap<&'a str, &'a Node>,
    outgoing: BTreeMap<&'a str, Vec<(&'a str, EdgeKind)>>,
    incoming: BTreeMap<&'a str, Vec<(&'a str, EdgeKind)>>,
}

impl<'a> GraphIndex<'a> {
    fn new(graph: &'a Graph) -> Self {
        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect();
        let mut outgoing: BTreeMap<&str, Vec<(&str, EdgeKind)>> = BTreeMap::new();
        let mut incoming: BTreeMap<&str, Vec<(&str, EdgeKind)>> = BTreeMap::new();
        for edge in &graph.edges {
            outgoing
                .entry(&edge.from)
                .or_default()
                .push((&edge.to, edge.kind));
            incoming
                .entry(&edge.to)
                .or_default()
                .push((&edge.from, edge.kind));
        }
        for values in outgoing.values_mut() {
            values.sort();
        }
        for values in incoming.values_mut() {
            values.sort();
        }
        Self {
            graph,
            nodes,
            outgoing,
            incoming,
        }
    }

    fn shortest_path(&self, from: &str, to: &str, kinds: &[EdgeKind]) -> Option<Vec<&'a Node>> {
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
            for (next, kind) in self.outgoing.get(current).into_iter().flatten() {
                if kinds.contains(kind) && !previous.contains_key(next) {
                    previous.insert(next, Some(current));
                    queue.push_back(next);
                }
            }
        }
        None
    }

    fn reachable(&self, from: &str) -> Vec<&'a Node> {
        let mut queue = VecDeque::from([from]);
        let mut seen = BTreeSet::from([from]);
        while let Some(current) = queue.pop_front() {
            for (next, _) in self.outgoing.get(current).into_iter().flatten() {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        seen.into_iter()
            .filter_map(|id| self.nodes.get(id).copied())
            .collect()
    }

    fn cycles(&self, kinds: &[EdgeKind]) -> Vec<Vec<String>> {
        fn visit(
            index: &GraphIndex<'_>,
            kinds: &[EdgeKind],
            current: &str,
            visiting: &mut Vec<String>,
            visited: &mut BTreeSet<String>,
            cycles: &mut BTreeSet<Vec<String>>,
        ) {
            if let Some(position) = visiting.iter().position(|item| item == current) {
                let mut cycle = visiting[position..].to_vec();
                cycle.push(current.to_owned());
                let canonical = canonical_cycle(cycle);
                cycles.insert(canonical);
                return;
            }
            if visited.contains(current) {
                return;
            }
            visiting.push(current.to_owned());
            for (next, kind) in index.outgoing.get(current).into_iter().flatten() {
                if kinds.contains(kind) {
                    visit(index, kinds, next, visiting, visited, cycles);
                }
            }
            let _ = visiting.pop();
            visited.insert(current.to_owned());
        }
        let mut visited = BTreeSet::new();
        let mut cycles = BTreeSet::new();
        for id in self.nodes.keys() {
            visit(self, kinds, id, &mut Vec::new(), &mut visited, &mut cycles);
        }
        cycles.into_iter().collect()
    }

    fn dominates(&self, dominator: &str, node: &str) -> bool {
        if dominator == node {
            return true;
        }
        let entrypoints: BTreeSet<&str> = if self.graph.entrypoints.is_empty() {
            self.nodes
                .keys()
                .copied()
                .filter(|id| !self.incoming.contains_key(id))
                .collect()
        } else {
            self.graph.entrypoints.iter().map(String::as_str).collect()
        };
        if entrypoints.is_empty() {
            return false;
        }
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
            for (next, kind) in self.outgoing.get(current).into_iter().flatten() {
                if matches!(kind, EdgeKind::Control | EdgeKind::Call)
                    && *next != avoided
                    && seen.insert(next)
                {
                    queue.push_back(next);
                }
            }
        }
        false
    }
}

fn canonical_cycle(mut cycle: Vec<String>) -> Vec<String> {
    if cycle.len() > 1 && cycle.first() == cycle.last() {
        let _ = cycle.pop();
    }
    if cycle.is_empty() {
        return cycle;
    }
    let mut rotations = Vec::new();
    for offset in 0..cycle.len() {
        let mut value = cycle[offset..].to_vec();
        value.extend_from_slice(&cycle[..offset]);
        value.push(value.first().cloned().unwrap_or_default());
        rotations.push(value);
    }
    rotations.into_iter().min().unwrap_or_default()
}

#[derive(Clone)]
struct Dataflow {
    values: BTreeMap<String, AbstractValue>,
    complete: bool,
}

impl Dataflow {
    fn solve(graph: &Graph) -> Self {
        let mut values: BTreeMap<String, AbstractValue> = graph
            .nodes
            .iter()
            .map(|node| {
                let value = node
                    .attributes
                    .values()
                    .fold(AbstractValue::default(), |current, value| {
                        current.join(value)
                    });
                (node.id.clone(), value)
            })
            .collect();
        let propagating_kinds = [
            EdgeKind::Data,
            EdgeKind::Read,
            EdgeKind::Write,
            EdgeKind::Persist,
        ];
        let mut outgoing: BTreeMap<&str, Vec<&Edge>> = BTreeMap::new();
        for edge in graph
            .edges
            .iter()
            .filter(|edge| propagating_kinds.contains(&edge.kind))
        {
            outgoing.entry(&edge.from).or_default().push(edge);
        }
        for edges in outgoing.values_mut() {
            edges.sort_by(|left, right| left.id.cmp(&right.id));
        }

        let mut queue: VecDeque<String> = graph.nodes.iter().map(|node| node.id.clone()).collect();
        let mut queued: BTreeSet<String> = queue.iter().cloned().collect();
        while let Some(source_id) = queue.pop_front() {
            queued.remove(&source_id);
            let source = values.get(&source_id).cloned().unwrap_or_default();
            for edge in outgoing.get(source_id.as_str()).into_iter().flatten() {
                let target = values.get(&edge.to).cloned().unwrap_or_default();
                let joined = target.join(&source);
                if joined != target {
                    values.insert(edge.to.clone(), joined);
                    if queued.insert(edge.to.clone()) {
                        queue.push_back(edge.to.clone());
                    }
                }
            }
        }
        Self {
            values,
            complete: true,
        }
    }

    fn at(&self, node: &Node) -> AbstractValue {
        self.values.get(&node.id).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
struct RuleResult {
    property: Option<Property>,
    diagnostics: Vec<Diagnostic>,
}

fn property(id: &str, state: PropertyState, explanation: &str) -> Property {
    Property {
        id: id.to_owned(),
        state,
        subject: None,
        explanation: explanation.to_owned(),
    }
}

fn trace(label: &str, node: &Node) -> TraceHop {
    TraceHop {
        node_id: node.id.clone(),
        label: label.to_owned(),
        span: node.span.clone(),
    }
}

fn data_trace(
    graph: &Graph,
    index: &GraphIndex<'_>,
    dataflow: &Dataflow,
    target: &Node,
) -> Vec<TraceHop> {
    for source in graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Resource && dataflow.at(node).is_untrusted())
    {
        if let Some(path) = index.shortest_path(
            &source.id,
            &target.id,
            &[
                EdgeKind::Data,
                EdgeKind::Read,
                EdgeKind::Write,
                EdgeKind::Persist,
            ],
        ) {
            let path_length = path.len();
            return path
                .into_iter()
                .enumerate()
                .map(|(position, node)| {
                    let label = if position == 0 {
                        "untrusted source"
                    } else if position + 1 == path_length {
                        "command sink"
                    } else {
                        "data flow"
                    };
                    trace(label, node)
                })
                .collect();
        }
    }
    vec![trace("command sink contains untrusted data", target)]
}

fn reasons(value: &AbstractValue) -> Vec<UnknownReason> {
    let mut output = BTreeSet::new();
    if let Value::Unknown(values) = &value.value {
        output.extend(values.iter().cloned());
    }
    if let Trust::Unknown(values) = &value.trust {
        output.extend(values.iter().cloned());
    }
    if let Secrecy::Unknown(values) = &value.secrecy {
        output.extend(values.iter().cloned());
    }
    output.into_iter().collect()
}

fn command_source(node: &Node) -> &str {
    node.attributes
        .get("command")
        .and_then(AbstractValue::constants)
        .and_then(|values| values.iter().max_by_key(|value| value.len()))
        .map_or(node.name.as_str(), String::as_str)
}

fn script_effects(node: &Node) -> Vec<ObservableEffect> {
    let lower = command_source(node).to_ascii_lowercase();
    let mut effects = BTreeSet::from([ObservableEffect::CommandExecution]);
    if [
        "curl ",
        "curl.exe",
        "docker login",
        "helm registry login",
        "wget ",
        "invoke-webrequest",
        "invoke-restmethod",
        "podman login",
        "requests.",
        "urllib.",
        "httpclient",
        "fetch(",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        effects.insert(ObservableEffect::NetworkRequest);
    }
    if [
        " > ",
        ">>",
        "set-content",
        "out-file",
        "writealltext",
        "open(",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        effects.insert(ObservableEffect::FileWrite);
    }
    if lower.contains("git push") || lower.contains("gh pr merge") || lower.contains("gh release") {
        effects.insert(ObservableEffect::RepositoryChange);
    }
    if [
        "kubectl apply",
        "terraform apply",
        "az deployment",
        "aws cloudformation deploy",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        effects.insert(ObservableEffect::DeploymentChange);
    }
    if [
        ".github/workflows",
        ".gitlab-ci.yml",
        "azure-pipelines",
        ".circleci/config",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        && [" > ", ">>", "set-content", "writealltext"]
            .iter()
            .any(|marker| lower.contains(marker))
    {
        effects.insert(ObservableEffect::WorkflowChange);
    }
    effects.into_iter().collect()
}

/// Return the explicit and script-inferred effects for one IR node.
///
/// This deterministic view is shared by verification and exact dependency
/// source summarization.
#[must_use]
pub fn inferred_effects(node: &Node) -> Vec<ObservableEffect> {
    let mut effects = node.effects.clone();
    if node.kind == NodeKind::Command {
        effects.extend(script_effects(node));
    }
    effects
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScriptShell {
    Posix,
    Bash,
    PowerShell,
    Cmd,
    Python,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScriptToken {
    text: String,
    quoted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScriptExpansion {
    text: String,
    quoted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScriptSummary {
    unknowns: Vec<UnknownReason>,
    expansions: Vec<ScriptExpansion>,
    unsafe_interpolation: bool,
    secret_to_network: bool,
    secret_to_output: bool,
}

fn script_shell(node: &Node) -> ScriptShell {
    let Some(name) = node
        .attributes
        .get("shell")
        .and_then(AbstractValue::constants)
        .and_then(|values| values.first())
    else {
        return ScriptShell::Bash;
    };
    match name.to_ascii_lowercase().as_str() {
        "sh" | "posix" => ScriptShell::Posix,
        "bash" => ScriptShell::Bash,
        "pwsh" | "powershell" => ScriptShell::PowerShell,
        "cmd" | "cmd.exe" => ScriptShell::Cmd,
        "python" | "python3" => ScriptShell::Python,
        other => ScriptShell::Unknown(other.to_owned()),
    }
}

fn script_tokens(source: &str) -> Vec<ScriptToken> {
    fn flush(tokens: &mut Vec<ScriptToken>, buffer: &mut String, quoted: &mut bool) {
        if !buffer.is_empty() {
            tokens.push(ScriptToken {
                text: std::mem::take(buffer),
                quoted: *quoted,
            });
        }
        *quoted = false;
    }

    let mut tokens = Vec::new();
    let mut buffer = String::new();
    let mut quote = None;
    let mut token_quoted = false;
    let mut escaped = false;
    for character in source.chars() {
        if let Some(delimiter) = quote {
            token_quoted = true;
            if escaped {
                buffer.push(character);
                escaped = false;
            } else if character == '\\' && delimiter == '"' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            } else {
                buffer.push(character);
            }
        } else {
            match character {
                '\'' | '"' => {
                    token_quoted = true;
                    quote = Some(character);
                }
                ' ' | '\t' | '\r' | '\n' => {
                    flush(&mut tokens, &mut buffer, &mut token_quoted);
                }
                _ => buffer.push(character),
            }
        }
    }
    flush(&mut tokens, &mut buffer, &mut token_quoted);
    tokens
}

fn script_expansions(shell: &ScriptShell, tokens: &[ScriptToken]) -> Vec<ScriptExpansion> {
    tokens
        .iter()
        .filter(|token| match shell {
            ScriptShell::Posix
            | ScriptShell::Bash
            | ScriptShell::PowerShell
            | ScriptShell::Unknown(_) => token.text.contains('$') || token.text.contains('`'),
            ScriptShell::Cmd => {
                token.text.len() > 1 && (token.text.contains('%') || token.text.contains('!'))
            }
            ScriptShell::Python => false,
        })
        .map(|token| ScriptExpansion {
            text: token.text.clone(),
            quoted: token.quoted,
        })
        .collect()
}

fn shell_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

fn bounded_variable(value: &str, needle: &str) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = value[offset..].find(needle) {
        let start = offset + relative;
        let after = start + needle.len();
        if value
            .as_bytes()
            .get(after)
            .is_none_or(|byte| !shell_identifier_byte(*byte))
        {
            return true;
        }
        offset = start.saturating_add(1);
    }
    false
}

fn expansion_mentions(environment: &str, expansion: &str) -> bool {
    let environment = environment.to_ascii_lowercase();
    let expansion = expansion.to_ascii_lowercase();
    bounded_variable(&expansion, &format!("${environment}"))
        || bounded_variable(&expansion, &format!("$env:{environment}"))
        || [
            format!("${{{environment}}}"),
            format!("${{env:{environment}}}"),
            format!("%{environment}%"),
            format!("!{environment}!"),
        ]
        .iter()
        .any(|form| expansion.contains(form))
}

fn unsafe_untrusted_flow(
    graph: &Graph,
    index: &GraphIndex<'_>,
    dataflow: &Dataflow,
    command: &Node,
    summary: &ScriptSummary,
) -> bool {
    let paths: Vec<_> = graph
        .nodes
        .iter()
        .filter(|source| {
            matches!(source.kind, NodeKind::Resource | NodeKind::Parameter)
                && dataflow.at(source).is_untrusted()
        })
        .filter_map(|source| {
            index.shortest_path(
                &source.id,
                &command.id,
                &[
                    EdgeKind::Data,
                    EdgeKind::Read,
                    EdgeKind::Write,
                    EdgeKind::Persist,
                ],
            )
        })
        .collect();
    if paths.is_empty() {
        return summary.unsafe_interpolation;
    }
    paths.iter().any(|path| {
        path.iter()
            .find_map(|node| {
                (node.kind == NodeKind::Resource)
                    .then(|| node.name.strip_prefix("env:"))
                    .flatten()
            })
            .map_or_else(
                || summary.unsafe_interpolation,
                |environment| {
                    summary.expansions.iter().any(|expansion| {
                        expansion_mentions(environment, &expansion.text) && !expansion.quoted
                    })
                },
            )
    })
}

fn injection_rule(graph: &Graph, index: &GraphIndex<'_>, dataflow: &Dataflow) -> RuleResult {
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for command in graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Command)
    {
        let value = dataflow.at(command);
        let summary = script_summary(command);
        if value.is_untrusted() && unsafe_untrusted_flow(graph, index, dataflow, command, &summary)
        {
            states.push(PropertyState::Violated);
            diagnostics.push(Diagnostic::new(
                "WV-SEC-001",
                Severity::Error,
                Confidence::High,
                "untrusted workflow data reaches a shell command boundary",
                command.span.clone(),
                data_trace(graph, index, dataflow, command),
                [Capability::Shell],
                ["abstract trust = untrusted".to_owned(), "script boundary = unquoted or provider-substituted".to_owned()],
                Some(Fix {
                    kind: "environment-boundary".to_owned(),
                    description: "pass the value through an environment variable and quote it in the target shell".to_owned(),
                    replacement: None,
                    span: Some(command.span.clone()),
                }),
            ));
        } else {
            let unknowns = reasons(&value);
            states.push(if unknowns.is_empty() {
                PropertyState::Proved
            } else {
                PropertyState::Unknown(unknowns)
            });
        }
    }
    RuleResult {
        property: Some(property(
            "WV-SEC-001",
            PropertyState::combine(states),
            "untrusted values do not cross an unquoted command boundary",
        )),
        diagnostics,
    }
}

fn secret_reference(source: &str) -> bool {
    script_tokens(source).iter().any(|token| {
        let text = token.text.to_ascii_lowercase();
        [
            "secret",
            "token",
            "password",
            "passwd",
            "private_key",
            "private-key",
            "access_key",
            "access-key",
            "credential",
        ]
        .into_iter()
        .any(|fragment| text.contains(fragment))
            && (text.contains('$')
                || text.contains('%')
                || text.contains('!')
                || text.contains("secrets.")
                || text.contains("environ")
                || text.contains("getenv")
                || text.contains("process.env"))
    })
}

fn output_command(source: &str) -> bool {
    ["echo ", "printf ", "write-output", "console.log", "print("]
        .into_iter()
        .any(|marker| source.contains(marker))
}

fn network_command(source: &str) -> bool {
    [
        "curl ",
        "curl.exe",
        "docker login",
        "helm registry login",
        "wget ",
        "invoke-webrequest",
        "invoke-restmethod",
        "podman login",
        "requests.",
        "urllib.",
        "httpclient",
        "fetch(",
    ]
    .into_iter()
    .any(|marker| source.contains(marker))
}

#[derive(Clone, Copy)]
enum TopLevelSeparator {
    Sequence,
    Pipeline,
}

fn separator_width(separator: TopLevelSeparator, source: &[u8], index: usize) -> Option<usize> {
    match separator {
        TopLevelSeparator::Sequence => match source[index] {
            b';' => Some(1),
            b'&' if source.get(index + 1) == Some(&b'&') => Some(2),
            b'|' if source.get(index + 1) == Some(&b'|') => Some(2),
            _ => None,
        },
        TopLevelSeparator::Pipeline => (source[index] == b'|').then_some(1),
    }
}

fn split_top_level(source: &str, separator: TopLevelSeparator) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut characters = source.char_indices();
    while let Some((index, character)) = characters.next() {
        let character_width = character.len_utf8();
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' && delimiter == '"' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(character),
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                if let Some(width) = separator_width(separator, bytes, index) {
                    let part = source[start..index].trim();
                    if !part.is_empty() {
                        parts.push(part);
                    }
                    for _ in character_width..width {
                        let _ = characters.next();
                    }
                    start = index.saturating_add(width);
                }
            }
            _ => {}
        }
    }
    let part = source[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

enum OutputDestination {
    StandardOutput,
    PrivateFile,
    Unknown(UnknownReason),
}

fn output_destination(shell: &ScriptShell, source: &str) -> OutputDestination {
    if *shell == ScriptShell::Python {
        return OutputDestination::StandardOutput;
    }
    if let ScriptShell::Unknown(name) = shell {
        return if source.contains('>') {
            OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(format!("shell {name}")))
        } else {
            OutputDestination::StandardOutput
        };
    }

    let mut redirects = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut characters = source.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' && delimiter == '"' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            '>' if depth == 0 => {
                let descriptor = source.as_bytes()[..index].last().is_some_and(|previous| {
                    previous.is_ascii_digit() || matches!(previous, b'&' | b'>')
                });
                let following = characters.peek().map(|(_, value)| *value);
                if !descriptor && following != Some('=') {
                    let mut after = index.saturating_add(character.len_utf8());
                    if following == Some('>')
                        && let Some((following_index, following_character)) = characters.next()
                    {
                        after = following_index.saturating_add(following_character.len_utf8());
                    }
                    redirects.push(after);
                }
            }
            _ => {}
        }
    }
    match redirects.as_slice() {
        [] => OutputDestination::StandardOutput,
        [after] => {
            let mut target = source[*after..].trim();
            if target.len() >= 2 {
                let first = target.as_bytes()[0];
                let last = target.as_bytes()[target.len() - 1];
                if matches!(first, b'\'' | b'"') && last == first {
                    target = &target[1..target.len() - 1];
                }
            }
            let lower = target.to_ascii_lowercase();
            if target.is_empty()
                || ["/dev/stdout", "/dev/stderr", "con", "conout$", "prn"].contains(&lower.as_str())
                || lower.starts_with("/proc/self/fd/")
            {
                OutputDestination::StandardOutput
            } else if target
                .chars()
                .any(|character| character.is_ascii_whitespace() || character == '&')
            {
                OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(
                    "compound shell output redirection".to_owned(),
                ))
            } else if target.contains('$') || target.contains('%') || target.contains('!') {
                OutputDestination::Unknown(UnknownReason::DynamicString(
                    "dynamic shell output redirection".to_owned(),
                ))
            } else {
                OutputDestination::PrivateFile
            }
        }
        _ => OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(
            "multiple shell output redirections".to_owned(),
        )),
    }
}

fn secret_observability(shell: &ScriptShell, source: &str) -> (bool, bool, Vec<UnknownReason>) {
    let mut network = false;
    let mut output = false;
    let mut unknowns = BTreeSet::new();
    for line in source.to_ascii_lowercase().lines() {
        for group in split_top_level(line, TopLevelSeparator::Sequence) {
            let stages = split_top_level(group, TopLevelSeparator::Pipeline);
            let has_secret = stages.iter().any(|stage| secret_reference(stage));
            if !has_secret {
                continue;
            }
            let group_network = stages.iter().any(|stage| network_command(stage));
            let producer = stages
                .iter()
                .any(|stage| secret_reference(stage) && output_command(stage));
            network |= group_network;
            if producer
                && !group_network
                && let Some(final_stage) = stages.last()
            {
                match output_destination(shell, final_stage) {
                    OutputDestination::PrivateFile => {}
                    OutputDestination::Unknown(reason) => {
                        unknowns.insert(reason);
                    }
                    OutputDestination::StandardOutput => {
                        output |= stages.len() == 1
                            || [
                                "base64",
                                "cat",
                                "jq",
                                "openssl enc",
                                "sed ",
                                "tee",
                                "tr ",
                                "xxd",
                            ]
                            .into_iter()
                            .any(|marker| final_stage.contains(marker));
                        if !output {
                            unknowns.insert(UnknownReason::UnsupportedSyntax(
                                "unresolved pipeline stdout behavior".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
    }
    (network, output, unknowns.into_iter().collect())
}

fn script_summary(node: &Node) -> ScriptSummary {
    let source = command_source(node);
    let shell = script_shell(node);
    let tokens = script_tokens(source);
    let expansions = script_expansions(&shell, &tokens);
    let provider_substitution = source.contains("${{")
        || source.contains("<<")
        || source.contains("$[")
        || (matches!(shell, ScriptShell::PowerShell | ScriptShell::Cmd) && source.contains("$("));
    let lower = source.to_ascii_lowercase();
    let dynamic_python = shell == ScriptShell::Python
        && ["eval(", "exec(", "subprocess", "os.system("]
            .into_iter()
            .any(|marker| lower.contains(marker));
    let unsafe_interpolation = provider_substitution
        || dynamic_python
        || expansions.iter().any(|expansion| !expansion.quoted);
    let (secret_to_network, secret_to_output, mut unknowns) = secret_observability(&shell, source);
    if let ScriptShell::Unknown(name) = shell {
        unknowns.push(UnknownReason::UnsupportedSyntax(format!("shell {name}")));
    }
    unknowns.sort();
    unknowns.dedup();
    ScriptSummary {
        unknowns,
        expansions,
        unsafe_interpolation,
        secret_to_network,
        secret_to_output,
    }
}

fn secret_sink_uncertainty(sink: &Node, summary: Option<&ScriptSummary>) -> Vec<UnknownReason> {
    let mut unknowns = sink.unknown.iter().cloned().collect::<BTreeSet<_>>();
    if let Some(summary) = summary {
        unknowns.extend(summary.unknowns.iter().cloned());
    }
    unknowns.into_iter().collect()
}

fn secret_rule(graph: &Graph, index: &GraphIndex<'_>, dataflow: &Dataflow) -> RuleResult {
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for sink in graph.nodes.iter().filter(|node| {
        node.kind == NodeKind::Command
            || node.effects.contains(&ObservableEffect::NetworkRequest)
            || (node.kind == NodeKind::Call && node.capabilities.contains(&Capability::Network))
    }) {
        let value = dataflow.at(sink);
        let summary = (sink.kind == NodeKind::Command).then(|| script_summary(sink));
        let explicit_credential_transport =
            sink.kind == NodeKind::Call && sink.effects.contains(&ObservableEffect::CredentialUse);
        let (network, output) = summary.as_ref().map_or_else(
            || {
                (
                    !explicit_credential_transport
                        && (sink.effects.contains(&ObservableEffect::NetworkRequest)
                            || sink.capabilities.contains(&Capability::Network)),
                    false,
                )
            },
            |summary| {
                (
                    summary.secret_to_network
                        || sink.effects.contains(&ObservableEffect::NetworkRequest)
                        || sink.capabilities.contains(&Capability::Network),
                    summary.secret_to_output,
                )
            },
        );
        let uncertainty = secret_sink_uncertainty(sink, summary.as_ref());
        let observable = network || output;
        if value.is_secret() && observable {
            states.push(PropertyState::Violated);
            let mut capabilities = vec![Capability::SecretAccess];
            if sink.kind == NodeKind::Command {
                capabilities.push(Capability::Shell);
            }
            if network {
                capabilities.push(Capability::Network);
            }
            diagnostics.push(Diagnostic::new(
                "WV-SEC-002",
                Severity::Critical,
                Confidence::High,
                if network {
                    "a secret reaches a network-capable command"
                } else {
                    "a secret reaches workflow output or logs"
                },
                sink.span.clone(),
                data_trace(graph, index, dataflow, sink),
                capabilities,
                [
                    "abstract secrecy = secret".to_owned(),
                    if network {
                        "script effect = network_request".to_owned()
                    } else {
                        "script effect = process output".to_owned()
                    },
                ],
                None,
            ));
        } else if value.is_secret() && !uncertainty.is_empty() {
            states.push(PropertyState::Unknown(uncertainty));
        } else if let Secrecy::Unknown(reasons) = &value.secrecy
            && observable
        {
            states.push(PropertyState::Unknown(reasons.clone()));
        } else if !uncertainty.is_empty() && sink.capabilities.contains(&Capability::Network) {
            states.push(PropertyState::Unknown(uncertainty));
        } else {
            states.push(PropertyState::Proved);
        }
    }
    RuleResult {
        property: Some(property(
            "WV-SEC-002",
            PropertyState::combine(states),
            "secret values do not reach network, output, or logging effects",
        )),
        diagnostics,
    }
}

fn supply_rule(graph: &Graph) -> RuleResult {
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for call in graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Call)
    {
        let locked = call
            .attributes
            .get("dependency.digest")
            .and_then(AbstractValue::constants)
            .is_some_and(|digests| {
                !digests.is_empty() && digests.iter().all(|value| valid_content_digest(value))
            });
        match if locked {
            DependencyClass::Immutable
        } else {
            classify_reference(&call.name)
        } {
            DependencyClass::Local | DependencyClass::Immutable => {
                states.push(PropertyState::Proved);
            }
            DependencyClass::Mutable => {
                states.push(PropertyState::Violated);
                diagnostics.push(Diagnostic::new(
                    "WV-SUPPLY-001",
                    Severity::Warning,
                    Confidence::High,
                    format!(
                        "dependency is not pinned to immutable content: {}",
                        call.name
                    ),
                    call.span.clone(),
                    vec![trace("mutable dependency", call)],
                    [],
                    [format!("reference = {}", call.name)],
                    Some(Fix {
                        kind: "pin-dependency".to_owned(),
                        description: "resolve and replace the reference with an immutable revision"
                            .to_owned(),
                        replacement: None,
                        span: Some(call.span.clone()),
                    }),
                ));
            }
            DependencyClass::Unknown => states.push(PropertyState::Unknown(vec![
                UnknownReason::UnresolvedDependency(call.name.clone()),
            ])),
        }
    }
    RuleResult {
        property: Some(property(
            "WV-SUPPLY-001",
            PropertyState::combine(states),
            "remote executable dependencies are content-addressed",
        )),
        diagnostics,
    }
}

fn correctness_rule(graph: &Graph, index: &GraphIndex<'_>) -> RuleResult {
    let mut diagnostics = Vec::new();
    for issue in graph.validate() {
        let span = issue
            .node_ids
            .iter()
            .find_map(|id| index.nodes.get(id.as_str()).map(|node| node.span.clone()))
            .unwrap_or_default();
        diagnostics.push(Diagnostic::new(
            "WV-CORRECT-001",
            Severity::Error,
            Confidence::High,
            issue.message,
            span,
            Vec::new(),
            [],
            [issue.code],
            None,
        ));
    }
    for (kinds, message) in [
        (&[EdgeKind::Control][..], "control dependency cycle"),
        (&[EdgeKind::Call][..], "recursive call graph"),
    ] {
        for cycle in index.cycles(kinds) {
            let span = cycle
                .iter()
                .find_map(|id| index.nodes.get(id.as_str()).map(|node| node.span.clone()))
                .unwrap_or_default();
            diagnostics.push(Diagnostic::new(
                "WV-CORRECT-001",
                Severity::Error,
                Confidence::High,
                message,
                span,
                Vec::new(),
                [],
                [cycle.join(" -> ")],
                None,
            ));
        }
    }
    let state = if !diagnostics.is_empty() {
        PropertyState::Violated
    } else if graph.nodes.is_empty() {
        PropertyState::NotApplicable
    } else {
        PropertyState::Proved
    };
    RuleResult {
        property: Some(property(
            "WV-CORRECT-001",
            state,
            "the lowered graph is well-formed, phase-valid, and acyclic",
        )),
        diagnostics,
    }
}

fn privileged_capability(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::RepositoryWrite
            | Capability::TokenWrite
            | Capability::Oidc
            | Capability::CloudCredential
            | Capability::SecretAccess
            | Capability::Network
            | Capability::FilesystemWrite
            | Capability::ArtifactRead
            | Capability::ArtifactWrite
            | Capability::CacheRead
            | Capability::CacheWrite
            | Capability::Deployment
            | Capability::SelfHostedPersistence
            | Capability::AiTool
    )
}

fn permission_capability_matches(
    capability: Capability,
    effects: &BTreeSet<ObservableEffect>,
) -> bool {
    if !privileged_capability(capability) {
        return true;
    }
    match capability {
        Capability::Oidc | Capability::CloudCredential => {
            effects.contains(&ObservableEffect::DeploymentChange)
                || effects.contains(&ObservableEffect::CredentialUse)
        }
        Capability::SelfHostedPersistence | Capability::FilesystemWrite => {
            effects.contains(&ObservableEffect::FileWrite)
                || effects.contains(&ObservableEffect::WorkflowChange)
        }
        Capability::ArtifactRead | Capability::ArtifactWrite => {
            effects.contains(&ObservableEffect::ArtifactPublish)
        }
        Capability::CacheRead | Capability::CacheWrite => {
            effects.contains(&ObservableEffect::CachePublish)
        }
        Capability::RepositoryWrite => {
            effects.contains(&ObservableEffect::RepositoryChange)
                || effects.contains(&ObservableEffect::WorkflowChange)
        }
        Capability::TokenWrite => effects.contains(&ObservableEffect::RepositoryChange),
        Capability::Network => effects.contains(&ObservableEffect::NetworkRequest),
        Capability::Deployment => effects.contains(&ObservableEffect::DeploymentChange),
        Capability::SecretAccess => effects.contains(&ObservableEffect::CredentialUse),
        Capability::AiTool => effects.contains(&ObservableEffect::AiAgentExecution),
        Capability::RepositoryRead
        | Capability::TokenRead
        | Capability::FilesystemRead
        | Capability::Shell => true,
    }
}

fn permission_rule(graph: &Graph, index: &GraphIndex<'_>) -> RuleResult {
    let grants: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| matches!(node.kind, NodeKind::Workflow | NodeKind::Job))
        .flat_map(|node| {
            node.capabilities
                .iter()
                .copied()
                .map(move |capability| (node, capability))
        })
        .collect();
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for (owner, capability) in &grants {
        let reachable = index.reachable(&owner.id);
        let effects: BTreeSet<_> = reachable
            .iter()
            .flat_map(|node| {
                node.effects
                    .iter()
                    .copied()
                    .chain(if node.kind == NodeKind::Command {
                        script_effects(node)
                    } else {
                        Vec::new()
                    })
            })
            .collect();
        let unknowns: BTreeSet<_> = reachable
            .iter()
            .filter_map(|node| node.unknown.clone())
            .collect();
        if permission_capability_matches(*capability, &effects) {
            states.push(PropertyState::Proved);
        } else if !unknowns.is_empty() {
            states.push(PropertyState::Unknown(unknowns.into_iter().collect()));
        } else {
            states.push(PropertyState::Violated);
            diagnostics.push(Diagnostic::new(
                "WV-PERM-001",
                Severity::Warning,
                Confidence::High,
                format!("granted capability is not required: {}", capability.name()),
                owner.span.clone(),
                vec![trace("capability grant", owner)],
                [*capability],
                ["no reachable effect requires this capability".to_owned()],
                Some(Fix {
                    kind: "reduce-permissions".to_owned(),
                    description: "remove the unused grant".to_owned(),
                    replacement: None,
                    span: Some(owner.span.clone()),
                }),
            ));
        }
    }
    RuleResult {
        property: Some(property(
            "WV-PERM-001",
            if grants.is_empty() {
                PropertyState::NotApplicable
            } else {
                PropertyState::combine(states)
            },
            "granted capabilities are required by a reachable effect",
        )),
        diagnostics,
    }
}

fn privileged(node: &Node) -> bool {
    let mut effects = node.effects.clone();
    if node.kind == NodeKind::Command {
        effects.extend(script_effects(node));
    }
    effects.iter().any(|effect| {
        matches!(
            effect,
            ObservableEffect::RepositoryChange
                | ObservableEffect::DeploymentChange
                | ObservableEffect::WorkflowChange
        )
    })
}

fn trusted_authorization_gate(node: &Node, dataflow: &Dataflow) -> bool {
    let mechanism = node
        .attributes
        .get("mechanism")
        .and_then(AbstractValue::constants)
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| matches!(value.to_ascii_lowercase().as_str(), "approval" | "manual"))
        });
    let protected_reference = node.condition.atoms().into_iter().any(|atom| {
        let lower = atom.to_ascii_lowercase();
        [
            "(github.ref_protected==true)",
            "(true==github.ref_protected)",
            "(ci_commit_ref_protected==\"true\")",
            "(\"true\"==ci_commit_ref_protected)",
            "github.ref_protected",
        ]
        .contains(&lower.as_str())
            && node.condition.implies(&Condition::atom(atom))
    });
    let lower_name = node.name.to_ascii_lowercase();
    let explicit_approval = lower_name == "environment approval"
        || (node.provider == Provider::Circleci && lower_name.starts_with("approval:"));
    let value = dataflow.at(node);
    (mechanism || protected_reference || explicit_approval)
        && !value.is_untrusted()
        && reasons(&value).is_empty()
}

fn environment_authorization_reasons(
    graph: &Graph,
    index: &GraphIndex<'_>,
    sink: &Node,
) -> Vec<UnknownReason> {
    graph
        .nodes
        .iter()
        .filter(|resource| {
            resource.kind == NodeKind::Resource
                && resource
                    .name
                    .to_ascii_lowercase()
                    .starts_with("environment:")
                && index
                    .shortest_path(
                        &resource.id,
                        &sink.id,
                        &[EdgeKind::Grant, EdgeKind::Control, EdgeKind::Call],
                    )
                    .is_some()
        })
        .map(|resource| {
            resource.unknown.clone().unwrap_or_else(|| {
                UnknownReason::ExternalState(format!("protection rules for {}", resource.name))
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn authorization_rule(graph: &Graph, index: &GraphIndex<'_>, dataflow: &Dataflow) -> RuleResult {
    let gates: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Gate && trusted_authorization_gate(node, dataflow))
        .collect();
    let sinks: Vec<_> = graph.nodes.iter().filter(|node| privileged(node)).collect();
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for sink in sinks {
        if gates.iter().any(|gate| index.dominates(&gate.id, &sink.id)) {
            states.push(PropertyState::Proved);
        } else {
            let environment_reasons = environment_authorization_reasons(graph, index, sink);
            if !environment_reasons.is_empty() {
                states.push(PropertyState::Unknown(environment_reasons));
                continue;
            }
            states.push(PropertyState::Violated);
            let trace = graph
                .entrypoints
                .iter()
                .find_map(|entrypoint| {
                    index.shortest_path(entrypoint, &sink.id, &[EdgeKind::Control])
                })
                .map_or_else(
                    || vec![trace("privileged sink without dominating gate", sink)],
                    |path| {
                        path.into_iter()
                            .map(|node| trace("authorization bypass", node))
                            .collect()
                    },
                );
            diagnostics.push(Diagnostic::new(
                "WV-AUTH-001",
                Severity::Error,
                Confidence::High,
                "a privileged effect is reachable without a dominating authorization gate",
                sink.span.clone(),
                trace,
                sink.capabilities.clone(),
                ["dominator set contains no Gate node".to_owned()],
                None,
            ));
        }
    }
    RuleResult {
        property: Some(property(
            "WV-AUTH-001",
            PropertyState::combine(states),
            "every privileged effect is dominated by an authorization gate",
        )),
        diagnostics,
    }
}

fn integrity_rule(
    graph: &Graph,
    index: &GraphIndex<'_>,
    dataflow: &Dataflow,
    rule_id: &str,
    label: &str,
) -> RuleResult {
    let resources: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == NodeKind::Resource
                && (node
                    .name
                    .to_ascii_lowercase()
                    .starts_with(&format!("{label}:"))
                    || node.capabilities.iter().any(|capability| match label {
                        "artifact" => {
                            matches!(
                                capability,
                                Capability::ArtifactRead | Capability::ArtifactWrite
                            )
                        }
                        "cache" => {
                            matches!(capability, Capability::CacheRead | Capability::CacheWrite)
                        }
                        _ => false,
                    }))
        })
        .collect();
    let sinks: Vec<_> = graph.nodes.iter().filter(|node| privileged(node)).collect();
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for resource in &resources {
        let value = dataflow.at(resource);
        let attack = value
            .is_untrusted()
            .then(|| {
                sinks.iter().find_map(|sink| {
                    index
                        .shortest_path(
                            &resource.id,
                            &sink.id,
                            &[
                                EdgeKind::Control,
                                EdgeKind::Data,
                                EdgeKind::Read,
                                EdgeKind::Write,
                                EdgeKind::Persist,
                                EdgeKind::Call,
                            ],
                        )
                        .map(|path| (*sink, path))
                })
            })
            .flatten();
        if let Some((sink, path)) = attack {
            states.push(PropertyState::Violated);
            diagnostics.push(Diagnostic::new(
                rule_id,
                Severity::Critical,
                Confidence::High,
                format!("untrusted data can poison {label} consumed by a privileged effect"),
                sink.span.clone(),
                path.iter()
                    .map(|node| trace(&format!("{label} propagation"), node))
                    .collect(),
                [],
                [
                    format!("resource = {}", resource.name),
                    "abstract trust = untrusted".to_owned(),
                ],
                None,
            ));
        } else {
            let unknowns = reasons(&value);
            states.push(if unknowns.is_empty() {
                PropertyState::Proved
            } else {
                PropertyState::Unknown(unknowns)
            });
        }
    }
    RuleResult {
        property: Some(property(
            rule_id,
            if resources.is_empty() {
                PropertyState::NotApplicable
            } else {
                PropertyState::combine(states)
            },
            &format!("{label} integrity is preserved across producers and consumers"),
        )),
        diagnostics,
    }
}

fn toctou_rule(graph: &Graph, index: &GraphIndex<'_>, dataflow: &Dataflow) -> RuleResult {
    let checkouts: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == NodeKind::Call
                && (node.name.to_ascii_lowercase().contains("checkout")
                    || node.name.to_ascii_lowercase().contains("clone"))
        })
        .collect();
    let sinks: Vec<_> = graph.nodes.iter().filter(|node| privileged(node)).collect();
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for checkout in &checkouts {
        let attack = classify_reference(&checkout.name) != DependencyClass::Immutable
            && dataflow.at(checkout).is_untrusted();
        let path = attack
            .then(|| {
                sinks.iter().find_map(|sink| {
                    index.shortest_path(
                        &checkout.id,
                        &sink.id,
                        &[EdgeKind::Control, EdgeKind::Data, EdgeKind::Call],
                    )
                })
            })
            .flatten();
        if let Some(path) = path {
            states.push(PropertyState::Violated);
            diagnostics.push(Diagnostic::new(
                "WV-TOCTOU-001",
                Severity::Critical,
                Confidence::High,
                "an untrusted mutable checkout reaches a privileged effect",
                checkout.span.clone(),
                path.iter()
                    .map(|node| trace("mutable workspace", node))
                    .collect(),
                [],
                [
                    "checkout reference is mutable".to_owned(),
                    "checkout selector is untrusted".to_owned(),
                ],
                None,
            ));
        } else {
            states.push(PropertyState::Proved);
        }
    }
    RuleResult {
        property: Some(property(
            "WV-TOCTOU-001",
            if checkouts.is_empty() {
                PropertyState::NotApplicable
            } else {
                PropertyState::combine(states)
            },
            "untrusted checkout selection cannot race a privileged consumer",
        )),
        diagnostics,
    }
}

fn credential_rule(graph: &Graph, dataflow: &Dataflow) -> RuleResult {
    let candidates: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == NodeKind::Call
                && node
                    .capabilities
                    .contains(&Capability::SelfHostedPersistence)
        })
        .collect();
    let mut states = Vec::new();
    let mut diagnostics = Vec::new();
    for candidate in &candidates {
        let value = dataflow.at(candidate);
        if value.is_secret() {
            states.push(PropertyState::Violated);
            diagnostics.push(Diagnostic::new(
                "WV-CRED-001",
                Severity::Critical,
                Confidence::High,
                "a credential can persist beyond its intended step or job",
                candidate.span.clone(),
                vec![trace("persistent consumer", candidate)],
                [Capability::SecretAccess, Capability::SelfHostedPersistence],
                ["abstract secrecy = secret".to_owned()],
                None,
            ));
        } else {
            let unknowns = reasons(&value);
            states.push(if unknowns.is_empty() {
                PropertyState::Proved
            } else {
                PropertyState::Unknown(unknowns)
            });
        }
    }
    RuleResult {
        property: Some(property(
            "WV-CRED-001",
            if candidates.is_empty() {
                PropertyState::NotApplicable
            } else {
                PropertyState::combine(states)
            },
            "credentials do not persist into reusable runner state",
        )),
        diagnostics,
    }
}

fn ai_rule(graph: &Graph, dataflow: &Dataflow) -> RuleResult {
    let agents: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| {
            matches!(node.kind, NodeKind::Call | NodeKind::Command)
                && (node.effects.contains(&ObservableEffect::AiAgentExecution)
                    || node.capabilities.contains(&Capability::AiTool)
                    || [
                        "copilot",
                        "openai",
                        "claude",
                        "gemini",
                        "ai-agent",
                        "agent-action",
                    ]
                    .iter()
                    .any(|marker| node.name.to_ascii_lowercase().contains(marker)))
        })
        .collect();
    let vulnerable: Vec<_> = agents
        .iter()
        .copied()
        .filter(|node| {
            dataflow.at(node).is_untrusted()
                && (node.capabilities.contains(&Capability::Network)
                    || node.capabilities.contains(&Capability::AiTool))
        })
        .collect();
    let diagnostics = vulnerable
        .iter()
        .map(|node| {
            Diagnostic::new(
                "WV-AI-001",
                Severity::Critical,
                Confidence::High,
                "untrusted prompt data reaches an AI agent with tool or network authority",
                node.span.clone(),
                vec![trace("AI agent sink", node)],
                [Capability::AiTool, Capability::Network],
                Vec::<String>::new(),
                None,
            )
        })
        .collect();
    RuleResult {
        property: Some(property(
            "WV-AI-001",
            if agents.is_empty() {
                PropertyState::NotApplicable
            } else if vulnerable.is_empty() {
                PropertyState::Proved
            } else {
                PropertyState::Violated
            },
            "AI agent input is trusted or isolated from tools and network",
        )),
        diagnostics,
    }
}

fn self_rule(graph: &Graph) -> RuleResult {
    let write_granted = graph
        .nodes
        .iter()
        .any(|node| node.capabilities.contains(&Capability::RepositoryWrite));
    let offenders: Vec<_> = if write_granted {
        graph
            .nodes
            .iter()
            .filter(|node| {
                node.kind == NodeKind::Command
                    && script_effects(node).contains(&ObservableEffect::WorkflowChange)
            })
            .collect()
    } else {
        Vec::new()
    };
    let diagnostics = offenders
        .iter()
        .map(|node| {
            Diagnostic::new(
                "WV-SELF-001",
                Severity::Critical,
                Confidence::High,
                "workflow code can modify CI configuration with repository write authority",
                node.span.clone(),
                vec![trace("self-modifying command", node)],
                [
                    Capability::RepositoryWrite,
                    Capability::FilesystemWrite,
                    Capability::Shell,
                ],
                Vec::<String>::new(),
                None,
            )
        })
        .collect();
    RuleResult {
        property: Some(property(
            "WV-SELF-001",
            if !write_granted {
                PropertyState::NotApplicable
            } else if offenders.is_empty() {
                PropertyState::Proved
            } else {
                PropertyState::Violated
            },
            "workflow execution cannot rewrite trusted CI definitions",
        )),
        diagnostics,
    }
}

/// Run all language-independent verification properties.
#[must_use]
pub fn verify(_persona: Persona, graph: &Graph) -> VerificationResult {
    let index = GraphIndex::new(graph);
    let dataflow = Dataflow::solve(graph);
    let mut rules = vec![
        correctness_rule(graph, &index),
        injection_rule(graph, &index, &dataflow),
        secret_rule(graph, &index, &dataflow),
        supply_rule(graph),
        permission_rule(graph, &index),
        authorization_rule(graph, &index, &dataflow),
        integrity_rule(graph, &index, &dataflow, "WV-ARTIFACT-001", "artifact"),
        integrity_rule(graph, &index, &dataflow, "WV-CACHE-001", "cache"),
        toctou_rule(graph, &index, &dataflow),
        credential_rule(graph, &dataflow),
        ai_rule(graph, &dataflow),
        self_rule(graph),
    ];
    let mut properties: Vec<_> = rules
        .iter_mut()
        .filter_map(|rule| rule.property.take())
        .collect();
    let mut diagnostics: Vec<_> = rules
        .into_iter()
        .flat_map(|rule| rule.diagnostics)
        .collect();
    properties.sort();
    diagnostics.sort();
    VerificationResult {
        properties,
        diagnostics,
        complete: dataflow.complete && graph.nodes.iter().all(|node| node.unknown.is_none()),
        analyzed_nodes: graph.nodes.len(),
        analyzed_edges: graph.edges.len(),
    }
}

#[must_use]
pub fn should_fail(persona: Persona, result: &VerificationResult) -> bool {
    match persona {
        Persona::Audit => false,
        Persona::Gate => result.diagnostics.iter().any(|diagnostic| {
            diagnostic.confidence == Confidence::High
                && matches!(diagnostic.severity, Severity::Critical | Severity::Error)
        }),
        Persona::Paranoid => {
            !result.diagnostics.is_empty()
                || result
                    .properties
                    .iter()
                    .any(|property| matches!(property.state, PropertyState::Unknown(_)))
        }
    }
}

/// Compose provider graphs and connect content-addressed local calls to their
/// compiled entrypoints. The returned program is deterministic and contains
/// each semantic node and edge exactly once.
#[must_use]
pub fn compose_program(graphs: &[Graph]) -> Graph {
    let provider = graphs
        .first()
        .map_or(workflow_verifier_domain::Provider::Github, |graph| {
            graph.provider
        });
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();
    let mut entrypoints = BTreeSet::new();
    for graph in graphs {
        for node in &graph.nodes {
            nodes.entry(node.id.clone()).or_insert_with(|| node.clone());
        }
        for edge in &graph.edges {
            edges.entry(edge.id.clone()).or_insert_with(|| edge.clone());
        }
        entrypoints.extend(graph.entrypoints.iter().cloned());
    }
    for caller in graphs {
        for call in caller
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Call)
        {
            let Some(target) = local_call_target(graphs, caller, call) else {
                continue;
            };
            if let Some(composed_call) = nodes.get_mut(&call.id) {
                composed_call.unknown = None;
            }
            if caller.source == target.source {
                continue;
            }
            for entrypoint in &target.entrypoints {
                for kind in [EdgeKind::Call, EdgeKind::Control] {
                    let edge = Edge::new(
                        kind,
                        call.id.clone(),
                        entrypoint.clone(),
                        Condition::True,
                        Some("local-unit".to_owned()),
                    );
                    edges.entry(edge.id.clone()).or_insert(edge);
                }
            }
        }
    }
    let written_resources: BTreeSet<_> = edges
        .values()
        .filter(|edge| matches!(edge.kind, EdgeKind::Write | EdgeKind::Persist))
        .map(|edge| edge.to.clone())
        .collect();
    let read_resources: BTreeSet<_> = edges
        .values()
        .filter(|edge| matches!(edge.kind, EdgeKind::Read | EdgeKind::Data))
        .map(|edge| edge.from.clone())
        .collect();
    let writers: Vec<_> = nodes
        .values()
        .filter(|node| node.kind == NodeKind::Resource && written_resources.contains(&node.id))
        .cloned()
        .collect();
    let readers: Vec<_> = nodes
        .values()
        .filter(|node| node.kind == NodeKind::Resource && read_resources.contains(&node.id))
        .cloned()
        .collect();
    for writer in &writers {
        for reader in readers
            .iter()
            .filter(|reader| reader.name == writer.name && reader.id != writer.id)
        {
            let edge = Edge::new(
                EdgeKind::Persist,
                writer.id.clone(),
                reader.id.clone(),
                Condition::True,
                Some("cross-file resource".to_owned()),
            );
            edges.entry(edge.id.clone()).or_insert(edge);
        }
    }
    let mut output = Graph {
        provider,
        source: "<program>".to_owned(),
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
        entrypoints: entrypoints.into_iter().collect(),
    };
    output.finalize();
    output
}

fn local_call_target<'a>(graphs: &'a [Graph], caller: &Graph, call: &Node) -> Option<&'a Graph> {
    if let Some(target) = call
        .attributes
        .get("dependency.revision")
        .and_then(AbstractValue::constants)
        .and_then(|values| values.iter().find_map(|value| value.strip_prefix("local:")))
    {
        let target = normalize_slashes(target)
            .trim_start_matches("./")
            .to_owned();
        return unique_graph(graphs, |graph| normalized_source(graph) == target);
    }

    let reference = local_reference(&call.name)?;
    let stripped = reference.trim_start_matches("./");
    let caller_source = normalize_slashes(&caller.source);
    let caller_parent = caller_source
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let mut candidates = BTreeSet::from([stripped.to_owned()]);
    if !yaml_reference(stripped) {
        candidates.insert(format!("{stripped}/action.yml"));
        candidates.insert(format!("{stripped}/action.yaml"));
    }
    if !caller_parent.is_empty()
        && !reference.starts_with('/')
        && let Some(relative) = normalize_relative(&format!("{caller_parent}/{reference}"))
    {
        candidates.insert(relative);
    }
    unique_graph(graphs, |graph| {
        candidates.contains(&normalized_source(graph))
    })
}

fn unique_graph(graphs: &[Graph], predicate: impl Fn(&Graph) -> bool) -> Option<&Graph> {
    let mut matches = graphs.iter().filter(|graph| predicate(graph));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn normalized_source(graph: &Graph) -> String {
    normalize_slashes(&graph.source)
        .trim_start_matches("./")
        .to_owned()
}

fn local_reference(name: &str) -> Option<String> {
    let name = name.strip_prefix("child:").unwrap_or(name);
    let name = if name.starts_with('@') {
        name
    } else {
        name.split_once('@')
            .map_or(name, |(reference, _)| reference)
    };
    let normalized = normalize_slashes(name);
    (normalized.starts_with("./")
        || normalized.starts_with("../")
        || normalized.starts_with(".github/")
        || yaml_reference(&normalized))
    .then_some(normalized)
}

fn yaml_reference(value: &str) -> bool {
    std::path::Path::new(value)
        .extension()
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
        })
}

fn normalize_relative(value: &str) -> Option<String> {
    let normalized = normalize_slashes(value);
    let mut components = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            component => components.push(component),
        }
    }
    Some(components.join("/"))
}

/// Compose all graphs, then run the ordinary whole-program verifier.
#[must_use]
pub fn verify_program(persona: Persona, graphs: &[Graph]) -> VerificationResult {
    let composed = compose_program(graphs);
    verify(persona, &composed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SOURCE: &str = "workflow.yml";

    fn test_span() -> Span {
        Span {
            file: TEST_SOURCE.to_owned(),
            ..Span::default()
        }
    }

    fn test_value(value: &str, trust: Trust, secrecy: Secrecy) -> AbstractValue {
        AbstractValue::string_constant(value, trust, secrecy, Vec::new())
    }

    fn test_node(kind: NodeKind, name: &str) -> Node {
        test_node_in(TEST_SOURCE, kind, name)
    }

    fn test_node_in(source: &str, kind: NodeKind, name: &str) -> Node {
        let span = Span {
            file: source.to_owned(),
            ..Span::default()
        };
        Node::simple(
            Provider::Github,
            kind,
            name,
            workflow_verifier_domain::Phase::Run,
            span,
        )
    }

    fn test_command(source: &str) -> Node {
        Node::new(
            Provider::Github,
            NodeKind::Command,
            source,
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::from([(
                "command".to_owned(),
                AbstractValue::string_constant(source, Trust::Trusted, Secrecy::Public, Vec::new()),
            )]),
            [Capability::Shell],
            [],
            None,
        )
    }

    fn state<'a>(result: &'a VerificationResult, rule_id: &str) -> &'a PropertyState {
        &result
            .properties
            .iter()
            .find(|property| property.id == rule_id)
            .expect("rule property must be explicit")
            .state
    }

    #[test]
    fn public_names_json_and_total_diagnostic_order_are_exact() {
        assert_eq!(
            [
                Severity::Critical,
                Severity::Error,
                Severity::Warning,
                Severity::Note,
            ]
            .map(Severity::name),
            ["critical", "error", "warning", "note"]
        );
        assert_eq!(
            [Confidence::High, Confidence::Medium, Confidence::Low].map(Confidence::name),
            ["high", "medium", "low"]
        );
        assert_eq!(
            [
                PropertyState::Proved,
                PropertyState::Violated,
                PropertyState::Unknown(Vec::new()),
                PropertyState::NotApplicable,
            ]
            .map(|property| property.name()),
            ["Proved", "Violated", "Unknown", "NotApplicable"]
        );
        assert_eq!(
            [Persona::Gate, Persona::Audit, Persona::Paranoid].map(Persona::name),
            ["gate", "audit", "paranoid"]
        );

        let reason = UnknownReason::MissingEvidence("semantic summary".to_owned());
        let property = Property {
            id: "WV-TEST-001".to_owned(),
            state: PropertyState::Unknown(vec![reason.clone()]),
            subject: Some("subject".to_owned()),
            explanation: "explanation".to_owned(),
        };
        let property_json = property.to_json();
        assert!(
            matches!(property_json, JsonValue::Object(_)),
            "property JSON must be an object"
        );
        let JsonValue::Object(fields) = property_json else {
            return;
        };
        assert_eq!(
            fields.get("reasons"),
            Some(&JsonValue::Array(vec![reason.to_json()]))
        );
        assert_eq!(
            fields.get("state"),
            Some(&JsonValue::String("Unknown".to_owned()))
        );

        let first = Diagnostic::new(
            "WV-TEST-001",
            Severity::Note,
            Confidence::Low,
            "first",
            test_span(),
            Vec::new(),
            [],
            Vec::<String>::new(),
            None,
        );
        let second = Diagnostic::new(
            "WV-TEST-002",
            Severity::Note,
            Confidence::Low,
            "second",
            test_span(),
            Vec::new(),
            [],
            Vec::<String>::new(),
            None,
        );
        assert_eq!(first.partial_cmp(&second), Some(first.cmp(&second)));
    }

    #[test]
    fn graph_index_obeys_edge_filters_reachability_dominance_and_cycle_order() {
        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let entry = test_node(NodeKind::Workflow, "entry");
        let gate = test_node(NodeKind::Gate, "gate");
        let sink = test_node(NodeKind::Command, "sink");
        let bypass = test_node(NodeKind::Step, "bypass");
        for node in [&entry, &gate, &sink, &bypass] {
            graph.add_node(node.clone());
        }
        graph.add_entrypoint(entry.id.clone());
        graph.add_edge(Edge::simple(
            EdgeKind::Control,
            entry.id.clone(),
            gate.id.clone(),
        ));
        graph.add_edge(Edge::simple(
            EdgeKind::Control,
            gate.id.clone(),
            sink.id.clone(),
        ));
        graph.add_edge(Edge::simple(
            EdgeKind::Data,
            entry.id.clone(),
            bypass.id.clone(),
        ));
        graph.finalize();

        let index = GraphIndex::new(&graph);
        assert_eq!(
            index
                .shortest_path(&entry.id, &sink.id, &[EdgeKind::Control])
                .expect("control path")
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            vec!["entry", "gate", "sink"]
        );
        assert!(
            index
                .shortest_path(&entry.id, &bypass.id, &[EdgeKind::Control])
                .is_none()
        );
        assert_eq!(
            index
                .reachable(&entry.id)
                .iter()
                .map(|node| node.name.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["entry", "gate", "sink", "bypass"])
        );
        assert!(index.dominates(&entry.id, &entry.id));
        assert!(index.dominates(&gate.id, &sink.id));
        assert!(!index.path_avoiding(&entry.id, &sink.id, &gate.id));

        let mut bypassed = graph.clone();
        bypassed.add_edge(Edge::simple(
            EdgeKind::Control,
            entry.id.clone(),
            bypass.id.clone(),
        ));
        bypassed.add_edge(Edge::simple(
            EdgeKind::Call,
            bypass.id.clone(),
            sink.id.clone(),
        ));
        bypassed.finalize();
        let bypassed_index = GraphIndex::new(&bypassed);
        assert!(bypassed_index.path_avoiding(&entry.id, &sink.id, &gate.id));
        assert!(!bypassed_index.dominates(&gate.id, &sink.id));

        let mut inferred_entrypoints = graph.clone();
        inferred_entrypoints.entrypoints.clear();
        let inferred_index = GraphIndex::new(&inferred_entrypoints);
        assert!(inferred_index.dominates(&gate.id, &sink.id));

        assert_eq!(
            canonical_cycle(vec![
                "beta".to_owned(),
                "gamma".to_owned(),
                "alpha".to_owned(),
                "beta".to_owned(),
            ]),
            vec![
                "alpha".to_owned(),
                "beta".to_owned(),
                "gamma".to_owned(),
                "alpha".to_owned(),
            ]
        );
        assert_eq!(canonical_cycle(Vec::new()), Vec::<String>::new());
        assert_eq!(
            canonical_cycle(vec!["only".to_owned()]),
            vec!["only".to_owned(), "only".to_owned()]
        );
    }

    #[test]
    fn dataflow_and_unknown_reason_collection_follow_semantic_edges_only() {
        let value_reason = UnknownReason::DynamicString("value".to_owned());
        let trust_reason = UnknownReason::ExternalState("trust".to_owned());
        let secrecy_reason = UnknownReason::MissingEvidence("secrecy".to_owned());
        let composite = AbstractValue {
            value_type: workflow_verifier_domain::ValueType::Dynamic,
            value: Value::Unknown(vec![value_reason.clone()]),
            trust: Trust::Unknown(vec![trust_reason.clone()]),
            secrecy: Secrecy::Unknown(vec![secrecy_reason.clone()]),
            provenance: Vec::new(),
        };
        assert_eq!(
            reasons(&composite),
            vec![trust_reason, value_reason, secrecy_reason]
        );

        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut source = test_node(NodeKind::Resource, "source");
        source.attributes.insert(
            "value".to_owned(),
            AbstractValue::string_constant(
                "tainted",
                Trust::Untrusted,
                Secrecy::Secret,
                Vec::new(),
            ),
        );
        let middle = test_node(NodeKind::Resource, "middle");
        let target = test_node(NodeKind::Command, "target");
        let control_only = test_node(NodeKind::Command, "control-only");
        for node in [&source, &middle, &target, &control_only] {
            graph.add_node(node.clone());
        }
        graph.add_edge(Edge::simple(
            EdgeKind::Data,
            source.id.clone(),
            middle.id.clone(),
        ));
        graph.add_edge(Edge::simple(
            EdgeKind::Read,
            middle.id.clone(),
            target.id.clone(),
        ));
        graph.add_edge(Edge::simple(
            EdgeKind::Control,
            source.id.clone(),
            control_only.id.clone(),
        ));
        graph.finalize();

        let dataflow = Dataflow::solve(&graph);
        assert!(dataflow.complete);
        assert!(dataflow.at(&source).is_untrusted());
        assert!(dataflow.at(&middle).is_untrusted());
        assert!(dataflow.at(&target).is_untrusted());
        assert!(!dataflow.at(&control_only).is_untrusted());
        assert_eq!(
            data_trace(&graph, &GraphIndex::new(&graph), &dataflow, &target)
                .iter()
                .map(|hop| hop.label.as_str())
                .collect::<Vec<_>>(),
            vec!["untrusted source", "data flow", "command sink"]
        );

        let mut direct_graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut direct_target = test_command("echo $UNTRUSTED");
        direct_target.attributes.insert(
            "input".to_owned(),
            test_value("untrusted", Trust::Untrusted, Secrecy::Public),
        );
        direct_graph.add_node(direct_target.clone());
        let direct_dataflow = Dataflow::solve(&direct_graph);
        assert_eq!(
            data_trace(
                &direct_graph,
                &GraphIndex::new(&direct_graph),
                &direct_dataflow,
                &direct_target,
            )
            .iter()
            .map(|hop| hop.label.as_str())
            .collect::<Vec<_>>(),
            vec!["command sink contains untrusted data"]
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table-driven contract covers the shell lexer and its derived effects"
    )]
    fn shell_lexing_expansion_boundaries_and_effects_are_exact() {
        assert_eq!(
            script_tokens(r#"plain '$QUOTED' "escaped \"$DOUBLE" tail"#),
            vec![
                ScriptToken {
                    text: "plain".to_owned(),
                    quoted: false,
                },
                ScriptToken {
                    text: "$QUOTED".to_owned(),
                    quoted: true,
                },
                ScriptToken {
                    text: "escaped \"$DOUBLE".to_owned(),
                    quoted: true,
                },
                ScriptToken {
                    text: "tail".to_owned(),
                    quoted: false,
                },
            ]
        );

        let tokens = vec![
            ScriptToken {
                text: "$POSIX".to_owned(),
                quoted: false,
            },
            ScriptToken {
                text: "`command`".to_owned(),
                quoted: true,
            },
            ScriptToken {
                text: "%CMD%".to_owned(),
                quoted: false,
            },
            ScriptToken {
                text: "!DELAYED!".to_owned(),
                quoted: false,
            },
        ];
        assert_eq!(
            script_expansions(&ScriptShell::Bash, &tokens),
            vec![
                ScriptExpansion {
                    text: "$POSIX".to_owned(),
                    quoted: false,
                },
                ScriptExpansion {
                    text: "`command`".to_owned(),
                    quoted: true,
                },
            ]
        );
        assert_eq!(
            script_expansions(&ScriptShell::Cmd, &tokens),
            vec![
                ScriptExpansion {
                    text: "%CMD%".to_owned(),
                    quoted: false,
                },
                ScriptExpansion {
                    text: "!DELAYED!".to_owned(),
                    quoted: false,
                },
            ]
        );
        assert!(
            script_expansions(
                &ScriptShell::Cmd,
                &[
                    ScriptToken {
                        text: "%".to_owned(),
                        quoted: false,
                    },
                    ScriptToken {
                        text: "!".to_owned(),
                        quoted: false,
                    },
                ],
            )
            .is_empty()
        );
        assert!(script_expansions(&ScriptShell::Python, &tokens).is_empty());

        assert!(shell_identifier_byte(b'a'));
        assert!(shell_identifier_byte(b'0'));
        assert!(shell_identifier_byte(b'_'));
        assert!(!shell_identifier_byte(b'A'));
        assert!(!shell_identifier_byte(b'-'));
        assert!(bounded_variable("$token-suffix", "$token"));
        assert!(!bounded_variable("$token_suffix", "$token"));
        assert!(!bounded_variable("prefix $token_suffix", "$token"));
        assert!(bounded_variable("$other $token", "$token"));
        assert!(expansion_mentions("TOKEN", "$TOKEN"));
        assert!(expansion_mentions("TOKEN", "$env:TOKEN"));
        assert!(expansion_mentions("TOKEN", "${TOKEN}"));
        assert!(expansion_mentions("TOKEN", "${env:TOKEN}"));
        assert!(expansion_mentions("TOKEN", "%TOKEN%"));
        assert!(expansion_mentions("TOKEN", "!TOKEN!"));
        assert!(!expansion_mentions("TOKEN", "$TOKEN_SUFFIX"));

        let all_effects = inferred_effects(&test_command(
            "curl https://example.test > .github/workflows/release.yml; git push; terraform apply",
        ));
        assert_eq!(
            all_effects,
            vec![
                ObservableEffect::RepositoryChange,
                ObservableEffect::NetworkRequest,
                ObservableEffect::FileWrite,
                ObservableEffect::CommandExecution,
                ObservableEffect::DeploymentChange,
                ObservableEffect::WorkflowChange,
            ]
        );
        assert_eq!(
            inferred_effects(&test_command("printf harmless")),
            vec![ObservableEffect::CommandExecution]
        );
        for source in [
            "git push origin HEAD",
            "gh pr merge 1",
            "gh release create v1",
        ] {
            assert!(
                inferred_effects(&test_command(source))
                    .contains(&ObservableEffect::RepositoryChange),
                "missing repository effect for {source:?}"
            );
        }
        assert!(
            !inferred_effects(&test_command("cat .github/workflows/ci.yml"))
                .contains(&ObservableEffect::WorkflowChange)
        );
        assert!(
            !inferred_effects(&test_command("printf changed > ordinary.txt"))
                .contains(&ObservableEffect::WorkflowChange)
        );
    }

    #[test]
    fn secret_source_sink_markers_and_observability_do_not_cross_command_groups() {
        for source in [
            "echo $SECRET",
            "printf %s %TOKEN%",
            "write-output !PASSWORD!",
            "console.log(process.env.PRIVATE_KEY)",
            "print(os.getenv('ACCESS_KEY'))",
            "echo $CREDENTIAL",
            "use secrets.token",
            "read environ['password']",
            "read getenv('passwd')",
        ] {
            assert!(
                secret_reference(source),
                "missing secret marker in {source:?}"
            );
        }
        for source in ["echo secret", "echo $PUBLIC", "tokenize $VALUE"] {
            assert!(
                !secret_reference(source),
                "false secret marker in {source:?}"
            );
        }
        for source in [
            "echo value",
            "printf value",
            "write-output value",
            "print(value)",
        ] {
            assert!(output_command(source));
        }
        assert!(!output_command("cat value"));
        for source in [
            "curl https://example.test",
            "wget https://example.test",
            "invoke-restmethod https://example.test",
            "requests.get(url)",
            "fetch(url)",
        ] {
            assert!(network_command(source));
        }
        assert!(!network_command("echo offline"));

        assert_eq!(
            secret_observability(&ScriptShell::Bash, "echo $TOKEN"),
            (false, true, Vec::new())
        );
        assert_eq!(
            secret_observability(&ScriptShell::Bash, "echo $TOKEN > private.txt"),
            (false, false, Vec::new())
        );
        assert_eq!(
            secret_observability(
                &ScriptShell::Bash,
                "echo setup; curl -H 'Authorization: Bearer '$TOKEN https://example.test",
            ),
            (true, false, Vec::new())
        );
        assert_eq!(
            secret_observability(&ScriptShell::Bash, "echo $TOKEN | base64"),
            (false, true, Vec::new())
        );
        assert!(matches!(
            secret_observability(&ScriptShell::Bash, "echo $TOKEN | custom-filter"),
            (false, false, reasons)
                if reasons == vec![UnknownReason::UnsupportedSyntax(
                    "unresolved pipeline stdout behavior".to_owned()
                )]
        ));
        assert_eq!(
            secret_observability(&ScriptShell::Bash, "echo setup; echo $TOKEN > private.txt"),
            (false, false, Vec::new())
        );
    }

    #[test]
    fn capability_effect_matching_is_exhaustive_and_least_privilege_preserving() {
        let non_privileged = [
            Capability::RepositoryRead,
            Capability::TokenRead,
            Capability::FilesystemRead,
            Capability::Shell,
        ];
        for capability in non_privileged {
            assert!(!privileged_capability(capability));
            assert!(permission_capability_matches(capability, &BTreeSet::new()));
        }

        let cases: &[(Capability, &[ObservableEffect])] = &[
            (
                Capability::RepositoryWrite,
                &[ObservableEffect::RepositoryChange],
            ),
            (
                Capability::RepositoryWrite,
                &[ObservableEffect::WorkflowChange],
            ),
            (
                Capability::TokenWrite,
                &[ObservableEffect::RepositoryChange],
            ),
            (Capability::Oidc, &[ObservableEffect::DeploymentChange]),
            (Capability::Oidc, &[ObservableEffect::CredentialUse]),
            (
                Capability::CloudCredential,
                &[ObservableEffect::DeploymentChange],
            ),
            (
                Capability::CloudCredential,
                &[ObservableEffect::CredentialUse],
            ),
            (Capability::SecretAccess, &[ObservableEffect::CredentialUse]),
            (Capability::Network, &[ObservableEffect::NetworkRequest]),
            (Capability::FilesystemWrite, &[ObservableEffect::FileWrite]),
            (
                Capability::FilesystemWrite,
                &[ObservableEffect::WorkflowChange],
            ),
            (
                Capability::ArtifactRead,
                &[ObservableEffect::ArtifactPublish],
            ),
            (
                Capability::ArtifactWrite,
                &[ObservableEffect::ArtifactPublish],
            ),
            (Capability::CacheRead, &[ObservableEffect::CachePublish]),
            (Capability::CacheWrite, &[ObservableEffect::CachePublish]),
            (
                Capability::Deployment,
                &[ObservableEffect::DeploymentChange],
            ),
            (
                Capability::SelfHostedPersistence,
                &[ObservableEffect::FileWrite],
            ),
            (
                Capability::SelfHostedPersistence,
                &[ObservableEffect::WorkflowChange],
            ),
            (Capability::AiTool, &[ObservableEffect::AiAgentExecution]),
        ];
        for (capability, effects) in cases {
            assert!(privileged_capability(*capability));
            assert!(
                permission_capability_matches(*capability, &effects.iter().copied().collect()),
                "{capability:?} must match {effects:?}"
            );
            assert!(
                !permission_capability_matches(*capability, &BTreeSet::new()),
                "{capability:?} must not match an empty effect set"
            );
        }
    }

    #[test]
    fn authorization_gate_trust_and_environment_uncertainty_are_explicit() {
        let trusted_value =
            AbstractValue::string_constant("manual", Trust::Trusted, Secrecy::Public, Vec::new());
        let untrusted_value =
            AbstractValue::string_constant("manual", Trust::Untrusted, Secrecy::Public, Vec::new());
        let mut trusted = test_node(NodeKind::Gate, "trusted");
        trusted
            .attributes
            .insert("mechanism".to_owned(), trusted_value);
        let mut untrusted = test_node(NodeKind::Gate, "untrusted");
        untrusted
            .attributes
            .insert("mechanism".to_owned(), untrusted_value);
        let mut protected = test_node(NodeKind::Gate, "protected");
        protected.condition = Condition::atom("github.ref_protected");
        let mut circle = test_node(NodeKind::Gate, "approval:release");
        circle.provider = Provider::Circleci;
        let github_named_approval = test_node(NodeKind::Gate, "approval:release");
        let unrelated_condition = {
            let mut node = test_node(NodeKind::Gate, "condition");
            node.condition = Condition::atom("github.actor");
            node
        };
        let unrelated = test_node(NodeKind::Gate, "reviewed");

        for gate in [
            &trusted,
            &untrusted,
            &protected,
            &circle,
            &github_named_approval,
            &unrelated_condition,
            &unrelated,
        ] {
            let mut graph = Graph::empty(gate.provider, TEST_SOURCE);
            graph.add_node(gate.clone());
            let dataflow = Dataflow::solve(&graph);
            let expected = matches!(gate.name.as_str(), "trusted" | "protected")
                || (gate.provider == Provider::Circleci && gate.name == "approval:release");
            assert_eq!(trusted_authorization_gate(gate, &dataflow), expected);
        }

        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let environment = Node::new(
            Provider::Github,
            NodeKind::Resource,
            "environment:production",
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            Some(UnknownReason::ExternalState(
                "production protection".to_owned(),
            )),
        );
        let unrelated_environment = test_node(NodeKind::Resource, "environment:staging");
        let sink = test_node(NodeKind::Command, "deploy");
        for node in [&environment, &unrelated_environment, &sink] {
            graph.add_node(node.clone());
        }
        graph.add_edge(Edge::simple(
            EdgeKind::Grant,
            environment.id.clone(),
            sink.id.clone(),
        ));
        graph.finalize();
        assert_eq!(
            environment_authorization_reasons(&graph, &GraphIndex::new(&graph), &sink),
            vec![UnknownReason::ExternalState(
                "production protection".to_owned()
            )]
        );
    }

    #[test]
    fn local_reference_normalization_accepts_only_unambiguous_local_yaml_targets() {
        let cases = [
            ("./action", Some("./action")),
            ("../shared/action", Some("../shared/action")),
            (
                ".github/workflows/reuse.yml",
                Some(".github/workflows/reuse.yml"),
            ),
            ("child:./action@local", Some("./action")),
            ("workflow.yaml", Some("workflow.yaml")),
            ("workflow.YML", Some("workflow.YML")),
            ("owner/action@revision", None),
            ("@scope/action", None),
            ("workflow.json", None),
        ];
        for (input, expected) in cases {
            assert_eq!(local_reference(input).as_deref(), expected, "{input:?}");
        }
        assert!(yaml_reference("nested/workflow.yml"));
        assert!(yaml_reference("nested/workflow.YAML"));
        assert!(!yaml_reference("nested/workflow.yml.txt"));
        assert_eq!(
            normalize_relative("jobs/./nested/../action.yml").as_deref(),
            Some("jobs/action.yml")
        );
        assert_eq!(normalize_relative("../escape.yml"), None);
        assert_eq!(normalize_relative("jobs/../../escape.yml"), None);

        let mut caller = Graph::empty(Provider::Github, "jobs/caller.yml");
        let call = test_node(NodeKind::Call, "./action/action.yml");
        caller.add_node(call.clone());
        let target = Graph::empty(Provider::Github, "jobs/action/action.yml");
        assert_eq!(
            local_call_target(&[caller.clone(), target.clone()], &caller, &call)
                .map(|graph| graph.source.as_str()),
            Some("jobs/action/action.yml")
        );

        let duplicate = target.clone();
        assert!(
            local_call_target(&[caller.clone(), target, duplicate], &caller, &call).is_none(),
            "ambiguous local targets must fail closed"
        );
    }

    #[test]
    fn script_summary_preserves_each_provider_substitution_and_shell_unknown() {
        let summarize = |source: &str, shell: &str| {
            let mut node = test_command(source);
            node.attributes.insert(
                "shell".to_owned(),
                test_value(shell, Trust::Trusted, Secrecy::Public),
            );
            script_summary(&node)
        };

        let safe = summarize("printf '%s' \"$TOKEN\"", "bash");
        assert!(!safe.unsafe_interpolation);
        assert_eq!(
            safe.expansions,
            vec![ScriptExpansion {
                text: "$TOKEN".to_owned(),
                quoted: true,
            }]
        );
        for source in [
            "echo ${{ inputs.value }}",
            "echo << pipeline.value >>",
            "echo $[variables.value]",
        ] {
            assert!(
                summarize(source, "bash").unsafe_interpolation,
                "provider substitution must be unsafe in {source:?}"
            );
        }
        assert!(summarize("eval(user_input)", "python").unsafe_interpolation);
        assert!(summarize("exec(user_input)", "python3").unsafe_interpolation);
        assert!(!summarize("print(user_input)", "python").unsafe_interpolation);
        assert!(summarize("write-output $(get-value)", "pwsh").unsafe_interpolation);
        assert!(summarize("write-output '$(get-value)'", "pwsh").unsafe_interpolation);
        assert!(summarize("echo \"$(value)\"", "cmd").unsafe_interpolation);
        assert!(!summarize("echo '$(value)'", "bash").unsafe_interpolation);

        let unknown = summarize("use $TOKEN", "fish");
        assert_eq!(
            unknown.unknowns,
            vec![UnknownReason::UnsupportedSyntax("shell fish".to_owned())]
        );
    }

    #[test]
    fn program_composition_links_local_entrypoints_and_avoids_same_file_recursion() {
        let mut caller = Graph::empty(Provider::Github, "workflows/ci.yml");
        let mut call = Node::new(
            Provider::Github,
            NodeKind::Call,
            "local action",
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::from([(
                "dependency.revision".to_owned(),
                test_value(
                    "local:actions/build/action.yml",
                    Trust::Trusted,
                    Secrecy::Public,
                ),
            )]),
            [],
            [],
            Some(UnknownReason::UnresolvedDependency(
                "local action".to_owned(),
            )),
        );
        caller.add_node(call.clone());

        let mut target = Graph::empty(Provider::Github, "actions/build/action.yml");
        let entrypoint = test_node(NodeKind::Step, "local entrypoint");
        target.add_node(entrypoint.clone());
        target.add_entrypoint(entrypoint.id.clone());
        let program = compose_program(&[caller, target]);
        call.unknown = None;
        assert_eq!(
            program
                .nodes
                .iter()
                .find(|node| node.id == call.id)
                .and_then(|node| node.unknown.as_ref()),
            None
        );
        for kind in [EdgeKind::Call, EdgeKind::Control] {
            assert!(program.edges.iter().any(|edge| {
                edge.kind == kind && edge.from == call.id && edge.to == entrypoint.id
            }));
        }

        let mut same_file = Graph::empty(Provider::Github, "action.yml");
        let mut recursive_call = Node::new(
            Provider::Github,
            NodeKind::Call,
            "self",
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::from([(
                "dependency.revision".to_owned(),
                test_value("local:action.yml", Trust::Trusted, Secrecy::Public),
            )]),
            [],
            [],
            Some(UnknownReason::RecursiveCall("action.yml".to_owned())),
        );
        let same_entrypoint = test_node(NodeKind::Step, "same-file entrypoint");
        same_file.add_node(recursive_call.clone());
        same_file.add_node(same_entrypoint.clone());
        same_file.add_entrypoint(same_entrypoint.id.clone());
        let same_program = compose_program(&[same_file]);
        recursive_call.unknown = None;
        assert_eq!(
            same_program
                .nodes
                .iter()
                .find(|node| node.id == recursive_call.id)
                .and_then(|node| node.unknown.as_ref()),
            None
        );
        assert!(
            !same_program
                .edges
                .iter()
                .any(|edge| { edge.from == recursive_call.id && edge.to == same_entrypoint.id })
        );
    }

    #[test]
    fn program_composition_does_not_invent_cross_file_resource_edges() {
        let mut producer = Graph::empty(Provider::Github, "producer.yml");
        let legitimate_writer = test_node_in("producer.yml", NodeKind::Resource, "legitimate");
        let producer_step = test_node_in("producer.yml", NodeKind::Step, "producer step");
        let unwritten_resource = test_node_in("producer.yml", NodeKind::Resource, "writer-filter");
        let written_non_resource = test_node_in("producer.yml", NodeKind::Job, "writer-filter");
        let reader_filter_writer =
            test_node_in("producer.yml", NodeKind::Resource, "reader-filter");
        for node in [
            &legitimate_writer,
            &producer_step,
            &unwritten_resource,
            &written_non_resource,
            &reader_filter_writer,
        ] {
            producer.add_node(node.clone());
        }
        for target in [
            &legitimate_writer,
            &written_non_resource,
            &reader_filter_writer,
        ] {
            producer.add_edge(Edge::simple(
                EdgeKind::Write,
                producer_step.id.clone(),
                target.id.clone(),
            ));
        }

        let mut consumer = Graph::empty(Provider::Github, "consumer.yml");
        let legitimate_reader = test_node_in("consumer.yml", NodeKind::Resource, "legitimate");
        let writer_filter_reader =
            test_node_in("consumer.yml", NodeKind::Resource, "writer-filter");
        let unwritten_reader = test_node_in("consumer.yml", NodeKind::Resource, "reader-filter");
        let read_non_resource = test_node_in("consumer.yml", NodeKind::Job, "reader-filter");
        let consumer_step = test_node_in("consumer.yml", NodeKind::Step, "consumer step");
        for node in [
            &legitimate_reader,
            &writer_filter_reader,
            &unwritten_reader,
            &read_non_resource,
            &consumer_step,
        ] {
            consumer.add_node(node.clone());
        }
        for source in [
            &legitimate_reader,
            &writer_filter_reader,
            &read_non_resource,
        ] {
            consumer.add_edge(Edge::simple(
                EdgeKind::Read,
                source.id.clone(),
                consumer_step.id.clone(),
            ));
        }

        let program = compose_program(&[producer, consumer]);
        assert_eq!(
            program
                .edges
                .iter()
                .filter(|edge| edge.label.as_deref() == Some("cross-file resource"))
                .map(|edge| (edge.from.as_str(), edge.to.as_str()))
                .collect::<Vec<_>>(),
            vec![(legitimate_writer.id.as_str(), legitimate_reader.id.as_str(),)]
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one contract compares all supply and permission outcomes"
    )]
    fn supply_and_permission_rules_cover_locked_mutable_used_and_unknown_cases() {
        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mutable = test_node(NodeKind::Call, "owner/action@main");
        let local = test_node(NodeKind::Call, "./local-action");
        let immutable = test_node(
            NodeKind::Call,
            "owner/action@0123456789abcdef0123456789abcdef01234567",
        );
        let mut locked = test_node(NodeKind::Call, "owner/action@main-locked");
        locked.attributes.insert(
            "dependency.digest".to_owned(),
            test_value(
                &format!("sha256:{}", sha256_hex("locked dependency")),
                Trust::Trusted,
                Secrecy::Public,
            ),
        );
        let mut invalid_digest = test_node(NodeKind::Call, "owner/action@invalid-digest");
        invalid_digest.attributes.insert(
            "dependency.digest".to_owned(),
            test_value("not-a-content-digest", Trust::Trusted, Secrecy::Public),
        );
        let mut empty_digest_set = test_node(NodeKind::Call, "owner/action@empty-digest-set");
        empty_digest_set.attributes.insert(
            "dependency.digest".to_owned(),
            AbstractValue {
                value_type: workflow_verifier_domain::ValueType::String,
                value: Value::String(
                    workflow_verifier_domain::abstract_value::StringValue::Constants(Vec::new()),
                ),
                trust: Trust::Trusted,
                secrecy: Secrecy::Public,
                provenance: Vec::new(),
            },
        );
        for node in [
            &mutable,
            &local,
            &immutable,
            &locked,
            &invalid_digest,
            &empty_digest_set,
        ] {
            graph.add_node(node.clone());
        }
        let result = verify(Persona::Gate, &graph);
        assert_eq!(state(&result, "WV-SUPPLY-001"), &PropertyState::Violated);
        assert_eq!(
            result
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.rule_id == "WV-SUPPLY-001")
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "dependency is not pinned to immutable content: owner/action@empty-digest-set",
                "dependency is not pinned to immutable content: owner/action@invalid-digest",
                "dependency is not pinned to immutable content: owner/action@main",
            ])
        );

        let mut used = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut owner = test_node(NodeKind::Workflow, "used-network");
        owner.capabilities = vec![Capability::Network];
        let network = test_command("curl https://example.test");
        used.add_node(owner.clone());
        used.add_node(network.clone());
        used.add_entrypoint(owner.id.clone());
        used.add_edge(Edge::simple(
            EdgeKind::Control,
            owner.id.clone(),
            network.id.clone(),
        ));
        used.finalize();
        assert_eq!(
            state(&verify(Persona::Gate, &used), "WV-PERM-001"),
            &PropertyState::Proved
        );

        let mut excessive = Graph::empty(Provider::Github, TEST_SOURCE);
        excessive.add_node(owner.clone());
        assert_eq!(
            state(&verify(Persona::Gate, &excessive), "WV-PERM-001"),
            &PropertyState::Violated
        );

        let mut unresolved = Graph::empty(Provider::Github, TEST_SOURCE);
        let unknown = Node::new(
            Provider::Github,
            NodeKind::Call,
            "unknown work",
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            Some(UnknownReason::MissingEvidence("call summary".to_owned())),
        );
        unresolved.add_node(owner.clone());
        unresolved.add_node(unknown.clone());
        unresolved.add_edge(Edge::simple(EdgeKind::Control, owner.id, unknown.id));
        unresolved.finalize();
        assert_eq!(
            state(&verify(Persona::Gate, &unresolved), "WV-PERM-001"),
            &PropertyState::Unknown(vec![UnknownReason::MissingEvidence(
                "call summary".to_owned()
            )])
        );
    }

    #[test]
    fn a_known_secret_reaching_a_network_capable_call_is_a_violation() {
        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut call = test_node(NodeKind::Call, "owner/uploader@revision");
        call.capabilities = vec![Capability::Network, Capability::SecretAccess];
        call.attributes.insert(
            "token".to_owned(),
            test_value("secret", Trust::Trusted, Secrecy::Secret),
        );
        graph.add_node(call);

        let result = verify(Persona::Gate, &graph);
        assert_eq!(state(&result, "WV-SEC-002"), &PropertyState::Violated);
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.rule_id == "WV-SEC-002"
                && diagnostic.capabilities.contains(&Capability::Network)
        }));
    }

    #[test]
    fn an_explicit_credential_transport_is_not_secret_exfiltration() {
        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut call = test_node(NodeKind::Call, "docker/login-action@revision");
        call.capabilities = vec![Capability::Network, Capability::SecretAccess];
        call.effects = vec![ObservableEffect::CredentialUse];
        call.attributes.insert(
            "password".to_owned(),
            test_value("secret", Trust::Trusted, Secrecy::Secret),
        );
        graph.add_node(call);

        let result = verify(Persona::Gate, &graph);
        assert_eq!(state(&result, "WV-SEC-002"), &PropertyState::Proved);
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.rule_id != "WV-SEC-002")
        );
    }

    #[test]
    // Every secret sink and the non-sink uncertainty cases form one rule
    // decision table and are intentionally reviewed together.
    #[allow(clippy::too_many_lines)]
    fn secret_rule_distinguishes_each_sink_shape_and_uncertain_non_sink() {
        let secret = test_value("secret", Trust::Trusted, Secrecy::Secret);
        let mut command = test_command("echo $TOKEN");
        command
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut effect_sink = test_node(NodeKind::Resource, "network effect");
        effect_sink.effects = vec![ObservableEffect::NetworkRequest];
        effect_sink
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut parsed_network = test_command("curl $TOKEN https://example.test");
        parsed_network
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut declared_network = test_command("use $TOKEN through declared effect");
        declared_network.effects = vec![ObservableEffect::NetworkRequest];
        declared_network
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut capable_network = test_command("use $TOKEN through capability");
        capable_network.capabilities.push(Capability::Network);
        capable_network
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut call_without_network = test_node(NodeKind::Call, "local secret consumer");
        call_without_network
            .attributes
            .insert("token".to_owned(), secret.clone());
        let mut resource_with_capability = test_node(NodeKind::Resource, "network capability");
        resource_with_capability.capabilities = vec![Capability::Network];
        resource_with_capability
            .attributes
            .insert("token".to_owned(), secret.clone());
        let uncertain_reason = UnknownReason::MissingEvidence("opaque resource".to_owned());
        let uncertain_non_sink = Node::new(
            Provider::Github,
            NodeKind::Resource,
            "uncertain local resource",
            workflow_verifier_domain::Phase::Run,
            test_span(),
            Condition::True,
            BTreeMap::new(),
            [],
            [],
            Some(uncertain_reason),
        );
        let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
        for node in [
            &command,
            &effect_sink,
            &parsed_network,
            &declared_network,
            &capable_network,
            &call_without_network,
            &resource_with_capability,
            &uncertain_non_sink,
        ] {
            graph.add_node(node.clone());
        }
        let result = verify(Persona::Gate, &graph);
        assert_eq!(state(&result, "WV-SEC-002"), &PropertyState::Violated);
        let diagnostics: Vec<_> = result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.rule_id == "WV-SEC-002")
            .collect();
        assert_eq!(
            diagnostics.len(),
            [
                &command,
                &effect_sink,
                &parsed_network,
                &declared_network,
                &capable_network,
            ]
            .len()
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.capabilities.contains(&Capability::Shell)
                && !diagnostic.capabilities.contains(&Capability::Network)
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.capabilities.contains(&Capability::Network)
                && !diagnostic.capabilities.contains(&Capability::Shell)
        }));

        let secrecy_reason = UnknownReason::ExternalState("secret classification".to_owned());
        let mut uncertain_output = test_command("echo $TOKEN");
        uncertain_output.attributes.insert(
            "token".to_owned(),
            AbstractValue {
                value_type: workflow_verifier_domain::ValueType::String,
                value: Value::String(
                    workflow_verifier_domain::abstract_value::StringValue::Constants(vec![
                        "token".to_owned(),
                    ]),
                ),
                trust: Trust::Trusted,
                secrecy: Secrecy::Unknown(vec![secrecy_reason.clone()]),
                provenance: Vec::new(),
            },
        );
        let mut uncertain_graph = Graph::empty(Provider::Github, TEST_SOURCE);
        uncertain_graph.add_node(uncertain_output);
        assert_eq!(
            state(&verify(Persona::Gate, &uncertain_graph), "WV-SEC-002"),
            &PropertyState::Unknown(vec![secrecy_reason])
        );

        let shell_reason = UnknownReason::UnsupportedSyntax("shell fish".to_owned());
        for (secrecy, expected) in [
            (
                Secrecy::Secret,
                PropertyState::Unknown(vec![shell_reason.clone()]),
            ),
            (Secrecy::Public, PropertyState::Proved),
        ] {
            let mut unknown_shell = test_command("use $TOKEN");
            unknown_shell.attributes.insert(
                "shell".to_owned(),
                test_value("fish", Trust::Trusted, Secrecy::Public),
            );
            unknown_shell.attributes.insert(
                "token".to_owned(),
                test_value("token", Trust::Trusted, secrecy),
            );
            let mut shell_graph = Graph::empty(Provider::Github, TEST_SOURCE);
            shell_graph.add_node(unknown_shell);
            assert_eq!(
                state(&verify(Persona::Gate, &shell_graph), "WV-SEC-002"),
                &expected
            );
        }

        let missing = UnknownReason::MissingEvidence("network behavior".to_owned());
        for (capabilities, expected) in [
            (
                vec![Capability::Network],
                PropertyState::Unknown(vec![missing.clone()]),
            ),
            (Vec::new(), PropertyState::Proved),
        ] {
            let mut sink = Node::new(
                Provider::Github,
                NodeKind::Resource,
                "uncertain network effect",
                workflow_verifier_domain::Phase::Run,
                test_span(),
                Condition::True,
                BTreeMap::new(),
                capabilities,
                [ObservableEffect::NetworkRequest],
                Some(missing.clone()),
            );
            sink.attributes.insert(
                "value".to_owned(),
                test_value("public", Trust::Trusted, Secrecy::Public),
            );
            let mut sink_graph = Graph::empty(Provider::Github, TEST_SOURCE);
            sink_graph.add_node(sink);
            assert_eq!(
                state(&verify(Persona::Gate, &sink_graph), "WV-SEC-002"),
                &expected
            );
        }
    }

    #[test]
    fn credential_ai_and_self_rule_filters_fail_closed_without_false_candidates() {
        let secret = test_value("secret", Trust::Trusted, Secrecy::Secret);
        let mut persistence_command = test_command("persistent command");
        persistence_command.capabilities = vec![Capability::SelfHostedPersistence];
        persistence_command
            .attributes
            .insert("credential".to_owned(), secret.clone());
        let mut ordinary_call = test_node(NodeKind::Call, "ordinary call");
        ordinary_call
            .attributes
            .insert("credential".to_owned(), secret);
        let mut credential_graph = Graph::empty(Provider::Github, TEST_SOURCE);
        credential_graph.add_node(persistence_command);
        credential_graph.add_node(ordinary_call);
        assert_eq!(
            state(&verify(Persona::Gate, &credential_graph), "WV-CRED-001"),
            &PropertyState::NotApplicable
        );

        let agent = |name: &str,
                     trust: Trust,
                     capabilities: Vec<Capability>,
                     effects: Vec<ObservableEffect>| {
            let mut node = test_node(NodeKind::Call, name);
            node.capabilities = capabilities;
            node.effects = effects;
            node.attributes.insert(
                "prompt".to_owned(),
                test_value("prompt", trust, Secrecy::Public),
            );
            node
        };
        let trusted_network = agent(
            "openai trusted",
            Trust::Trusted,
            vec![Capability::Network],
            Vec::new(),
        );
        let isolated_untrusted = agent("claude isolated", Trust::Untrusted, Vec::new(), Vec::new());
        let effect_agent = agent(
            "semantic executor",
            Trust::Trusted,
            Vec::new(),
            vec![ObservableEffect::AiAgentExecution],
        );
        let tool_agent = agent(
            "semantic tool",
            Trust::Untrusted,
            vec![Capability::AiTool],
            Vec::new(),
        );
        let unrelated_call = agent(
            "ordinary call",
            Trust::Untrusted,
            vec![Capability::Network],
            Vec::new(),
        );
        let mut named_resource = test_node(NodeKind::Resource, "openai configuration");
        named_resource.capabilities = vec![Capability::Network];
        named_resource.attributes.insert(
            "prompt".to_owned(),
            test_value("prompt", Trust::Untrusted, Secrecy::Public),
        );
        let mut ai_graph = Graph::empty(Provider::Github, TEST_SOURCE);
        for node in [
            &trusted_network,
            &isolated_untrusted,
            &effect_agent,
            &tool_agent,
            &unrelated_call,
            &named_resource,
        ] {
            ai_graph.add_node(node.clone());
        }
        let ai_result = verify(Persona::Gate, &ai_graph);
        assert_eq!(state(&ai_result, "WV-AI-001"), &PropertyState::Violated);
        assert_eq!(
            ai_result
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.rule_id == "WV-AI-001")
                .map(|diagnostic| diagnostic.span.clone())
                .collect::<Vec<_>>()
                .len(),
            [tool_agent].len()
        );

        let mut self_graph = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut owner = test_node(NodeKind::Workflow, "write grant");
        owner.capabilities = vec![Capability::RepositoryWrite];
        let harmless_command = test_command("printf harmless");
        let mut non_command_rewrite = test_node(NodeKind::Call, "rewrite metadata");
        non_command_rewrite.effects = vec![ObservableEffect::WorkflowChange];
        for node in [&owner, &harmless_command, &non_command_rewrite] {
            self_graph.add_node(node.clone());
        }
        assert_eq!(
            state(&verify(Persona::Gate, &self_graph), "WV-SELF-001"),
            &PropertyState::Proved
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table-driven contract compares the remaining verifier rule outcomes"
    )]
    fn integrity_toctou_credential_ai_and_self_modification_rules_reach_each_outcome() {
        let privileged_sink = || {
            let mut node = test_command("git push origin HEAD");
            node.effects = vec![ObservableEffect::RepositoryChange];
            node
        };

        for (resource_name, rule_id) in [
            ("artifact:bundle", "WV-ARTIFACT-001"),
            ("cache:build", "WV-CACHE-001"),
        ] {
            let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
            let mut resource = test_node(NodeKind::Resource, resource_name);
            resource.attributes.insert(
                "value".to_owned(),
                test_value("attacker controlled", Trust::Untrusted, Secrecy::Public),
            );
            let sink = privileged_sink();
            graph.add_node(resource.clone());
            graph.add_node(sink.clone());
            graph.add_edge(Edge::simple(EdgeKind::Data, resource.id, sink.id));
            graph.finalize();
            let result = verify(Persona::Gate, &graph);
            assert_eq!(state(&result, rule_id), &PropertyState::Violated);
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.rule_id == rule_id)
            );
        }

        for (capability, rule_id) in [
            (Capability::ArtifactRead, "WV-ARTIFACT-001"),
            (Capability::CacheWrite, "WV-CACHE-001"),
        ] {
            let mut graph = Graph::empty(Provider::Github, TEST_SOURCE);
            let mut resource = test_node(NodeKind::Resource, "semantic resource");
            resource.capabilities = vec![capability];
            graph.add_node(resource);
            assert_eq!(
                state(&verify(Persona::Gate, &graph), rule_id),
                &PropertyState::Proved
            );
        }
        let mut non_resource = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut artifact_named_call = test_node(NodeKind::Call, "artifact:bundle");
        artifact_named_call.capabilities = vec![Capability::ArtifactRead];
        non_resource.add_node(artifact_named_call);
        assert_eq!(
            state(&verify(Persona::Gate, &non_resource), "WV-ARTIFACT-001"),
            &PropertyState::NotApplicable
        );

        let mut toctou = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut checkout = test_node(NodeKind::Call, "actions/checkout@main");
        checkout.attributes.insert(
            "ref".to_owned(),
            test_value("pull request head", Trust::Untrusted, Secrecy::Public),
        );
        let sink = privileged_sink();
        toctou.add_node(checkout.clone());
        toctou.add_node(sink.clone());
        toctou.add_edge(Edge::simple(EdgeKind::Control, checkout.id, sink.id));
        toctou.finalize();
        assert_eq!(
            state(&verify(Persona::Gate, &toctou), "WV-TOCTOU-001"),
            &PropertyState::Violated
        );

        for (name, trust) in [
            (
                "actions/checkout@0123456789abcdef0123456789abcdef01234567",
                Trust::Untrusted,
            ),
            ("actions/checkout@main", Trust::Trusted),
        ] {
            let mut safe_graph = Graph::empty(Provider::Github, TEST_SOURCE);
            let mut safe_checkout = test_node(NodeKind::Call, name);
            safe_checkout.attributes.insert(
                "ref".to_owned(),
                test_value("selector", trust, Secrecy::Public),
            );
            let safe_sink = privileged_sink();
            safe_graph.add_node(safe_checkout.clone());
            safe_graph.add_node(safe_sink.clone());
            safe_graph.add_edge(Edge::simple(
                EdgeKind::Control,
                safe_checkout.id,
                safe_sink.id,
            ));
            safe_graph.finalize();
            assert_eq!(
                state(&verify(Persona::Gate, &safe_graph), "WV-TOCTOU-001"),
                &PropertyState::Proved
            );
        }
        let mut command_named_checkout = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut non_call = test_command("checkout dynamic workspace");
        non_call.attributes.insert(
            "selector".to_owned(),
            test_value("selector", Trust::Untrusted, Secrecy::Public),
        );
        command_named_checkout.add_node(non_call);
        assert_eq!(
            state(
                &verify(Persona::Gate, &command_named_checkout),
                "WV-TOCTOU-001"
            ),
            &PropertyState::NotApplicable
        );

        let mut credential = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut persistent = test_node(NodeKind::Call, "self-hosted cache");
        persistent.capabilities = vec![Capability::SelfHostedPersistence];
        persistent.attributes.insert(
            "credential".to_owned(),
            test_value("secret", Trust::Trusted, Secrecy::Secret),
        );
        credential.add_node(persistent);
        assert_eq!(
            state(&verify(Persona::Gate, &credential), "WV-CRED-001"),
            &PropertyState::Violated
        );

        let mut ai = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut agent = test_node(NodeKind::Call, "openai agent");
        agent.capabilities = vec![Capability::Network];
        agent.attributes.insert(
            "prompt".to_owned(),
            test_value("untrusted prompt", Trust::Untrusted, Secrecy::Public),
        );
        ai.add_node(agent);
        assert_eq!(
            state(&verify(Persona::Gate, &ai), "WV-AI-001"),
            &PropertyState::Violated
        );

        let mut self_modifying = Graph::empty(Provider::Github, TEST_SOURCE);
        let mut owner = test_node(NodeKind::Workflow, "write grant");
        owner.capabilities = vec![Capability::RepositoryWrite];
        let rewrite = test_command("printf changed > .github/workflows/ci.yml");
        self_modifying.add_node(owner);
        self_modifying.add_node(rewrite);
        assert_eq!(
            state(&verify(Persona::Gate, &self_modifying), "WV-SELF-001"),
            &PropertyState::Violated
        );

        let empty = Graph::empty(Provider::Github, TEST_SOURCE);
        let empty_result = verify(Persona::Gate, &empty);
        for rule_id in [
            "WV-ARTIFACT-001",
            "WV-CACHE-001",
            "WV-TOCTOU-001",
            "WV-CRED-001",
            "WV-AI-001",
            "WV-SELF-001",
        ] {
            assert_eq!(state(&empty_result, rule_id), &PropertyState::NotApplicable);
        }
    }

    #[test]
    fn top_level_split_respects_quotes_escapes_nesting_and_separator_width() {
        let sequence = "echo '$TOKEN;still' && (printf x | cat) || echo one\\;two; echo end";
        assert_eq!(
            split_top_level(sequence, TopLevelSeparator::Sequence),
            vec![
                "echo '$TOKEN;still'",
                "(printf x | cat)",
                "echo one\\;two",
                "echo end",
            ]
        );

        let pipeline = "printf '%s|x' \"$TOKEN\" | base64 | (cat | sed s/x/y/)";
        assert_eq!(
            split_top_level(pipeline, TopLevelSeparator::Pipeline),
            vec!["printf '%s|x' \"$TOKEN\"", "base64", "(cat | sed s/x/y/)",]
        );
        assert_eq!(
            split_top_level(
                "printf \"escaped \\\"; still quoted\"; echo done",
                TopLevelSeparator::Sequence,
            ),
            vec!["printf \"escaped \\\"; still quoted\"", "echo done"]
        );

        assert_eq!(
            separator_width(TopLevelSeparator::Sequence, b";", 0),
            Some(b";".len())
        );
        assert_eq!(
            separator_width(TopLevelSeparator::Sequence, b"&&", 0),
            Some(b"&&".len())
        );
        assert_eq!(
            separator_width(TopLevelSeparator::Sequence, b"||", 0),
            Some(b"||".len())
        );
        assert_eq!(
            separator_width(TopLevelSeparator::Pipeline, b"|", 0),
            Some(b"|".len())
        );
        assert_eq!(separator_width(TopLevelSeparator::Sequence, b"&", 0), None);
        assert_eq!(separator_width(TopLevelSeparator::Sequence, b"|", 0), None);
    }

    #[test]
    fn output_destination_distinguishes_stdout_private_and_unresolved_targets() {
        let stdout = [
            "echo $TOKEN",
            "echo $TOKEN 2>errors.log",
            "echo $TOKEN &>combined.log",
            "echo $TOKEN > /dev/stdout",
            "echo $TOKEN > '/dev/stderr'",
            "echo $TOKEN > /proc/self/fd/1",
            "echo '$TOKEN > private.txt'",
            "echo $TOKEN $(printf '>')",
            "(echo $TOKEN > private.txt)",
            "echo \"escaped \\\" > still quoted\"",
        ];
        for source in stdout {
            assert!(
                matches!(
                    output_destination(&ScriptShell::Bash, source),
                    OutputDestination::StandardOutput
                ),
                "expected stdout for {source:?}"
            );
        }

        for source in [
            "echo $TOKEN > private.txt",
            "echo $TOKEN >> 'private.txt'",
            "(echo nested); echo $TOKEN > private.txt",
        ] {
            assert!(
                matches!(
                    output_destination(&ScriptShell::Bash, source),
                    OutputDestination::PrivateFile
                ),
                "expected a private file for {source:?}"
            );
        }

        for source in [
            "echo $TOKEN >",
            "echo $TOKEN > first > second",
            "echo $TOKEN > two words",
        ] {
            assert!(
                matches!(
                    output_destination(&ScriptShell::Bash, source),
                    OutputDestination::StandardOutput | OutputDestination::Unknown(_)
                ),
                "expected a non-private destination for {source:?}"
            );
        }
        assert!(matches!(
            output_destination(&ScriptShell::Bash, "echo $TOKEN > $TARGET"),
            OutputDestination::Unknown(UnknownReason::DynamicString(_))
        ));
        for source in [
            "echo $TOKEN > %TARGET%",
            "echo $TOKEN > !TARGET!",
            "echo $TOKEN > $target$",
            "echo $TOKEN > 'private$",
        ] {
            assert!(
                matches!(
                    output_destination(&ScriptShell::Bash, source),
                    OutputDestination::Unknown(UnknownReason::DynamicString(_))
                ),
                "expected a dynamic target for {source:?}"
            );
        }
        assert!(matches!(
            output_destination(&ScriptShell::Bash, "echo $TOKEN > first > second"),
            OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(_))
        ));
        assert!(matches!(
            output_destination(&ScriptShell::Bash, "echo $TOKEN > two words"),
            OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(_))
        ));
        assert!(matches!(
            output_destination(&ScriptShell::Python, "print(secret) > file"),
            OutputDestination::StandardOutput
        ));
        assert!(matches!(
            output_destination(
                &ScriptShell::Unknown("fish".to_owned()),
                "echo $TOKEN > file"
            ),
            OutputDestination::Unknown(UnknownReason::UnsupportedSyntax(_))
        ));
    }
}
