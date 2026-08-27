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
        let propagating = [
            EdgeKind::Data,
            EdgeKind::Read,
            EdgeKind::Write,
            EdgeKind::Persist,
        ];
        let limit = graph
            .nodes
            .len()
            .saturating_mul(graph.edges.len().max(1))
            .saturating_add(1);
        let mut changed = true;
        let mut rounds = 0usize;
        while changed && rounds < limit {
            changed = false;
            rounds = rounds.saturating_add(1);
            for edge in graph
                .edges
                .iter()
                .filter(|edge| propagating.contains(&edge.kind))
            {
                let source = values.get(&edge.from).cloned().unwrap_or_default();
                let target = values.get(&edge.to).cloned().unwrap_or_default();
                let joined = target.join(&source);
                if joined != target {
                    values.insert(edge.to.clone(), joined);
                    changed = true;
                }
            }
        }
        Self {
            values,
            complete: !changed,
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
                || text.contains("getenv"))
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
    let mut index = 0usize;
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    while index < bytes.len() {
        let character = bytes[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == b'\\' && delimiter == b'"' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match character {
            b'\\' => escaped = true,
            b'\'' | b'"' => quote = Some(character),
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                if let Some(width) = separator_width(separator, bytes, index) {
                    let part = source[start..index].trim();
                    if !part.is_empty() {
                        parts.push(part);
                    }
                    index += width;
                    start = index;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
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

    let bytes = source.as_bytes();
    let mut redirects = Vec::new();
    let mut index = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    while index < bytes.len() {
        let character = bytes[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == b'\\' && delimiter == b'"' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        match character {
            b'\'' | b'"' => quote = Some(character),
            b'(' => depth = depth.saturating_add(1),
            b')' => depth = depth.saturating_sub(1),
            b'>' if depth == 0 => {
                let descriptor = index
                    .checked_sub(1)
                    .and_then(|value| bytes.get(value))
                    .is_some_and(|previous| {
                        previous.is_ascii_digit() || matches!(previous, b'&' | b'>')
                    });
                let following = bytes.get(index + 1).copied();
                if !descriptor && following != Some(b'=') {
                    let after = index + usize::from(following == Some(b'>')) + 1;
                    redirects.push(after);
                    index = after;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
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
                        if stages.len() > 1 && !output {
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
        let (network, output) = summary.as_ref().map_or_else(
            || {
                (
                    sink.effects.contains(&ObservableEffect::NetworkRequest),
                    false,
                )
            },
            |summary| (summary.secret_to_network, summary.secret_to_output),
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
    let name = match name.find('@') {
        Some(index) if !name.starts_with('@') => &name[..index],
        _ => name,
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
