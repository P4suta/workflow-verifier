#![forbid(unsafe_code)]

//! Re-entrant incremental analysis engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use workflow_verifier_domain::{
    AbstractValue, Graph, NodeKind, Provenance, Provider, Secrecy, Trust, UnknownReason,
};
use workflow_verifier_foundation::{
    Budget, JsonValue, PublicPath, content_digest, portable_path_key, valid_content_digest,
};
use workflow_verifier_frontend::{
    Compilation, DependencyStatus, compile_parsed, detect, entrypoint,
};
use workflow_verifier_product::{
    BuildInfo, Config, ConfigParseOptions, ConfigTrust, DependencySummary, GateResult, Lockfile,
    Report, ReportInput, ReportProvenance, evaluate_policy, link_local,
};
use workflow_verifier_syntax::YamlDocument;
use workflow_verifier_verifier::{
    Confidence, Diagnostic, Persona, Severity, VerificationResult, compose_program, should_fail,
    verify_program,
};

#[derive(Clone, Debug)]
pub struct SourceSnapshot {
    files: Arc<BTreeMap<String, Vec<u8>>>,
    digest: String,
    manifest_digest: String,
}

impl SourceSnapshot {
    /// Create an immutable, collision-checked source snapshot.
    ///
    /// # Errors
    /// Rejects non-portable paths, portable name collisions, and invalid UTF-8
    /// source bytes before any provider parser sees them.
    pub fn new(files: BTreeMap<String, Vec<u8>>) -> Result<Self, AnalysisError> {
        let digest = snapshot_digest(&files);
        Self::new_validated(files, digest.clone(), digest)
    }

    /// Create a snapshot whose analysis files are a projection of an already
    /// authenticated `source-manifest-v2` tree.
    ///
    /// # Errors
    /// Rejects invalid source paths/bytes and malformed content digests.
    pub fn new_authenticated(
        files: BTreeMap<String, Vec<u8>>,
        manifest_digest: String,
    ) -> Result<Self, AnalysisError> {
        if !valid_content_digest(&manifest_digest) {
            return Err(AnalysisError::invalid(
                "source manifest digest must be a lowercase sha256 content digest",
            ));
        }
        let digest = snapshot_digest(&files);
        Self::new_validated(files, digest, manifest_digest)
    }

    fn new_validated(
        files: BTreeMap<String, Vec<u8>>,
        digest: String,
        manifest_digest: String,
    ) -> Result<Self, AnalysisError> {
        let mut portable = BTreeMap::new();
        for (path, bytes) in &files {
            PublicPath::new(path.clone())
                .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
            std::str::from_utf8(bytes).map_err(|error| {
                AnalysisError::invalid(format!("{path}: source is not valid UTF-8: {error}"))
            })?;
            let key = portable_path_key(path);
            if let Some(previous) = portable.insert(key, path.clone()) {
                return Err(AnalysisError::invalid(format!(
                    "portable path collision: {previous} and {path}"
                )));
            }
        }
        Ok(Self {
            files: Arc::new(files),
            digest,
            manifest_digest,
        })
    }

    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
}

fn snapshot_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let entries = files
        .iter()
        .map(|(path, bytes)| {
            JsonValue::Object(BTreeMap::from([
                (
                    "digest".to_owned(),
                    JsonValue::String(content_digest(bytes)),
                ),
                ("path".to_owned(), JsonValue::String(path.clone())),
                (
                    "size".to_owned(),
                    JsonValue::Integer(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
                ),
            ]))
        })
        .collect();
    content_digest(
        JsonValue::Object(BTreeMap::from([
            ("files".to_owned(), JsonValue::Array(entries)),
            (
                "schema".to_owned(),
                JsonValue::String("source-manifest-v2".to_owned()),
            ),
        ]))
        .canonical(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub origin: String,
    pub trust: String,
    pub digest: String,
    pub bytes: Arc<[u8]>,
}

impl Default for ConfigSnapshot {
    fn default() -> Self {
        let bytes: Arc<[u8]> = Arc::from(&b""[..]);
        Self {
            origin: "built-in".to_owned(),
            trust: "built-in".to_owned(),
            digest: content_digest(&bytes),
            bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockSnapshot {
    pub digest: String,
    pub bytes: Arc<[u8]>,
}

impl Default for LockSnapshot {
    fn default() -> Self {
        let bytes: Arc<[u8]> = Arc::from(&b""[..]);
        Self {
            digest: content_digest(&bytes),
            bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisRequest {
    pub snapshot: SourceSnapshot,
    pub overlays: BTreeMap<String, String>,
    /// Explicit analysis roots. `None` discovers every provider entrypoint;
    /// `Some` analyzes only these roots plus recursively linked local sources.
    pub roots: Option<BTreeSet<String>>,
    pub config: ConfigSnapshot,
    pub lock: LockSnapshot,
    pub persona: Persona,
    pub budget: Budget,
    pub cancellation: CancellationToken,
    pub worker_count: usize,
    pub strict: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub span: workflow_verifier_foundation::Span,
}

#[derive(Clone, Debug)]
pub struct AnalysisResult {
    pub report: Report,
    pub symbols: Vec<Symbol>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisError {
    code: &'static str,
    message: String,
}

impl AnalysisError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "InvalidInput",
            message: message.into(),
        }
    }

    fn cancelled() -> Self {
        Self {
            code: "Cancelled",
            message: "analysis request was cancelled".to_owned(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "Internal",
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AnalysisError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineStatistics {
    pub parse_hits: u64,
    pub parse_misses: u64,
    pub lower_hits: u64,
    pub lower_misses: u64,
}

#[derive(Default)]
struct Statistics {
    parse_hits: AtomicU64,
    parse_misses: AtomicU64,
    lower_hits: AtomicU64,
    lower_misses: AtomicU64,
}

pub struct AnalysisEngine {
    parse_cache: Mutex<BTreeMap<String, Arc<YamlDocument>>>,
    lower_cache: Mutex<BTreeMap<String, Arc<Compilation>>>,
    reverse_dependencies: Mutex<BTreeMap<String, BTreeSet<String>>>,
    statistics: Statistics,
    build: BuildInfo,
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::with_build(BuildInfo {
            implementation: "rust".to_owned(),
            compiler: format!("rustc {}", option_env!("RUSTC_VERSION").unwrap_or("1.98.0")),
            target: option_env!("TARGET").unwrap_or("unknown-target").to_owned(),
            source_commit: option_env!("WORKFLOW_VERIFIER_SOURCE_COMMIT").map(str::to_owned),
            binary_digest: format!("sha256:{}", "0".repeat(64)),
        })
    }

    #[must_use]
    pub fn with_build(build: BuildInfo) -> Self {
        Self {
            parse_cache: Mutex::new(BTreeMap::new()),
            lower_cache: Mutex::new(BTreeMap::new()),
            reverse_dependencies: Mutex::new(BTreeMap::new()),
            statistics: Statistics::default(),
            build,
        }
    }

    /// Analyze one immutable request snapshot plus unsaved overlays.
    ///
    /// # Errors
    /// Returns typed cancellation, invalid-source, frontend, or poisoned-cache
    /// failures. No partial report is returned as complete.
    #[allow(clippy::too_many_lines)]
    pub fn analyze(&self, request: &AnalysisRequest) -> Result<AnalysisResult, AnalysisError> {
        check_cancelled(&request.cancellation)?;
        let config = parse_config(&request.config)?;
        let lock = parse_lock(&request.lock)?;
        let mut effective = effective_sources(&request.snapshot, &request.overlays)?;
        if request.config.trust == "trusted-policy" || request.config.trust == "trusted" {
            effective.retain(|path, _| {
                !config
                    .source_exclusions
                    .iter()
                    .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            });
        }
        let effective_bytes: BTreeMap<_, _> = effective
            .iter()
            .map(|(path, source)| (path.clone(), source.as_bytes().to_vec()))
            .collect();
        let effective_digest = if request.overlays.is_empty() {
            request.snapshot.manifest_digest().to_owned()
        } else {
            snapshot_digest(&effective_bytes)
        };
        let mut compilations = Vec::new();
        let mut inputs = Vec::new();
        for (path, source) in &effective {
            check_cancelled(&request.cancellation)?;
            let Some(provider) = detect(path, source) else {
                continue;
            };
            let selected_root = request
                .roots
                .as_ref()
                .is_some_and(|roots| roots.contains(path));
            if !config.frontends.contains(&provider)
                || request
                    .roots
                    .as_ref()
                    .is_some_and(|roots| !roots.contains(path))
                || (!selected_root && !entrypoint(provider, path, source))
            {
                continue;
            }
            let source_digest = content_digest(source);
            inputs.push(ReportInput {
                path: path.clone(),
                digest: source_digest.clone(),
            });
            let document = self.memoize_parse(path, source, &source_digest, request.budget)?;
            check_cancelled(&request.cancellation)?;
            let lower_key = content_digest(
                [
                    provider.name(),
                    path,
                    &source_digest,
                    &request.config.digest,
                    &request.lock.digest,
                ]
                .join("\0"),
            );
            let compilation = self.memoize_lower(provider, path, document, &lower_key)?;
            check_cancelled(&request.cancellation)?;
            compilations.push(compilation.as_ref().clone());
        }
        compilations = link_local(&effective, compilations, request.budget)
            .map_err(|errors| AnalysisError::invalid(errors.join("; ")))?;
        check_cancelled(&request.cancellation)?;
        inputs.clear();
        for compilation in &mut compilations {
            check_cancelled(&request.cancellation)?;
            apply_lock(compilation, &lock);
            self.index_dependencies(&compilation.graph.source, compilation)?;
            inputs.push(ReportInput {
                path: compilation.graph.source.clone(),
                digest: content_digest(compilation.cst.print()),
            });
        }
        compilations.sort_by(|left, right| left.graph.source.cmp(&right.graph.source));
        let graphs: Vec<_> = compilations
            .iter()
            .map(|value| value.graph.clone())
            .collect();
        check_cancelled(&request.cancellation)?;
        let mut verification = verify_program(request.persona, &graphs);
        check_cancelled(&request.cancellation)?;
        verification
            .diagnostics
            .retain(|diagnostic| !config.suppressed(diagnostic));
        let verifications: Vec<VerificationResult> = vec![verification];
        let composed = compose_graphs(&graphs);
        let mut policy_diagnostics = frontend_diagnostics(&compilations);
        policy_diagnostics.extend(evaluate_policy(&config.rules, &composed));
        policy_diagnostics.retain(|diagnostic| !config.suppressed(diagnostic));
        policy_diagnostics.sort();
        check_cancelled(&request.cancellation)?;
        let mut completeness_reasons = BTreeSet::new();
        if verifications
            .iter()
            .any(|verification| !verification.complete)
        {
            completeness_reasons.insert("Incomplete.Static_analysis".to_owned());
        }
        for dependency in compilations
            .iter()
            .flat_map(|compilation| &compilation.dependencies)
        {
            if matches!(dependency.status, DependencyStatus::Unresolved(_)) {
                completeness_reasons.insert(format!(
                    "Incomplete.Unresolved_dependency: {}",
                    dependency.reference
                ));
            }
        }
        if self.build.source_commit.is_none() {
            completeness_reasons.insert("Incomplete.Unbound_build_source_commit".to_owned());
        }
        let gate_failure = verifications
            .iter()
            .any(|verification| should_fail(request.persona, verification))
            || (request.persona != Persona::Audit && !policy_diagnostics.is_empty());
        let (gate_result, exit_code) = if gate_failure {
            (GateResult::Finding, 1)
        } else if request.strict && !completeness_reasons.is_empty() {
            (GateResult::Incomplete, 3)
        } else {
            (GateResult::Pass, 0)
        };
        let provider_profiles: Vec<_> = compilations
            .iter()
            .map(|compilation| format!("{}-semantic-v1", compilation.provider.name()))
            .collect();
        let report = Report::new(
            request.persona,
            inputs,
            graphs,
            verifications,
            policy_diagnostics,
            self.build.clone(),
            ReportProvenance {
                config_origin: config.provenance.origin,
                config_trust: config.provenance.trust.name().to_owned(),
                config_digest: config.provenance.digest,
                lock_digest: lock.integrity,
                source_manifest_digest: effective_digest,
                provider_profiles,
                completeness_reasons: completeness_reasons.into_iter().collect(),
                gate_result,
                exit_code,
            },
        );
        let mut symbols: Vec<_> = compilations
            .iter()
            .flat_map(|compilation| {
                compilation.graph.nodes.iter().map(|node| Symbol {
                    name: node.name.clone(),
                    kind: node.kind.name().to_owned(),
                    path: compilation.graph.source.clone(),
                    span: node.span.clone(),
                })
            })
            .collect();
        symbols.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.span.cmp(&right.span))
                .then(left.name.cmp(&right.name))
        });
        Ok(AnalysisResult { report, symbols })
    }

    fn memoize_parse(
        &self,
        path: &str,
        source: &str,
        digest: &str,
        budget: Budget,
    ) -> Result<Arc<YamlDocument>, AnalysisError> {
        // File identity is part of a parsed CST because every retained span
        // carries its logical path, even when two files have identical bytes.
        let cache_key = content_digest([path, digest].join("\0"));
        let mut cache = self
            .parse_cache
            .lock()
            .map_err(|_| AnalysisError::internal("parse cache lock was poisoned"))?;
        if let Some(document) = cache.get(&cache_key) {
            self.statistics.parse_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(document));
        }
        self.statistics.parse_misses.fetch_add(1, Ordering::Relaxed);
        let document = Arc::new(YamlDocument::parse(path, source, budget));
        cache.insert(cache_key, Arc::clone(&document));
        Ok(document)
    }

    fn memoize_lower(
        &self,
        provider: Provider,
        path: &str,
        document: Arc<YamlDocument>,
        key: &str,
    ) -> Result<Arc<Compilation>, AnalysisError> {
        let mut cache = self
            .lower_cache
            .lock()
            .map_err(|_| AnalysisError::internal("lower cache lock was poisoned"))?;
        if let Some(compilation) = cache.get(key) {
            self.statistics.lower_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(compilation));
        }
        self.statistics.lower_misses.fetch_add(1, Ordering::Relaxed);
        let compilation = compile_parsed(provider, path, document).map_err(|problems| {
            AnalysisError::invalid(
                problems
                    .iter()
                    .map(|problem| format!("{path}: {}: {}", problem.code, problem.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })?;
        let compilation = Arc::new(compilation);
        cache.insert(key.to_owned(), Arc::clone(&compilation));
        Ok(compilation)
    }

    fn index_dependencies(
        &self,
        owner: &str,
        compilation: &Compilation,
    ) -> Result<(), AnalysisError> {
        let mut reverse = self
            .reverse_dependencies
            .lock()
            .map_err(|_| AnalysisError::internal("dependency index lock was poisoned"))?;
        for dependency in &compilation.dependencies {
            if dependency.mutability == workflow_verifier_frontend::Mutability::Local {
                reverse
                    .entry(dependency.reference.clone())
                    .or_default()
                    .insert(owner.to_owned());
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn statistics(&self) -> EngineStatistics {
        EngineStatistics {
            parse_hits: self.statistics.parse_hits.load(Ordering::Relaxed),
            parse_misses: self.statistics.parse_misses.load(Ordering::Relaxed),
            lower_hits: self.statistics.lower_hits.load(Ordering::Relaxed),
            lower_misses: self.statistics.lower_misses.load(Ordering::Relaxed),
        }
    }
}

fn check_cancelled(token: &CancellationToken) -> Result<(), AnalysisError> {
    if token.is_cancelled() {
        Err(AnalysisError::cancelled())
    } else {
        Ok(())
    }
}

fn effective_sources(
    snapshot: &SourceSnapshot,
    overlays: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, AnalysisError> {
    let mut output = BTreeMap::new();
    let mut portable = BTreeMap::new();
    for (path, bytes) in snapshot.files() {
        let source = std::str::from_utf8(bytes)
            .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
        output.insert(path.clone(), source.to_owned());
        portable.insert(portable_path_key(path), path.clone());
    }
    for (path, source) in overlays {
        PublicPath::new(path.clone())
            .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
        let key = portable_path_key(path);
        if let Some(previous) = portable.get(&key)
            && previous != path
        {
            return Err(AnalysisError::invalid(format!(
                "portable path collision: {previous} and {path}"
            )));
        }
        portable.insert(key, path.clone());
        output.insert(path.clone(), source.clone());
    }
    Ok(output)
}

fn parse_config(snapshot: &ConfigSnapshot) -> Result<Config, AnalysisError> {
    if snapshot.bytes.is_empty() {
        return Ok(Config::default());
    }
    if content_digest(&snapshot.bytes) != snapshot.digest {
        return Err(AnalysisError::invalid(
            "configuration digest does not authenticate its bytes",
        ));
    }
    let source = std::str::from_utf8(&snapshot.bytes)
        .map_err(|error| AnalysisError::invalid(format!("configuration is not UTF-8: {error}")))?;
    let trust = match snapshot.trust.as_str() {
        "built-in" => ConfigTrust::BuiltIn,
        "repository" => ConfigTrust::Repository,
        "trusted" | "trusted-policy" => ConfigTrust::TrustedPolicy,
        value => {
            return Err(AnalysisError::invalid(format!(
                "unknown configuration trust {value}"
            )));
        }
    };
    Config::parse(
        source,
        ConfigParseOptions {
            origin: snapshot.origin.clone(),
            trust,
            today: None,
        },
    )
    .map_err(|errors| AnalysisError::invalid(errors.join("; ")))
}

fn parse_lock(snapshot: &LockSnapshot) -> Result<Lockfile, AnalysisError> {
    if snapshot.bytes.is_empty() {
        return Lockfile::new([]).map_err(AnalysisError::invalid);
    }
    if content_digest(&snapshot.bytes) != snapshot.digest {
        return Err(AnalysisError::invalid(
            "lock digest does not authenticate its bytes",
        ));
    }
    let source = std::str::from_utf8(&snapshot.bytes)
        .map_err(|error| AnalysisError::invalid(format!("lockfile is not UTF-8: {error}")))?;
    Lockfile::parse(source).map_err(AnalysisError::invalid)
}

fn lock_evidence(operation: &str, value: &str) -> AbstractValue {
    AbstractValue::string_constant(
        value,
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "workflow-verifier.lock".to_owned(),
            span: workflow_verifier_foundation::Span::default(),
            operation: operation.to_owned(),
        }],
    )
}

fn dependency_reference_matches(node: &workflow_verifier_domain::Node, reference: &str) -> bool {
    node.name == reference
        || node.name == format!("docker:{reference}")
        || node
            .attributes
            .get("dependency.reference")
            .and_then(AbstractValue::constants)
            .is_some_and(|values| values.iter().any(|value| value == reference))
}

fn apply_lock(compilation: &mut Compilation, lock: &Lockfile) {
    for dependency in &mut compilation.dependencies {
        if let Some(entry) = lock.find(dependency.provider, &dependency.reference) {
            dependency.status = DependencyStatus::Locked {
                revision: entry.revision.clone(),
                digest: entry.digest.clone(),
            };
        }
    }
    for node in &mut compilation.graph.nodes {
        if node.kind != NodeKind::Call {
            continue;
        }
        let Some(entry) = lock.entries().iter().find(|entry| {
            entry.provider == node.provider && dependency_reference_matches(node, &entry.reference)
        }) else {
            continue;
        };
        node.attributes.insert(
            "dependency.digest".to_owned(),
            lock_evidence("lock digest", &entry.digest),
        );
        node.attributes.insert(
            "dependency.revision".to_owned(),
            lock_evidence("lock revision", &entry.revision),
        );
        node.attributes.insert(
            "dependency.source".to_owned(),
            lock_evidence("lock source", &entry.source),
        );
        match entry.summary.as_ref() {
            None => {
                node.unknown = Some(UnknownReason::MissingEvidence(format!(
                    "lock entry has no semantic summary for {}",
                    entry.reference
                )));
            }
            Some(summary) => apply_summary(node, summary),
        }
    }
    compilation.graph.finalize();
}

fn apply_summary(node: &mut workflow_verifier_domain::Node, summary: &DependencySummary) {
    node.capabilities
        .extend(summary.capabilities.iter().copied());
    node.capabilities.sort();
    node.capabilities.dedup();
    node.effects.extend(summary.effects.iter().copied());
    node.effects.sort();
    node.effects.dedup();
    node.attributes.insert(
        "dependency.summary".to_owned(),
        lock_evidence(
            "lock semantic summary",
            if summary.complete {
                "complete"
            } else {
                "incomplete"
            },
        ),
    );
    node.unknown = if summary.complete {
        None
    } else {
        Some(UnknownReason::MissingEvidence(summary.reasons.join("; ")))
    };
}

fn compose_graphs(graphs: &[Graph]) -> Graph {
    compose_program(graphs)
}

fn frontend_diagnostics(compilations: &[Compilation]) -> Vec<Diagnostic> {
    let mut diagnostics = compilations
        .iter()
        .flat_map(|compilation| &compilation.problems)
        .map(|problem| {
            Diagnostic::new(
                problem.code.clone(),
                Severity::Error,
                Confidence::High,
                problem.message.clone(),
                problem.span.clone(),
                Vec::new(),
                [],
                ["frontend compiler".to_owned()],
                None,
            )
        })
        .collect::<Vec<_>>();
    diagnostics.sort();
    diagnostics
}
