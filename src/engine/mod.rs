#![forbid(unsafe_code)]

//! Stateless analysis and explicitly session-scoped incremental analysis.

use crate::domain::{
    AbstractValue, NodeKind, Program, Provenance, Provider, Secrecy, SourceId, Trust, UnknownReason,
};
use crate::foundation::{Budget, Digest, PublicPath, normalize_slashes, portable_path_key};
use crate::frontend::{Compilation, DependencyStatus, compile_parsed, detect, entrypoint};
use crate::product::{
    AnalysisProvenance, BuildInfo, CheckReportView, Config, ConfigParseOptions, ConfigTrust,
    DependencySummary, EXIT_CODE_FINDING, EXIT_CODE_INCOMPLETE, EXIT_CODE_PASS, Gate, GateResult,
    GraphDocumentView, GraphKind, Lockfile, ReportInput, SarifView, SemanticConformanceView,
    canonical_provider_profiles, evaluate_policy, link_local,
};
use crate::syntax::YamlDocument;
use crate::verifier::{
    Confidence, Diagnostic, Persona, Property, PropertyState, Severity, compose_program_owned,
    verify_program,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSource {
    pub path: String,
    pub text: Arc<str>,
    pub digest: Digest,
}

impl AnalysisSource {
    /// Construct one validated logical source.
    ///
    /// # Errors
    /// Rejects non-portable logical paths.
    pub fn new(path: impl Into<String>, text: impl Into<Arc<str>>) -> Result<Self, AnalysisError> {
        let path = normalize_slashes(&path.into());
        PublicPath::new(path.clone())
            .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
        let text = text.into();
        let digest = Digest::of_bytes(text.as_bytes());
        Ok(Self { path, text, digest })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub origin: String,
    pub trust: String,
    pub digest: Digest,
    pub bytes: Arc<[u8]>,
}

impl Default for ConfigSnapshot {
    fn default() -> Self {
        let bytes: Arc<[u8]> = Arc::from(&b""[..]);
        Self {
            origin: "built-in".to_owned(),
            trust: "built-in".to_owned(),
            digest: Digest::of_bytes(&bytes),
            bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockSnapshot {
    pub digest: Digest,
    pub bytes: Arc<[u8]>,
}

impl Default for LockSnapshot {
    fn default() -> Self {
        let bytes: Arc<[u8]> = Arc::from(&b""[..]);
        Self {
            digest: Digest::of_bytes(&bytes),
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

/// Complete immutable input to one analysis.
#[derive(Clone, Debug)]
pub struct AnalysisInput {
    pub sources: Arc<[AnalysisSource]>,
    /// `Some(text)` adds/replaces an unsaved document; `None` removes it.
    pub overlays: BTreeMap<String, Option<Arc<str>>>,
    pub roots: Option<BTreeSet<String>>,
    pub config: ConfigSnapshot,
    pub lock: LockSnapshot,
    pub persona: Persona,
    pub budget: Budget,
    pub cancellation: CancellationToken,
    pub strict: bool,
}

impl AnalysisInput {
    /// Build a canonical input from shared source texts.
    ///
    /// # Errors
    /// Rejects portable path collisions and duplicate paths.
    pub fn new(sources: impl IntoIterator<Item = AnalysisSource>) -> Result<Self, AnalysisError> {
        let mut sources: Vec<_> = sources.into_iter().collect();
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        validate_sources(&sources)?;
        Ok(Self {
            sources: sources.into(),
            overlays: BTreeMap::new(),
            roots: None,
            config: ConfigSnapshot::default(),
            lock: LockSnapshot::default(),
            persona: Persona::Gate,
            budget: Budget::default(),
            cancellation: CancellationToken::new(),
            strict: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub source: SourceId,
    pub span: crate::foundation::Span,
}

/// The one owned semantic result. Output formats are borrowed projections.
#[derive(Clone, Debug)]
pub struct AnalysisOutcome {
    program: Program,
    diagnostics: Vec<Diagnostic>,
    properties: Vec<Property>,
    symbols: Vec<Symbol>,
    gate: Gate,
    completeness_reasons: Vec<String>,
    provenance: AnalysisProvenance,
    inputs: Vec<ReportInput>,
    persona: Persona,
    build: BuildInfo,
}

impl AnalysisOutcome {
    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    #[must_use]
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    #[must_use]
    pub const fn gate(&self) -> Gate {
        self.gate
    }

    #[must_use]
    pub fn completeness_reasons(&self) -> &[String] {
        &self.completeness_reasons
    }

    #[must_use]
    pub const fn provenance(&self) -> &AnalysisProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn check_report(&self) -> CheckReportView<'_> {
        CheckReportView::new(
            &self.build,
            self.persona,
            &self.program,
            CheckReportView::results(
                &self.inputs,
                &self.diagnostics,
                &self.properties,
                self.gate,
                &self.completeness_reasons,
                &self.provenance,
            ),
        )
    }

    #[must_use]
    pub const fn graph(&self, kind: GraphKind) -> GraphDocumentView<'_> {
        GraphDocumentView::new(kind, &self.program)
    }

    #[must_use]
    pub fn sarif(&self) -> SarifView<'_> {
        let report = self.check_report();
        SarifView::new(
            &self.program,
            &self.diagnostics,
            self.gate,
            report.digest(),
            report.analysis_digest(),
            self.provenance.analysis_manifest_digest,
        )
    }

    /// Test-only language-neutral projection for the OCaml semantic oracle.
    #[doc(hidden)]
    #[must_use]
    pub fn semantic_conformance(&self) -> SemanticConformanceView<'_> {
        SemanticConformanceView::new(
            &self.program,
            &self.diagnostics,
            &self.properties,
            self.gate,
            &self.completeness_reasons,
        )
    }
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

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AnalysisError {}

#[derive(Clone, Debug, Default)]
pub struct Analyzer {
    build: BuildInfo,
}

impl Analyzer {
    #[must_use]
    pub const fn with_build(build: BuildInfo) -> Self {
        Self { build }
    }

    /// Analyze without retaining any cache or session state.
    ///
    /// # Errors
    /// Returns typed cancellation, invalid-input, frontend, or budget errors.
    pub fn analyze(&self, input: AnalysisInput) -> Result<AnalysisOutcome, AnalysisError> {
        analyze_with(&mut StatelessBackend, input, &self.build)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionStatistics {
    pub parse_hits: u64,
    pub parse_misses: u64,
    pub lower_hits: u64,
    pub lower_misses: u64,
}

/// Mutable incremental state owned only by an LSP session.
#[derive(Debug, Default)]
pub struct AnalysisSession {
    parse_cache: BTreeMap<Digest, Arc<YamlDocument>>,
    lower_cache: BTreeMap<Digest, Arc<Compilation>>,
    reverse_dependencies: BTreeMap<String, BTreeSet<String>>,
    statistics: SessionStatistics,
    build: BuildInfo,
}

impl AnalysisSession {
    #[must_use]
    pub fn with_build(build: BuildInfo) -> Self {
        Self {
            build,
            ..Self::default()
        }
    }

    /// Analyze while reusing this session's parse/lower caches.
    ///
    /// # Errors
    /// Returns typed cancellation, invalid-input, frontend, or budget errors.
    pub fn analyze(&mut self, input: AnalysisInput) -> Result<AnalysisOutcome, AnalysisError> {
        let build = self.build.clone();
        analyze_with(self, input, &build)
    }

    /// Parse a document through the session cache for syntax-first LSP work.
    ///
    /// # Errors
    /// Returns a typed invalid input only if the cache identity cannot be built.
    pub fn parse_document(
        &mut self,
        path: &str,
        source: &str,
        budget: Budget,
    ) -> Result<Arc<YamlDocument>, AnalysisError> {
        let digest = Digest::of_bytes(source);
        Backend::parse(self, path, source, digest, budget)
    }

    /// Changed sources plus all transitively dependent local sources.
    ///
    /// # Errors
    /// Rejects non-portable changed paths.
    pub fn affected_sources(&self, changed_paths: &[String]) -> Result<Vec<String>, AnalysisError> {
        let mut affected = BTreeSet::new();
        let mut pending = BTreeSet::new();
        for path in changed_paths {
            PublicPath::new(path.clone())
                .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
            affected.insert(path.clone());
            pending.insert(path.clone());
        }
        while let Some(path) = pending.pop_first() {
            if let Some(owners) = self.reverse_dependencies.get(&path) {
                for owner in owners {
                    if affected.insert(owner.clone()) {
                        pending.insert(owner.clone());
                    }
                }
            }
        }
        Ok(affected.into_iter().collect())
    }

    #[must_use]
    pub const fn statistics(&self) -> SessionStatistics {
        self.statistics
    }
}

trait Backend {
    fn parse(
        &mut self,
        path: &str,
        source: &str,
        digest: Digest,
        budget: Budget,
    ) -> Result<Arc<YamlDocument>, AnalysisError>;

    fn lower(
        &mut self,
        provider: Provider,
        path: &str,
        document: Arc<YamlDocument>,
        key: Digest,
    ) -> Result<Compilation, AnalysisError>;

    fn replace_dependency_index(&mut self, _compilations: &[Compilation]) {}
}

struct StatelessBackend;

impl Backend for StatelessBackend {
    fn parse(
        &mut self,
        path: &str,
        source: &str,
        _digest: Digest,
        budget: Budget,
    ) -> Result<Arc<YamlDocument>, AnalysisError> {
        Ok(Arc::new(YamlDocument::parse(path, source, budget)))
    }

    fn lower(
        &mut self,
        provider: Provider,
        path: &str,
        document: Arc<YamlDocument>,
        _key: Digest,
    ) -> Result<Compilation, AnalysisError> {
        lower(provider, path, document)
    }
}

impl Backend for AnalysisSession {
    fn parse(
        &mut self,
        path: &str,
        source: &str,
        digest: Digest,
        budget: Budget,
    ) -> Result<Arc<YamlDocument>, AnalysisError> {
        let mut key = Digest::builder(b"workflow-verifier/parse-cache/1");
        key.add(path).add(digest.as_bytes());
        let key = key.finish();
        if let Some(document) = self.parse_cache.get(&key) {
            self.statistics.parse_hits = self.statistics.parse_hits.saturating_add(1);
            return Ok(Arc::clone(document));
        }
        self.statistics.parse_misses = self.statistics.parse_misses.saturating_add(1);
        let document = Arc::new(YamlDocument::parse(path, source, budget));
        self.parse_cache.insert(key, Arc::clone(&document));
        Ok(document)
    }

    fn lower(
        &mut self,
        provider: Provider,
        path: &str,
        document: Arc<YamlDocument>,
        key: Digest,
    ) -> Result<Compilation, AnalysisError> {
        if let Some(compilation) = self.lower_cache.get(&key) {
            self.statistics.lower_hits = self.statistics.lower_hits.saturating_add(1);
            return Ok(compilation.as_ref().clone());
        }
        self.statistics.lower_misses = self.statistics.lower_misses.saturating_add(1);
        let compilation = lower(provider, path, document)?;
        self.lower_cache.insert(key, Arc::new(compilation.clone()));
        Ok(compilation)
    }

    fn replace_dependency_index(&mut self, compilations: &[Compilation]) {
        let mut next = BTreeMap::<String, BTreeSet<String>>::new();
        for compilation in compilations {
            for dependency in &compilation.dependencies {
                if dependency.mutability != crate::frontend::Mutability::Local {
                    continue;
                }
                let target = match &dependency.status {
                    DependencyStatus::Locked { revision, .. } => revision
                        .strip_prefix("local:")
                        .unwrap_or(&dependency.reference),
                    DependencyStatus::Unresolved(_) => &dependency.reference,
                };
                next.entry(target.to_owned())
                    .or_default()
                    .insert(compilation.graph.source_path().to_owned());
            }
        }
        self.reverse_dependencies = next;
    }
}

fn lower(
    provider: Provider,
    path: &str,
    document: Arc<YamlDocument>,
) -> Result<Compilation, AnalysisError> {
    compile_parsed(provider, path, document).map_err(|problems| {
        AnalysisError::invalid(
            problems
                .iter()
                .map(|problem| format!("{path}: {}: {}", problem.code, problem.message))
                .collect::<Vec<_>>()
                .join("; "),
        )
    })
}

fn compile_sources(
    backend: &mut impl Backend,
    effective: &BTreeMap<String, Arc<str>>,
    roots: Option<&BTreeSet<String>>,
    config: &Config,
    cache_digests: (Digest, Digest),
    budget: Budget,
    cancellation: &CancellationToken,
) -> Result<Vec<Compilation>, AnalysisError> {
    let mut compilations = Vec::new();
    for (path, source) in effective {
        check_cancelled(cancellation)?;
        let Some(provider) = detect(path, source) else {
            continue;
        };
        let selected_root = roots.is_some_and(|roots| roots.contains(path));
        if !config.frontends.contains(&provider)
            || roots.is_some_and(|roots| !roots.contains(path))
            || (!selected_root && !entrypoint(provider, path, source))
        {
            continue;
        }
        let source_digest = Digest::of_bytes(source.as_bytes());
        let document = backend.parse(path, source, source_digest, budget)?;
        check_cancelled(cancellation)?;
        let mut lower_key = Digest::builder(b"workflow-verifier/lower-cache/1");
        lower_key
            .add(provider.name())
            .add(path)
            .add(source_digest.as_bytes())
            .add(cache_digests.0.as_bytes())
            .add(cache_digests.1.as_bytes());
        compilations.push(backend.lower(provider, path, document, lower_key.finish())?);
    }
    let compilations = link_local(effective, compilations, budget)
        .map_err(|errors| AnalysisError::invalid(errors.join("; ")))?;
    check_cancelled(cancellation)?;
    Ok(compilations)
}

struct CompiledProgram {
    program: Program,
    frontend_problems: Vec<(String, crate::frontend::FrontendProblem)>,
    provider_profiles: Vec<String>,
    completeness_reasons: BTreeSet<String>,
}

fn assemble_program(
    backend: &mut impl Backend,
    mut compilations: Vec<Compilation>,
    lock: &Lockfile,
    build: &BuildInfo,
    cancellation: &CancellationToken,
) -> Result<CompiledProgram, AnalysisError> {
    for compilation in &mut compilations {
        apply_lock(compilation, lock);
    }
    backend.replace_dependency_index(&compilations);
    compilations.sort_by(|left, right| {
        left.graph
            .source_path()
            .cmp(right.graph.source_path())
            .then(left.provider.cmp(&right.provider))
    });

    let mut completeness_reasons = BTreeSet::new();
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
    if build.source_commit.is_none() {
        completeness_reasons.insert("Incomplete.Unbound_build_source_commit".to_owned());
    }
    let frontend_problems: Vec<_> = compilations
        .iter()
        .flat_map(|compilation| {
            compilation
                .problems
                .iter()
                .cloned()
                .map(|problem| (compilation.graph.source_path().to_owned(), problem))
                .collect::<Vec<_>>()
        })
        .collect();
    let provider_profiles = canonical_provider_profiles(
        compilations
            .iter()
            .map(|compilation| format!("{}-semantic-v1", compilation.provider.name())),
    );
    let graphs: Vec<_> = compilations
        .into_iter()
        .map(|compilation| compilation.graph)
        .collect();
    let program = compose_program_owned(graphs);
    check_cancelled(cancellation)?;
    Ok(CompiledProgram {
        program,
        frontend_problems,
        provider_profiles,
        completeness_reasons,
    })
}

struct VerifiedProgram {
    diagnostics: Vec<Diagnostic>,
    properties: Vec<Property>,
    policy_failure: bool,
    complete: bool,
}

fn verify_compiled(
    program: &Program,
    frontend_problems: &[(String, crate::frontend::FrontendProblem)],
    config: &Config,
    persona: Persona,
) -> VerifiedProgram {
    let mut verification = verify_program(persona, program);
    let complete = verification.complete;
    verification
        .diagnostics
        .retain(|diagnostic| !config.suppressed(diagnostic, program));
    let mut diagnostics = verification.diagnostics;
    diagnostics.extend(frontend_diagnostics(frontend_problems, program));
    let policy_diagnostics = evaluate_policy(&config.rules, program);
    let policy_failure = persona != Persona::Audit && !policy_diagnostics.is_empty();
    diagnostics.extend(policy_diagnostics);
    diagnostics.retain(|diagnostic| !config.suppressed(diagnostic, program));
    diagnostics.sort();
    diagnostics.dedup_by(|left, right| left.id == right.id);
    let mut properties = verification.properties;
    properties.sort();
    properties.dedup();
    VerifiedProgram {
        diagnostics,
        properties,
        policy_failure,
        complete,
    }
}

fn report_surfaces(
    program: &Program,
    effective: &BTreeMap<String, Arc<str>>,
) -> (Vec<ReportInput>, Vec<Symbol>) {
    let inputs = program
        .sources
        .iter()
        .filter_map(|source| {
            effective.get(&source.path).map(|text| ReportInput {
                source: source.id,
                path: source.path.clone(),
                digest: Digest::of_bytes(text.as_bytes()),
            })
        })
        .collect();
    let mut symbols: Vec<_> = program
        .nodes
        .iter()
        .map(|node| Symbol {
            name: node.name.clone(),
            kind: node.kind.name().to_owned(),
            source: node.span.source,
            span: node.span,
        })
        .collect();
    symbols.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then(left.span.cmp(&right.span))
            .then(left.name.cmp(&right.name))
    });
    (inputs, symbols)
}

fn analyze_with(
    backend: &mut impl Backend,
    input: AnalysisInput,
    build: &BuildInfo,
) -> Result<AnalysisOutcome, AnalysisError> {
    let AnalysisInput {
        sources,
        overlays,
        roots,
        config: config_snapshot,
        lock: lock_snapshot,
        persona,
        budget,
        cancellation,
        strict,
    } = input;
    check_cancelled(&cancellation)?;
    validate_sources(&sources)?;
    let config = parse_config(&config_snapshot)?;
    let lock = parse_lock(&lock_snapshot)?;
    let mut effective = effective_sources(&sources, &overlays)?;
    if matches!(config_snapshot.trust.as_str(), "trusted-policy" | "trusted") {
        effective.retain(|path, _| {
            !config
                .source_exclusions
                .iter()
                .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
        });
    }
    let manifest_digest = analysis_manifest_digest(&effective);
    let compilations = compile_sources(
        backend,
        &effective,
        roots.as_ref(),
        &config,
        (config_snapshot.digest, lock_snapshot.digest),
        budget,
        &cancellation,
    )?;
    let mut compiled = assemble_program(backend, compilations, &lock, build, &cancellation)?;
    let verified = verify_compiled(
        &compiled.program,
        &compiled.frontend_problems,
        &config,
        persona,
    );
    if !verified.complete {
        compiled
            .completeness_reasons
            .insert("Incomplete.Static_analysis".to_owned());
    }
    check_cancelled(&cancellation)?;
    let gate_failure = outcome_should_fail(persona, &verified.diagnostics, &verified.properties)
        || verified.policy_failure;
    let (result, exit_code) = if gate_failure {
        (GateResult::Finding, EXIT_CODE_FINDING)
    } else if strict && !compiled.completeness_reasons.is_empty() {
        (GateResult::Incomplete, EXIT_CODE_INCOMPLETE)
    } else {
        (GateResult::Pass, EXIT_CODE_PASS)
    };
    let gate = Gate { result, exit_code };
    let (inputs, symbols) = report_surfaces(&compiled.program, &effective);
    let completeness_reasons = compiled.completeness_reasons.into_iter().collect();
    Ok(AnalysisOutcome {
        program: compiled.program,
        diagnostics: verified.diagnostics,
        properties: verified.properties,
        symbols,
        gate,
        completeness_reasons,
        provenance: AnalysisProvenance {
            config_origin: config.provenance.origin,
            config_trust: config.provenance.trust.name().to_owned(),
            config_digest: config_snapshot.digest,
            lock_digest: lock_snapshot.digest,
            analysis_manifest_digest: manifest_digest,
            provider_profiles: compiled.provider_profiles,
        },
        inputs,
        persona,
        build: build.clone(),
    })
}

fn outcome_should_fail(
    persona: Persona,
    diagnostics: &[Diagnostic],
    properties: &[Property],
) -> bool {
    match persona {
        Persona::Audit => false,
        Persona::Gate => diagnostics.iter().any(|diagnostic| {
            diagnostic.confidence == Confidence::High
                && matches!(diagnostic.severity, Severity::Critical | Severity::Error)
        }),
        Persona::Paranoid => {
            !diagnostics.is_empty()
                || properties
                    .iter()
                    .any(|property| matches!(property.state, PropertyState::Unknown(_)))
        }
    }
}

fn validate_sources(sources: &[AnalysisSource]) -> Result<(), AnalysisError> {
    let mut portable = BTreeMap::new();
    for source in sources {
        PublicPath::new(source.path.clone())
            .map_err(|error| AnalysisError::invalid(format!("{}: {error}", source.path)))?;
        if Digest::of_bytes(source.text.as_bytes()) != source.digest {
            return Err(AnalysisError::invalid(format!(
                "{}: source digest does not authenticate its text",
                source.path
            )));
        }
        let key = portable_path_key(&source.path);
        if let Some(previous) = portable.insert(key, source.path.clone()) {
            return Err(AnalysisError::invalid(format!(
                "portable path collision: {previous} and {}",
                source.path
            )));
        }
    }
    Ok(())
}

fn effective_sources(
    sources: &[AnalysisSource],
    overlays: &BTreeMap<String, Option<Arc<str>>>,
) -> Result<BTreeMap<String, Arc<str>>, AnalysisError> {
    let mut output: BTreeMap<_, _> = sources
        .iter()
        .map(|source| (source.path.clone(), Arc::clone(&source.text)))
        .collect();
    let mut portable: BTreeMap<_, _> = sources
        .iter()
        .map(|source| (portable_path_key(&source.path), source.path.clone()))
        .collect();
    for (raw_path, source) in overlays {
        let path = normalize_slashes(raw_path);
        PublicPath::new(path.clone())
            .map_err(|error| AnalysisError::invalid(format!("{path}: {error}")))?;
        let key = portable_path_key(&path);
        if let Some(previous) = portable.get(&key)
            && previous != &path
        {
            return Err(AnalysisError::invalid(format!(
                "portable path collision: {previous} and {path}"
            )));
        }
        if let Some(source) = source {
            portable.insert(key, path.clone());
            output.insert(path, Arc::clone(source));
        } else {
            portable.remove(&key);
            output.remove(&path);
        }
    }
    Ok(output)
}

fn analysis_manifest_digest(sources: &BTreeMap<String, Arc<str>>) -> Digest {
    let mut digest = Digest::builder(b"workflow-verifier-analysis-manifest/1");
    for (path, source) in sources {
        digest
            .add(path)
            .add(Digest::of_bytes(source.as_bytes()).as_bytes());
    }
    digest.finish()
}

fn check_cancelled(token: &CancellationToken) -> Result<(), AnalysisError> {
    if token.is_cancelled() {
        Err(AnalysisError::cancelled())
    } else {
        Ok(())
    }
}

fn parse_config(snapshot: &ConfigSnapshot) -> Result<Config, AnalysisError> {
    if snapshot.bytes.is_empty() {
        return Ok(Config::default());
    }
    if Digest::of_bytes(&snapshot.bytes) != snapshot.digest {
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
    if Digest::of_bytes(&snapshot.bytes) != snapshot.digest {
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
            span: crate::foundation::Span::default(),
            operation: operation.to_owned(),
        }],
    )
}

fn dependency_reference_matches(node: &crate::domain::Node, reference: &str) -> bool {
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

fn apply_summary(node: &mut crate::domain::Node, summary: &DependencySummary) {
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

fn frontend_diagnostics(
    problems: &[(String, crate::frontend::FrontendProblem)],
    program: &Program,
) -> Vec<Diagnostic> {
    let source_ids: BTreeMap<_, _> = program
        .sources
        .iter()
        .map(|source| (source.path.as_str(), source.id))
        .collect();
    problems
        .iter()
        .map(|(path, problem)| {
            let mut span = problem.span;
            span.source = source_ids.get(path.as_str()).copied().unwrap_or_default();
            Diagnostic::new(
                problem.code.clone(),
                Severity::Error,
                Confidence::High,
                problem.message.clone(),
                span,
                Diagnostic::details(Vec::new(), [], ["frontend compiler".to_owned()], None),
            )
        })
        .collect()
}

// ---- Static workspace loading ------------------------------------------------

#[derive(Clone, Debug)]
pub struct LoadOptions {
    pub target: PathBuf,
    pub config: Option<PathBuf>,
    pub config_trust: String,
    pub lockfile: Option<PathBuf>,
    pub persona: Persona,
    pub budget: Budget,
    pub strict: bool,
}

impl LoadOptions {
    #[must_use]
    pub fn new(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
            config: None,
            config_trust: "repository".to_owned(),
            lockfile: None,
            persona: Persona::Gate,
            budget: Budget::default(),
            strict: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadError(String);

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

#[derive(Clone, Debug)]
pub struct WorkspaceEntry {
    pub path: PathBuf,
    pub is_directory: bool,
    pub is_file: bool,
}

pub trait WorkspaceFileSystem {
    /// Resolves a path to its canonical workspace location.
    ///
    /// # Errors
    /// Returns an implementation-defined path-resolution error.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, String>;
    fn is_file(&self, path: &Path) -> bool;
    fn is_directory(&self, path: &Path) -> bool;
    /// Lists the immediate entries of a directory.
    ///
    /// # Errors
    /// Returns an implementation-defined directory I/O error.
    fn read_directory(&self, path: &Path) -> Result<Vec<WorkspaceEntry>, String>;
    /// Reads the exact bytes of a relevant analysis input.
    ///
    /// # Errors
    /// Returns an implementation-defined file I/O error.
    fn read(&self, path: &Path) -> Result<Arc<[u8]>, String>;
}

#[derive(Clone, Debug)]
pub struct WorkspaceLoader<F> {
    filesystem: F,
}

impl<F> WorkspaceLoader<F> {
    #[must_use]
    pub const fn new(filesystem: F) -> Self {
        Self { filesystem }
    }
}

impl<F: WorkspaceFileSystem> WorkspaceLoader<F> {
    /// Load only files that can influence static analysis. Directory discovery
    /// inspects names and file types; unrelated file contents are never read.
    ///
    /// # Errors
    /// Returns a bounded path, I/O, UTF-8, or input-validation error.
    pub fn load(&self, options: LoadOptions) -> Result<AnalysisInput, LoadError> {
        let LoadOptions {
            target,
            config: config_path,
            config_trust,
            lockfile,
            persona,
            budget,
            strict,
        } = options;
        let target = self
            .filesystem
            .canonicalize(&target)
            .map_err(|error| LoadError(format!("cannot open target: {error}")))?;
        let target_is_file = self.filesystem.is_file(&target);
        let root = if target_is_file {
            target
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| LoadError("workflow target has no parent".to_owned()))?
        } else if self.filesystem.is_directory(&target) {
            target.clone()
        } else {
            return Err(LoadError(
                "target is not a regular file or directory".to_owned(),
            ));
        };
        let config = self.load_config(&root, config_path.as_deref(), config_trust.as_str())?;
        let trusted_exclusions = if matches!(config.trust.as_str(), "trusted" | "trusted-policy") {
            parse_config(&config)
                .map_err(|error| LoadError(error.to_string()))?
                .source_exclusions
        } else {
            Vec::new()
        };

        let mut candidates = Vec::new();
        self.discover(&root, &root, &trusted_exclusions, &mut candidates)?;
        candidates.sort();

        let selected = target_is_file
            .then(|| relative_path(&root, &target))
            .transpose()?;
        let roots = selected.as_ref().map(|path| BTreeSet::from([path.clone()]));
        let initial: Vec<_> = candidates
            .iter()
            .filter(|path| {
                selected
                    .as_ref()
                    .map_or_else(|| entrypoint_path(path), |selected| *path == selected)
            })
            .cloned()
            .collect();
        let mut loaded = BTreeMap::<String, Arc<str>>::new();
        for path in initial {
            self.read_source(&root, &path, &mut loaded)?;
        }
        loop {
            let next = candidates.iter().find(|candidate| {
                !loaded.contains_key(*candidate)
                    && loaded.iter().any(|(owner, source)| {
                        source_references_candidate(owner, source, candidate)
                    })
            });
            let Some(next) = next.cloned() else {
                break;
            };
            self.read_source(&root, &next, &mut loaded)?;
        }

        let sources = loaded
            .into_iter()
            .map(|(path, text)| {
                AnalysisSource::new(path, text).map_err(|error| LoadError(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut input =
            AnalysisInput::new(sources).map_err(|error| LoadError(error.to_string()))?;
        input.roots = roots;
        input.persona = persona;
        input.budget = budget;
        input.strict = strict;
        input.config = config;
        if let Some(lock) = self.load_lock(&root, lockfile.as_deref())? {
            input.lock = lock;
        }
        Ok(input)
    }

    fn load_config(
        &self,
        root: &Path,
        explicit: Option<&Path>,
        trust: &str,
    ) -> Result<ConfigSnapshot, LoadError> {
        let path = explicit.map(Path::to_path_buf).or_else(|| {
            let automatic = root.join(".workflow-verifier.toml");
            self.filesystem.is_file(&automatic).then_some(automatic)
        });
        let Some(path) = path else {
            return Ok(ConfigSnapshot::default());
        };
        let bytes = self
            .filesystem
            .read(&path)
            .map_err(|error| LoadError(format!("cannot read config: {error}")))?;
        let origin = path.strip_prefix(root).ok().map_or_else(
            || {
                path.file_name()
                    .map_or("external", |name| name.to_str().unwrap_or("external"))
                    .to_owned()
            },
            normalize_path,
        );
        let origin = match trust {
            "trusted" | "trusted-policy" => format!("trusted-policy:{origin}"),
            "repository" => format!("repository:{origin}"),
            _ => origin,
        };
        Ok(ConfigSnapshot {
            origin,
            trust: trust.to_owned(),
            digest: Digest::of_bytes(&bytes),
            bytes,
        })
    }

    fn load_lock(
        &self,
        root: &Path,
        explicit: Option<&Path>,
    ) -> Result<Option<LockSnapshot>, LoadError> {
        let path = explicit.map(Path::to_path_buf).or_else(|| {
            let automatic = root.join("workflow-verifier.lock");
            self.filesystem.is_file(&automatic).then_some(automatic)
        });
        let Some(path) = path else {
            return Ok(None);
        };
        let bytes = self
            .filesystem
            .read(&path)
            .map_err(|error| LoadError(format!("cannot read lockfile: {error}")))?;
        Ok(Some(LockSnapshot {
            digest: Digest::of_bytes(&bytes),
            bytes,
        }))
    }

    fn discover(
        &self,
        root: &Path,
        directory: &Path,
        exclusions: &[String],
        output: &mut Vec<String>,
    ) -> Result<(), LoadError> {
        for entry in self
            .filesystem
            .read_directory(directory)
            .map_err(LoadError)?
        {
            let logical = relative_path(root, &entry.path)?;
            if source_excluded(&logical, exclusions) {
                continue;
            }
            let name = entry
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if entry.is_directory {
                if !matches!(
                    name,
                    ".git" | ".hg" | ".svn" | "target" | "_build" | "node_modules" | "vendor"
                ) {
                    self.discover(root, &entry.path, exclusions, output)?;
                }
            } else if entry.is_file && yaml_path(&entry.path) {
                output.push(logical);
            }
        }
        Ok(())
    }

    fn read_source(
        &self,
        root: &Path,
        logical: &str,
        output: &mut BTreeMap<String, Arc<str>>,
    ) -> Result<(), LoadError> {
        let bytes = self
            .filesystem
            .read(&root.join(logical))
            .map_err(|error| LoadError(format!("cannot read {logical}: {error}")))?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| LoadError(format!("{logical} is not UTF-8: {error}")))?;
        output.insert(logical.to_owned(), Arc::<str>::from(source));
        Ok(())
    }
}

fn relative_path(root: &Path, path: &Path) -> Result<String, LoadError> {
    path.strip_prefix(root)
        .map(normalize_path)
        .map_err(|_| LoadError("path escapes the workspace root".to_owned()))
}

fn normalize_path(path: &Path) -> String {
    normalize_slashes(&path.to_string_lossy())
}

fn yaml_path(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
    })
}

fn entrypoint_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    (lower.starts_with(".github/workflows/") && yaml_path(Path::new(path)))
        || lower == ".gitlab-ci.yml"
        || matches!(
            lower.as_str(),
            "azure-pipelines.yml" | "azure-pipelines.yaml"
        )
        || matches!(
            lower.as_str(),
            ".circleci/config.yml" | ".circleci/config.yaml"
        )
}

fn source_excluded(path: &str, exclusions: &[String]) -> bool {
    exclusions.iter().any(|prefix| {
        let prefix = normalize_slashes(prefix).trim_end_matches('/').to_owned();
        path == prefix || path.starts_with(&format!("{prefix}/"))
    })
}

fn source_references_candidate(owner: &str, source: &str, candidate: &str) -> bool {
    if source.contains(candidate) || source.contains(&format!("./{candidate}")) {
        return true;
    }
    let owner_parent = owner.rsplit_once('/').map_or("", |(parent, _)| parent);
    let relative = candidate
        .strip_prefix(owner_parent)
        .map_or(candidate, |value| value.trim_start_matches('/'));
    if source.contains(relative) || source.contains(&format!("./{relative}")) {
        return true;
    }
    for suffix in ["/action.yml", "/action.yaml"] {
        if let Some(directory) = relative.strip_suffix(suffix)
            && (source.contains(&format!("./{directory}")) || source.contains(directory))
        {
            return true;
        }
    }
    false
}
