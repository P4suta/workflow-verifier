use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::{NodeKind, Provider};
use workflow_verifier_engine::{
    AnalysisEngine, AnalysisRequest, CancellationToken, ConfigSnapshot, LockSnapshot,
    SourceSnapshot,
};
use workflow_verifier_foundation::{Budget, content_digest};
use workflow_verifier_product::{LockEntry, Lockfile};
use workflow_verifier_verifier::Persona;

fn snapshot(source: &str) -> SourceSnapshot {
    SourceSnapshot::new(BTreeMap::from([(
        ".github/workflows/ci.yml".to_owned(),
        source.as_bytes().to_vec(),
    )]))
    .expect("valid snapshot")
}

fn request(snapshot: SourceSnapshot) -> AnalysisRequest {
    AnalysisRequest {
        snapshot,
        overlays: BTreeMap::new(),
        roots: None,
        config: ConfigSnapshot::default(),
        lock: LockSnapshot::default(),
        persona: Persona::Gate,
        budget: Budget::default(),
        cancellation: CancellationToken::new(),
        worker_count: 1,
        strict: false,
    }
}

#[test]
fn authenticated_source_manifest_digest_is_reported_without_rehashing_analysis_files() {
    let manifest_digest = format!("sha256:{}", "f".repeat(64));
    let snapshot = SourceSnapshot::new_authenticated(
        BTreeMap::from([(
            ".github/workflows/ci.yml".to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n".to_vec(),
        )]),
        manifest_digest.clone(),
    )
    .expect("authenticated snapshot");
    let result = AnalysisEngine::new()
        .analyze(&request(snapshot))
        .expect("analysis succeeds");
    assert_eq!(
        result.report.provenance.source_manifest_digest,
        manifest_digest
    );
}

#[test]
fn lock_is_applied_before_whole_program_verification() {
    let source = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
    let lock = Lockfile::new([LockEntry::new(
        Provider::Github,
        "actions/checkout@v4",
        "0123456789abcdef0123456789abcdef01234567",
        format!("sha256:{}", "a".repeat(64)),
        "https://github.com/actions/checkout",
    )])
    .expect("valid lock");
    let bytes: std::sync::Arc<[u8]> = lock.to_canonical_json().into_bytes().into();
    let mut analysis = request(snapshot(source));
    analysis.lock = LockSnapshot {
        digest: content_digest(&bytes),
        bytes,
    };
    let result = AnalysisEngine::new()
        .analyze(&analysis)
        .expect("locked analysis succeeds");
    assert_eq!(result.report.verifications.len(), 1);
    assert!(
        result
            .report
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.rule_id != "WV-SUPPLY-001")
    );
    let call = result.report.graphs[0]
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Call)
        .expect("call node");
    assert!(call.attributes.contains_key("dependency.digest"));
}

#[test]
fn trusted_config_policy_is_evaluated_and_strict_controls_incomplete_exit() {
    let source = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
    let config = r#"
version = 2

[[rules]]
id = "ORG-CALL"
kind = "forbid"
message = "organization policy forbids remote calls"
severity = "error"
selector = { kind = "call" }
"#;
    let bytes: std::sync::Arc<[u8]> = config.as_bytes().into();
    let mut analysis = request(snapshot(source));
    analysis.config = ConfigSnapshot {
        origin: "trusted-policy:policy.toml".to_owned(),
        trust: "trusted-policy".to_owned(),
        digest: content_digest(&bytes),
        bytes,
    };
    let result = AnalysisEngine::new()
        .analyze(&analysis)
        .expect("policy analysis succeeds");
    assert!(
        result
            .report
            .policy_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "ORG-CALL")
    );

    let dynamic = "on: push\njobs:\n  build:\n    steps:\n      - uses: ${{ matrix.action }}\n";
    let non_strict = request(snapshot(dynamic));
    assert_eq!(
        AnalysisEngine::new()
            .analyze(&non_strict)
            .unwrap()
            .report
            .provenance
            .exit_code,
        0
    );
    let mut strict = request(snapshot(dynamic));
    strict.strict = true;
    assert_eq!(
        AnalysisEngine::new()
            .analyze(&strict)
            .unwrap()
            .report
            .provenance
            .exit_code,
        3
    );
}

#[test]
fn engine_links_local_dependencies_from_the_same_immutable_snapshot() {
    let sources = BTreeMap::from([
        (
            ".github/workflows/ci.yml".to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n"
                .to_vec(),
        ),
        (
            ".github/actions/demo/action.yml".to_owned(),
            b"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n".to_vec(),
        ),
    ]);
    let result = AnalysisEngine::new()
        .analyze(&request(SourceSnapshot::new(sources).unwrap()))
        .expect("local program analysis");
    assert_eq!(result.report.graphs.len(), 2);
    assert_eq!(result.report.inputs.len(), 2);
    let local_call = result
        .report
        .graphs
        .iter()
        .flat_map(|graph| &graph.nodes)
        .find(|node| node.name == "./.github/actions/demo")
        .expect("local call");
    assert!(local_call.unknown.is_none());
    assert!(local_call.attributes.contains_key("dependency.digest"));
}

#[test]
fn explicit_roots_exclude_unrelated_entrypoints_but_keep_local_dependencies() {
    let sources = BTreeMap::from([
        (
            ".github/workflows/selected.yml".to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n"
                .to_vec(),
        ),
        (
            ".github/actions/demo/action.yml".to_owned(),
            b"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n".to_vec(),
        ),
        (
            ".github/workflows/unrelated.yml".to_owned(),
            b"on: push\njobs:\n  unrelated:\n    steps:\n      - run: echo unrelated\n".to_vec(),
        ),
    ]);
    let mut analysis = request(SourceSnapshot::new(sources).unwrap());
    analysis.roots = Some(BTreeSet::from(
        [".github/workflows/selected.yml".to_owned()],
    ));
    let result = AnalysisEngine::new()
        .analyze(&analysis)
        .expect("selected program analysis");
    let graph_sources: Vec<_> = result
        .report
        .graphs
        .iter()
        .map(|graph| graph.source.as_str())
        .collect();
    assert_eq!(
        graph_sources,
        vec![
            ".github/actions/demo/action.yml",
            ".github/workflows/selected.yml"
        ]
    );
}

#[test]
fn analysis_is_reentrant_memoized_and_worker_order_independent() {
    let engine = AnalysisEngine::new();
    let base = snapshot("on: push\njobs:\n  build:\n    steps:\n      - run: echo ok\n");
    let first = engine
        .analyze(&request(base.clone()))
        .expect("analysis succeeds");
    let mut parallel = request(base);
    parallel.worker_count = 8;
    let second = engine.analyze(&parallel).expect("analysis succeeds");
    assert_eq!(first.report.semantic_digest, second.report.semantic_digest);
    assert!(engine.statistics().parse_hits >= 1);
    assert!(engine.statistics().lower_hits >= 1);
}

#[test]
fn identical_content_in_distinct_files_keeps_path_scoped_spans() {
    let source = b"on: push\njobs:\n  build:\n    steps:\n      - run: echo ok\n".to_vec();
    let snapshot = SourceSnapshot::new(BTreeMap::from([
        (".github/workflows/alpha.yml".to_owned(), source.clone()),
        (".github/workflows/beta.yml".to_owned(), source),
    ]))
    .expect("valid snapshot");
    let result = AnalysisEngine::new()
        .analyze(&request(snapshot))
        .expect("analysis succeeds");

    assert_eq!(result.report.graphs.len(), 2);
    for graph in &result.report.graphs {
        assert!(
            graph
                .nodes
                .iter()
                .all(|node| node.span.file == graph.source),
            "cached CST span escaped its source: {}",
            graph.source
        );
    }
}

#[test]
fn unsaved_overlay_changes_analysis_without_mutating_snapshot() {
    let engine = AnalysisEngine::new();
    let base = snapshot("on: push\njobs: {}\n");
    let original_digest = base.digest().to_owned();
    let mut analysis = request(base.clone());
    analysis.overlays.insert(
        ".github/workflows/ci.yml".to_owned(),
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n".to_owned(),
    );
    let result = engine
        .analyze(&analysis)
        .expect("overlay analysis succeeds");
    assert!(
        result
            .report
            .diagnostics()
            .iter()
            .any(|item| item.rule_id == "WV-SUPPLY-001")
    );
    assert_eq!(base.digest(), original_digest);
}

#[test]
fn cancellation_is_typed_and_observed_before_work() {
    let engine = AnalysisEngine::new();
    let analysis = request(snapshot("on: push\njobs: {}\n"));
    analysis.cancellation.cancel();
    let error = engine.analyze(&analysis).expect_err("cancelled request");
    assert_eq!(error.code(), "Cancelled");
}

#[test]
fn malformed_frontend_errors_retain_the_logical_source_path() {
    let error = AnalysisEngine::new()
        .analyze(&request(snapshot(
            "on: push\njobs:\n  build: {missing-colon}\n",
        )))
        .expect_err("malformed flow mapping must fail");
    let rendered = error.to_string();
    assert!(rendered.contains(".github/workflows/ci.yml"), "{rendered}");
    assert!(rendered.contains("YAML-SYNTAX"), "{rendered}");
}
