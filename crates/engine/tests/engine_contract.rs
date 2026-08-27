use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::{Capability, Node, NodeKind, ObservableEffect, Provider};
use workflow_verifier_engine::{
    AnalysisEngine, AnalysisRequest, AnalysisResult, CancellationToken, ConfigSnapshot,
    LockSnapshot, SourceSnapshot,
};
use workflow_verifier_foundation::{Budget, content_digest, valid_content_digest};
use workflow_verifier_product::{DependencySummary, LockEntry, Lockfile};
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

fn config_snapshot(source: &str, trust: &str) -> ConfigSnapshot {
    let bytes: std::sync::Arc<[u8]> = source.as_bytes().into();
    ConfigSnapshot {
        origin: "engine contract policy".to_owned(),
        trust: trust.to_owned(),
        digest: content_digest(&bytes),
        bytes,
    }
}

fn lock_snapshot(lock: &Lockfile) -> LockSnapshot {
    let bytes: std::sync::Arc<[u8]> = lock.to_canonical_json().into_bytes().into();
    LockSnapshot {
        digest: content_digest(&bytes),
        bytes,
    }
}

fn call_named<'a>(result: &'a AnalysisResult, name: &str) -> &'a Node {
    result
        .report
        .graphs
        .iter()
        .flat_map(|graph| &graph.nodes)
        .find(|node| node.kind == NodeKind::Call && node.name == name)
        .unwrap_or_else(|| panic!("missing call node {name}"))
}

#[test]
fn source_snapshot_digest_is_content_addressed_and_well_formed() {
    let first = snapshot("on: push\njobs: {}\n");
    let same = snapshot("on: push\njobs: {}\n");
    let changed = snapshot("on: pull_request\njobs: {}\n");

    assert!(valid_content_digest(first.digest()));
    assert_eq!(first.digest(), same.digest());
    assert_ne!(first.digest(), changed.digest());
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
fn trusted_source_exclusions_match_exact_paths_and_path_segment_prefixes() {
    let sources = BTreeMap::from([
        (
            ".github/workflows/exact.yml".to_owned(),
            b"on: push\njobs: {}\n".to_vec(),
        ),
        (
            ".github/workflows/generated/nested.yml".to_owned(),
            b"on: push\njobs: {}\n".to_vec(),
        ),
        (
            ".github/workflows/generated-sibling.yml".to_owned(),
            b"on: push\njobs: {}\n".to_vec(),
        ),
    ]);
    let policy = r#"version = 2
source_exclusions = [
  ".github/workflows/exact.yml",
  ".github/workflows/generated",
]
"#;

    for trust in ["trusted-policy", "trusted"] {
        let mut analysis = request(SourceSnapshot::new(sources.clone()).expect("valid snapshot"));
        analysis.config = config_snapshot(policy, trust);
        let result = AnalysisEngine::new()
            .analyze(&analysis)
            .expect("trusted exclusion analysis");
        assert_eq!(
            result
                .report
                .graphs
                .iter()
                .map(|graph| graph.source.as_str())
                .collect::<Vec<_>>(),
            vec![".github/workflows/generated-sibling.yml"]
        );
    }
}

#[test]
fn provider_documents_that_are_not_entrypoints_need_a_local_link() {
    let standalone_action = SourceSnapshot::new(BTreeMap::from([(
        ".github/actions/demo/action.yml".to_owned(),
        b"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n".to_vec(),
    )]))
    .expect("valid standalone action");
    let result = AnalysisEngine::new()
        .analyze(&request(standalone_action))
        .expect("standalone action is ignored");
    assert!(result.report.graphs.is_empty());
    assert!(result.report.inputs.is_empty());
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
fn lock_entries_bind_to_their_exact_call_and_apply_semantic_summaries() {
    let checkout_reference = "actions/checkout@v4";
    let setup_reference = "actions/setup-node@v4";
    let checkout_digest = content_digest(b"checkout implementation");
    let setup_digest = content_digest(b"setup-node implementation");
    let mut checkout = LockEntry::new(
        Provider::Github,
        checkout_reference,
        "checkout-revision",
        checkout_digest.clone(),
        "https://github.com/actions/checkout",
    );
    checkout.summary = Some(DependencySummary::new(
        true,
        Vec::<String>::new(),
        [Capability::SecretAccess],
        [ObservableEffect::CredentialUse],
    ));
    let setup = LockEntry::new(
        Provider::Github,
        setup_reference,
        "setup-node-revision",
        setup_digest.clone(),
        "https://github.com/actions/setup-node",
    );
    let lock = Lockfile::new([checkout, setup]).expect("valid two-entry lock");
    let source = format!(
        "on: push\njobs:\n  build:\n    steps:\n      - uses: {checkout_reference}\n      - uses: {setup_reference}\n"
    );
    let mut analysis = request(snapshot(&source));
    analysis.lock = lock_snapshot(&lock);
    let result = AnalysisEngine::new()
        .analyze(&analysis)
        .expect("locked analysis succeeds");

    let checkout_call = call_named(&result, checkout_reference);
    assert_eq!(
        checkout_call
            .attributes
            .get("dependency.digest")
            .and_then(|value| value.constants()),
        Some(std::slice::from_ref(&checkout_digest))
    );
    assert!(
        checkout_call
            .capabilities
            .contains(&Capability::SecretAccess)
    );
    assert!(
        checkout_call
            .effects
            .contains(&ObservableEffect::CredentialUse)
    );
    assert!(checkout_call.unknown.is_none());
    assert_eq!(
        checkout_call
            .attributes
            .get("dependency.summary")
            .and_then(|value| value.constants()),
        Some(&["complete".to_owned()][..])
    );

    let setup_call = call_named(&result, setup_reference);
    assert_eq!(
        setup_call
            .attributes
            .get("dependency.digest")
            .and_then(|value| value.constants()),
        Some(std::slice::from_ref(&setup_digest))
    );
}

#[test]
fn lock_matching_rejects_cross_provider_entries() {
    let reference = "actions/checkout@v4";
    let wrong_provider = LockEntry::new(
        Provider::Gitlab,
        reference,
        "gitlab-revision",
        content_digest(b"wrong provider implementation"),
        "https://gitlab.com/example/checkout",
    );
    let lock = Lockfile::new([wrong_provider]).expect("valid cross-provider lock fixture");
    let mut analysis = request(snapshot(&format!(
        "on: push\njobs:\n  build:\n    steps:\n      - uses: {reference}\n"
    )));
    analysis.lock = lock_snapshot(&lock);
    let result = AnalysisEngine::new()
        .analyze(&analysis)
        .expect("analysis succeeds without applying the wrong provider");
    assert!(
        !call_named(&result, reference)
            .attributes
            .contains_key("dependency.digest")
    );
}

#[test]
fn lock_matching_supports_docker_calls_and_circleci_orb_aliases() {
    let image = "ghcr.io/example/build@sha256:container";
    let docker_lock = Lockfile::new([LockEntry::new(
        Provider::Github,
        image,
        "container-revision",
        content_digest(b"container implementation"),
        "https://ghcr.io/example/build",
    )])
    .expect("valid container lock");
    let docker_sources = BTreeMap::from([
        (
            ".github/workflows/ci.yml".to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/container\n"
                .to_vec(),
        ),
        (
            ".github/actions/container/action.yml".to_owned(),
            format!("name: container\nruns:\n  using: docker\n  image: {image}\n").into_bytes(),
        ),
    ]);
    let mut docker_analysis = request(SourceSnapshot::new(docker_sources).expect("valid sources"));
    docker_analysis.lock = lock_snapshot(&docker_lock);
    let docker_result = AnalysisEngine::new()
        .analyze(&docker_analysis)
        .expect("docker lock analysis");
    assert!(
        call_named(&docker_result, &format!("docker:{image}"))
            .attributes
            .contains_key("dependency.digest")
    );

    let orb_reference = "circleci/node@5";
    let orb_lock = Lockfile::new([LockEntry::new(
        Provider::Circleci,
        orb_reference,
        "orb-revision",
        content_digest(b"orb implementation"),
        "https://circleci.com/developer/orbs/orb/circleci/node",
    )])
    .expect("valid orb lock");
    let circleci = r"version: 2.1
orbs:
  node: circleci/node@5
jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - node/test
workflows:
  delivery:
    jobs:
      - build
";
    let mut orb_analysis = request(
        SourceSnapshot::new(BTreeMap::from([(
            ".circleci/config.yml".to_owned(),
            circleci.as_bytes().to_vec(),
        )]))
        .expect("valid CircleCI snapshot"),
    );
    orb_analysis.lock = lock_snapshot(&orb_lock);
    let orb_result = AnalysisEngine::new()
        .analyze(&orb_analysis)
        .expect("orb lock analysis");
    assert!(
        call_named(&orb_result, "orb:node/test")
            .attributes
            .contains_key("dependency.digest")
    );
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
fn policy_findings_fail_gate_persona_but_remain_advisory_for_audit() {
    let policy = r#"
version = 2

[[rules]]
id = "ORG-STEP"
kind = "forbid"
message = "organization policy forbids steps"
severity = "error"
selector = { kind = "step" }
"#;
    let source = "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n";

    let mut gate = request(snapshot(source));
    gate.config = config_snapshot(policy, "trusted-policy");
    let gate_result = AnalysisEngine::new()
        .analyze(&gate)
        .expect("gate policy analysis");
    assert_eq!(gate_result.report.provenance.exit_code, 1);
    assert!(
        gate_result
            .report
            .policy_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "ORG-STEP")
    );

    let mut audit = gate;
    audit.persona = Persona::Audit;
    let audit_result = AnalysisEngine::new()
        .analyze(&audit)
        .expect("audit policy analysis");
    assert_eq!(audit_result.report.provenance.exit_code, 0);
    assert!(
        audit_result
            .report
            .policy_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "ORG-STEP")
    );
}

#[test]
fn static_analysis_completeness_reason_tracks_verifier_completeness() {
    let safe = AnalysisEngine::new()
        .analyze(&request(snapshot(
            "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
        )))
        .expect("complete analysis");
    assert!(
        !safe
            .report
            .provenance
            .completeness_reasons
            .iter()
            .any(|reason| reason == "Incomplete.Static_analysis")
    );

    let dynamic = AnalysisEngine::new()
        .analyze(&request(snapshot(
            "on: push\njobs:\n  build:\n    steps:\n      - uses: ${{ matrix.action }}\n",
        )))
        .expect("incomplete analysis still produces a report");
    assert!(
        dynamic
            .report
            .provenance
            .completeness_reasons
            .iter()
            .any(|reason| reason == "Incomplete.Static_analysis")
    );
}

#[test]
fn engine_links_local_dependencies_from_the_same_immutable_snapshot() {
    let action_path = ".github/actions/demo/action.yml";
    let workflow_path = ".github/workflows/ci.yml";
    let sources = BTreeMap::from([
        (
            workflow_path.to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n"
                .to_vec(),
        ),
        (
            action_path.to_owned(),
            b"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n".to_vec(),
        ),
    ]);
    let engine = AnalysisEngine::new();
    let result = engine
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
    assert_eq!(
        engine
            .affected_sources(&[action_path.to_owned()])
            .expect("dependency index is readable"),
        vec![action_path.to_owned(), workflow_path.to_owned()]
    );
}

#[test]
fn dependency_index_is_replaced_when_a_local_reference_is_removed() {
    let action_path = ".github/actions/demo/action.yml";
    let workflow_path = ".github/workflows/ci.yml";
    let action = b"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n";
    let engine = AnalysisEngine::new();
    let linked = SourceSnapshot::new(BTreeMap::from([
        (
            workflow_path.to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n"
                .to_vec(),
        ),
        (action_path.to_owned(), action.to_vec()),
    ]))
    .expect("valid linked snapshot");
    engine
        .analyze(&request(linked))
        .expect("linked analysis succeeds");
    assert_eq!(
        engine
            .affected_sources(&[action_path.to_owned()])
            .expect("dependency index is readable"),
        vec![action_path.to_owned(), workflow_path.to_owned()]
    );

    let unlinked = SourceSnapshot::new(BTreeMap::from([
        (
            workflow_path.to_owned(),
            b"on: push\njobs:\n  build:\n    steps:\n      - run: echo independent\n".to_vec(),
        ),
        (action_path.to_owned(), action.to_vec()),
    ]))
    .expect("valid unlinked snapshot");
    engine
        .analyze(&request(unlinked))
        .expect("unlinked analysis succeeds");
    assert_eq!(
        engine
            .affected_sources(&[action_path.to_owned()])
            .expect("dependency index is readable"),
        vec![action_path.to_owned()]
    );
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
fn adapter_parse_populates_the_analysis_cst_cache() {
    let engine = AnalysisEngine::new();
    let source = "on: push\njobs:\n  build:\n    steps:\n      - run: echo cached\n";
    let document = engine
        .parse_document(".github/workflows/ci.yml", source, Budget::default())
        .expect("adapter parse succeeds");
    assert!(document.problems().is_empty());
    assert_eq!(engine.statistics().parse_misses, 1);

    engine
        .analyze(&request(snapshot(source)))
        .expect("analysis reuses the parsed document");
    assert_eq!(engine.statistics().parse_misses, 1);
    assert_eq!(engine.statistics().parse_hits, 1);
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

#[test]
fn recoverable_frontend_problems_are_reported_as_policy_diagnostics() {
    let result = AnalysisEngine::new()
        .analyze(&request(snapshot(
            "on: push\njobs:\n  build:\n    needs: missing-job\n    steps:\n      - run: echo safe\n",
        )))
        .expect("semantic frontend problem preserves a report");
    assert!(
        result
            .report
            .policy_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.rule_id == "GH-UNKNOWN-NEEDS")
    );
}
