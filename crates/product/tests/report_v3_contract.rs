use std::collections::BTreeMap;
use workflow_verifier_domain::{Graph, Node, NodeKind, Phase, Provider};
use workflow_verifier_foundation::{JsonValue, Position, Span, valid_content_digest};
use workflow_verifier_product::{BuildInfo, GateResult, Report, ReportInput, ReportProvenance};
use workflow_verifier_verifier::{Persona, verify};

fn graph() -> Graph {
    let mut graph = Graph::empty(Provider::Github, ".github/workflows/ci.yml");
    let node = Node::simple(
        Provider::Github,
        NodeKind::Workflow,
        "CI",
        Phase::Compile,
        Span::new(
            ".github/workflows/ci.yml",
            Position::default(),
            Position {
                byte: 2,
                line: 1,
                column: 3,
            },
        ),
    );
    graph.add_entrypoint(node.id.clone());
    graph.add_node(node);
    graph
}

fn build(compiler: &str, binary: char) -> BuildInfo {
    BuildInfo {
        implementation: "rust".to_owned(),
        compiler: compiler.to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        source_commit: None,
        binary_digest: format!("sha256:{}", binary.to_string().repeat(64)),
    }
}

fn provenance() -> ReportProvenance {
    ReportProvenance {
        config_origin: ".workflow-verifier.toml".to_owned(),
        config_trust: "built-in".to_owned(),
        config_digest: format!("sha256:{}", "1".repeat(64)),
        lock_digest: format!("sha256:{}", "2".repeat(64)),
        source_manifest_digest: format!("sha256:{}", "3".repeat(64)),
        provider_profiles: vec!["github-semantic-v1".to_owned()],
        completeness_reasons: Vec::new(),
        gate_result: GateResult::Pass,
        exit_code: 0,
    }
}

fn report(build: BuildInfo) -> Report {
    let graph = graph();
    let verification = verify(Persona::Gate, &graph);
    Report::new(
        Persona::Gate,
        vec![ReportInput {
            path: ".github/workflows/ci.yml".to_owned(),
            digest: format!("sha256:{}", "4".repeat(64)),
        }],
        vec![graph],
        vec![verification],
        Vec::new(),
        build,
        provenance(),
    )
}

#[test]
fn report_v3_has_full_and_semantic_self_digests() {
    let report = report(build("rustc 1.98.0", 'a'));
    assert!(valid_content_digest(&report.digest));
    assert!(valid_content_digest(&report.semantic_digest));
    assert!(report.verify_digests());
    let parsed = JsonValue::parse(&report.to_canonical_json()).expect("strict canonical report");
    assert_eq!(
        parsed.member("schema").and_then(JsonValue::as_str),
        Some("report-v3")
    );
    assert_eq!(
        parsed
            .member("tool")
            .and_then(|tool| tool.member("build"))
            .and_then(|build| build.member("implementation"))
            .and_then(JsonValue::as_str),
        Some("rust")
    );
}

#[test]
fn build_provenance_changes_full_digest_but_not_semantics() {
    let first = report(build("rustc 1.98.0", 'a'));
    let second = report(build("rustc 1.98.1", 'b'));
    assert_ne!(first.digest, second.digest);
    assert_eq!(first.semantic_digest, second.semantic_digest);
}

#[test]
fn report_order_and_absolute_working_directory_do_not_leak() {
    let report = report(build("rustc 1.98.0", 'a'));
    let canonical = report.to_canonical_json();
    assert!(!canonical.contains("/home/"));
    assert!(!canonical.contains("timing"));
    assert!(canonical.ends_with('\n'));
    assert!(!canonical.ends_with("\n\n"));
    let object = JsonValue::parse(&canonical).expect("strict report");
    assert!(matches!(
        object.member("summary"),
        Some(JsonValue::Object(_))
    ));
    let _type_witness: BTreeMap<String, JsonValue> = BTreeMap::new();
}
