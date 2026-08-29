use workflow_verifier::internal::conformance::domain::{Node, NodeKind, Phase, Program, Provider};
use workflow_verifier::internal::conformance::foundation::{
    Digest, Position, SourceId, Span, valid_content_digest,
};
use workflow_verifier::internal::conformance::product::{
    AnalysisProvenance, BuildInfo, CheckReportView, Gate, GateResult, GraphDocumentView, GraphKind,
    ReportInput, authenticate_check_report, authenticate_graph_document,
};
use workflow_verifier::internal::conformance::verifier::Persona;

fn program() -> Program {
    let mut program = Program::empty(Provider::Github, ".github/workflows/ci.yml");
    let node = Node::simple(
        Provider::Github,
        NodeKind::Workflow,
        "CI",
        Phase::Compile,
        Span::new(
            SourceId(0),
            Position::default(),
            Position {
                byte: 2,
                line: 1,
                column: 3,
            },
        ),
    );
    program.add_entrypoint(node.id);
    program.add_node(node);
    program.finalize();
    program
}

fn build(compiler: &str) -> BuildInfo {
    BuildInfo {
        compiler: compiler.to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
        source_commit: Some("test-commit".to_owned()),
    }
}

fn provenance() -> AnalysisProvenance {
    AnalysisProvenance {
        config_origin: ".workflow-verifier.toml".to_owned(),
        config_trust: "built-in".to_owned(),
        config_digest: Digest::of_bytes(b"config"),
        lock_digest: Digest::of_bytes(b"lock"),
        analysis_manifest_digest: Digest::of_bytes(b"manifest"),
        provider_profiles: vec!["github-semantic-v1".to_owned()],
    }
}

#[test]
fn report_1_has_full_and_tool_independent_analysis_digests() {
    let program = program();
    let inputs = [ReportInput {
        source: SourceId(0),
        path: ".github/workflows/ci.yml".to_owned(),
        digest: Digest::of_bytes(b"workflow"),
    }];
    let provenance = provenance();
    let gate = Gate {
        result: GateResult::Pass,
        exit_code: 0,
    };
    let first_build = build("rustc 1.98.0");
    let second_build = build("rustc 1.99.0");
    let first = CheckReportView::new(
        &first_build,
        Persona::Gate,
        &program,
        CheckReportView::results(&inputs, &[], &[], gate, &[], &provenance),
    );
    let second = CheckReportView::new(
        &second_build,
        Persona::Gate,
        &program,
        CheckReportView::results(&inputs, &[], &[], gate, &[], &provenance),
    );

    assert!(valid_content_digest(&first.digest().to_string()));
    assert!(valid_content_digest(&first.analysis_digest().to_string()));
    assert_ne!(first.digest(), second.digest());
    assert_eq!(first.analysis_digest(), second.analysis_digest());
    let document: serde_json::Value =
        serde_json::from_str(&first.to_canonical_json()).expect("valid report JSON");
    assert_eq!(document["schema"], "workflow-verifier-report/1");
    assert!(document.get("graphs").is_none());
    assert!(document["tool"].get("binary_digest").is_none());
    assert!(authenticate_check_report(&first.to_canonical_json()).is_ok());

    let tampered = first
        .to_canonical_json()
        .replace("\"persona\":\"gate\"", "\"persona\":\"audit\"");
    assert!(authenticate_check_report(&tampered).is_err());
}

#[test]
fn graph_1_uses_dense_numeric_endpoints_without_edge_ids() {
    let program = program();
    let view = GraphDocumentView::new(GraphKind::All, &program);
    let document: serde_json::Value =
        serde_json::from_str(&view.to_canonical_json()).expect("valid graph JSON");
    assert_eq!(document["schema"], "workflow-verifier-graph/1");
    assert_eq!(document["nodes"][0]["id"], 0);
    assert!(document["nodes"][0]["source"].is_number());
    assert!(document["nodes"][0].get("provider").is_none());
    assert!(
        document["edges"]
            .as_array()
            .expect("edge array")
            .iter()
            .all(|edge| edge.get("id").is_none())
    );
    assert!(authenticate_graph_document(&view.to_canonical_json()).is_ok());
    let tampered = view
        .to_canonical_json()
        .replace("\"name\":\"CI\"", "\"name\":\"CI🔥\"");
    assert!(authenticate_graph_document(&tampered).is_err());
}
