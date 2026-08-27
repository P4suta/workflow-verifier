use std::collections::BTreeMap;
use workflow_verifier_domain::{
    AbstractValue, Capability, Condition, Graph, Node, NodeKind, ObservableEffect, Phase, Provider,
    Secrecy, Trust,
};
use workflow_verifier_foundation::{Budget, JsonValue, Span, content_digest, valid_content_digest};
use workflow_verifier_product::{
    AnalysisCacheEntry, CacheKeyInput, Config, ConfigParseOptions, ConfigTrust, DependencySummary,
    FixProposal, LockEntry, Lockfile, PolicyExpectation, PolicyPredicate, PolicyRule,
    PolicyRuleKind, PolicySelector, Report, Severity, Suppression, cache_key, evaluate_policy,
    evaluate_policy_fixture, link_local, migrate_config_v1, report_to_sarif,
};
use workflow_verifier_syntax::YamlDocument;
use workflow_verifier_verifier::{Confidence, Diagnostic, Persona};

fn node_with_capability(capability: Capability) -> Node {
    Node::new(
        Provider::Github,
        NodeKind::Command,
        "git push",
        Phase::Run,
        Span::default(),
        Condition::True,
        BTreeMap::from([(
            "value".to_owned(),
            AbstractValue::string_constant("input", Trust::Untrusted, Secrecy::Public, Vec::new()),
        )]),
        [capability],
        [],
        None,
    )
}

fn lock_source_with_summary(summary: JsonValue) -> String {
    let entry = JsonValue::Object(BTreeMap::from([
        (
            "digest".to_owned(),
            JsonValue::String(format!("sha256:{}", "a".repeat(64))),
        ),
        (
            "provider".to_owned(),
            JsonValue::String("github".to_owned()),
        ),
        (
            "reference".to_owned(),
            JsonValue::String("acme/action@v1".to_owned()),
        ),
        (
            "revision".to_owned(),
            JsonValue::String("revision".to_owned()),
        ),
        (
            "source".to_owned(),
            JsonValue::String("https://github.com/acme/action".to_owned()),
        ),
        ("summary".to_owned(), summary),
    ]));
    let unsigned = JsonValue::Object(BTreeMap::from([
        ("entries".to_owned(), JsonValue::Array(vec![entry.clone()])),
        ("schema".to_owned(), JsonValue::String("lock-v2".to_owned())),
    ]));
    JsonValue::Object(BTreeMap::from([
        ("entries".to_owned(), JsonValue::Array(vec![entry])),
        (
            "integrity".to_owned(),
            JsonValue::String(content_digest(unsigned.canonical())),
        ),
        ("schema".to_owned(), JsonValue::String("lock-v2".to_owned())),
    ]))
    .canonical_line()
}

#[test]
fn lock_v2_semantic_summaries_are_typed_exact_and_canonical() {
    let summary = DependencySummary::new(
        false,
        ["metadata incomplete".to_owned()],
        [Capability::Shell],
        [ObservableEffect::CommandExecution],
    );
    let mut entry = LockEntry::new(
        Provider::Github,
        "acme/action@v1",
        "revision",
        format!("sha256:{}", "a".repeat(64)),
        "https://github.com/acme/action",
    );
    entry.summary = Some(summary.clone());
    let lock = Lockfile::new([entry]).expect("typed lock-v2");
    assert_eq!(
        Lockfile::parse(&lock.to_canonical_json())
            .unwrap()
            .entries()[0]
            .summary,
        Some(summary)
    );

    let unknown_capability = JsonValue::Object(BTreeMap::from([
        (
            "capabilities".to_owned(),
            JsonValue::Array(vec![JsonValue::String("magic_shell".to_owned())]),
        ),
        ("complete".to_owned(), JsonValue::Boolean(true)),
        ("effects".to_owned(), JsonValue::Array(Vec::new())),
        ("reasons".to_owned(), JsonValue::Array(Vec::new())),
    ]));
    assert!(
        Lockfile::parse(&lock_source_with_summary(unknown_capability))
            .is_err_and(|error| error.contains("unknown dependency summary capabilities"))
    );

    let extended = JsonValue::Object(BTreeMap::from([
        ("capabilities".to_owned(), JsonValue::Array(Vec::new())),
        ("complete".to_owned(), JsonValue::Boolean(true)),
        ("effects".to_owned(), JsonValue::Array(Vec::new())),
        ("reasons".to_owned(), JsonValue::Array(Vec::new())),
        ("surprise".to_owned(), JsonValue::Boolean(true)),
    ]));
    assert!(Lockfile::parse(&lock_source_with_summary(extended)).is_err());
}

#[test]
fn trusted_config_v2_is_typed_canonical_and_repository_config_cannot_weaken_policy() {
    let source = r#"
version = 2
persona = "audit"
frontends = ["github", "gitlab", "azure", "circleci"]
offline = true
source_exclusions = ["generated"]

[resolver]
require_immutable = true
allowed_origins = [{ origin = "https://git.example.test:443", path_prefixes = ["/org"] }]
"#;
    let config = Config::parse(
        source,
        ConfigParseOptions {
            origin: "policy.toml".to_owned(),
            trust: ConfigTrust::TrustedPolicy,
            today: Some("2026-08-27".to_owned()),
        },
    )
    .expect("trusted config");
    assert_eq!(
        config.resolver.allowed_origins[0].origin,
        "https://git.example.test"
    );
    assert_eq!(config.resolver.allowed_origins[0].path_prefixes, ["/org/"]);
    assert!(valid_content_digest(&config.provenance.digest));
    assert!(JsonValue::parse(&config.to_canonical_json()).is_ok());

    let repository = Config::parse(
        source,
        ConfigParseOptions {
            trust: ConfigTrust::Repository,
            ..ConfigParseOptions::default()
        },
    );
    assert!(repository.is_err());
    assert!(
        Config::parse(
            "version = 2\nsurprise = true\n",
            ConfigParseOptions::default()
        )
        .is_err()
    );
}

#[test]
fn config_trust_persona_and_suppression_matching_are_exact() {
    assert_eq!(
        [
            ConfigTrust::BuiltIn,
            ConfigTrust::TrustedPolicy,
            ConfigTrust::Repository,
        ]
        .map(ConfigTrust::name),
        ["built-in", "trusted-policy", "repository"]
    );
    let paranoid = Config::parse(
        "version = 2\npersona = \"paranoid\"\n",
        ConfigParseOptions::default(),
    )
    .expect("paranoid is a supported persona");
    assert_eq!(paranoid.persona, Persona::Paranoid);

    let diagnostic = Diagnostic::new(
        "WV-SEC-001",
        Severity::Error,
        Confidence::High,
        "finding",
        Span {
            file: ".github\\workflows\\ci.yml".to_owned(),
            ..Span::default()
        },
        Vec::new(),
        [],
        Vec::<String>::new(),
        None,
    );
    let suppression = |rule: &str, path: &str| Suppression {
        rule: rule.to_owned(),
        path: path.to_owned(),
        reason: "owned exception".to_owned(),
        owner: "platform".to_owned(),
        expiry: "not-evaluated-by-matcher".to_owned(),
    };
    for entry in [
        suppression("WV-SEC-001", "**"),
        suppression("WV-SEC-001", ".github/workflows/ci.yml"),
    ] {
        let config = Config {
            suppressions: vec![entry],
            ..Config::default()
        };
        assert!(config.suppressed(&diagnostic));
    }
    for entry in [
        suppression("WV-SEC-002", "**"),
        suppression("WV-SEC-001", ".github/workflows/other.yml"),
    ] {
        let config = Config {
            suppressions: vec![entry],
            ..Config::default()
        };
        assert!(!config.suppressed(&diagnostic));
    }
}

#[test]
fn policy_selectors_emit_stable_diagnostics() {
    let node = node_with_capability(Capability::RepositoryWrite);
    let mut graph = Graph::empty(Provider::Github, ".github/workflows/ci.yml");
    graph.add_entrypoint(node.id.clone());
    graph.add_node(node);
    let rule = PolicyRule {
        id: "ORG-WRITE".to_owned(),
        kind: PolicyRuleKind::Forbid,
        selector: PolicySelector::All(vec![PolicyPredicate::Capability(
            Capability::RepositoryWrite,
        )]),
        message: "repository writes are forbidden".to_owned(),
        severity: Severity::Error,
    };
    let first = evaluate_policy(std::slice::from_ref(&rule), &graph);
    let second = evaluate_policy(&[rule], &graph);
    assert_eq!(first, second);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].rule_id, "ORG-WRITE");
    assert_eq!(first[0].trace[0].label, "policy selector matched");
}

#[test]
fn policy_fixture_v1_is_strict_sorted_and_compares_rule_sets() {
    let expectation = PolicyExpectation::parse(
        r#"{"expected_rules":["ORG-WRITE","ORG-NET"],"schema":"policy-fixture-v1"}"#,
    )
    .expect("valid expectation");
    assert_eq!(expectation.expected_rules(), ["ORG-NET", "ORG-WRITE"]);
    assert!(
        PolicyExpectation::parse(
            r#"{"expected_rules":["ORG-NET","ORG-NET"],"schema":"policy-fixture-v1"}"#
        )
        .is_err()
    );
    assert!(
        PolicyExpectation::parse(
            r#"{"expected_rules":[],"extra":true,"schema":"policy-fixture-v1"}"#
        )
        .is_err()
    );

    let mut graph = Graph::empty(Provider::Github, ".github/workflows/case.yml");
    graph.add_node(node_with_capability(Capability::RepositoryWrite));
    let diagnostic = evaluate_policy(
        &[PolicyRule {
            id: "ORG-WRITE".to_owned(),
            kind: PolicyRuleKind::Forbid,
            selector: PolicySelector::All(vec![PolicyPredicate::Capability(
                Capability::RepositoryWrite,
            )]),
            message: "write denied".to_owned(),
            severity: Severity::Error,
        }],
        &graph,
    );
    let result = evaluate_policy_fixture(".github\\workflows\\case.yml", &expectation, &diagnostic);
    assert!(!result.passed());
    assert_eq!(result.missing_rules(), ["ORG-NET"]);
    assert!(result.unexpected_rules().is_empty());
    assert_eq!(
        result
            .to_json()
            .member("fixture")
            .and_then(JsonValue::as_str),
        Some(".github/workflows/case.yml")
    );
}

#[test]
fn config_v1_migration_adds_non_ambient_security_metadata_and_revalidates_v2() {
    let legacy = r#"
version = 1
persona = "gate"

[[suppressions]]
rule = "WV-SEC-001"
path = ".github/workflows/ci.yml"
reason = "tracked exception"

[resolver]
allowed_sources = ["https://CI.Example.test/includes"]

[sandbox]
backend = "oci:docker"
image = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    assert!(migrate_config_v1(legacy, None, None, Some("2026-08-27")).is_err());
    let migrated = migrate_config_v1(
        legacy,
        Some("platform-team"),
        Some("2027-01-31"),
        Some("2026-08-27"),
    )
    .expect("valid v1 migration");
    assert!(migrated.ends_with('\n'));
    assert!(migrated.contains("version = 2"));
    assert!(migrated.contains("allowed_origins"));
    assert!(!migrated.contains("allowed_sources"));
    assert!(migrated.contains("owner = \"platform-team\""));
    assert!(migrated.contains("expiry = \"2027-01-31\""));
    let parsed = Config::parse(
        &migrated,
        ConfigParseOptions {
            origin: "migration:test".to_owned(),
            trust: ConfigTrust::TrustedPolicy,
            today: Some("2026-08-27".to_owned()),
        },
    )
    .expect("migrated config is strict config-v2");
    assert_eq!(
        parsed.resolver.allowed_origins[0].origin,
        "https://ci.example.test"
    );
    assert_eq!(
        parsed.resolver.allowed_origins[0].path_prefixes,
        ["/includes/"]
    );
    assert_eq!(
        parsed.sandbox.capsule_digest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[test]
fn safe_fixes_are_atomic_preserve_trivia_and_reparse() {
    let source = "uses: actions/checkout@v4 # keep rationale\npermissions: write-all\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    let pin = FixProposal::pin_dependency(
        &document,
        "actions/checkout@v4",
        "0123456789abcdef0123456789abcdef01234567",
    )
    .expect("pin proposal");
    let permission = FixProposal::reduce_write_all(
        &document,
        &[Capability::RepositoryWrite, Capability::TokenWrite],
    )
    .expect("permission proposal");
    let combined = FixProposal::combine(&[pin, permission]).expect("non-overlapping transaction");
    let edited = combined.apply(&document).expect("safe edit");
    assert!(edited.contains("actions/checkout@0123456789abcdef0123456789abcdef01234567"));
    assert!(edited.contains("# keep rationale"));
    assert!(edited.contains("permissions: read-all"));
    assert!(
        YamlDocument::parse("ci.yml", &edited, Budget::default())
            .invalid_regions()
            .is_empty()
    );
    assert!(
        combined
            .unified_diff("ci.yml", source, &edited)
            .starts_with("--- ci.yml\n+++ ci.yml\n")
    );
}

#[test]
fn local_linking_is_recursive_content_addressed_and_cannot_escape() {
    let root_source =
        "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/demo\n";
    let root = workflow_verifier_frontend::compile_auto(
        ".github/workflows/ci.yml",
        root_source,
        Budget::default(),
    )
    .expect("root workflow");
    let sources = BTreeMap::from([
        (
            ".github/workflows/ci.yml".to_owned(),
            root_source.to_owned(),
        ),
        (
            ".github/actions/demo/action.yml".to_owned(),
            "name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n".to_owned(),
        ),
    ]);
    let linked = link_local(&sources, vec![root], Budget::default()).expect("local link");
    assert_eq!(linked.len(), 2);
    let call = linked
        .iter()
        .flat_map(|compilation| &compilation.graph.nodes)
        .find(|node| node.name == "./.github/actions/demo")
        .expect("local call");
    assert!(call.unknown.is_none());
    assert!(call.attributes.contains_key("dependency.digest"));

    let escaping_source =
        "on: push\njobs:\n  build:\n    steps:\n      - uses: ../../outside/action\n";
    let escaping = workflow_verifier_frontend::compile_auto(
        ".github/workflows/ci.yml",
        escaping_source,
        Budget::default(),
    )
    .expect("syntactically valid workflow");
    assert!(link_local(&BTreeMap::new(), vec![escaping], Budget::default()).is_err());
}

#[test]
fn cache_key_and_entry_are_order_independent_and_self_authenticating() {
    let inputs = vec![
        CacheKeyInput {
            path: "b.yml".to_owned(),
            digest: "sha256:b".to_owned(),
        },
        CacheKeyInput {
            path: "a.yml".to_owned(),
            digest: "sha256:a".to_owned(),
        },
    ];
    let first = cache_key("0.1.0", "config", "lock", &inputs);
    let mut reverse = inputs;
    reverse.reverse();
    assert_eq!(first, cache_key("0.1.0", "config", "lock", &reverse));
    let entry =
        AnalysisCacheEntry::new(first, 1, "{\"schema\":\"report-v3\"}\n").expect("cache entry");
    assert!(entry.verify_integrity());
    assert_eq!(
        AnalysisCacheEntry::parse(&entry.to_canonical_json()),
        Ok(entry)
    );
    assert!(AnalysisCacheEntry::new("key", 6, "report").is_err());
}

#[test]
fn sarif_output_is_canonical_and_carries_report_identity() {
    let report: Report = super_report_fixture::report();
    let sarif = report_to_sarif(&report);
    let root = JsonValue::parse(&sarif).expect("strict SARIF JSON");
    assert_eq!(
        root.member("version").and_then(JsonValue::as_str),
        Some("2.1.0")
    );
    assert!(sarif.contains(&report.digest));
    assert!(sarif.ends_with('\n'));
}

mod super_report_fixture {
    use workflow_verifier_domain::{Graph, Node, NodeKind, Phase, Provider};
    use workflow_verifier_foundation::{Position, Span};
    use workflow_verifier_product::{BuildInfo, GateResult, Report, ReportInput, ReportProvenance};
    use workflow_verifier_verifier::{Persona, verify};

    pub fn report() -> Report {
        let mut graph = Graph::empty(Provider::Github, ".github/workflows/ci.yml");
        let node = Node::simple(
            Provider::Github,
            NodeKind::Command,
            "echo safe",
            Phase::Run,
            Span::new(
                ".github/workflows/ci.yml",
                Position::default(),
                Position {
                    byte: 9,
                    line: 1,
                    column: 10,
                },
            ),
        );
        graph.add_entrypoint(node.id.clone());
        graph.add_node(node);
        let verification = verify(Persona::Gate, &graph);
        Report::new(
            Persona::Gate,
            vec![ReportInput {
                path: ".github/workflows/ci.yml".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            }],
            vec![graph],
            vec![verification],
            Vec::new(),
            BuildInfo {
                implementation: "rust".to_owned(),
                compiler: "rustc".to_owned(),
                target: "test".to_owned(),
                source_commit: None,
                binary_digest: format!("sha256:{}", "b".repeat(64)),
            },
            ReportProvenance {
                config_origin: "built-in".to_owned(),
                config_trust: "built-in".to_owned(),
                config_digest: format!("sha256:{}", "c".repeat(64)),
                lock_digest: format!("sha256:{}", "d".repeat(64)),
                source_manifest_digest: format!("sha256:{}", "e".repeat(64)),
                provider_profiles: vec!["github-semantic-v1".to_owned()],
                completeness_reasons: Vec::new(),
                gate_result: GateResult::Pass,
                exit_code: 0,
            },
        )
    }
}
