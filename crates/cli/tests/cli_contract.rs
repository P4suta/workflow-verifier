use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::{JsonValue, content_digest};
use workflow_verifier_helper_runtime::{source_snapshot, source_snapshot_with_exclusions};
use workflow_verifier_product::{Config, ConfigParseOptions, ConfigTrust, LockEntry, Lockfile};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("workflow-verifier-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create fixture");
        Self(path)
    }

    fn write(&self, path: &str, source: &str) -> PathBuf {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parents");
        }
        fs::write(&path, source).expect("write fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(cwd: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_workflow-verifier"))
        .args(arguments)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output()
        .expect("invoke workflow-verifier")
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 process output")
}

#[test]
fn version_help_and_invalid_input_follow_the_public_exit_contract() {
    let fixture = Fixture::new();
    let version = invoke(&fixture.0, &["version"]);
    assert_eq!(version.status.code(), Some(0));
    assert_eq!(text(&version.stdout), "workflow-verifier 0.1.0\n");
    assert!(version.stderr.is_empty());

    let help = invoke(&fixture.0, &["--help"]);
    assert_eq!(help.status.code(), Some(0));
    for command in [
        "check",
        "resolve",
        "explain",
        "graph",
        "diff",
        "fix",
        "policy",
        "sandbox",
        "doctor",
        "completion",
        "migrate",
        "version",
        "lsp",
        "auth",
    ] {
        assert!(
            text(&help.stdout).contains(command),
            "help omitted {command}"
        );
    }

    let invalid = invoke(&fixture.0, &["check", "--format", "xml", "."]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(text(&invalid.stderr).contains("--format"));

    let token_on_argv = invoke(
        &fixture.0,
        &["auth", "login", "github", "--token", "do-not-print-this"],
    );
    assert_eq!(token_on_argv.status.code(), Some(2));
    assert!(!text(&token_on_argv.stderr).contains("do-not-print-this"));
}

#[test]
fn check_json_is_report_v3_and_output_is_atomic_machine_stdout() {
    let fixture = Fixture::new();
    let workflow = fixture.write(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    let output = invoke(
        &fixture.0,
        &["check", "--format", "json", workflow.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty());
    let report = JsonValue::parse(text(&output.stdout)).expect("strict product JSON");
    assert_eq!(
        report.member("schema").and_then(JsonValue::as_str),
        Some("report-v3")
    );
    assert_eq!(
        report
            .member("tool")
            .and_then(|tool| tool.member("build"))
            .and_then(|build| build.member("implementation"))
            .and_then(JsonValue::as_str),
        Some("rust")
    );
    let build = report
        .member("tool")
        .and_then(|tool| tool.member("build"))
        .expect("build provenance");
    let expected_binary_digest = content_digest(
        fs::read(env!("CARGO_BIN_EXE_workflow-verifier")).expect("read analyzer binary"),
    );
    assert_eq!(
        build.member("binary_digest").and_then(JsonValue::as_str),
        Some(expected_binary_digest.as_str())
    );
    assert!(
        build
            .member("compiler")
            .and_then(JsonValue::as_str)
            .is_some_and(|value| value.starts_with("rustc "))
    );
    assert!(
        build
            .member("target")
            .and_then(JsonValue::as_str)
            .is_some_and(|value| value != "unknown-target" && value.contains('-'))
    );

    let path = fixture.0.join("report.json");
    let written = invoke(
        &fixture.0,
        &[
            "check",
            "--format",
            "json",
            "--output",
            path.to_str().unwrap(),
            workflow.to_str().unwrap(),
        ],
    );
    assert_eq!(written.status.code(), Some(0));
    assert!(written.stdout.is_empty());
    assert_eq!(fs::read_to_string(path).unwrap(), text(&output.stdout));
}

#[test]
fn explicit_file_target_scopes_analysis_to_the_selected_source() {
    let fixture = Fixture::new();
    let selected = fixture.write(
        "selected.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: ./actions/demo\n",
    );
    fixture.write(
        "unrelated.yml",
        "on: push\njobs:\n  unrelated:\n    steps:\n      - run: echo unrelated\n",
    );
    let action = fixture.write(
        "actions/demo/action.yml",
        "name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n",
    );

    let selected_output = invoke(
        &fixture.0,
        &["check", "--format", "json", selected.to_str().unwrap()],
    );
    assert_eq!(
        selected_output.status.code(),
        Some(0),
        "{}",
        text(&selected_output.stderr)
    );
    let report = JsonValue::parse(text(&selected_output.stdout)).expect("report-v3");
    let sources: Vec<_> = report
        .member("graphs")
        .and_then(JsonValue::as_array)
        .expect("graphs")
        .iter()
        .filter_map(|graph| graph.member("source").and_then(JsonValue::as_str))
        .collect();
    assert_eq!(sources, vec!["selected.yml"]);

    let action_output = invoke(
        &fixture.0,
        &["check", "--format", "json", action.to_str().unwrap()],
    );
    assert_eq!(
        action_output.status.code(),
        Some(0),
        "{}",
        text(&action_output.stderr)
    );
    let report = JsonValue::parse(text(&action_output.stdout)).expect("report-v3");
    let sources: Vec<_> = report
        .member("graphs")
        .and_then(JsonValue::as_array)
        .expect("graphs")
        .iter()
        .filter_map(|graph| graph.member("source").and_then(JsonValue::as_str))
        .collect();
    assert_eq!(sources, vec!["action.yml"]);

    let nested = fixture.write(
        ".github/workflows/nested.yml",
        "on: push\njobs:\n  nested:\n    steps:\n      - run: echo nested\n",
    );
    let nested_output = invoke(
        &fixture.0,
        &["check", "--format", "json", nested.to_str().unwrap()],
    );
    assert_eq!(
        nested_output.status.code(),
        Some(0),
        "{}",
        text(&nested_output.stderr)
    );
    let report = JsonValue::parse(text(&nested_output.stdout)).expect("report-v3");
    let sources: Vec<_> = report
        .member("graphs")
        .and_then(JsonValue::as_array)
        .expect("graphs")
        .iter()
        .filter_map(|graph| graph.member("source").and_then(JsonValue::as_str))
        .collect();
    assert_eq!(sources, vec!["nested.yml"]);
    assert_eq!(
        report
            .member("snapshot")
            .and_then(|snapshot| snapshot.member("digest"))
            .and_then(JsonValue::as_str),
        Some(
            &*source_snapshot(nested.parent().expect("nested workflow parent"))
                .expect("file-target source snapshot")
                .manifest
                .digest,
        )
    );
}

#[test]
fn resolve_scopes_an_explicit_file_without_widening_its_workspace() {
    let fixture = Fixture::new();
    let selected = fixture.write(
        "selected.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: ./actions/demo\n",
    );
    fixture.write(
        "actions/demo/action.yml",
        "name: demo\nruns:\n  using: composite\n  steps:\n    - uses: acme/selected@v1\n",
    );
    fixture.write(
        "unrelated.yml",
        "on: push\njobs:\n  unrelated:\n    steps:\n      - uses: acme/unrelated@v1\n",
    );

    let output = invoke(&fixture.0, &["resolve", selected.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("./actions/demo"));
    assert!(!text(&output.stderr).contains("acme/selected@v1"));
    assert!(!text(&output.stderr).contains("acme/unrelated@v1"));
}

#[test]
fn resolve_walks_local_dependency_closure_for_a_workspace_target() {
    let fixture = Fixture::new();
    fixture.write(
        ".github/workflows/selected.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: ./actions/demo\n",
    );
    fixture.write(
        "actions/demo/action.yml",
        "name: demo\nruns:\n  using: composite\n  steps:\n    - uses: acme/selected@v1\n",
    );

    let output = invoke(&fixture.0, &["resolve", "."]);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("acme/selected@v1"));
    assert!(!text(&output.stderr).contains("./actions/demo"));
}

#[test]
fn trusted_config_persona_and_provenance_apply_unless_cli_overrides_them() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\npersona = \"audit\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    let configured = invoke(
        &fixture.0,
        &[
            "check",
            "--format",
            "json",
            "--trust-repository-config",
            ".",
        ],
    );
    assert_eq!(
        configured.status.code(),
        Some(0),
        "{}",
        text(&configured.stderr)
    );
    let report = JsonValue::parse(text(&configured.stdout)).expect("report-v3");
    assert_eq!(
        report.member("persona").and_then(JsonValue::as_str),
        Some("audit")
    );
    assert_eq!(
        report
            .member("configuration")
            .and_then(|configuration| configuration.member("origin"))
            .and_then(JsonValue::as_str),
        Some("trusted-policy:.workflow-verifier.toml")
    );

    let overridden = invoke(
        &fixture.0,
        &[
            "check",
            "--format",
            "json",
            "--trust-repository-config",
            "--persona",
            "paranoid",
            ".",
        ],
    );
    assert_eq!(overridden.status.code(), Some(0));
    assert_eq!(
        JsonValue::parse(text(&overridden.stdout))
            .unwrap()
            .member("persona")
            .and_then(JsonValue::as_str),
        Some("paranoid")
    );
}

#[test]
fn audit_findings_are_reported_without_overriding_the_engine_exit_contract() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\npersona = \"audit\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let output = invoke(
        &fixture.0,
        &[
            "check",
            "--format",
            "json",
            "--trust-repository-config",
            ".",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let report = JsonValue::parse(text(&output.stdout)).expect("report-v3");
    assert!(
        !report
            .member("diagnostics")
            .and_then(JsonValue::as_array)
            .expect("diagnostics")
            .is_empty()
    );
    assert_eq!(
        report
            .member("gate")
            .and_then(|value| value.member("exit_code"))
            .and_then(JsonValue::as_i64),
        Some(0)
    );
}

#[test]
fn explicit_config_and_lock_paths_are_resolved_from_the_invocation_directory() {
    let fixture = Fixture::new();
    fixture.write("policy.toml", "version = 2\npersona = \"audit\"\n");
    let lock = Lockfile::new([LockEntry::new(
        Provider::Github,
        "actions/checkout@v4",
        "0123456789abcdef0123456789abcdef01234567",
        format!("sha256:{}", "a".repeat(64)),
        "https://github.com/actions/checkout",
    )])
    .expect("valid lock");
    fixture.write("pin.lock", &lock.to_canonical_json());
    let workflow = fixture.write(
        "repository/.github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let output = invoke(
        &fixture.0,
        &[
            "check",
            "--format",
            "json",
            "--policy",
            "policy.toml",
            "--lockfile",
            "pin.lock",
            workflow.to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let report = JsonValue::parse(text(&output.stdout)).expect("report-v3");
    assert_eq!(
        report
            .member("configuration")
            .and_then(|configuration| configuration.member("origin"))
            .and_then(JsonValue::as_str),
        Some("trusted-policy:policy.toml")
    );
    let diagnostics = report
        .member("diagnostics")
        .and_then(JsonValue::as_array)
        .expect("diagnostics");
    assert!(diagnostics.iter().all(|diagnostic| {
        diagnostic.member("rule_id").and_then(JsonValue::as_str) != Some("WV-SUPPLY-001")
    }));
}

#[test]
fn fix_accepts_a_workspace_directory_and_emits_deterministic_verified_edits() {
    let fixture = Fixture::new();
    let revision = "0123456789abcdef0123456789abcdef01234567";
    let lock = Lockfile::new([LockEntry::new(
        Provider::Github,
        "actions/checkout@v4",
        revision,
        format!("sha256:{}", "a".repeat(64)),
        "https://github.com/actions/checkout",
    )])
    .expect("valid lock");
    fixture.write(
        "repository/workflow-verifier.lock",
        &lock.to_canonical_json(),
    );
    fixture.write(
        "repository/.github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );

    let first = invoke(
        &fixture.0,
        &["fix", "--trust-repository-config", "repository"],
    );
    let second = invoke(
        &fixture.0,
        &["fix", "--trust-repository-config", "repository"],
    );
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let diff = text(&first.stdout);
    assert!(diff.starts_with("--- .github/workflows/ci.yml\n"));
    assert!(diff.contains(&format!("actions/checkout@{revision}")));
}

#[test]
fn policy_files_inside_the_analyzed_source_tree_are_rejected() {
    let fixture = Fixture::new();
    let policy = fixture.write(
        "repository/policy.toml",
        "version = 2\npersona = \"audit\"\n",
    );
    fixture.write(
        "repository/.github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    let output = invoke(
        &fixture.0,
        &[
            "check",
            "--policy",
            policy.to_str().expect("UTF-8 policy path"),
            "repository",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text(&output.stderr).contains("outside the analyzed source tree"));
}

#[test]
fn expired_suppressions_are_rejected_using_the_cli_clock_boundary() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        r#"version = 2
persona = "audit"

[[suppressions]]
rule = "WV-SUPPLY-001"
path = "**"
reason = "temporary exception"
owner = "security-team"
expiry = "2000-01-01"
"#,
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let output = invoke(&fixture.0, &["check", "--trust-repository-config", "."]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text(&output.stderr).contains("expired"));
    assert!(text(&output.stderr).contains("2000-01-01"));
}

#[test]
fn text_findings_have_rule_confidence_source_and_action() {
    let fixture = Fixture::new();
    let workflow = fixture.write(
        ".github/workflows/ci.yml",
        "on: pull_request\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n",
    );
    let output = invoke(&fixture.0, &["check", workflow.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("WV-SEC-001"));
    assert!(stdout.contains("confidence:"));
    assert!(stdout.contains("github.event.pull_request.title"));
    assert!(stdout.contains("Next action:"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn explain_filters_a_real_finding_and_includes_trace_and_capabilities() {
    let fixture = Fixture::new();
    let workflow = fixture.write(
        ".github/workflows/ci.yml",
        "on: pull_request\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n",
    );
    let explained = invoke(
        &fixture.0,
        &[
            "explain",
            "WV-SEC-001",
            workflow.to_str().expect("UTF-8 fixture path"),
        ],
    );
    assert_eq!(
        explained.status.code(),
        Some(0),
        "{}",
        text(&explained.stderr)
    );
    assert!(explained.stderr.is_empty());
    let stdout = text(&explained.stdout);
    assert!(stdout.contains("WV-SEC-001:"));
    assert!(stdout.contains("trace:"));
    assert!(stdout.contains("  - untrusted source "));
    assert!(stdout.contains("  - command sink "));
    assert!(stdout.contains("capabilities: shell"));

    let absent = invoke(
        &fixture.0,
        &[
            "explain",
            "WV-DOES-NOT-EXIST",
            workflow.to_str().expect("UTF-8 fixture path"),
        ],
    );
    assert_eq!(absent.status.code(), Some(2));
    assert!(absent.stdout.is_empty());
    assert!(text(&absent.stderr).contains("no finding for WV-DOES-NOT-EXIST"));
}

#[test]
fn doctor_v2_is_canonical_read_only_machine_output() {
    let fixture = Fixture::new();
    let before = fs::read_dir(&fixture.0).unwrap().count();
    let output = invoke(&fixture.0, &["doctor", "--format", "json"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty());
    let json = JsonValue::parse(text(&output.stdout)).expect("strict doctor JSON");
    assert_eq!(
        json.member("schema").and_then(JsonValue::as_str),
        Some("doctor-v2")
    );
    let frontends = json
        .member("frontends")
        .and_then(JsonValue::as_array)
        .expect("frontends");
    assert_eq!(frontends.len(), 4);
    assert_eq!(
        json.member("resolver_network").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(json.canonical() + "\n", text(&output.stdout));
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), before);

    let text_output = invoke(&fixture.0, &["doctor"]);
    assert_eq!(text_output.status.code(), Some(0));
    assert!(text(&text_output.stdout).contains("frontends: github, gitlab, azure, circleci"));
    assert!(text(&text_output.stdout).contains("resolver network: available"));

    let invalid = invoke(&fixture.0, &["doctor", "--format", "yaml"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
}

#[test]
fn policy_test_executes_strict_expectation_sidecars() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\n\n[[rules]]\nid = \"ORG-NET\"\nkind = \"forbid\"\nmessage = \"network denied\"\nselector.effect = \"network\"\n",
    );
    fixture.write(
        ".github/workflows/case.yml",
        "on: push\njobs:\n  check:\n    steps:\n      - run: curl https://example.invalid\n",
    );
    let sidecar = fixture.write(
        ".github/workflows/case.yml.expect.json",
        "{\"expected_rules\":[\"ORG-NET\"],\"schema\":\"policy-fixture-v1\"}\n",
    );
    let passing = invoke(&fixture.0, &["policy", "test", "."]);
    assert_eq!(passing.status.code(), Some(0), "{}", text(&passing.stderr));
    let json = JsonValue::parse(text(&passing.stdout)).expect("strict policy result");
    assert_eq!(
        json.member("schema").and_then(JsonValue::as_str),
        Some("policy-test-v1")
    );
    assert_eq!(json.canonical() + "\n", text(&passing.stdout));
    assert!(text(&passing.stdout).contains(".github/workflows/case.yml"));

    fs::write(
        sidecar,
        "{\"expected_rules\":[],\"schema\":\"policy-fixture-v1\"}\n",
    )
    .unwrap();
    let failing = invoke(&fixture.0, &["policy", "test", "."]);
    assert_eq!(failing.status.code(), Some(1));
    assert!(failing.stderr.is_empty());
    assert_eq!(
        JsonValue::parse(text(&failing.stdout))
            .unwrap()
            .member("passed")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn migrate_revalidates_config_v1_and_authenticates_lock_v1() {
    let fixture = Fixture::new();
    let legacy = fixture.write(
        "legacy.toml",
        "version = 1\npersona = \"gate\"\n\n[[suppressions]]\nrule = \"WV-SEC-001\"\npath = \".github/workflows/ci.yml\"\nreason = \"tracked exception\"\n\n[resolver]\nallowed_sources = [\"https://ci.example.test/includes\"]\n\n[sandbox]\nbackend = \"oci:docker\"\nimage = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    );
    let missing = invoke(
        &fixture.0,
        &["migrate", legacy.to_str().expect("UTF-8 fixture path")],
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(text(&missing.stderr).contains("--suppression-owner"));

    let output_path = fixture.0.join("config-v2.toml");
    let migrated = invoke(
        &fixture.0,
        &[
            "migrate",
            "--suppression-owner",
            "platform-team",
            "--suppression-expiry",
            "2027-01-31",
            "--output",
            output_path.to_str().expect("UTF-8 fixture path"),
            legacy.to_str().expect("UTF-8 fixture path"),
        ],
    );
    assert_eq!(
        migrated.status.code(),
        Some(0),
        "{}",
        text(&migrated.stderr)
    );
    assert!(migrated.stdout.is_empty());
    let config_source = fs::read_to_string(output_path).unwrap();
    Config::parse(
        &config_source,
        ConfigParseOptions {
            origin: "migration:test".to_owned(),
            trust: ConfigTrust::TrustedPolicy,
            today: Some("2026-08-27".to_owned()),
        },
    )
    .expect("strict migrated config");

    let unsigned = JsonValue::Object(BTreeMap::from([
        ("entries".to_owned(), JsonValue::Array(Vec::new())),
        ("schema".to_owned(), JsonValue::String("lock-v1".to_owned())),
    ]));
    let legacy_lock = JsonValue::Object(BTreeMap::from([
        ("entries".to_owned(), JsonValue::Array(Vec::new())),
        (
            "integrity".to_owned(),
            JsonValue::String(content_digest(unsigned.canonical())),
        ),
        ("schema".to_owned(), JsonValue::String("lock-v1".to_owned())),
    ]))
    .canonical_line();
    fixture.write("--legacy.lock", &legacy_lock);
    let lock = invoke(&fixture.0, &["migrate", "--", "--legacy.lock"]);
    assert_eq!(lock.status.code(), Some(0), "{}", text(&lock.stderr));
    let lock = Lockfile::parse(text(&lock.stdout)).expect("canonical migrated lock");
    assert_eq!(lock.schema, "lock-v2");
    assert!(lock.verify_integrity());

    fixture.write(
        "old-report.json",
        "{\"diagnostics\":[],\"schema\":\"report-v1\"}\n",
    );
    let report = invoke(&fixture.0, &["migrate", "old-report.json"]);
    assert_eq!(report.status.code(), Some(2));
    assert!(text(&report.stderr).contains("not migratable"));
}

#[test]
fn sandbox_replay_verify_and_audit_authenticate_persisted_protocol_data() {
    let fixture = Fixture::new();
    let plan_source = include_str!("../../../test/fixtures/protocol/runner-v2-complete.json");
    let run_source = include_str!("../../../test/fixtures/protocol/sandbox-run-v2-complete.json");
    let evidence_source = run_source
        .strip_prefix("{\"evidence\":")
        .and_then(|value| {
            value
                .split_once(",\"outcome\":")
                .map(|(evidence, _)| evidence)
        })
        .expect("evidence projection");
    fixture.write("plan.json", plan_source);
    fixture.write("evidence.json", evidence_source);

    let replay = invoke(&fixture.0, &["sandbox", "replay", "evidence.json"]);
    assert_eq!(replay.status.code(), Some(0), "{}", text(&replay.stderr));
    assert_eq!(
        JsonValue::parse(text(&replay.stdout))
            .unwrap()
            .member("schema")
            .and_then(JsonValue::as_str),
        Some("evidence-v2")
    );

    let verify = invoke(
        &fixture.0,
        &["sandbox", "verify", "plan.json", "evidence.json"],
    );
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify.stderr));
    assert!(verify.stderr.is_empty());

    let audit = invoke(
        &fixture.0,
        &["sandbox", "audit", "plan.json", "evidence.json"],
    );
    assert_eq!(audit.status.code(), Some(0), "{}", text(&audit.stderr));
    let audit = JsonValue::parse(text(&audit.stdout)).expect("strict audit");
    assert_eq!(
        audit.member("schema").and_then(JsonValue::as_str),
        Some("sandbox-audit-v1")
    );
    assert_eq!(
        audit
            .member("status")
            .and_then(|status| status.member("state"))
            .and_then(JsonValue::as_str),
        Some("verified")
    );

    let tampered = evidence_source.replacen("\"sequence\":0", "\"sequence\":2", 1);
    fixture.write("tampered.json", &tampered);
    let rejected = invoke(
        &fixture.0,
        &["sandbox", "verify", "plan.json", "tampered.json"],
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
}

#[test]
fn sandbox_plan_is_deterministic_job_scoped_and_never_executes() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\n\n[sandbox]\nbackend = \"oci:docker\"\ncapsule_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  ignored:\n    steps:\n      - run: echo ignored\n  build:\n    steps:\n      - run: echo ${{ inputs.release }}\n",
    );
    let arguments = [
        "sandbox",
        "plan",
        "--trust-repository-config",
        "--job",
        "build",
        "--input",
        "release=true",
        ".",
    ];
    let first = invoke(&fixture.0, &arguments);
    let second = invoke(&fixture.0, &arguments);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let plan = JsonValue::parse(text(&first.stdout)).expect("strict runner plan");
    assert_eq!(
        plan.member("schema").and_then(JsonValue::as_str),
        Some("runner-v2")
    );
    assert_eq!(
        plan.member("status")
            .and_then(|status| status.member("state"))
            .and_then(JsonValue::as_str),
        Some("complete")
    );
    let serialized = text(&first.stdout);
    assert!(serialized.contains("echo true"));
    assert!(!serialized.contains("echo ignored"));
    assert!(serialized.contains("network_deny"));
}

#[test]
fn sandbox_plan_authenticates_the_exact_helper_source_tree() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\n\n[sandbox]\nbackend = \"oci:docker\"\ncapsule_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    fixture.write("README.md", "first revision\n");
    let arguments = [
        "sandbox",
        "plan",
        "--trust-repository-config",
        "--job",
        "build",
        ".",
    ];

    let first = invoke(&fixture.0, &arguments);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    let first_plan = JsonValue::parse(text(&first.stdout)).expect("strict runner plan");
    let first_digest = first_plan
        .member("source_digest")
        .and_then(JsonValue::as_str)
        .expect("source digest");
    assert_eq!(
        first_digest,
        source_snapshot(&fixture.0)
            .expect("helper source snapshot")
            .manifest
            .digest
    );

    fixture.write("README.md", "second revision\n");
    let second = invoke(&fixture.0, &arguments);
    assert_eq!(second.status.code(), Some(0), "{}", text(&second.stderr));
    let second_plan = JsonValue::parse(text(&second.stdout)).expect("strict runner plan");
    let second_digest = second_plan
        .member("source_digest")
        .and_then(JsonValue::as_str)
        .expect("source digest");
    assert_ne!(first_digest, second_digest);
    assert_eq!(
        second_digest,
        source_snapshot(&fixture.0)
            .expect("helper source snapshot")
            .manifest
            .digest
    );
}

#[test]
fn trusted_source_exclusions_bind_analysis_and_helper_to_the_same_snapshot() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\nsource_exclusions = [\"generated\"]\n\n[sandbox]\nbackend = \"oci:docker\"\ncapsule_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    fixture.write(
        "generated/.github/workflows/untrusted.yml",
        "on: push\njobs:\n  injected:\n    steps:\n      - run: echo excluded\n",
    );
    let output = invoke(
        &fixture.0,
        &[
            "sandbox",
            "plan",
            "--trust-repository-config",
            "--job",
            "build",
            ".",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let plan = JsonValue::parse(text(&output.stdout)).expect("strict runner plan");
    let actual = plan
        .member("source_digest")
        .and_then(JsonValue::as_str)
        .expect("source digest");
    let expected = source_snapshot_with_exclusions(&fixture.0, &["generated".to_owned()])
        .expect("helper snapshot with trusted policy");
    assert_eq!(actual, expected.manifest.digest);
    assert!(
        expected
            .regular_file("generated/.github/workflows/untrusted.yml")
            .is_none()
    );
}

#[test]
fn sandbox_run_has_no_implicit_executor_fallback() {
    let fixture = Fixture::new();
    fixture.write(
        ".workflow-verifier.toml",
        "version = 2\n\n[sandbox]\nbackend = \"oci:definitely-missing-workflow-verifier-engine\"\ncapsule_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
    );
    fixture.write(
        ".github/workflows/ci.yml",
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    let output = invoke(
        &fixture.0,
        &[
            "sandbox",
            "run",
            "--trust-repository-config",
            "--job",
            "build",
            ".",
        ],
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert!(
        text(&output.stderr).contains("unavailable")
            || text(&output.stderr).contains("infrastructure")
    );
}

#[test]
fn graph_diff_fix_resolve_and_completion_are_composed() {
    let fixture = Fixture::new();
    let base = fixture.write(
        "base/.github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
    );
    let head = fixture.write(
        "head/.github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let lock = Lockfile::new([LockEntry::new(
        Provider::Github,
        "actions/checkout@v4",
        "0123456789abcdef0123456789abcdef01234567",
        format!("sha256:{}", "a".repeat(64)),
        "https://github.com/actions/checkout",
    )])
    .expect("valid fixture lock");
    let lock_path = fixture.write("pin.lock", &lock.to_canonical_json());
    let graph = invoke(
        &fixture.0,
        &["graph", "--format", "dot", head.to_str().unwrap()],
    );
    assert_eq!(graph.status.code(), Some(0), "{}", text(&graph.stderr));
    assert!(text(&graph.stdout).starts_with("digraph workflow {\n"));

    let diff = invoke(
        &fixture.0,
        &["diff", base.to_str().unwrap(), head.to_str().unwrap()],
    );
    assert_eq!(diff.status.code(), Some(0), "{}", text(&diff.stderr));
    assert_eq!(
        JsonValue::parse(text(&diff.stdout))
            .unwrap()
            .member("schema")
            .and_then(JsonValue::as_str),
        Some("semantic-diff-v1")
    );

    let fix = invoke(
        &fixture.0,
        &[
            "fix",
            "--lockfile",
            lock_path.to_str().unwrap(),
            head.to_str().unwrap(),
        ],
    );
    assert_eq!(fix.status.code(), Some(0), "{}", text(&fix.stderr));
    assert!(text(&fix.stdout).contains("--- "));
    assert!(fs::read_to_string(&head).unwrap().contains("@v4"));

    let resolve = invoke(&fixture.0, &["resolve", head.to_str().unwrap()]);
    assert_eq!(resolve.status.code(), Some(3));
    assert!(text(&resolve.stderr).contains("Incomplete.Unresolved_dependency"));

    let completion = invoke(&fixture.0, &["completion", "bash"]);
    assert_eq!(completion.status.code(), Some(0));
    assert!(text(&completion.stdout).contains("workflow-verifier"));
}

#[test]
fn network_granted_resolve_writes_a_canonical_lock_without_exposing_auth_values() {
    let fixture = Fixture::new();
    let digest = format!("sha256:{}", "1".repeat(64));
    let workflow = fixture.write(
        ".github/workflows/ci.yml",
        &format!("on: push\njobs:\n  build:\n    steps:\n      - uses: docker://alpine@{digest}\n"),
    );

    let resolved = invoke(
        &fixture.0,
        &[
            "resolve",
            "--allow-network",
            workflow.to_str().expect("UTF-8 fixture path"),
        ],
    );

    assert_eq!(
        resolved.status.code(),
        Some(0),
        "{}",
        text(&resolved.stderr)
    );
    assert!(resolved.stderr.is_empty());
    let lock = Lockfile::parse(text(&resolved.stdout)).expect("canonical lock-v2");
    assert_eq!(lock.entries().len(), 1);
    assert_eq!(lock.entries()[0].revision, digest);
    assert_eq!(
        fs::read_to_string(fixture.0.join(".github/workflows/workflow-verifier.lock"),).unwrap(),
        text(&resolved.stdout)
    );

    let missing = Fixture::new();
    let workflow = missing.write(
        ".github/workflows/ci.yml",
        &format!("on: push\njobs:\n  build:\n    steps:\n      - uses: docker://alpine@{digest}\n"),
    );
    let rejected = invoke(
        &missing.0,
        &[
            "resolve",
            "--allow-network",
            "--auth-from-env",
            "github@github.com=WV_TEST_INTENTIONALLY_MISSING_AUTH_VALUE",
            workflow.to_str().expect("UTF-8 fixture path"),
        ],
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert!(text(&rejected.stderr).contains("WV_TEST_INTENTIONALLY_MISSING_AUTH_VALUE"));
    assert!(
        !missing
            .0
            .join(".github/workflows/workflow-verifier.lock")
            .exists()
    );
}

#[test]
fn network_profile_requires_explicit_network_consent_and_cannot_come_from_the_repository() {
    let repository = Fixture::new();
    let trusted_config = Fixture::new();
    let workflow = repository.write(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let external_profile = trusted_config.write("network-v1.toml", "version = 1\n");

    let no_consent = invoke(
        &repository.0,
        &[
            "resolve",
            "--network-profile",
            external_profile.to_str().unwrap(),
            workflow.to_str().unwrap(),
        ],
    );
    assert_eq!(no_consent.status.code(), Some(2));
    assert!(no_consent.stdout.is_empty());
    assert!(text(&no_consent.stderr).contains("requires --allow-network"));

    let repository_profile = repository.write("network-v1.toml", "version = 1\n");
    let repository_controlled = invoke(
        &repository.0,
        &[
            "resolve",
            "--allow-network",
            "--network-profile",
            repository_profile.to_str().unwrap(),
            workflow.to_str().unwrap(),
        ],
    );
    assert_eq!(repository_controlled.status.code(), Some(2));
    assert!(repository_controlled.stdout.is_empty());
    assert!(text(&repository_controlled.stderr).contains("outside the analyzed repository"));
    assert!(!repository.0.join("workflow-verifier.lock").exists());
}
