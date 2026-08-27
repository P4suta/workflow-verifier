use workflow_verifier_domain::{
    Capability, EdgeKind, NodeKind, ObservableEffect, Provider, UnknownReason,
};
use workflow_verifier_foundation::Budget;
use workflow_verifier_frontend::{DependencyKind, PipelinePhase, compile_auto, detect, entrypoint};

#[test]
fn detects_all_four_provider_identities() {
    let cases = [
        (
            ".github/workflows/ci.yml",
            "on: push\njobs: {}\n",
            Provider::Github,
        ),
        (
            ".gitlab-ci.yml",
            "stages: [test]\ntest:\n  script: echo ok\n",
            Provider::Gitlab,
        ),
        (
            "azure-pipelines.yml",
            "trigger: [main]\njobs: []\n",
            Provider::Azure,
        ),
        (
            ".circleci/config.yml",
            "version: 2.1\nworkflows: {}\n",
            Provider::Circleci,
        ),
    ];
    for (path, source, provider) in cases {
        assert_eq!(detect(path, source), Some(provider));
        assert!(entrypoint(provider, path, source));
    }
}

#[test]
fn github_lowers_jobs_steps_calls_commands_and_needs() {
    let source = r#"name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
  deploy:
    needs: build
    permissions:
      id-token: write
    steps:
      - uses: acme/deploy@0123456789abcdef0123456789abcdef01234567
"#;
    let compilation = compile_auto(".github/workflows/ci.yml", source, Budget::default())
        .expect("GitHub workflow compiles");
    assert_eq!(compilation.provider, Provider::Github);
    assert_eq!(
        compilation.phases,
        vec![
            PipelinePhase::Detected,
            PipelinePhase::Parsed,
            PipelinePhase::Expanded,
            PipelinePhase::Resolved,
            PipelinePhase::Lowered,
        ]
    );
    assert_eq!(
        compilation
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Job)
            .count(),
        2
    );
    assert_eq!(
        compilation
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Step)
            .count(),
        3
    );
    assert_eq!(compilation.dependencies.len(), 2);
    let command = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Command)
        .expect("command node");
    let command_value = command.attributes.get("command").expect("command value");
    assert!(command_value.is_untrusted());
    assert!(
        compilation
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Control)
    );
}

#[test]
fn github_unnamed_workflow_uses_its_logical_path_as_identity() {
    let path = ".github/workflows/unnamed.yml";
    let compilation = compile_auto(
        path,
        "on: push\njobs:\n  build:\n    steps:\n      - run: echo safe\n",
        Budget::default(),
    )
    .expect("unnamed workflow compiles");
    let workflow = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Workflow)
        .expect("workflow node");
    assert_eq!(workflow.name, path);
}

#[test]
fn github_reports_unknown_needs_and_dependency_cycles() {
    let source = r"on: push
jobs:
  build:
    needs: [missing, deploy]
    runs-on: ubuntu-latest
    steps: []
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps: []
";
    let compilation = compile_auto(".github/workflows/ci.yml", source, Budget::default())
        .expect("semantic reference mistakes remain structured problems");
    let observed: Vec<_> = compilation
        .problems
        .iter()
        .map(|problem| (problem.code.as_str(), problem.message.as_str()))
        .collect();
    assert!(
        observed.contains(&("GH-UNKNOWN-NEEDS", "build references unknown missing")),
        "{observed:?}"
    );
    assert!(
        observed.iter().any(|(code, _)| *code == "GH-NEEDS-CYCLE"),
        "{observed:?}"
    );
}

#[test]
fn gitlab_azure_and_circleci_lower_provider_native_dependencies() {
    let cases = [
        (
            ".gitlab-ci.yml",
            "include:\n  - project: group/templates\n    ref: main\n    file: /ci.yml\nstages: [test]\ntest:\n  stage: test\n  script: echo ok\n",
            Provider::Gitlab,
            "group/templates:/ci.yml@main",
        ),
        (
            "azure-pipelines.yml",
            "trigger: [main]\nsteps:\n  - task: NodeTool@0\n  - template: templates/build.yml\n",
            Provider::Azure,
            "NodeTool@0",
        ),
        (
            ".circleci/config.yml",
            "version: 2.1\norbs:\n  node: circleci/node@5.2.0\njobs:\n  test:\n    steps:\n      - node/install\nworkflows:\n  ci:\n    jobs: [test]\n",
            Provider::Circleci,
            "circleci/node@5.2.0",
        ),
    ];
    for (path, source, provider, reference) in cases {
        let compilation = compile_auto(path, source, Budget::default()).expect("workflow compiles");
        assert_eq!(compilation.provider, provider);
        assert!(
            compilation
                .dependencies
                .iter()
                .any(|item| item.reference == reference)
        );
        assert!(!compilation.graph.nodes.is_empty());
        assert!(
            compilation.graph.validate().is_empty(),
            "{:?}",
            compilation.graph.validate()
        );
    }
}

#[test]
fn gitlab_collects_every_native_include_form_and_child_pipeline_include() {
    let source = r"include:
  - local: /.gitlab/ci/build.yml
  - remote: https://example.invalid/shared.yml
  - component: gitlab.example/acme/component@1.2.3
  - template: Jobs/Code-Quality.gitlab-ci.yml
  - project: group/templates
    ref: main
    file: [/ci/one.yml, /ci/two.yml]
stages: [test]
child:
  stage: test
  trigger:
    include:
      - local: child.yml
  script: echo ok
";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab include forms compile");
    let observed: Vec<_> = compilation
        .dependencies
        .iter()
        .map(|dependency| (dependency.kind, dependency.reference.as_str()))
        .collect();
    for expected in [
        (DependencyKind::Include, "/.gitlab/ci/build.yml"),
        (DependencyKind::Include, "child.yml"),
        (
            DependencyKind::Include,
            "https://example.invalid/shared.yml",
        ),
        (
            DependencyKind::Component,
            "gitlab.example/acme/component@1.2.3",
        ),
        (DependencyKind::Template, "Jobs/Code-Quality.gitlab-ci.yml"),
        (
            DependencyKind::Repository,
            "group/templates:/ci/one.yml@main",
        ),
        (
            DependencyKind::Repository,
            "group/templates:/ci/two.yml@main",
        ),
    ] {
        assert!(
            observed.contains(&expected),
            "missing {expected:?}: {observed:?}"
        );
    }

    let child_job = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Job && node.name == "child")
        .expect("child job");
    let child_call = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Call && node.name == "child:child.yml")
        .expect("child pipeline call");
    for kind in [EdgeKind::Control, EdgeKind::Call] {
        assert!(compilation.graph.edges.iter().any(|edge| {
            edge.kind == kind && edge.from == child_job.id && edge.to == child_call.id
        }));
    }
}

#[test]
fn gitlab_dependency_identity_is_the_reference_and_keeps_the_last_span() {
    let source = "one:\n  image: registry.example/tool:1\n  script: echo one\ntwo:\n  image: registry.example/tool:1\n  script: echo two\n";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab duplicate dependency references compile");
    let dependencies: Vec<_> = compilation
        .dependencies
        .iter()
        .filter(|dependency| dependency.reference == "registry.example/tool:1")
        .collect();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(
        dependencies[0].span.start.byte,
        source.rfind("registry.example/tool:1").expect("last image")
    );
    assert_eq!(
        compilation
            .graph
            .nodes
            .iter()
            .filter(|node| {
                node.kind == NodeKind::Call && node.name == "registry.example/tool:1"
            })
            .count(),
        1
    );
}

#[test]
fn gitlab_reports_unknown_stages_needs_and_extends_after_template_lookup() {
    let source = r"stages: [build]
.base:
  stage: build
known:
  extends: .base
  script: echo known
broken:
  extends: [.base, .missing]
  stage: deploy
  needs:
    - known
    - job: absent
  script: echo broken
";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("semantic reference mistakes remain structured problems");
    let observed: Vec<_> = compilation
        .problems
        .iter()
        .map(|problem| (problem.code.as_str(), problem.message.as_str()))
        .collect();
    for expected in [
        ("GL-UNKNOWN-STAGE", "broken uses unknown stage deploy"),
        ("GL-UNKNOWN-NEEDS", "broken references unknown absent"),
        ("GL-UNKNOWN-EXTENDS", "broken extends unknown .missing"),
    ] {
        assert!(
            observed.contains(&expected),
            "missing {expected:?}: {observed:?}"
        );
    }
    assert!(
        !observed
            .iter()
            .any(|(_, message)| message.contains(".base"))
    );
    let calls: Vec<_> = compilation
        .graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Call)
        .map(|node| node.name.as_str())
        .collect();
    assert!(calls.contains(&"extends:.base"), "{calls:?}");
    assert!(calls.contains(&"extends:.missing"), "{calls:?}");
    assert!(
        compilation
            .graph
            .nodes
            .iter()
            .any(|node| { node.kind == NodeKind::Resource && node.name == "template:.base" })
    );
}

#[test]
fn gitlab_lowers_all_script_phases_and_tracks_untrusted_provider_variables() {
    let source = r"job:
  before_script:
    - |
      if [[ $CI_MERGE_REQUEST_TARGET_BRANCH_NAME =~ stable ]]; then
        echo $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
      fi
  script:
    - echo build
  after_script:
    - echo cleanup
";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab script phases compile");
    let commands: Vec<_> = compilation
        .graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Command)
        .collect();
    assert_eq!(commands.len(), 3);
    assert_eq!(
        compilation
            .graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Step)
            .count(),
        3
    );
    let before_script = commands
        .iter()
        .find(|node| node.name.contains("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"))
        .expect("before_script command");
    assert_eq!(
        (before_script.span.start.byte, before_script.span.stop.byte),
        (
            source.find("- |").expect("block header") + 2,
            source.find("\n  script:").expect("next job field")
        )
    );
    assert!(
        before_script
            .attributes
            .get("command")
            .is_some_and(workflow_verifier_domain::AbstractValue::is_untrusted)
    );
    let source_node = compilation
        .graph
        .nodes
        .iter()
        .find(|node| {
            node.kind == NodeKind::Resource && node.name == "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
        })
        .expect("provider variable resource");
    assert!(
        source_node
            .attributes
            .get("value")
            .is_some_and(workflow_verifier_domain::AbstractValue::is_untrusted)
    );
    assert!(compilation.graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Data && edge.from == source_node.id && edge.to == before_script.id
    }));
}

#[test]
fn gitlab_default_stages_and_first_rule_gate_match_reference_order() {
    let source = r#"rebase:
  stage: rebase
  rules:
    - if: $REPO_REBASE_BRANCHES != "" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - git push origin HEAD
"#;
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab stage and rule compile");
    let mut stages: Vec<_> = compilation
        .graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Stage)
        .map(|node| {
            (
                node.attributes
                    .get("order")
                    .and_then(|value| value.constants())
                    .and_then(|values| values.first())
                    .cloned()
                    .expect("stage order"),
                node.name.as_str(),
            )
        })
        .collect();
    stages.sort();
    assert_eq!(
        stages,
        vec![
            ("0".to_owned(), ".post"),
            ("1".to_owned(), ".pre"),
            ("2".to_owned(), "build"),
            ("3".to_owned(), "deploy"),
            ("4".to_owned(), "rebase"),
            ("5".to_owned(), "test"),
        ]
    );
    let gate = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Gate)
        .expect("first rule gate");
    assert_eq!(gate.name, "rule:rebase");
    assert_eq!(
        gate.unknown,
        Some(UnknownReason::PhaseUnavailable(
            "REPO_REBASE_BRANCHES is unavailable during plan".to_owned()
        ))
    );
    assert_eq!(
        gate.condition.atoms(),
        vec![
            "(CI_COMMIT_BRANCH==CI_DEFAULT_BRANCH)",
            "(REPO_REBASE_BRANCHES!=\"\")",
        ]
    );
    let branch = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Resource && node.name == "CI_COMMIT_BRANCH")
        .expect("condition reference");
    assert_eq!(
        (branch.span.start.byte, branch.span.stop.byte),
        (
            source.find("$CI_COMMIT_BRANCH").expect("reference start"),
            source.find("$CI_COMMIT_BRANCH").expect("reference start") + "$CI_COMMIT_BRANCH".len()
        )
    );
}

#[test]
fn gitlab_tagged_reference_rule_remains_an_explicit_opaque_condition() {
    let source = r"job:
  rules:
    - if: !reference [.shared-rules, condition]
  script: echo ok
";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab reference rule compiles conservatively");
    let gate = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Gate)
        .expect("rule gate");
    assert_eq!(gate.condition.atoms(), vec!["gitlab:<opaque condition>"]);
    assert_eq!(
        gate.unknown,
        Some(UnknownReason::UnsupportedSyntax(
            "condition expression".to_owned()
        ))
    );
}

#[test]
fn gitlab_workflow_first_rule_gates_the_compile_entrypoint() {
    let source = r#"workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "web"
job:
  script: echo ok
"#;
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab workflow rule compiles");
    let graph = &compilation.graph;
    let workflow = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Workflow)
        .expect("workflow");
    let gate = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Gate && node.name == "workflow-rule:GitLab pipeline")
        .expect("workflow rule gate");
    assert_eq!(graph.entrypoints, vec![gate.id.clone()]);
    assert_eq!(
        gate.unknown,
        Some(UnknownReason::PhaseUnavailable(
            "CI_PIPELINE_SOURCE is unavailable during compile".to_owned()
        ))
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == gate.id
            && edge.to == workflow.id
            && edge.label.as_deref() == Some("gate")
    }));
    let reference = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Resource && node.name == "CI_PIPELINE_SOURCE")
        .expect("workflow condition reference");
    assert_eq!(reference.phase.name(), "compile");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Data
            && edge.from == reference.id
            && edge.to == gate.id
            && edge.label.as_deref() == Some("CI_PIPELINE_SOURCE")
    }));
}

#[test]
fn gitlab_root_variables_are_compile_time_data_resources() {
    let source = "variables:\n  TOP: value\njob:\n  script: echo ok\n";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab variables compile");
    let workflow = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Workflow)
        .expect("workflow");
    let variable = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Resource && node.name == "variable:TOP")
        .expect("root variable resource");
    assert_eq!(variable.phase.name(), "compile");
    assert_eq!(
        (variable.span.start.byte, variable.span.stop.byte),
        (
            source.find("TOP: value").expect("variable start"),
            source.find("TOP: value").expect("variable start") + "TOP: value".len()
        )
    );
    assert!(compilation.graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Data
            && edge.from == variable.id
            && edge.to == workflow.id
            && edge.label.as_deref() == Some("TOP")
    }));
}

#[test]
fn gitlab_inherited_job_resources_manual_gate_matrix_and_scripts_are_lowered() {
    let source = r"default:
  after_script: [echo default cleanup]
.base:
  before_script: [echo inherited setup]
  variables: {FROM_BASE: yes}
  cache: {key: shared}
  artifacts: {paths: [out]}
  when: manual
job:
  extends: .base
  environment:
    name: production
  parallel:
    matrix:
      - OS: [linux, macos]
  script: [echo build]
";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab inherited job features compile");
    let graph = &compilation.graph;
    let job = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Job)
        .expect("job");
    assert!(job.capabilities.contains(&Capability::Deployment));
    assert!(job.effects.contains(&ObservableEffect::DeploymentChange));

    for (kind, name) in [
        (NodeKind::Resource, "variable:FROM_BASE"),
        (NodeKind::Resource, "environment:production"),
        (NodeKind::Resource, "cache:job"),
        (NodeKind::Resource, "artifact:job"),
        (NodeKind::Parameter, "matrix.OS"),
        (NodeKind::Gate, "manual:job"),
    ] {
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.kind == kind && node.name == name),
            "missing {kind:?} {name}"
        );
    }
    let commands: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Command)
        .map(|node| node.name.as_str())
        .collect();
    for expected in ["echo inherited setup", "echo build", "echo default cleanup"] {
        assert!(commands.contains(&expected), "{commands:?}");
    }
    let environment = graph
        .nodes
        .iter()
        .find(|node| node.name == "environment:production")
        .expect("environment");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Grant && edge.from == environment.id && edge.to == job.id
    }));
    let cache = graph
        .nodes
        .iter()
        .find(|node| node.name == "cache:job")
        .expect("cache");
    assert!(
        graph.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Read && edge.from == cache.id && edge.to == job.id
        })
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Write && edge.from == job.id && edge.to == cache.id
    }));
}

#[test]
fn gitlab_needs_is_linked_from_the_effective_inherited_job_body() {
    let source = "upstream:\n  script: echo upstream\n.with-needs:\n  needs: [upstream]\ndownstream:\n  extends: .with-needs\n  script: echo downstream\n";
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab inherited needs compile");
    let upstream = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Job && node.name == "upstream")
        .expect("upstream job");
    let downstream = compilation
        .graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Job && node.name == "downstream")
        .expect("downstream job");
    assert!(compilation.graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == upstream.id
            && edge.to == downstream.id
            && edge.label.as_deref() == Some("needs")
    }));
}

#[test]
fn gitlab_needs_precedes_the_rule_gate_and_matrix_qualified_needs_stays_unresolved() {
    let source = r#"upstream:
  script: echo upstream
gated:
  needs: [upstream]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script: echo gated
matrix-consumer:
  needs:
    - "upstream: [linux]"
  script: echo matrix
"#;
    let compilation = compile_auto(".gitlab-ci.yml", source, Budget::default())
        .expect("GitLab gated and matrix needs compile");
    let named = |kind, name| {
        compilation
            .graph
            .nodes
            .iter()
            .find(|node| node.kind == kind && node.name == name)
            .expect("named graph node")
    };
    let upstream = named(NodeKind::Job, "upstream");
    let gated = named(NodeKind::Job, "gated");
    let gate = named(NodeKind::Gate, "rule:gated");
    let matrix_consumer = named(NodeKind::Job, "matrix-consumer");
    assert!(compilation.graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == upstream.id
            && edge.to == gate.id
            && edge.label.as_deref() == Some("needs")
    }));
    assert!(!compilation.graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == upstream.id
            && (edge.to == gated.id || edge.to == matrix_consumer.id)
            && edge.label.as_deref() == Some("needs")
    }));
}

#[test]
fn circleci_full_semantic_surface_is_lowered() {
    let source = r"version: 2.1
setup: true
parameters:
  deploy:
    type: boolean
    default: false
orbs:
  node: circleci/node@5
executors:
  linux:
    docker:
      - image: cimg/base:current
commands:
  greet:
    parameters:
      subject:
        type: string
    steps:
      - run: echo hello
jobs:
  build:
    executor: linux
    steps:
      - greet:
          subject: world
      - node/test
workflows:
  delivery:
    jobs:
      - approve:
          type: approval
      - build:
          requires: [approve]
          filters:
            branches:
              only: main
          matrix:
            parameters:
              image: [one, two]
";
    let compilation = compile_auto(".circleci/config.yml", source, Budget::default())
        .expect("CircleCI semantic surface compiles");
    let graph = &compilation.graph;
    let named = |kind, name| {
        graph
            .nodes
            .iter()
            .find(|node| node.kind == kind && node.name == name)
            .expect("named CircleCI node")
    };
    let pipeline_parameter = named(NodeKind::Parameter, "pipeline.deploy");
    assert!(pipeline_parameter.attributes.contains_key("value"));
    let executor = named(NodeKind::Resource, "executor:linux");
    let job = named(NodeKind::Job, "build");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Read && edge.from == executor.id && edge.to == job.id
    }));
    let definition = named(NodeKind::Resource, "command-definition:greet");
    let command_call = named(NodeKind::Call, "command:greet");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Call && edge.from == command_call.id && edge.to == definition.id
    }));
    named(NodeKind::Command, "echo hello");
    named(NodeKind::Call, "orb:node/test");
    let approval = named(NodeKind::Gate, "approval:approve");
    let filter = named(NodeKind::Gate, "filter:delivery:build");
    assert_eq!(filter.phase.name(), "plan");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == approval.id
            && edge.to == filter.id
            && edge.label.as_deref() == Some("requires")
    }));
    named(NodeKind::Parameter, "matrix.image");
    assert!(graph.nodes.iter().any(|node| {
        node.kind == NodeKind::Effect
            && node.name == "dynamic config"
            && node.effects.contains(&ObservableEffect::WorkflowChange)
    }));
    assert!(
        compilation
            .dependencies
            .iter()
            .any(|dependency| dependency.kind == DependencyKind::Orb)
    );
    assert!(compilation.dependencies.iter().any(|dependency| {
        dependency.kind == DependencyKind::ContainerImage
            && dependency.reference == "cimg/base:current"
    }));
    assert!(graph.validate().is_empty(), "{:?}", graph.validate());
}

#[test]
fn circleci_reports_unknown_requirements_and_dependency_cycles() {
    let source = r"version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:current
    steps: [checkout]
workflows:
  delivery:
    jobs:
      - build:
          requires: [missing, deploy]
      - deploy:
          requires: [build]
      - ghost
";
    let compilation = compile_auto(".circleci/config.yml", source, Budget::default())
        .expect("semantic reference mistakes remain structured problems");
    let observed: Vec<_> = compilation
        .problems
        .iter()
        .map(|problem| (problem.code.as_str(), problem.message.as_str()))
        .collect();
    assert!(
        observed.contains(&("CC-UNKNOWN-REQUIREMENT", "build requires unknown missing")),
        "{observed:?}"
    );
    let unknown_requirement = compilation
        .problems
        .iter()
        .find(|problem| problem.code == "CC-UNKNOWN-REQUIREMENT")
        .expect("unknown requirement problem");
    assert_eq!(
        unknown_requirement.span.start.byte,
        source
            .find("build:\n          requires")
            .expect("invocation key")
    );
    assert!(
        observed
            .iter()
            .any(|(code, _)| *code == "CC-REQUIRES-CYCLE"),
        "{observed:?}"
    );
    assert!(
        observed.contains(&("CC-UNKNOWN-JOB", "delivery invokes unknown job ghost")),
        "{observed:?}"
    );
}

#[test]
fn malformed_yaml_never_disappears_into_an_empty_success() {
    let problems = compile_auto(".github/workflows/ci.yml", "jobs: [\n", Budget::default())
        .expect_err("malformed source is rejected");
    assert!(problems.iter().any(|problem| problem.code == "YAML-SYNTAX"));
}

#[test]
fn github_permissions_spans_and_default_shell_match_the_reference_contract() {
    let source = include_str!("../../../test/fixtures/determinism/.github/workflows/ci.yml");
    let compilation = compile_auto(".github/workflows/ci.yml", source, Budget::default())
        .expect("determinism fixture compiles");
    let graph = compilation.graph;
    let workflow = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Workflow)
        .expect("workflow");
    let job = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Job)
        .expect("job");
    for owner in [workflow, job] {
        assert_eq!(
            owner.capabilities,
            vec![Capability::RepositoryRead, Capability::TokenRead]
        );
    }
    let trigger = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Trigger)
        .expect("trigger");
    assert_eq!((trigger.span.start.byte, trigger.span.stop.byte), (24, 29));
    let mut steps: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Step)
        .collect();
    steps.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        (steps[0].span.start.byte, steps[0].span.stop.byte),
        (121, 146)
    );
    assert_eq!(
        (steps[1].span.start.byte, steps[1].span.stop.byte),
        (155, 178)
    );
    let command = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Command)
        .expect("command");
    assert_eq!(
        command
            .attributes
            .get("shell")
            .and_then(|value| value.constants())
            .map(<[String]>::to_vec),
        Some(vec!["default".to_owned()])
    );
    let ids: Vec<_> = graph.nodes.iter().map(|node| node.id.as_str()).collect();
    for expected in [
        "wv_0cc50543912ac689d8d4",
        "wv_2a299503a63b00d48167",
        "wv_300ca8a13af487edea0b",
        "wv_65ac9e56c198d03c05b7",
        "wv_7bd167fcadabfeaace88",
        "wv_874565f56ca574e81d8e",
        "wv_aa7974a1abee72e19d99",
    ] {
        assert!(ids.contains(&expected), "missing reference node {expected}");
    }
}

#[test]
fn github_matrix_environment_outputs_env_and_condition_references_are_lowered() {
    let source = r"name: CI
on: push
jobs:
  build:
    strategy:
      matrix:
        os: [linux, macos]
    environment:
      name: production
    outputs:
      digest: ${{ steps.hash.outputs.digest }}
    if: startsWith(github.repository_owner, 'acme')
    runs-on: ${{ matrix.os }}
    steps:
      - id: hash
        run: echo build
        env:
          TOKEN: ${{ secrets.BUILD_TOKEN }}
";
    let compilation = compile_auto(".github/workflows/ci.yml", source, Budget::default())
        .expect("GitHub resources compile");
    let graph = &compilation.graph;
    let named = |kind, name| {
        graph
            .nodes
            .iter()
            .find(|node| node.kind == kind && node.name == name)
            .expect("named GitHub node")
    };
    let job = named(NodeKind::Job, "build");
    assert!(job.capabilities.contains(&Capability::Deployment));
    assert!(job.effects.contains(&ObservableEffect::DeploymentChange));
    let gate = named(NodeKind::Gate, "if:job:build");
    assert_eq!(
        gate.condition.atoms(),
        vec!["startsWith(github.repository_owner,\"acme\")"]
    );
    let matrix = named(NodeKind::Parameter, "matrix.os");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Data && edge.from == matrix.id && edge.to == job.id
    }));
    let environment = named(NodeKind::Resource, "environment:production");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Grant && edge.from == environment.id && edge.to == job.id
    }));
    let output = named(NodeKind::Resource, "output:build.digest");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Write && edge.from == job.id && edge.to == output.id
    }));
    let command = named(NodeKind::Command, "echo build");
    let binding = named(NodeKind::Resource, "env:TOKEN");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Data && edge.from == binding.id && edge.to == command.id
    }));
    for reference in [
        "github.repository_owner",
        "steps.hash.outputs.digest",
        "secrets.BUILD_TOKEN",
    ] {
        named(NodeKind::Resource, reference);
    }
}

#[test]
fn github_composite_action_lowers_inputs_outputs_and_executable_steps() {
    let source = r#"name: Demo action
inputs:
  message:
    required: true
outputs:
  result:
    value: ${{ steps.run.outputs.result }}
runs:
  using: composite
  steps:
    - id: run
      shell: bash
      run: echo "${{ inputs.message }}"
"#;
    let compilation = compile_auto(".github/actions/demo/action.yml", source, Budget::default())
        .expect("composite action compiles");
    let graph = compilation.graph;

    assert_eq!(
        graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Workflow)
            .count(),
        1
    );
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| { node.kind == NodeKind::Parameter && node.name == "input:message" })
    );
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| { node.kind == NodeKind::Resource && node.name == "output:action.result" })
    );
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| { node.kind == NodeKind::Job && node.name == "composite action" })
    );
    let command = graph
        .nodes
        .iter()
        .find(|node| node.kind == NodeKind::Command)
        .expect("composite command");
    assert_eq!(command.name, "echo \"${{ inputs.message }}\"");
    assert_eq!(
        command
            .attributes
            .get("shell")
            .and_then(|value| value.constants())
            .map(<[String]>::to_vec),
        Some(vec!["bash".to_owned()])
    );
    assert!(graph.validate().is_empty(), "{:?}", graph.validate());
}

#[test]
#[allow(clippy::too_many_lines)]
fn azure_full_semantic_surface_is_lowered() {
    let source = r"trigger: [main]
pr: [main]
schedules:
  - cron: 0 0 * * *
parameters:
  - name: release
    default: false
variables:
  plain: value
resources:
  repositories:
    - repository: shared
      type: github
      name: acme/templates
      ref: refs/tags/v1
stages:
  - stage: Build
    condition: eq(parameters.release, true)
    jobs:
      - job: compile
        strategy:
          matrix:
            linux:
              image: ubuntu
        steps:
          - checkout: self
          - task: PublishBuildArtifacts@1
          - template: steps/build.yml@shared
          - bash: echo $(plain)
      - deployment: deploy
        dependsOn: compile
        condition: succeeded()
        environment:
          name: production
        variables:
          - name: scoped
            value: secret
        steps:
          - pwsh: Write-Host ok
  - stage: Release
    dependsOn: Build
    jobs: []
extends:
  parameters:
    ${{ if eq(parameters.release, true) }}:
      enabled: true
";
    let compilation = compile_auto("azure-pipelines.yml", source, Budget::default())
        .expect("Azure semantic surface compiles");
    let graph = &compilation.graph;
    let named = |kind, name| {
        graph
            .nodes
            .iter()
            .find(|node| node.kind == kind && node.name == name)
            .expect("named Azure node")
    };

    for trigger in ["trigger", "pr", "schedules"] {
        named(NodeKind::Trigger, trigger);
    }
    named(NodeKind::Parameter, "release");
    named(NodeKind::Resource, "variable:plain");
    let repository = named(NodeKind::Resource, "repository:shared");
    let repository_call = named(NodeKind::Call, "acme/templates@refs/tags/v1");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Call && edge.from == repository.id && edge.to == repository_call.id
    }));

    let build = named(NodeKind::Stage, "Build");
    let release = named(NodeKind::Stage, "Release");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == build.id
            && edge.to == release.id
            && edge.label.as_deref() == Some("dependsOn")
    }));
    named(NodeKind::Gate, "condition:stage:Build");
    let compile = named(NodeKind::Job, "compile");
    let deploy = named(NodeKind::Job, "deploy");
    let deploy_gate = named(NodeKind::Gate, "condition:job:deploy");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Control
            && edge.from == compile.id
            && edge.to == deploy_gate.id
            && edge.label.as_deref() == Some("dependsOn")
    }));
    assert!(deploy.capabilities.contains(&Capability::Deployment));
    assert!(deploy.effects.contains(&ObservableEffect::DeploymentChange));
    named(NodeKind::Parameter, "matrix.linux");
    let environment = named(NodeKind::Resource, "environment:production");
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Grant && edge.from == environment.id && edge.to == deploy.id
    }));
    named(NodeKind::Resource, "variable:scoped");
    named(NodeKind::Call, "checkout:self");
    let publish = named(NodeKind::Call, "PublishBuildArtifacts@1");
    assert!(publish.capabilities.contains(&Capability::ArtifactWrite));
    assert!(publish.effects.contains(&ObservableEffect::ArtifactPublish));
    named(NodeKind::Call, "steps/build.yml@shared");
    named(NodeKind::Command, "echo $(plain)");
    named(NodeKind::Command, "Write-Host ok");
    named(
        NodeKind::Opaque,
        "template-directive:${{ if eq(parameters.release, true) }}",
    );
    assert!(compilation.dependencies.iter().any(|dependency| {
        dependency.kind == DependencyKind::Repository
            && dependency.reference == "acme/templates@refs/tags/v1"
    }));
    assert!(compilation.dependencies.iter().any(|dependency| {
        dependency.kind == DependencyKind::Template
            && dependency.reference == "steps/build.yml@shared"
    }));
    assert!(graph.validate().is_empty(), "{:?}", graph.validate());
}
