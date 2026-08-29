#[path = "support/digest.rs"]
mod digest_support;
#[path = "support/scenario.rs"]
mod scenario_support;

use digest_support::digest;
use scenario_support::scenario;
use workflow_verifier::internal::conformance::foundation::Budget;
use workflow_verifier::internal::conformance::frontend::compile_auto;
use workflow_verifier::internal::conformance::sandbox::{RunnerPlatform, plan_scenario};

fn compile(source: &str) -> workflow_verifier::internal::conformance::domain::Graph {
    compile_auto(".github/workflows/ci.yml", source, Budget::default())
        .expect("valid GitHub workflow")
        .graph
}

#[test]
fn missing_and_ambiguous_entrypoints_and_jobs_are_rejected() {
    let selected = scenario(RunnerPlatform::LinuxX86_64);
    assert_eq!(
        plan_scenario(&selected, &digest("image"), &[]).unwrap_err(),
        "scenario workflow entrypoint was not compiled: .github/workflows/ci.yml"
    );

    let graph = compile("on: push\njobs:\n  other:\n    steps:\n      - run: true\n");
    assert_eq!(
        plan_scenario(&selected, &digest("image"), std::slice::from_ref(&graph)).unwrap_err(),
        "scenario job was not found: build"
    );

    let selected_graph = compile("on: push\njobs:\n  build:\n    steps:\n      - run: true\n");
    assert_eq!(
        plan_scenario(
            &selected,
            &digest("image"),
            &[selected_graph.clone(), selected_graph]
        )
        .unwrap_err(),
        "scenario workflow entrypoint is ambiguous: .github/workflows/ci.yml"
    );
}

#[test]
fn dependency_closure_is_recursive_ordered_and_excludes_unrelated_jobs() {
    let graph = compile(
        r"on: push
jobs:
  prepare:
    steps:
      - run: echo prepare
  intermediate:
    needs: prepare
    steps:
      - run: echo intermediate
  build:
    needs: intermediate
    steps:
      - run: echo build
  unrelated:
    steps:
      - run: echo unrelated
",
    );
    let plan = plan_scenario(
        &scenario(RunnerPlatform::LinuxX86_64),
        &digest("image"),
        &[graph],
    )
    .unwrap();
    assert_eq!(plan.selected_jobs, ["build", "intermediate", "prepare"]);
    let commands: Vec<_> = plan
        .steps
        .iter()
        .map(|step| step.argv.last().unwrap().as_str())
        .collect();
    assert_eq!(
        commands,
        ["echo prepare", "echo intermediate", "echo build"]
    );
    assert!(plan.incomplete_reasons.is_empty());
}

#[test]
fn unknown_conditions_are_explicit_and_false_work_is_silent() {
    let graph = compile(
        r"on: push
jobs:
  build:
    steps:
      - if: github.ref == inputs.expected_ref
        run: echo unknown
      - if: github.event_name != 'push'
        uses: external/action@v1
",
    );
    let plan = plan_scenario(
        &scenario(RunnerPlatform::LinuxX86_64),
        &digest("image"),
        &[graph],
    )
    .unwrap();
    assert!(plan.steps.is_empty());
    assert_eq!(plan.incomplete_reasons.len(), 1);
    assert!(plan.incomplete_reasons[0].contains("Unknown_expression"));
}

#[test]
fn reachable_unresolved_calls_are_never_silently_dropped() {
    let graph =
        compile("on: push\njobs:\n  build:\n    steps:\n      - uses: external/action@v1\n");
    let plan = plan_scenario(
        &scenario(RunnerPlatform::LinuxX86_64),
        &digest("image"),
        &[graph],
    )
    .unwrap();
    assert!(
        plan.incomplete_reasons
            .iter()
            .any(|reason| reason.contains("Unresolved_call"))
    );
}
