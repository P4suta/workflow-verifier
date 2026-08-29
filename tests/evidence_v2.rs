use workflow_verifier::internal::runner_protocol::{
    Evidence, EvidenceBody, RunResult, controls_digest, sha256_hex, validate_plan,
};

const PLAN: &str = include_str!("../test/fixtures/protocol/runner-v2-complete.json");
const RUN: &str = include_str!("../test/fixtures/protocol/sandbox-run-v2-complete.json");

#[test]
fn persisted_run_and_evidence_round_trip_and_bind_to_the_authenticated_plan() {
    let plan = validate_plan(PLAN).expect("canonical plan");
    let run = RunResult::parse(RUN).expect("canonical sandbox run");
    assert_eq!(run.canonical_json(), RUN);
    run.evidence
        .validate_for_plan(&plan)
        .expect("evidence binds to runner-v2");

    let evidence_source = RUN
        .strip_prefix("{\"evidence\":")
        .and_then(|value| value.split_once(",\"outcome\":").map(|(value, _)| value))
        .expect("fixture evidence projection");
    let evidence = Evidence::parse(evidence_source).expect("standalone evidence");
    assert_eq!(evidence.canonical_json(), run.evidence.canonical_json());
}

#[test]
fn tampering_unknown_fields_and_broken_event_chains_fail_closed() {
    let tampered = RUN.replacen("\"sequence\":0", "\"sequence\":1", 1);
    assert!(RunResult::parse(&tampered).is_err());

    let unknown = RUN.replacen(
        "\"schema\":\"sandbox-run-v2\"",
        "\"schema\":\"sandbox-run-v2\",\"surprise\":true",
        1,
    );
    assert!(RunResult::parse(&unknown).is_err());

    let duplicate = RUN.replacen(
        "\"schema\":\"sandbox-run-v2\"",
        "\"schema\":\"sandbox-run-v2\",\"schema\":\"sandbox-run-v2\"",
        1,
    );
    assert!(RunResult::parse(&duplicate).is_err());
}

#[test]
fn evidence_backend_identity_must_match_the_authenticated_plan() {
    let plan = validate_plan(PLAN).expect("canonical plan");
    let mut evidence = Evidence::for_plan(&plan);
    evidence.append(EvidenceBody::BackendAttested {
        id: "oci:podman".to_owned(),
        version: "0.1.0".to_owned(),
        platform: "linux-x86_64".to_owned(),
        controls_digest: controls_digest(&plan.controls),
    });
    for control in &plan.controls {
        evidence.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }
    for step in &plan.steps {
        let (executable, argv) = step.argv.split_first().expect("planned command");
        evidence.append(EvidenceBody::ProcessStarted {
            executable: executable.clone(),
            argv: argv.to_vec(),
        });
        evidence.append(EvidenceBody::ProcessExited { code: 0 });
    }
    evidence.append(EvidenceBody::ResourceObserved {
        wall_time_ms: 1,
        cpu_time_ms: 0,
        peak_memory_bytes: 0,
        processes: 1,
        output_bytes: 0,
        scratch_bytes: 0,
        scratch_entries: 0,
    });
    evidence.append(EvidenceBody::LogRecorded {
        digest: format!("sha256:{}", sha256_hex(b"")),
    });
    evidence.append(EvidenceBody::FilesystemFinal {
        digest: plan.source_digest.clone(),
    });

    assert!(
        evidence
            .validate_for_plan(&plan)
            .is_err_and(|error| error.contains("backend attestation identity"))
    );
}
