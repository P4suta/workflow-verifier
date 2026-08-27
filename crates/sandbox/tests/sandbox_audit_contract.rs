mod support;

use support::valid_request;
use workflow_verifier_runner_protocol::{EvidenceBody, controls_digest};
use workflow_verifier_sandbox::{
    Evidence, RunnerPlan, SandboxAudit, SandboxAuditStatus, ValidatedPlan, validate_plan,
};

const HTTPS_DEFAULT_PORT: u16 = 443;
const PROCESS_FAILURE: i32 = 1;

fn fixture_plan() -> ValidatedPlan {
    validate_plan(include_str!(
        "../../../test/fixtures/protocol/runner-v2-complete.json"
    ))
    .expect("published runner-v2 fixture")
}

fn evidence_with_attestation(
    plan: &ValidatedPlan,
    id: &str,
    version: &str,
    platform: &str,
    attested_controls_digest: String,
) -> Evidence {
    let mut evidence = Evidence::for_plan(plan);
    evidence.append(EvidenceBody::BackendAttested {
        id: id.to_owned(),
        version: version.to_owned(),
        platform: platform.to_owned(),
        controls_digest: attested_controls_digest,
    });
    for control in &plan.controls {
        evidence.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }
    evidence
}

fn complete_evidence(plan: &ValidatedPlan) -> Evidence {
    evidence_with_attestation(
        plan,
        &plan.backend,
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        controls_digest(&plan.controls),
    )
}

fn reasons(status: &SandboxAuditStatus) -> &[String] {
    match status {
        SandboxAuditStatus::Incomplete(reasons) => reasons,
        SandboxAuditStatus::Verified => panic!("expected incomplete audit"),
    }
}

#[test]
fn runtime_events_produce_effects_and_failures_without_losing_evidence() {
    let plan = fixture_plan();
    let mut evidence = complete_evidence(&plan);
    evidence.append(EvidenceBody::ProcessStarted {
        executable: "/bin/sh".to_owned(),
        argv: vec!["-c".to_owned(), "true".to_owned()],
    });
    evidence.append(EvidenceBody::ProcessExited { code: 0 });
    evidence.append(EvidenceBody::ProcessExited {
        code: PROCESS_FAILURE,
    });
    evidence.append(EvidenceBody::FilesystemAccess {
        path: "/workspace/input".to_owned(),
        operation: "read".to_owned(),
        allowed: true,
    });
    evidence.append(EvidenceBody::FilesystemAccess {
        path: "/workspace/output".to_owned(),
        operation: "write".to_owned(),
        allowed: true,
    });
    evidence.append(EvidenceBody::NetworkAttempt {
        host: "example.com".to_owned(),
        port: HTTPS_DEFAULT_PORT,
        allowed: false,
    });
    evidence.append(EvidenceBody::BackendError("runtime unavailable".to_owned()));

    let audit = SandboxAudit::evaluate(&plan, &evidence).expect("valid evidence chain");
    let reasons = reasons(audit.status());
    assert!(reasons.contains(&format!("process exited with code {PROCESS_FAILURE}")));
    assert!(reasons.contains(&"backend error: runtime unavailable".to_owned()));
    let canonical = audit.to_canonical_json();
    for effect in [
        "command_execution",
        "file_read",
        "file_write",
        "network_request",
    ] {
        assert!(canonical.contains(effect), "missing effect {effect}");
    }
    assert_eq!(audit.event_count(), evidence.event_count());
}

#[test]
fn backend_attestation_is_required_exactly_once() {
    let plan = fixture_plan();
    let mut missing = Evidence::for_plan(&plan);
    for control in &plan.controls {
        missing.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }
    let audit = SandboxAudit::evaluate(&plan, &missing).unwrap();
    assert!(
        reasons(audit.status())
            .iter()
            .any(|reason| reason.contains("attestation is missing"))
    );

    let mut multiple = complete_evidence(&plan);
    multiple.append(EvidenceBody::BackendAttested {
        id: plan.backend.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: std::env::consts::OS.to_owned(),
        controls_digest: controls_digest(&plan.controls),
    });
    let audit = SandboxAudit::evaluate(&plan, &multiple).unwrap();
    assert!(
        reasons(audit.status())
            .iter()
            .any(|reason| reason.contains("multiple backend attestations"))
    );
}

#[test]
fn every_backend_attestation_identity_field_is_checked_independently() {
    let plan = fixture_plan();
    let cases = [
        (
            "different-backend",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            controls_digest(&plan.controls),
            "identity does not match",
        ),
        (
            plan.backend.as_str(),
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            support::digest("wrong-controls"),
            "controls digest does not match",
        ),
    ];
    for (id, version, platform, attested_digest, expected) in cases {
        let evidence = evidence_with_attestation(&plan, id, version, platform, attested_digest);
        let audit = SandboxAudit::evaluate(&plan, &evidence).unwrap();
        assert!(
            reasons(audit.status())
                .iter()
                .any(|reason| reason.contains(expected)),
            "missing reason containing {expected}"
        );
    }

    for (version, platform) in [("", std::env::consts::OS), (env!("CARGO_PKG_VERSION"), "")] {
        let evidence = evidence_with_attestation(
            &plan,
            &plan.backend,
            version,
            platform,
            controls_digest(&plan.controls),
        );
        assert!(SandboxAudit::evaluate(&plan, &evidence).is_err());
    }
}

#[test]
fn every_requested_control_needs_its_own_attestation() {
    let plan = fixture_plan();
    let mut evidence = Evidence::for_plan(&plan);
    evidence.append(EvidenceBody::BackendAttested {
        id: plan.backend.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: std::env::consts::OS.to_owned(),
        controls_digest: controls_digest(&plan.controls),
    });
    let omitted = plan.controls[0];
    for control in plan.controls.iter().skip(1) {
        evidence.append(EvidenceBody::ControlAttested(control.name().to_owned()));
    }
    let audit = SandboxAudit::evaluate(&plan, &evidence).unwrap();
    assert!(reasons(audit.status()).contains(&format!("control not attested: {}", omitted.name())));
}

#[test]
fn an_incomplete_plan_cannot_be_upgraded_by_complete_runtime_evidence() {
    let mut request = valid_request();
    request.steps[0].supported = false;
    let runner_plan = RunnerPlan::build(request).expect("inspectable incomplete plan");
    let plan = runner_plan.validated();
    let evidence = complete_evidence(plan);
    let audit = SandboxAudit::evaluate(plan, &evidence).unwrap();
    assert!(
        reasons(audit.status())
            .iter()
            .any(|reason| reason.contains("Unsupported_step"))
    );
}

#[test]
fn verified_audit_requires_no_reconciliation_reasons() {
    let plan = fixture_plan();
    let evidence = complete_evidence(&plan);
    let audit = SandboxAudit::evaluate(&plan, &evidence).unwrap();
    assert_eq!(audit.status(), &SandboxAuditStatus::Verified);
}
