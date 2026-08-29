use crate::domain::{Graph, ObservableEffect, UnknownReason};
use crate::foundation::JsonValue;
use crate::internal::runner_protocol::{
    Evidence, EvidenceBody, PlanStatus, ValidatedPlan, controls_digest,
};
use crate::verifier::{Property, PropertyState, observable_effects};
use std::collections::{BTreeMap, BTreeSet};

const RUNTIME_ENVELOPE_RULE_ID: &str = "WV-RUNTIME-001";
const CONTAINED_EFFECTS_EXPLANATION: &str =
    "observed runtime effects are contained in the static effect envelope";
const MISSING_STATIC_GRAPHS_DETAIL: &str = "static graphs were not supplied";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxAuditStatus {
    Verified,
    Incomplete(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAudit {
    plan_digest: String,
    source_digest: String,
    backend: String,
    controls_digest: String,
    status: SandboxAuditStatus,
    observed_effects: Vec<ObservableEffect>,
    reconciliation: Option<Property>,
    event_count: usize,
    evidence_tail: String,
}

impl SandboxAudit {
    /// Reconcile an authenticated evidence chain with its runner-v2 plan.
    ///
    /// # Errors
    /// Rejects structurally invalid evidence or evidence bound to another plan.
    pub fn evaluate(plan: &ValidatedPlan, evidence: &Evidence) -> Result<Self, String> {
        Self::evaluate_internal(plan, evidence, None)
    }

    /// Reconcile an authenticated evidence chain with its plan and static IR.
    ///
    /// # Errors
    /// Rejects structurally invalid evidence or evidence bound to another plan.
    pub fn evaluate_with_graphs(
        plan: &ValidatedPlan,
        evidence: &Evidence,
        graphs: &[Graph],
    ) -> Result<Self, String> {
        Self::evaluate_internal(plan, evidence, Some(graphs))
    }

    fn evaluate_internal(
        plan: &ValidatedPlan,
        evidence: &Evidence,
        graphs: Option<&[Graph]>,
    ) -> Result<Self, String> {
        if evidence.plan_digest() != plan.digest {
            return Err("evidence is bound to a different execution plan".to_owned());
        }
        evidence.validate()?;
        let expected_controls_digest = controls_digest(&plan.controls);
        let mut backend_attestations = Vec::new();
        let mut attested_controls = BTreeSet::new();
        let mut reasons = match &plan.status {
            PlanStatus::Complete => Vec::new(),
            PlanStatus::Incomplete(values) => values.clone(),
        };
        let mut observed_effects = BTreeSet::new();
        for body in evidence.bodies() {
            match body {
                EvidenceBody::BackendAttested {
                    id,
                    version,
                    platform,
                    controls_digest,
                } => backend_attestations.push((id, version, platform, controls_digest)),
                EvidenceBody::ControlAttested(control) => {
                    attested_controls.insert(control.as_str());
                }
                EvidenceBody::BackendError(message) => {
                    reasons.push(format!("backend error: {message}"));
                }
                EvidenceBody::ProcessExited { code } if *code != 0 => {
                    reasons.push(format!("process exited with code {code}"));
                }
                EvidenceBody::ProcessStarted { .. } => {
                    observed_effects.insert(ObservableEffect::CommandExecution);
                }
                EvidenceBody::FilesystemAccess { operation, .. } => {
                    observed_effects.insert(if operation.to_ascii_lowercase().contains("write") {
                        ObservableEffect::FileWrite
                    } else {
                        ObservableEffect::FileRead
                    });
                }
                EvidenceBody::NetworkAttempt { .. } => {
                    observed_effects.insert(ObservableEffect::NetworkRequest);
                }
                _ => {}
            }
        }
        match backend_attestations.as_slice() {
            [] => reasons.push("backend attestation is missing from evidence".to_owned()),
            [(id, _, _, observed)] => {
                if *id != &plan.backend {
                    reasons.push("backend attestation identity does not match the plan".to_owned());
                }
                if *observed != &expected_controls_digest {
                    reasons.push(
                        "backend attestation controls digest does not match the plan".to_owned(),
                    );
                }
                // `Evidence::validate` already rejects empty version/platform
                // identities before reconciliation reaches this branch.
            }
            _ => reasons.push("multiple backend attestations are ambiguous".to_owned()),
        }
        for control in &plan.controls {
            if !attested_controls.contains(control.name()) {
                reasons.push(format!("control not attested: {}", control.name()));
            }
        }
        let reconciliation =
            graphs.map(|graphs| reconcile_runtime_envelope(graphs, &observed_effects));
        if let Some(property) = reconciliation
            .as_ref()
            .filter(|property| reconciliation_requires_incomplete_status(property))
        {
            reasons.push(property.explanation.clone());
        }
        reasons.sort();
        reasons.dedup();
        let status = if reasons.is_empty() {
            SandboxAuditStatus::Verified
        } else {
            SandboxAuditStatus::Incomplete(reasons)
        };
        Ok(Self {
            plan_digest: plan.digest.clone(),
            source_digest: plan.source_digest.clone(),
            backend: plan.backend.clone(),
            controls_digest: expected_controls_digest,
            status,
            observed_effects: observed_effects.into_iter().collect(),
            reconciliation,
            event_count: evidence.event_count(),
            evidence_tail: evidence.tail_digest().to_owned(),
        })
    }

    #[must_use]
    pub fn status(&self) -> &SandboxAuditStatus {
        &self.status
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let status = match &self.status {
            SandboxAuditStatus::Verified => JsonValue::Object(BTreeMap::from([(
                "state".to_owned(),
                JsonValue::String("verified".to_owned()),
            )])),
            SandboxAuditStatus::Incomplete(reasons) => JsonValue::Object(BTreeMap::from([
                (
                    "reasons".to_owned(),
                    JsonValue::Array(reasons.iter().cloned().map(JsonValue::String).collect()),
                ),
                (
                    "state".to_owned(),
                    JsonValue::String("incomplete".to_owned()),
                ),
            ])),
        };
        JsonValue::Object(BTreeMap::from([
            (
                "backend".to_owned(),
                JsonValue::String(self.backend.clone()),
            ),
            (
                "controls_digest".to_owned(),
                JsonValue::String(self.controls_digest.clone()),
            ),
            (
                "event_count".to_owned(),
                JsonValue::Integer(i64::try_from(self.event_count).unwrap_or(i64::MAX)),
            ),
            (
                "evidence_tail".to_owned(),
                JsonValue::String(self.evidence_tail.clone()),
            ),
            (
                "observed_effects".to_owned(),
                JsonValue::Array(
                    self.observed_effects
                        .iter()
                        .map(|effect| JsonValue::String(effect.name().to_owned()))
                        .collect(),
                ),
            ),
            (
                "plan_digest".to_owned(),
                JsonValue::String(self.plan_digest.clone()),
            ),
            (
                "reconciliation".to_owned(),
                self.reconciliation
                    .as_ref()
                    .map_or(JsonValue::Null, Property::to_json),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("sandbox-audit-v1".to_owned()),
            ),
            (
                "source_digest".to_owned(),
                JsonValue::String(self.source_digest.clone()),
            ),
            ("status".to_owned(), status),
        ]))
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }
}

fn reconciliation_requires_incomplete_status(property: &Property) -> bool {
    matches!(
        property.state,
        PropertyState::Violated | PropertyState::Unknown(_)
    )
}

fn reconcile_runtime_envelope(
    graphs: &[Graph],
    observed_effects: &BTreeSet<ObservableEffect>,
) -> Property {
    let static_effects: BTreeSet<_> = observable_effects(graphs).into_iter().collect();
    let unknowns: Vec<_> = graphs
        .iter()
        .flat_map(|graph| &graph.nodes)
        .filter_map(|node| node.unknown.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let unexpected: Vec<_> = observed_effects
        .difference(&static_effects)
        .copied()
        .collect();
    let state = if unexpected.is_empty() {
        PropertyState::Proved
    } else if graphs.is_empty() {
        PropertyState::Unknown(vec![UnknownReason::ExternalState(
            MISSING_STATIC_GRAPHS_DETAIL.to_owned(),
        )])
    } else if unknowns.is_empty() {
        PropertyState::Violated
    } else {
        PropertyState::Unknown(unknowns)
    };
    let explanation = if unexpected.is_empty() {
        CONTAINED_EFFECTS_EXPLANATION.to_owned()
    } else {
        format!(
            "runtime observed effects outside the static envelope: {}",
            unexpected
                .iter()
                .map(|effect| effect.name())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Property {
        id: RUNTIME_ENVELOPE_RULE_ID.to_owned(),
        state,
        subject: None,
        explanation,
    }
}
