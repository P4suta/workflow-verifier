#![forbid(unsafe_code)]

mod json;
mod sha256;
pub mod vm;

pub use sha256::Sha256;

use std::collections::BTreeMap;

pub const BACKEND_ATTESTATION_SCHEMA: &str = "backend-attestation-v1";
/// Hexadecimal width fixed by the SHA-256 digest format.
pub const SHA256_HEX_DIGITS: usize = 64;
/// Sentinel mandated by runner-v2 for a workload that cannot be bound yet.
pub const UNRESOLVED_CONTENT_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

// These values are the published runner-v2 portable profile. Their authority is
// `schema/runner-v2.schema.json`, where every corresponding property is `const`.
pub const RUNNER_V2_CPU_CORES: u64 = 1;
pub const RUNNER_V2_WALL_TIME_SECONDS: u64 = 900;
pub const RUNNER_V2_MEMORY_BYTES: u64 = 2_147_483_648;
pub const RUNNER_V2_OUTPUT_BYTES: u64 = 16_777_216;
pub const RUNNER_V2_PROCESSES: u64 = 128;
pub const RUNNER_V2_SCRATCH_BYTES: u64 = 4_294_967_296;
pub const RUNNER_V2_SCRATCH_ENTRIES: u64 = 100_000;
const BYTES_PER_MEBIBYTE: u64 = 1_048_576;
pub const RUNNER_V2_MEMORY_MIB: u64 = RUNNER_V2_MEMORY_BYTES / BYTES_PER_MEBIBYTE;

// Stable workflow-verifier process outcomes shared by the CLI and native
// helpers. These values are part of the published 0..=5 invocation contract.
const HELPER_EXIT_SUCCESS: i32 = 0;
const HELPER_EXIT_INVALID_INPUT: i32 = 2;
const HELPER_EXIT_INCOMPLETE: i32 = 3;
const HELPER_EXIT_INFRASTRUCTURE: i32 = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Control {
    SourceReadOnly,
    ScratchOverlay,
    NetworkDeny,
    EgressBroker,
    ProcessIsolation,
    ResourceLimits,
    SecretRedaction,
    Namespace,
    Seccomp,
    Landlock,
    CgroupV2,
    AppContainer,
    RestrictedToken,
    JobObject,
    AppSandbox,
    VirtualMachine,
}

impl Control {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SourceReadOnly => "source_read_only",
            Self::ScratchOverlay => "scratch_overlay",
            Self::NetworkDeny => "network_deny",
            Self::EgressBroker => "egress_broker",
            Self::ProcessIsolation => "process_isolation",
            Self::ResourceLimits => "resource_limits",
            Self::SecretRedaction => "secret_redaction",
            Self::Namespace => "namespace",
            Self::Seccomp => "seccomp",
            Self::Landlock => "landlock",
            Self::CgroupV2 => "cgroup_v2",
            Self::AppContainer => "app_container",
            Self::RestrictedToken => "restricted_token",
            Self::JobObject => "job_object",
            Self::AppSandbox => "app_sandbox",
            Self::VirtualMachine => "virtual_machine",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "source_read_only" => Self::SourceReadOnly,
            "scratch_overlay" => Self::ScratchOverlay,
            "network_deny" => Self::NetworkDeny,
            "egress_broker" => Self::EgressBroker,
            "process_isolation" => Self::ProcessIsolation,
            "resource_limits" => Self::ResourceLimits,
            "secret_redaction" => Self::SecretRedaction,
            "namespace" => Self::Namespace,
            "seccomp" => Self::Seccomp,
            "landlock" => Self::Landlock,
            "cgroup_v2" => Self::CgroupV2,
            "app_container" => Self::AppContainer,
            "restricted_token" => Self::RestrictedToken,
            "job_object" => Self::JobObject,
            "app_sandbox" => Self::AppSandbox,
            "virtual_machine" => Self::VirtualMachine,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanStatus {
    Complete,
    Incomplete(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Step {
    pub id: String,
    pub image: String,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: String,
    pub supported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub cpu_seconds: u64,
    pub memory_mb: u64,
    pub processes: u64,
    pub output_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProfile {
    pub kind: String,
    pub runner_platform: String,
    pub workload_digest: String,
    pub rootfs_digest: Option<String>,
    pub helper_digest: Option<String>,
    pub boot_digest: Option<String>,
    pub capability_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub reference: String,
    pub digest: Option<String>,
    pub available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceBody {
    BackendAttested {
        id: String,
        version: String,
        platform: String,
        controls_digest: String,
    },
    ControlAttested(String),
    ProcessStarted {
        executable: String,
        argv: Vec<String>,
    },
    ProcessExited {
        code: i32,
    },
    FilesystemAccess {
        path: String,
        operation: String,
        allowed: bool,
    },
    NetworkAttempt {
        host: String,
        port: u16,
        allowed: bool,
    },
    ArtifactRecorded {
        path: String,
        digest: String,
    },
    SecretRedacted {
        name: String,
    },
    ResourceObserved {
        wall_time_ms: u64,
        cpu_time_ms: u64,
        peak_memory_bytes: u64,
        processes: u64,
        output_bytes: u64,
        scratch_bytes: u64,
        scratch_entries: u64,
    },
    LogRecorded {
        digest: String,
    },
    FilesystemFinal {
        digest: String,
    },
    BackendError(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EvidenceEvent {
    sequence: usize,
    previous_digest: String,
    digest: String,
    body: EvidenceBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    plan_digest: String,
    bindings: EvidenceBindings,
    requested_limits: Limits,
    effective_limits: Limits,
    source_digest: String,
    events: Vec<EvidenceEvent>,
    forensic_sidecars: Vec<ForensicSidecar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
// These names intentionally mirror the public evidence-v2 binding fields.
#[expect(
    clippy::struct_field_names,
    reason = "field names exactly mirror the published evidence-v2 wire bindings"
)]
struct EvidenceBindings {
    scenario_digest: String,
    source_digest: String,
    lock_digest: String,
    runtime_digest: String,
    controls_digest: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ForensicSidecar {
    kind: String,
    digest: String,
}

fn object(fields: impl IntoIterator<Item = (&'static str, json::Value)>) -> json::Value {
    json::Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn strings(values: &[String]) -> json::Value {
    json::Value::Array(values.iter().cloned().map(json::Value::String).collect())
}

fn limits_json(limits: &Limits) -> json::Value {
    object([
        (
            "cpu_cores",
            json::Value::Integer(
                i64::try_from(RUNNER_V2_CPU_CORES).expect("portable CPU limit fits i64"),
            ),
        ),
        (
            "memory_bytes",
            json::Value::Integer(
                i64::try_from(limits.memory_mb.saturating_mul(BYTES_PER_MEBIBYTE))
                    .expect("portable memory limit fits i64"),
            ),
        ),
        (
            "output_bytes",
            json::Value::Integer(
                i64::try_from(limits.output_bytes).expect("portable output limit fits i64"),
            ),
        ),
        (
            "processes",
            json::Value::Integer(
                i64::try_from(limits.processes).expect("portable process limit fits i64"),
            ),
        ),
        (
            "scratch_bytes",
            json::Value::Integer(
                i64::try_from(RUNNER_V2_SCRATCH_BYTES).expect("portable scratch limit fits i64"),
            ),
        ),
        (
            "scratch_entries",
            json::Value::Integer(
                i64::try_from(RUNNER_V2_SCRATCH_ENTRIES)
                    .expect("portable scratch entry limit fits i64"),
            ),
        ),
        (
            "wall_time_seconds",
            json::Value::Integer(
                i64::try_from(limits.cpu_seconds).expect("portable wall limit fits i64"),
            ),
        ),
    ])
}

fn runtime_json(runtime: &RuntimeProfile) -> json::Value {
    let nullable = |value: &Option<String>| {
        value.as_ref().map_or(json::Value::Null, |value| {
            json::Value::String(value.clone())
        })
    };
    object([
        ("boot_digest", nullable(&runtime.boot_digest)),
        (
            "capability_fingerprint",
            nullable(&runtime.capability_fingerprint),
        ),
        ("helper_digest", nullable(&runtime.helper_digest)),
        ("kind", json::Value::String(runtime.kind.clone())),
        ("rootfs_digest", nullable(&runtime.rootfs_digest)),
        (
            "runner_platform",
            json::Value::String(runtime.runner_platform.clone()),
        ),
        (
            "workload_digest",
            json::Value::String(runtime.workload_digest.clone()),
        ),
    ])
}

// Keep the complete tagged-union mapping together so schema reviews can verify
// that every evidence event is serialized exactly once.
#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive tagged-union mapping serializes every evidence-v2 event"
)]
fn evidence_body_json(body: &EvidenceBody) -> json::Value {
    match body {
        EvidenceBody::BackendAttested {
            id,
            version,
            platform,
            controls_digest,
        } => object([
            (
                "controls_digest",
                json::Value::String(controls_digest.clone()),
            ),
            ("id", json::Value::String(id.clone())),
            ("kind", json::Value::String("backend_attested".to_owned())),
            ("platform", json::Value::String(platform.clone())),
            ("version", json::Value::String(version.clone())),
        ]),
        EvidenceBody::ControlAttested(control) => object([
            ("control", json::Value::String(control.clone())),
            ("kind", json::Value::String("control_attested".to_owned())),
        ]),
        EvidenceBody::ProcessStarted { executable, argv } => object([
            ("argv", strings(argv)),
            ("executable", json::Value::String(executable.clone())),
            ("kind", json::Value::String("process_started".to_owned())),
        ]),
        EvidenceBody::ProcessExited { code } => object([
            ("code", json::Value::Integer(i64::from(*code))),
            ("kind", json::Value::String("process_exited".to_owned())),
        ]),
        EvidenceBody::FilesystemAccess {
            path,
            operation,
            allowed,
        } => object([
            ("allowed", json::Value::Bool(*allowed)),
            ("kind", json::Value::String("filesystem_access".to_owned())),
            ("operation", json::Value::String(operation.clone())),
            ("path", json::Value::String(path.replace('\\', "/"))),
        ]),
        EvidenceBody::NetworkAttempt {
            host,
            port,
            allowed,
        } => object([
            ("allowed", json::Value::Bool(*allowed)),
            ("host", json::Value::String(host.clone())),
            ("kind", json::Value::String("network_attempt".to_owned())),
            ("port", json::Value::Integer(i64::from(*port))),
        ]),
        EvidenceBody::ArtifactRecorded { path, digest } => object([
            ("digest", json::Value::String(digest.clone())),
            ("kind", json::Value::String("artifact_recorded".to_owned())),
            ("path", json::Value::String(path.replace('\\', "/"))),
        ]),
        EvidenceBody::SecretRedacted { name } => object([
            ("kind", json::Value::String("secret_redacted".to_owned())),
            ("name", json::Value::String(name.clone())),
        ]),
        EvidenceBody::ResourceObserved {
            wall_time_ms,
            cpu_time_ms,
            peak_memory_bytes,
            processes,
            output_bytes,
            scratch_bytes,
            scratch_entries,
        } => object([
            (
                "cpu_time_ms",
                json::Value::Integer(
                    i64::try_from(*cpu_time_ms).expect("cpu observation fits i64"),
                ),
            ),
            ("kind", json::Value::String("resource_observed".to_owned())),
            (
                "output_bytes",
                json::Value::Integer(
                    i64::try_from(*output_bytes).expect("output observation fits i64"),
                ),
            ),
            (
                "peak_memory_bytes",
                json::Value::Integer(
                    i64::try_from(*peak_memory_bytes).expect("memory observation fits i64"),
                ),
            ),
            (
                "processes",
                json::Value::Integer(
                    i64::try_from(*processes).expect("process observation fits i64"),
                ),
            ),
            (
                "scratch_bytes",
                json::Value::Integer(
                    i64::try_from(*scratch_bytes).expect("scratch observation fits i64"),
                ),
            ),
            (
                "scratch_entries",
                json::Value::Integer(
                    i64::try_from(*scratch_entries).expect("scratch entry observation fits i64"),
                ),
            ),
            (
                "wall_time_ms",
                json::Value::Integer(
                    i64::try_from(*wall_time_ms).expect("wall observation fits i64"),
                ),
            ),
        ]),
        EvidenceBody::LogRecorded { digest } => object([
            ("digest", json::Value::String(digest.clone())),
            ("kind", json::Value::String("log_recorded".to_owned())),
        ]),
        EvidenceBody::FilesystemFinal { digest } => object([
            ("digest", json::Value::String(digest.clone())),
            ("kind", json::Value::String("filesystem_final".to_owned())),
        ]),
        EvidenceBody::BackendError(message) => object([
            ("kind", json::Value::String("backend_error".to_owned())),
            ("message", json::Value::String(message.clone())),
        ]),
    }
}

fn unsigned_evidence_event(
    sequence: usize,
    previous_digest: &str,
    body: &EvidenceBody,
) -> json::Value {
    object([
        ("body", evidence_body_json(body)),
        (
            "previous_digest",
            json::Value::String(previous_digest.to_owned()),
        ),
        (
            "sequence",
            json::Value::Integer(i64::try_from(sequence).expect("event sequence fits i64")),
        ),
    ])
}

impl Evidence {
    #[must_use]
    pub fn new(plan_digest: impl Into<String>) -> Self {
        let plan_digest = plan_digest.into();
        let limits = portable_limits();
        Self {
            bindings: EvidenceBindings {
                scenario_digest: plan_digest.clone(),
                source_digest: plan_digest.clone(),
                lock_digest: plan_digest.clone(),
                runtime_digest: plan_digest.clone(),
                controls_digest: plan_digest.clone(),
            },
            requested_limits: limits.clone(),
            effective_limits: limits,
            source_digest: plan_digest.clone(),
            plan_digest,
            events: Vec::new(),
            forensic_sidecars: Vec::new(),
        }
    }

    #[must_use]
    pub fn for_plan(plan: &ValidatedPlan) -> Self {
        let runtime_digest = format!(
            "sha256:{}",
            sha256::digest(json::canonical(&runtime_json(&plan.runtime)).as_bytes())
        );
        Self {
            plan_digest: plan.digest.clone(),
            bindings: EvidenceBindings {
                scenario_digest: plan.scenario_digest.clone(),
                source_digest: plan.source_digest.clone(),
                lock_digest: plan.lock_digest.clone(),
                runtime_digest,
                controls_digest: controls_digest(&plan.controls),
            },
            requested_limits: plan.limits.clone(),
            effective_limits: plan.limits.clone(),
            source_digest: plan.source_digest.clone(),
            events: Vec::new(),
            forensic_sidecars: Vec::new(),
        }
    }

    pub fn append(&mut self, body: EvidenceBody) {
        let sequence = self.events.len();
        let previous_digest = self
            .events
            .last()
            .map_or_else(|| self.plan_digest.clone(), |event| event.digest.clone());
        let unsigned = unsigned_evidence_event(sequence, &previous_digest, &body);
        let digest = format!(
            "sha256:{}",
            sha256::digest(json::canonical(&unsigned).as_bytes())
        );
        self.events.push(EvidenceEvent {
            sequence,
            previous_digest,
            digest,
            body,
        });
    }

    // Evidence-v2 is deliberately assembled in schema order in one auditable
    // function; splitting this object risks silently omitting a required field.
    #[expect(
        clippy::too_many_lines,
        reason = "evidence-v2 fields are assembled in published wire order for auditability"
    )]
    fn json(&self) -> json::Value {
        let mut wall_time_ms = 0;
        let mut cpu_time_ms = 0;
        let mut peak_memory_bytes = 0;
        let mut processes = 0;
        let mut output_bytes = 0;
        let mut scratch_bytes = 0;
        let mut scratch_entries = 0;
        let mut redacted_log_digest = format!("sha256:{}", sha256::digest(b""));
        let mut final_filesystem_digest = self.source_digest.clone();
        for event in &self.events {
            match &event.body {
                EvidenceBody::ResourceObserved {
                    wall_time_ms: wall,
                    cpu_time_ms: cpu,
                    peak_memory_bytes: memory,
                    processes: process_count,
                    output_bytes: output,
                    scratch_bytes: scratch,
                    scratch_entries: entries,
                } => {
                    wall_time_ms = *wall;
                    cpu_time_ms = *cpu;
                    peak_memory_bytes = *memory;
                    processes = *process_count;
                    output_bytes = *output;
                    scratch_bytes = *scratch;
                    scratch_entries = *entries;
                }
                EvidenceBody::LogRecorded { digest } => redacted_log_digest.clone_from(digest),
                EvidenceBody::FilesystemFinal { digest } => {
                    final_filesystem_digest.clone_from(digest);
                }
                _ => {}
            }
        }
        let events = self
            .events
            .iter()
            .map(|event| {
                let unsigned =
                    unsigned_evidence_event(event.sequence, &event.previous_digest, &event.body);
                let json::Value::Object(mut fields) = unsigned else {
                    unreachable!("event is an object")
                };
                fields.insert(
                    "digest".to_owned(),
                    json::Value::String(event.digest.clone()),
                );
                json::Value::Object(fields)
            })
            .collect();
        let mut artifact_records = self
            .events
            .iter()
            .filter_map(|event| match &event.body {
                EvidenceBody::ArtifactRecorded { path, digest } => {
                    Some((path.replace('\\', "/"), digest.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        artifact_records.sort_by(|left, right| left.0.cmp(&right.0));
        let artifacts = artifact_records
            .into_iter()
            .map(|(path, digest)| {
                object([
                    ("digest", json::Value::String(digest)),
                    ("path", json::Value::String(path)),
                ])
            })
            .collect();
        object([
            ("artifacts", json::Value::Array(artifacts)),
            (
                "bindings",
                object([
                    (
                        "controls_digest",
                        json::Value::String(self.bindings.controls_digest.clone()),
                    ),
                    (
                        "lock_digest",
                        json::Value::String(self.bindings.lock_digest.clone()),
                    ),
                    (
                        "runtime_digest",
                        json::Value::String(self.bindings.runtime_digest.clone()),
                    ),
                    (
                        "scenario_digest",
                        json::Value::String(self.bindings.scenario_digest.clone()),
                    ),
                    (
                        "source_digest",
                        json::Value::String(self.bindings.source_digest.clone()),
                    ),
                ]),
            ),
            ("effective_limits", limits_json(&self.effective_limits)),
            ("events", json::Value::Array(events)),
            (
                "final_filesystem_digest",
                json::Value::String(final_filesystem_digest),
            ),
            (
                "forensic_sidecars",
                json::Value::Array(
                    self.forensic_sidecars
                        .iter()
                        .map(|sidecar| {
                            object([
                                ("digest", json::Value::String(sidecar.digest.clone())),
                                ("kind", json::Value::String(sidecar.kind.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "observed_resources",
                object([
                    (
                        "cpu_time_ms",
                        json::Value::Integer(
                            i64::try_from(cpu_time_ms).expect("cpu observation fits i64"),
                        ),
                    ),
                    (
                        "output_bytes",
                        json::Value::Integer(
                            i64::try_from(output_bytes).expect("output observation fits i64"),
                        ),
                    ),
                    (
                        "peak_memory_bytes",
                        json::Value::Integer(
                            i64::try_from(peak_memory_bytes).expect("memory observation fits i64"),
                        ),
                    ),
                    (
                        "processes",
                        json::Value::Integer(
                            i64::try_from(processes).expect("process observation fits i64"),
                        ),
                    ),
                    (
                        "scratch_bytes",
                        json::Value::Integer(
                            i64::try_from(scratch_bytes).expect("scratch observation fits i64"),
                        ),
                    ),
                    (
                        "scratch_entries",
                        json::Value::Integer(
                            i64::try_from(scratch_entries)
                                .expect("scratch entry observation fits i64"),
                        ),
                    ),
                    (
                        "wall_time_ms",
                        json::Value::Integer(
                            i64::try_from(wall_time_ms).expect("wall observation fits i64"),
                        ),
                    ),
                ]),
            ),
            ("plan_digest", json::Value::String(self.plan_digest.clone())),
            (
                "redacted_log_digest",
                json::Value::String(redacted_log_digest),
            ),
            ("requested_limits", limits_json(&self.requested_limits)),
            ("schema", json::Value::String("evidence-v2".to_owned())),
        ])
    }

    #[must_use]
    pub fn canonical_json(&self) -> String {
        json::canonical(&self.json())
    }

    /// Parse and authenticate a persisted `evidence-v2` document.
    ///
    /// # Errors
    /// Rejects malformed JSON, unknown fields, invalid digests, broken event
    /// chains, and redundant summaries which disagree with their events.
    pub fn parse(source: &str) -> Result<Self, String> {
        let root = json::parse(source)?;
        parse_evidence_value(&root)
    }

    /// Validate the evidence envelope and its hash-linked event chain.
    ///
    /// # Errors
    /// Returns the first structural, digest, limit, path, or chain mismatch.
    pub fn validate(&self) -> Result<(), String> {
        let digests = [
            self.plan_digest.as_str(),
            self.bindings.scenario_digest.as_str(),
            self.bindings.source_digest.as_str(),
            self.bindings.lock_digest.as_str(),
            self.bindings.runtime_digest.as_str(),
            self.bindings.controls_digest.as_str(),
        ];
        if digests
            .into_iter()
            .any(|digest| !valid_content_digest(digest))
        {
            return Err("evidence-v2 contains an invalid SHA-256 digest".to_owned());
        }
        if self.source_digest != self.bindings.source_digest {
            return Err("evidence source binding mismatch".to_owned());
        }
        if self.requested_limits != portable_limits() || self.effective_limits != portable_limits()
        {
            return Err("evidence-v2 portable limits do not match runner-v2".to_owned());
        }
        for sidecar in &self.forensic_sidecars {
            if sidecar.kind.trim().is_empty() || !valid_content_digest(&sidecar.digest) {
                return Err("forensic sidecar identity is invalid".to_owned());
            }
        }
        let mut previous = self.plan_digest.as_str();
        for (expected_sequence, event) in self.events.iter().enumerate() {
            if event.sequence != expected_sequence {
                return Err("evidence sequence is not contiguous".to_owned());
            }
            if event.previous_digest != previous {
                return Err("evidence previous digest mismatch".to_owned());
            }
            validate_evidence_body(&event.body)?;
            let expected = format!(
                "sha256:{}",
                sha256::digest(
                    json::canonical(&unsigned_evidence_event(
                        event.sequence,
                        &event.previous_digest,
                        &event.body,
                    ))
                    .as_bytes(),
                )
            );
            if event.digest != expected {
                return Err("evidence event digest mismatch".to_owned());
            }
            previous = &event.digest;
        }
        Ok(())
    }

    /// Prove that persisted evidence was produced for exactly this runner-v2
    /// plan and contains the required control and process attestations.
    ///
    /// # Errors
    /// Returns a stable mismatch when any binding or lifecycle is incomplete.
    #[expect(
        clippy::too_many_lines,
        reason = "all evidence-v2 cross-field bindings form one authenticated schema check"
    )]
    pub fn validate_for_plan(&self, plan: &ValidatedPlan) -> Result<(), String> {
        self.validate()?;
        let expected = Self::for_plan(plan);
        if self.plan_digest != plan.digest {
            return Err("evidence plan digest mismatch".to_owned());
        }
        if self.bindings != expected.bindings {
            return Err("evidence provenance bindings do not match runner-v2".to_owned());
        }
        // `self.validate()` has already proved that requested and effective
        // limits are the same portable profile, so one comparison is complete.
        if self.requested_limits != plan.limits {
            return Err("evidence limits do not match runner-v2".to_owned());
        }
        let backend_attestations: Vec<_> = self
            .events
            .iter()
            .filter_map(|event| match &event.body {
                EvidenceBody::BackendAttested {
                    id,
                    controls_digest,
                    ..
                } => Some((id.as_str(), controls_digest.as_str())),
                _ => None,
            })
            .collect();
        if backend_attestations.len() != 1 {
            return Err("evidence-v2 requires exactly one backend attestation".to_owned());
        }
        let (backend_id, attested_controls) = backend_attestations[0];
        if backend_id != plan.backend {
            return Err("backend attestation identity does not match runner-v2".to_owned());
        }
        // Non-empty backend identity fields were authenticated by
        // `validate_evidence_body` during `self.validate()` above.
        if attested_controls != expected.bindings.controls_digest {
            return Err("backend attestation controls do not match runner-v2".to_owned());
        }
        let controls: Vec<_> = self
            .events
            .iter()
            .filter_map(|event| match &event.body {
                EvidenceBody::ControlAttested(control) => Some(control.as_str()),
                _ => None,
            })
            .collect();
        let expected_controls: Vec<_> =
            plan.controls.iter().map(|control| control.name()).collect();
        if controls != expected_controls {
            return Err("control attestations do not exactly match runner-v2".to_owned());
        }
        for (predicate, message) in [
            (
                EvidenceBodyKind::Resource,
                "evidence-v2 requires exactly one resource observation",
            ),
            (
                EvidenceBodyKind::Log,
                "evidence-v2 requires exactly one redacted log record",
            ),
            (
                EvidenceBodyKind::FilesystemFinal,
                "evidence-v2 requires exactly one final filesystem record",
            ),
        ] {
            if self
                .events
                .iter()
                .filter(|event| predicate.matches(&event.body))
                .count()
                != 1
            {
                return Err(message.to_owned());
            }
        }
        let starts: Vec<_> = self
            .events
            .iter()
            .filter_map(|event| match &event.body {
                EvidenceBody::ProcessStarted { executable, argv } => {
                    Some((executable.as_str(), argv.as_slice()))
                }
                _ => None,
            })
            .collect();
        let exits = self
            .events
            .iter()
            .filter(|event| matches!(event.body, EvidenceBody::ProcessExited { .. }))
            .count();
        if starts.len() != exits {
            return Err("process lifecycle start/exit events are unbalanced".to_owned());
        }
        if !plan.steps.is_empty() && starts.is_empty() {
            return Err("evidence-v2 is missing the planned process lifecycle".to_owned());
        }
        if starts.len() > plan.steps.len()
            || !starts
                .iter()
                .zip(&plan.steps)
                .all(|((executable, argv), step)| {
                    step.argv
                        .split_first()
                        .is_some_and(|(expected, rest)| expected == executable && rest == *argv)
                })
        {
            return Err("process lifecycle does not match the ordered runner-v2 steps".to_owned());
        }
        Ok(())
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn tail_digest(&self) -> &str {
        self.events
            .last()
            .map_or(self.plan_digest.as_str(), |event| event.digest.as_str())
    }

    pub fn bodies(&self) -> impl Iterator<Item = &EvidenceBody> {
        self.events.iter().map(|event| &event.body)
    }
}

#[derive(Clone, Copy)]
enum EvidenceBodyKind {
    Resource,
    Log,
    FilesystemFinal,
}

impl EvidenceBodyKind {
    fn matches(self, body: &EvidenceBody) -> bool {
        matches!(
            (self, body),
            (Self::Resource, EvidenceBody::ResourceObserved { .. })
                | (Self::Log, EvidenceBody::LogRecorded { .. })
                | (Self::FilesystemFinal, EvidenceBody::FilesystemFinal { .. })
        )
    }
}

fn portable_limits() -> Limits {
    Limits {
        cpu_seconds: RUNNER_V2_WALL_TIME_SECONDS,
        memory_mb: RUNNER_V2_MEMORY_MIB,
        processes: RUNNER_V2_PROCESSES,
        output_bytes: RUNNER_V2_OUTPUT_BYTES,
    }
}

fn parse_evidence_value(root: &json::Value) -> Result<Evidence, String> {
    let fields = root
        .object()
        .ok_or_else(|| "evidence-v2 must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "artifacts",
            "bindings",
            "effective_limits",
            "events",
            "final_filesystem_digest",
            "forensic_sidecars",
            "observed_resources",
            "plan_digest",
            "redacted_log_digest",
            "requested_limits",
            "schema",
        ],
        "evidence-v2",
    )?;
    if string_field(fields, "schema")? != "evidence-v2" {
        return Err("evidence schema must be evidence-v2".to_owned());
    }
    let bindings = parse_evidence_bindings(field(fields, "bindings")?)?;
    let events = field(fields, "events")?
        .array()
        .ok_or_else(|| "evidence events must be an array".to_owned())?
        .iter()
        .map(parse_evidence_event)
        .collect::<Result<Vec<_>, _>>()?;
    let forensic_sidecars = parse_forensic_sidecars(field(fields, "forensic_sidecars")?)?;
    let evidence = Evidence {
        plan_digest: string_field(fields, "plan_digest")?,
        requested_limits: parse_evidence_limits(field(fields, "requested_limits")?)?,
        effective_limits: parse_evidence_limits(field(fields, "effective_limits")?)?,
        source_digest: bindings.source_digest.clone(),
        bindings,
        events,
        forensic_sidecars,
    };
    evidence.validate()?;
    if json::canonical(&evidence.json()) != json::canonical(root) {
        return Err("evidence summaries do not match the authenticated event chain".to_owned());
    }
    Ok(evidence)
}

fn parse_evidence_bindings(value: &json::Value) -> Result<EvidenceBindings, String> {
    let fields = value
        .object()
        .ok_or_else(|| "evidence bindings must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "controls_digest",
            "lock_digest",
            "runtime_digest",
            "scenario_digest",
            "source_digest",
        ],
        "evidence bindings",
    )?;
    Ok(EvidenceBindings {
        scenario_digest: string_field(fields, "scenario_digest")?,
        source_digest: string_field(fields, "source_digest")?,
        lock_digest: string_field(fields, "lock_digest")?,
        runtime_digest: string_field(fields, "runtime_digest")?,
        controls_digest: string_field(fields, "controls_digest")?,
    })
}

fn parse_evidence_limits(value: &json::Value) -> Result<Limits, String> {
    let fields = value
        .object()
        .ok_or_else(|| "evidence limits must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "cpu_cores",
            "memory_bytes",
            "output_bytes",
            "processes",
            "scratch_bytes",
            "scratch_entries",
            "wall_time_seconds",
        ],
        "evidence limits",
    )?;
    let limits = Limits {
        cpu_seconds: integer_field(fields, "wall_time_seconds")?,
        memory_mb: integer_field(fields, "memory_bytes")? / BYTES_PER_MEBIBYTE,
        processes: integer_field(fields, "processes")?,
        output_bytes: integer_field(fields, "output_bytes")?,
    };
    if integer_field(fields, "cpu_cores")? != RUNNER_V2_CPU_CORES
        || integer_field(fields, "memory_bytes")? != RUNNER_V2_MEMORY_BYTES
        || integer_field(fields, "scratch_bytes")? != RUNNER_V2_SCRATCH_BYTES
        || integer_field(fields, "scratch_entries")? != RUNNER_V2_SCRATCH_ENTRIES
        || limits != portable_limits()
    {
        return Err("evidence-v2 portable limits do not match runner-v2".to_owned());
    }
    Ok(limits)
}

fn parse_forensic_sidecars(value: &json::Value) -> Result<Vec<ForensicSidecar>, String> {
    value
        .array()
        .ok_or_else(|| "forensic_sidecars must be an array".to_owned())?
        .iter()
        .map(|value| {
            let fields = value
                .object()
                .ok_or_else(|| "forensic sidecar must be an object".to_owned())?;
            exact_fields(fields, &["digest", "kind"], "forensic sidecar")?;
            Ok(ForensicSidecar {
                kind: string_field(fields, "kind")?,
                digest: string_field(fields, "digest")?,
            })
        })
        .collect()
}

fn parse_evidence_event(value: &json::Value) -> Result<EvidenceEvent, String> {
    let fields = value
        .object()
        .ok_or_else(|| "evidence event must be an object".to_owned())?;
    exact_fields(
        fields,
        &["body", "digest", "previous_digest", "sequence"],
        "evidence event",
    )?;
    Ok(EvidenceEvent {
        sequence: usize::try_from(integer_field(fields, "sequence")?)
            .map_err(|_| "evidence sequence is out of range".to_owned())?,
        previous_digest: string_field(fields, "previous_digest")?,
        digest: string_field(fields, "digest")?,
        body: parse_evidence_body(field(fields, "body")?)?,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one exhaustive tagged-union parser covers every evidence-v2 event"
)]
fn parse_evidence_body(value: &json::Value) -> Result<EvidenceBody, String> {
    let fields = value
        .object()
        .ok_or_else(|| "evidence event body must be an object".to_owned())?;
    let kind = string_field(fields, "kind")?;
    match kind.as_str() {
        "backend_attested" => {
            exact_fields(
                fields,
                &["controls_digest", "id", "kind", "platform", "version"],
                "backend_attested",
            )?;
            Ok(EvidenceBody::BackendAttested {
                id: string_field(fields, "id")?,
                version: string_field(fields, "version")?,
                platform: string_field(fields, "platform")?,
                controls_digest: string_field(fields, "controls_digest")?,
            })
        }
        "control_attested" => {
            exact_fields(fields, &["control", "kind"], "control_attested")?;
            Ok(EvidenceBody::ControlAttested(string_field(
                fields, "control",
            )?))
        }
        "process_started" => {
            exact_fields(fields, &["argv", "executable", "kind"], "process_started")?;
            Ok(EvidenceBody::ProcessStarted {
                executable: string_field(fields, "executable")?,
                argv: string_array(field(fields, "argv")?, "argv")?,
            })
        }
        "process_exited" => {
            exact_fields(fields, &["code", "kind"], "process_exited")?;
            let code = field(fields, "code")?
                .integer()
                .ok_or_else(|| "process exit code must be an integer".to_owned())?;
            Ok(EvidenceBody::ProcessExited {
                code: i32::try_from(code)
                    .map_err(|_| "process exit code is out of range".to_owned())?,
            })
        }
        "filesystem_access" => {
            exact_fields(
                fields,
                &["allowed", "kind", "operation", "path"],
                "filesystem_access",
            )?;
            Ok(EvidenceBody::FilesystemAccess {
                path: string_field(fields, "path")?,
                operation: string_field(fields, "operation")?,
                allowed: boolean_field(fields, "allowed")?,
            })
        }
        "network_attempt" => {
            exact_fields(
                fields,
                &["allowed", "host", "kind", "port"],
                "network_attempt",
            )?;
            Ok(EvidenceBody::NetworkAttempt {
                host: string_field(fields, "host")?,
                port: u16::try_from(integer_field(fields, "port")?)
                    .map_err(|_| "network port is out of range".to_owned())?,
                allowed: boolean_field(fields, "allowed")?,
            })
        }
        "artifact_recorded" => {
            exact_fields(fields, &["digest", "kind", "path"], "artifact_recorded")?;
            Ok(EvidenceBody::ArtifactRecorded {
                path: string_field(fields, "path")?,
                digest: string_field(fields, "digest")?,
            })
        }
        "secret_redacted" => {
            exact_fields(fields, &["kind", "name"], "secret_redacted")?;
            Ok(EvidenceBody::SecretRedacted {
                name: string_field(fields, "name")?,
            })
        }
        "resource_observed" => {
            exact_fields(
                fields,
                &[
                    "cpu_time_ms",
                    "kind",
                    "output_bytes",
                    "peak_memory_bytes",
                    "processes",
                    "scratch_bytes",
                    "scratch_entries",
                    "wall_time_ms",
                ],
                "resource_observed",
            )?;
            Ok(EvidenceBody::ResourceObserved {
                wall_time_ms: integer_field(fields, "wall_time_ms")?,
                cpu_time_ms: integer_field(fields, "cpu_time_ms")?,
                peak_memory_bytes: integer_field(fields, "peak_memory_bytes")?,
                processes: integer_field(fields, "processes")?,
                output_bytes: integer_field(fields, "output_bytes")?,
                scratch_bytes: integer_field(fields, "scratch_bytes")?,
                scratch_entries: integer_field(fields, "scratch_entries")?,
            })
        }
        "log_recorded" => {
            exact_fields(fields, &["digest", "kind"], "log_recorded")?;
            Ok(EvidenceBody::LogRecorded {
                digest: string_field(fields, "digest")?,
            })
        }
        "filesystem_final" => {
            exact_fields(fields, &["digest", "kind"], "filesystem_final")?;
            Ok(EvidenceBody::FilesystemFinal {
                digest: string_field(fields, "digest")?,
            })
        }
        "backend_error" => {
            exact_fields(fields, &["kind", "message"], "backend_error")?;
            Ok(EvidenceBody::BackendError(string_field(fields, "message")?))
        }
        _ => Err(format!("unknown evidence event kind {kind}")),
    }
}

fn validate_evidence_body(body: &EvidenceBody) -> Result<(), String> {
    let digest = match body {
        EvidenceBody::BackendAttested {
            id,
            version,
            platform,
            controls_digest,
        } => {
            if id.trim().is_empty() || version.trim().is_empty() || platform.trim().is_empty() {
                return Err("backend attestation identity must not be empty".to_owned());
            }
            Some(controls_digest)
        }
        EvidenceBody::ControlAttested(control) => {
            if Control::parse(control).is_none() {
                return Err(format!("unknown control attestation {control}"));
            }
            None
        }
        EvidenceBody::ProcessStarted { executable, .. } => {
            if executable.trim().is_empty() {
                return Err("process executable must not be empty".to_owned());
            }
            None
        }
        EvidenceBody::FilesystemAccess {
            path, operation, ..
        } => {
            if path.trim().is_empty() || operation.trim().is_empty() {
                return Err("filesystem evidence must identify path and operation".to_owned());
            }
            None
        }
        EvidenceBody::NetworkAttempt { host, port, .. } => {
            if host.trim().is_empty() || *port == 0 {
                return Err("network evidence host and port are invalid".to_owned());
            }
            None
        }
        EvidenceBody::ArtifactRecorded { path, digest } => {
            if !root_relative_path(path) {
                return Err("evidence artifact paths must be root-relative".to_owned());
            }
            Some(digest)
        }
        EvidenceBody::SecretRedacted { name } => {
            if name.trim().is_empty() {
                return Err("redacted secret name must not be empty".to_owned());
            }
            None
        }
        EvidenceBody::LogRecorded { digest } | EvidenceBody::FilesystemFinal { digest } => {
            Some(digest)
        }
        EvidenceBody::BackendError(message) => {
            if message.trim().is_empty() {
                return Err("backend error evidence must not be empty".to_owned());
            }
            None
        }
        EvidenceBody::ProcessExited { .. } | EvidenceBody::ResourceObserved { .. } => None,
    };
    if digest.is_some_and(|digest| !valid_content_digest(digest)) {
        Err("evidence-v2 contains an invalid SHA-256 digest".to_owned())
    } else {
        Ok(())
    }
}

fn root_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(['/', '\\'])
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Completed,
    StepFailed { step: String, code: Option<i32> },
    TimedOut { step: String },
    OutputLimitExceeded { step: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResult {
    pub evidence: Evidence,
    pub outcome: Outcome,
}

impl RunResult {
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let outcome = match &self.outcome {
            Outcome::Completed => object([("state", json::Value::String("completed".to_owned()))]),
            Outcome::StepFailed { step, code } => object([
                (
                    "code",
                    code.map_or(json::Value::Null, |value| {
                        json::Value::Integer(i64::from(value))
                    }),
                ),
                ("state", json::Value::String("step_failed".to_owned())),
                ("step", json::Value::String(step.clone())),
            ]),
            Outcome::TimedOut { step } => object([
                ("state", json::Value::String("timed_out".to_owned())),
                ("step", json::Value::String(step.clone())),
            ]),
            Outcome::OutputLimitExceeded { step } => object([
                (
                    "state",
                    json::Value::String("output_limit_exceeded".to_owned()),
                ),
                ("step", json::Value::String(step.clone())),
            ]),
        };
        let value = object([
            ("evidence", self.evidence.json()),
            ("outcome", outcome),
            ("schema", json::Value::String("sandbox-run-v2".to_owned())),
        ]);
        format!("{}\n", json::canonical(&value))
    }

    /// Parse a persisted `sandbox-run-v2` result and authenticate its evidence.
    ///
    /// # Errors
    /// Rejects malformed/unknown fields, invalid outcomes, or invalid evidence.
    pub fn parse(source: &str) -> Result<Self, String> {
        let root = json::parse(source)?;
        let fields = root
            .object()
            .ok_or_else(|| "sandbox-run-v2 must be an object".to_owned())?;
        exact_fields(fields, &["evidence", "outcome", "schema"], "sandbox-run-v2")?;
        if string_field(fields, "schema")? != "sandbox-run-v2" {
            return Err("sandbox run schema must be sandbox-run-v2".to_owned());
        }
        let result = Self {
            evidence: parse_evidence_value(field(fields, "evidence")?)?,
            outcome: parse_outcome(field(fields, "outcome")?)?,
        };
        if result.canonical_json().trim_end() != json::canonical(&root) {
            return Err("sandbox-run-v2 summary is not internally consistent".to_owned());
        }
        Ok(result)
    }
}

fn parse_outcome(value: &json::Value) -> Result<Outcome, String> {
    let fields = value
        .object()
        .ok_or_else(|| "sandbox outcome must be an object".to_owned())?;
    match string_field(fields, "state")?.as_str() {
        "completed" => {
            exact_fields(fields, &["state"], "completed outcome")?;
            Ok(Outcome::Completed)
        }
        "step_failed" => {
            exact_fields(fields, &["code", "state", "step"], "step_failed outcome")?;
            let code = match field(fields, "code")? {
                json::Value::Null => None,
                json::Value::Integer(value) => Some(
                    i32::try_from(*value)
                        .map_err(|_| "sandbox outcome code is out of range".to_owned())?,
                ),
                _ => return Err("sandbox outcome code must be an integer or null".to_owned()),
            };
            Ok(Outcome::StepFailed {
                step: nonempty_string_field(fields, "step")?,
                code,
            })
        }
        "timed_out" => {
            exact_fields(fields, &["state", "step"], "timed_out outcome")?;
            Ok(Outcome::TimedOut {
                step: nonempty_string_field(fields, "step")?,
            })
        }
        "output_limit_exceeded" => {
            exact_fields(fields, &["state", "step"], "output_limit_exceeded outcome")?;
            Ok(Outcome::OutputLimitExceeded {
                step: nonempty_string_field(fields, "step")?,
            })
        }
        state => Err(format!("unknown sandbox outcome {state}")),
    }
}

fn nonempty_string_field(
    fields: &BTreeMap<String, json::Value>,
    name: &str,
) -> Result<String, String> {
    let value = string_field(fields, name)?;
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(value)
    }
}

#[must_use]
pub fn quote_json(value: &str) -> String {
    json::canonical(&json::Value::String(value.to_owned()))
}

#[must_use]
pub fn sha256_hex(value: &[u8]) -> String {
    sha256::digest(value)
}

#[must_use]
pub fn controls_digest(controls: &[Control]) -> String {
    let value = json::Value::Array(
        controls
            .iter()
            .map(|control| json::Value::String(control.name().to_owned()))
            .collect(),
    );
    format!(
        "sha256:{}",
        sha256::digest(json::canonical(&value).as_bytes())
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPlan {
    pub digest: String,
    pub backend: String,
    pub scenario_digest: String,
    pub provider_profile: String,
    pub selected_jobs: Vec<String>,
    pub controls: Vec<Control>,
    pub status: PlanStatus,
    pub source_digest: String,
    pub lock_digest: String,
    pub runtime: RuntimeProfile,
    pub limits: Limits,
    pub network_destinations: Vec<String>,
    pub secret_names: Vec<String>,
    pub dependencies: Vec<Dependency>,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub id: &'static str,
    pub version: &'static str,
    pub platform: &'static str,
    pub available: bool,
    pub controls: Vec<Control>,
    pub reasons: Vec<String>,
}

impl Descriptor {
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let controls = self
            .controls
            .iter()
            .map(|control| format!("\"{}\"", control.name()))
            .collect::<Vec<_>>()
            .join(",");
        let reasons = self
            .reasons
            .iter()
            .map(|reason| quote_json(reason))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"available\":{},\"controls\":[{}],\"id\":\"{}\",\"platform\":\"{}\",\"reasons\":[{}],\"schema\":\"{}\",\"version\":\"{}\"}}\n",
            self.available,
            controls,
            self.id,
            self.platform,
            reasons,
            BACKEND_ATTESTATION_SCHEMA,
            self.version
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchError {
    IncompletePlan(Vec<String>),
    UnsupportedPlatform { backend: String, platform: String },
    BackendMismatch { expected: String, actual: String },
    MissingControls(Vec<Control>),
    InvalidPlan(String),
    Infrastructure(String),
    StepFailed { step: String, code: Option<i32> },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LaunchError {}

fn field<'a>(
    object: &'a BTreeMap<String, json::Value>,
    name: &str,
) -> Result<&'a json::Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("runner plan needs field {name}"))
}

fn exact_fields(
    object: &BTreeMap<String, json::Value>,
    expected: &[&str],
    context: &str,
) -> Result<(), String> {
    let actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    let mut sorted_expected = expected.to_vec();
    sorted_expected.sort_unstable();
    if actual == sorted_expected {
        Ok(())
    } else {
        Err(format!(
            "{context} fields are [{}], expected [{}]",
            object.keys().cloned().collect::<Vec<_>>().join(", "),
            expected.join(", ")
        ))
    }
}

fn string_field(object: &BTreeMap<String, json::Value>, name: &str) -> Result<String, String> {
    field(object, name)?
        .string()
        .map(str::to_owned)
        .ok_or_else(|| format!("{name} must be a string"))
}

fn integer_field(object: &BTreeMap<String, json::Value>, name: &str) -> Result<u64, String> {
    let value = field(object, name)?
        .integer()
        .ok_or_else(|| format!("{name} must be an integer"))?;
    u64::try_from(value).map_err(|_| format!("{name} cannot be negative"))
}

fn boolean_field(object: &BTreeMap<String, json::Value>, name: &str) -> Result<bool, String> {
    field(object, name)?
        .bool()
        .ok_or_else(|| format!("{name} must be boolean"))
}

fn nullable_string_field(
    object: &BTreeMap<String, json::Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match field(object, name)? {
        json::Value::Null => Ok(None),
        json::Value::String(value) => Ok(Some(value.clone())),
        _ => Err(format!("{name} must be a string or null")),
    }
}

fn string_array(value: &json::Value, name: &str) -> Result<Vec<String>, String> {
    value
        .array()
        .ok_or_else(|| format!("{name} must be an array"))?
        .iter()
        .map(|value| {
            value
                .string()
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} must contain strings"))
        })
        .collect()
}

fn validate_digest(root: &json::Value, supplied: &str) -> Result<(), String> {
    let json::Value::Object(mut unsigned) = root.clone() else {
        return Err("runner plan must be an object".to_owned());
    };
    unsigned.remove("digest");
    let expected = format!(
        "sha256:{}",
        sha256::digest(json::canonical(&json::Value::Object(unsigned)).as_bytes())
    );
    if supplied == expected {
        Ok(())
    } else {
        Err("runner plan digest mismatch".to_owned())
    }
}

fn parse_backend(object: &BTreeMap<String, json::Value>) -> Result<String, String> {
    let backend = string_field(object, "backend")?;
    let native = matches!(
        backend.as_str(),
        "linux-native" | "windows-native" | "macos-vm"
    );
    let oci = backend.strip_prefix("oci:").is_some_and(|engine| {
        !engine.is_empty()
            && engine
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    });
    if native || oci {
        Ok(backend)
    } else {
        Err(format!("unknown backend {backend}"))
    }
}

fn parse_controls(object: &BTreeMap<String, json::Value>) -> Result<Vec<Control>, String> {
    let controls = string_array(field(object, "controls")?, "controls")?
        .into_iter()
        .map(|name| Control::parse(&name).ok_or_else(|| format!("unknown control {name}")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut unique = controls.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() == controls.len() {
        Ok(controls)
    } else {
        Err("controls must be unique".to_owned())
    }
}

fn parse_status(object: &BTreeMap<String, json::Value>) -> Result<PlanStatus, String> {
    let status = field(object, "status")?
        .object()
        .ok_or_else(|| "status must be an object".to_owned())?;
    match string_field(status, "state")?.as_str() {
        "complete" => {
            exact_fields(status, &["state"], "complete status")?;
            Ok(PlanStatus::Complete)
        }
        "incomplete" => {
            exact_fields(status, &["reasons", "state"], "incomplete status")?;
            let reasons = string_array(field(status, "reasons")?, "reasons")?;
            if reasons.is_empty() {
                Err("incomplete status needs at least one reason".to_owned())
            } else {
                Ok(PlanStatus::Incomplete(reasons))
            }
        }
        other => Err(format!("unknown plan status {other}")),
    }
}

fn parse_limits(object: &BTreeMap<String, json::Value>) -> Result<Limits, String> {
    let fields = field(object, "limits")?
        .object()
        .ok_or_else(|| "limits must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "cpu_cores",
            "memory_bytes",
            "output_bytes",
            "processes",
            "scratch_bytes",
            "scratch_entries",
            "wall_time_seconds",
        ],
        "limits",
    )?;
    let cpu_cores = integer_field(fields, "cpu_cores")?;
    let memory_bytes = integer_field(fields, "memory_bytes")?;
    let scratch_bytes = integer_field(fields, "scratch_bytes")?;
    let scratch_entries = integer_field(fields, "scratch_entries")?;
    let limits = Limits {
        cpu_seconds: integer_field(fields, "wall_time_seconds")?,
        memory_mb: memory_bytes / BYTES_PER_MEBIBYTE,
        processes: integer_field(fields, "processes")?,
        output_bytes: integer_field(fields, "output_bytes")?,
    };
    if cpu_cores == RUNNER_V2_CPU_CORES
        && memory_bytes == RUNNER_V2_MEMORY_BYTES
        && limits == portable_limits()
        && scratch_bytes == RUNNER_V2_SCRATCH_BYTES
        && scratch_entries == RUNNER_V2_SCRATCH_ENTRIES
    {
        Ok(limits)
    } else {
        Err("runner-v2 portable limits do not match the published profile".to_owned())
    }
}

fn parse_runtime(object: &BTreeMap<String, json::Value>) -> Result<RuntimeProfile, String> {
    let fields = field(object, "runtime")?
        .object()
        .ok_or_else(|| "runtime must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "boot_digest",
            "capability_fingerprint",
            "helper_digest",
            "kind",
            "rootfs_digest",
            "runner_platform",
            "workload_digest",
        ],
        "runtime",
    )?;
    let runtime = RuntimeProfile {
        kind: string_field(fields, "kind")?,
        runner_platform: string_field(fields, "runner_platform")?,
        workload_digest: string_field(fields, "workload_digest")?,
        rootfs_digest: nullable_string_field(fields, "rootfs_digest")?,
        helper_digest: nullable_string_field(fields, "helper_digest")?,
        boot_digest: nullable_string_field(fields, "boot_digest")?,
        capability_fingerprint: nullable_string_field(fields, "capability_fingerprint")?,
    };
    let optional_digests = [
        runtime.rootfs_digest.as_deref(),
        runtime.helper_digest.as_deref(),
        runtime.boot_digest.as_deref(),
        runtime.capability_fingerprint.as_deref(),
    ];
    if !valid_content_digest(&runtime.workload_digest)
        || optional_digests
            .into_iter()
            .flatten()
            .any(|digest| !valid_content_digest(digest))
    {
        Err("runtime identities must be SHA-256 content digests".to_owned())
    } else {
        Ok(runtime)
    }
}

fn parse_network(
    object: &BTreeMap<String, json::Value>,
    controls: &[Control],
) -> Result<Vec<String>, String> {
    let fields = field(object, "network")?
        .object()
        .ok_or_else(|| "network must be an object".to_owned())?;
    exact_fields(fields, &["destinations", "mode"], "network")?;
    let mode = string_field(fields, "mode")?;
    let destinations = string_array(field(fields, "destinations")?, "destinations")?;
    let denied = controls.contains(&Control::NetworkDeny);
    if (denied && mode != "deny") || (!denied && mode != "allowlist") {
        return Err("network mode contradicts requested controls".to_owned());
    }
    if denied && !destinations.is_empty() {
        return Err("network-deny plans cannot contain destinations".to_owned());
    }
    if !denied && destinations.is_empty() {
        return Err("network-enabled plans require an HTTPS destination policy".to_owned());
    }
    if destinations.iter().any(|destination| {
        !destination.starts_with("https://")
            || destination.contains('@')
            || destination.contains('\\')
            || destination.contains('?')
            || destination.contains('#')
            || destination.contains("..")
            || destination.contains('%')
    }) {
        return Err(
            "network destinations must be normalized HTTPS origin/path policies".to_owned(),
        );
    }
    Ok(destinations)
}

fn parse_dependencies(object: &BTreeMap<String, json::Value>) -> Result<Vec<Dependency>, String> {
    field(object, "dependencies")?
        .array()
        .ok_or_else(|| "dependencies must be an array".to_owned())?
        .iter()
        .map(|value| {
            let fields = value
                .object()
                .ok_or_else(|| "dependency must be an object".to_owned())?;
            exact_fields(fields, &["available", "digest", "reference"], "dependency")?;
            Ok(Dependency {
                reference: string_field(fields, "reference")?,
                digest: nullable_string_field(fields, "digest")?,
                available: boolean_field(fields, "available")?,
            })
        })
        .collect()
}

fn parse_step(value: &json::Value) -> Result<Step, String> {
    let fields = value
        .object()
        .ok_or_else(|| "step must be an object".to_owned())?;
    exact_fields(
        fields,
        &[
            "argv",
            "environment",
            "id",
            "image",
            "supported",
            "working_directory",
        ],
        "step",
    )?;
    let environment = field(fields, "environment")?
        .object()
        .ok_or_else(|| "environment must be an object".to_owned())?
        .iter()
        .map(|(name, value)| {
            value
                .string()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| "environment value must be a string".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let argv = string_array(field(fields, "argv")?, "argv")?;
    if argv.is_empty() {
        return Err("step argv cannot be empty".to_owned());
    }
    Ok(Step {
        id: string_field(fields, "id")?,
        image: string_field(fields, "image")?,
        argv,
        environment,
        working_directory: string_field(fields, "working_directory")?,
        supported: boolean_field(fields, "supported")?,
    })
}

fn parse_steps(object: &BTreeMap<String, json::Value>) -> Result<Vec<Step>, String> {
    field(object, "steps")?
        .array()
        .ok_or_else(|| "steps must be an array".to_owned())?
        .iter()
        .map(parse_step)
        .collect()
}

fn validate_status(
    status: &PlanStatus,
    backend: &str,
    runtime: &RuntimeProfile,
    dependencies: &[Dependency],
    steps: &[Step],
) -> Result<(), String> {
    let mut reasons = dependencies
        .iter()
        .filter(|dependency| !dependency.available || dependency.digest.is_none())
        .map(|dependency| format!("unresolved dependency: {}", dependency.reference))
        .chain(
            steps
                .iter()
                .filter(|step| !step.supported)
                .map(|step| format!("unsupported step: {}", step.id)),
        )
        .chain(
            steps
                .iter()
                .filter(|step| !resolved_content_digest(&step.image))
                .map(|step| format!("unresolved capsule: {}", step.id)),
        )
        .collect::<Vec<_>>();
    if !resolved_content_digest(&runtime.workload_digest) {
        reasons.push("unresolved runtime workload".to_owned());
    }
    if matches!(backend, "linux-native" | "windows-native" | "macos-vm")
        && runtime
            .helper_digest
            .as_deref()
            .is_none_or(|digest| !resolved_content_digest(digest))
    {
        reasons.push("unresolved runtime helper".to_owned());
    }
    if backend == "macos-vm"
        && runtime
            .boot_digest
            .as_deref()
            .is_none_or(|digest| !resolved_content_digest(digest))
    {
        reasons.push("unresolved macOS boot bundle".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    match status {
        PlanStatus::Complete if !reasons.is_empty() => {
            Err("complete plan contains unresolved or unsupported work".to_owned())
        }
        PlanStatus::Incomplete(_) | PlanStatus::Complete => Ok(()),
    }
}

fn valid_content_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == SHA256_HEX_DIGITS
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn resolved_content_digest(value: &str) -> bool {
    valid_content_digest(value) && value != UNRESOLVED_CONTENT_DIGEST
}

/// Parses canonical runner-v2 JSON and verifies its content digest.
///
/// # Errors
///
/// Returns a descriptive error for malformed JSON, schema/type violations,
/// unknown controls, or a digest mismatch.
// Validation is a single fail-closed pass over runner-v2. Keeping the cross-field
// checks adjacent makes their ordering and completeness reviewable.
#[expect(
    clippy::too_many_lines,
    reason = "runner-v2 validation keeps every published field and cross-field invariant adjacent"
)]
pub fn validate_plan(source: &str) -> Result<ValidatedPlan, String> {
    let root = json::parse(source)?;
    let object = root
        .object()
        .ok_or_else(|| "runner plan must be an object".to_owned())?;
    exact_fields(
        object,
        &[
            "backend",
            "controls",
            "dependencies",
            "digest",
            "limits",
            "lock_digest",
            "network",
            "provider_profile",
            "runtime",
            "scenario_digest",
            "schema",
            "secret_names",
            "selected_jobs",
            "source_digest",
            "status",
            "steps",
        ],
        "runner plan",
    )?;
    let digest = string_field(object, "digest")?;
    let schema = string_field(object, "schema")?;
    if schema != "runner-v2" {
        return Err(format!("unsupported runner schema {schema}"));
    }
    validate_digest(&root, &digest)?;
    let backend = parse_backend(object)?;
    let scenario_digest = string_field(object, "scenario_digest")?;
    let provider_profile = string_field(object, "provider_profile")?;
    let selected_jobs = string_array(field(object, "selected_jobs")?, "selected_jobs")?;
    let source_digest = string_field(object, "source_digest")?;
    let lock_digest = string_field(object, "lock_digest")?;
    let controls = parse_controls(object)?;
    let network_destinations = parse_network(object, &controls)?;
    let secret_names = string_array(field(object, "secret_names")?, "secret_names")?;
    let status = parse_status(object)?;
    let limits = parse_limits(object)?;
    let runtime = parse_runtime(object)?;
    let dependencies = parse_dependencies(object)?;
    let steps = parse_steps(object)?;
    if !valid_content_digest(&scenario_digest)
        || !valid_content_digest(&source_digest)
        || !valid_content_digest(&lock_digest)
    {
        return Err("scenario/source/lock identities must be SHA-256 digests".to_owned());
    }
    if provider_profile.trim().is_empty() || selected_jobs.is_empty() {
        return Err("provider profile and selected jobs are required".to_owned());
    }
    let platform_matches = match backend.as_str() {
        value if value.starts_with("oci:") || value == "linux-native" => {
            runtime.runner_platform.starts_with("linux-")
        }
        "windows-native" => runtime.runner_platform.starts_with("windows-"),
        "macos-vm" => runtime.runner_platform.starts_with("macos-"),
        _ => false,
    };
    let expected_kind = match backend.as_str() {
        value if value.starts_with("oci:") => "oci-capsule",
        "linux-native" => "linux-capsule",
        "windows-native" => "windows-runtime-profile",
        "macos-vm" => "macos-vm",
        _ => unreachable!("backend was validated"),
    };
    if !platform_matches || runtime.kind != expected_kind {
        return Err("runtime profile contradicts the selected backend".to_owned());
    }
    let mut images = steps.iter().map(|step| &step.image).collect::<Vec<_>>();
    images.sort_unstable();
    images.dedup();
    let expected_workload = if images.len() == 1 {
        images[0].as_str()
    } else {
        UNRESOLVED_CONTENT_DIGEST
    };
    if runtime.workload_digest != expected_workload {
        return Err("runtime workload digest contradicts selected steps".to_owned());
    }
    let rootfs_matches = match backend.as_str() {
        value if value.starts_with("oci:") || value == "linux-native" || value == "macos-vm" => {
            runtime.rootfs_digest.as_deref() == Some(runtime.workload_digest.as_str())
        }
        "windows-native" => runtime.rootfs_digest.is_none() && runtime.boot_digest.is_none(),
        _ => false,
    };
    if !rootfs_matches {
        return Err("runtime rootfs/boot bindings contradict the selected backend".to_owned());
    }
    validate_status(&status, &backend, &runtime, &dependencies, &steps)?;
    Ok(ValidatedPlan {
        digest,
        backend,
        scenario_digest,
        provider_profile,
        selected_jobs,
        controls,
        status,
        source_digest,
        lock_digest,
        runtime,
        limits,
        network_destinations,
        secret_names,
        dependencies,
        steps,
    })
}

/// Checks that a validated plan targets an available backend with every
/// requested containment control.
///
/// # Errors
///
/// Returns a fail-closed [`LaunchError`] for incomplete plans, platform or
/// backend mismatches, and missing controls.
pub fn validate_launch(descriptor: &Descriptor, plan: &ValidatedPlan) -> Result<(), LaunchError> {
    if let PlanStatus::Incomplete(reasons) = &plan.status {
        return Err(LaunchError::IncompletePlan(reasons.clone()));
    }
    if descriptor.id != plan.backend {
        return Err(LaunchError::BackendMismatch {
            expected: descriptor.id.to_owned(),
            actual: plan.backend.clone(),
        });
    }
    if descriptor.platform != std::env::consts::OS {
        return Err(LaunchError::UnsupportedPlatform {
            backend: descriptor.id.to_owned(),
            platform: std::env::consts::OS.to_owned(),
        });
    }
    if !descriptor.available {
        return Err(LaunchError::UnsupportedPlatform {
            backend: descriptor.id.to_owned(),
            platform: std::env::consts::OS.to_owned(),
        });
    }
    let missing = plan
        .controls
        .iter()
        .copied()
        .filter(|control| !descriptor.controls.contains(control))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LaunchError::MissingControls(missing))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelperMode {
    Doctor,
    Validate,
    Run {
        source_root: String,
        trusted_exclusions: Vec<String>,
    },
}

/// Parses the deliberately small native-helper command surface.
///
/// # Errors
///
/// Rejects unknown, duplicate, missing, or reordered arguments.
pub fn parse_helper_arguments(arguments: &[String]) -> Result<HelperMode, String> {
    match arguments {
        [] => Ok(HelperMode::Doctor),
        [mode] if mode == "--doctor" => Ok(HelperMode::Doctor),
        [mode] if mode == "--validate" => Ok(HelperMode::Validate),
        [mode, source_option, source_root, rest @ ..]
            if mode == "--run" && source_option == "--source" && !source_root.is_empty() =>
        {
            let (pairs, remainder) = rest.as_chunks::<2>();
            let trusted_exclusions = pairs
                .iter()
                .map(|pair| match pair {
                    [option, value] if option == "--exclude" && !value.is_empty() => {
                        Ok(value.clone())
                    }
                    _ => Err(
                        "--run accepts only repeated --exclude PREFIX arguments after --source"
                            .to_owned(),
                    ),
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !remainder.is_empty() {
                return Err("--exclude requires a non-empty prefix".to_owned());
            }
            Ok(HelperMode::Run {
                source_root: source_root.clone(),
                trusted_exclusions,
            })
        }
        _ => Err(
            "usage: helper --doctor|--validate|--run --source SOURCE_ROOT [--exclude PREFIX ...]"
                .to_owned(),
        ),
    }
}

pub fn helper_main(
    descriptor: &Descriptor,
    launch: fn(&ValidatedPlan, &str, &[String]) -> Result<RunResult, LaunchError>,
) -> i32 {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = match parse_helper_arguments(&arguments) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("{error}");
            return HELPER_EXIT_INVALID_INPUT;
        }
    };
    if mode == HelperMode::Doctor {
        print!("{}", descriptor.canonical_json());
        return HELPER_EXIT_SUCCESS;
    }
    let mut source = String::new();
    if let Err(error) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut source) {
        eprintln!("failed to read runner plan: {error}");
        return HELPER_EXIT_INVALID_INPUT;
    }
    let plan = match validate_plan(&source) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("invalid runner plan: {error}");
            return HELPER_EXIT_INVALID_INPUT;
        }
    };
    if mode == HelperMode::Validate {
        println!("{{\"digest\":\"{}\",\"valid\":true}}", plan.digest);
        return HELPER_EXIT_SUCCESS;
    }
    let HelperMode::Run {
        source_root,
        trusted_exclusions,
    } = mode
    else {
        unreachable!("doctor and validate modes returned above")
    };
    match launch(&plan, &source_root, &trusted_exclusions) {
        Ok(result) => {
            print!("{}", result.canonical_json());
            HELPER_EXIT_SUCCESS
        }
        Err(LaunchError::IncompletePlan(reasons)) => {
            eprintln!("incomplete plan: {}", reasons.join("; "));
            HELPER_EXIT_INCOMPLETE
        }
        Err(
            error @ (LaunchError::BackendMismatch { .. }
            | LaunchError::MissingControls(_)
            | LaunchError::InvalidPlan(_)),
        ) => {
            eprintln!("invalid sandbox input: {error}");
            HELPER_EXIT_INVALID_INPUT
        }
        Err(error) => {
            eprintln!("sandbox infrastructure failure: {error}");
            HELPER_EXIT_INFRASTRUCTURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Control, Dependency, Descriptor, Evidence, EvidenceBody, EvidenceBodyKind, ForensicSidecar,
        HELPER_EXIT_SUCCESS, HelperMode, LaunchError, Outcome, PlanStatus, RuntimeProfile,
        SHA256_HEX_DIGITS, Step, UNRESOLVED_CONTENT_DIGEST, ValidatedPlan, controls_digest,
        evidence_body_json, exact_fields, json, limits_json, nonempty_string_field, object,
        parse_backend, parse_dependencies, parse_evidence_body, parse_evidence_limits,
        parse_forensic_sidecars, parse_helper_arguments, parse_limits, parse_network,
        parse_outcome, parse_runtime, portable_limits, quote_json, resolved_content_digest,
        root_relative_path, sha256, string_field, valid_content_digest, validate_digest,
        validate_evidence_body, validate_launch, validate_plan, validate_status,
    };
    use std::collections::BTreeMap;

    const PLAN_SOURCE: &str = include_str!("../../test/fixtures/protocol/runner-v2-complete.json");
    // IANA's default HTTPS port; used to exercise the network evidence field.
    const HTTPS_PORT: u16 = 443;
    // A non-zero signed process result used to prove exact i32 preservation.
    const FIXTURE_PROCESS_EXIT: i32 = 17;

    fn content_digest(digit: char) -> String {
        format!("sha256:{}", digit.to_string().repeat(SHA256_HEX_DIGITS))
    }

    fn fixture_plan() -> ValidatedPlan {
        validate_plan(PLAN_SOURCE).expect("published complete runner-v2 fixture")
    }

    fn nested_object_mut<'a>(
        fields: &'a mut BTreeMap<String, json::Value>,
        name: &str,
    ) -> &'a mut BTreeMap<String, json::Value> {
        let Some(json::Value::Object(value)) = fields.get_mut(name) else {
            panic!("fixture field {name} must be an object")
        };
        value
    }

    fn signed_plan(mutator: impl FnOnce(&mut BTreeMap<String, json::Value>)) -> String {
        let mut root = json::parse(PLAN_SOURCE).expect("runner fixture JSON");
        let json::Value::Object(fields) = &mut root else {
            panic!("runner fixture must be an object")
        };
        mutator(fields);
        fields.remove("digest");
        let unsigned = json::Value::Object(fields.clone());
        let digest = format!(
            "sha256:{}",
            sha256::digest(json::canonical(&unsigned).as_bytes())
        );
        fields.insert("digest".to_owned(), json::Value::String(digest));
        json::canonical(&root)
    }

    fn standard_evidence_bodies(plan: &ValidatedPlan) -> Vec<EvidenceBody> {
        let mut bodies = vec![EvidenceBody::BackendAttested {
            id: plan.backend.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            platform: "portable-test".to_owned(),
            controls_digest: controls_digest(&plan.controls),
        }];
        bodies.extend(
            plan.controls
                .iter()
                .map(|control| EvidenceBody::ControlAttested(control.name().to_owned())),
        );
        for step in &plan.steps {
            let (executable, argv) = step.argv.split_first().expect("validated non-empty argv");
            bodies.push(EvidenceBody::ProcessStarted {
                executable: executable.clone(),
                argv: argv.to_vec(),
            });
            bodies.push(EvidenceBody::ProcessExited {
                code: HELPER_EXIT_SUCCESS,
            });
        }
        bodies.extend([
            EvidenceBody::ResourceObserved {
                wall_time_ms: 1,
                cpu_time_ms: 0,
                peak_memory_bytes: 0,
                processes: 1,
                output_bytes: 0,
                scratch_bytes: 0,
                scratch_entries: 0,
            },
            EvidenceBody::LogRecorded {
                digest: format!("sha256:{}", sha256::digest(b"")),
            },
            EvidenceBody::FilesystemFinal {
                digest: plan.source_digest.clone(),
            },
        ]);
        bodies
    }

    fn evidence_from_bodies(
        plan: &ValidatedPlan,
        bodies: impl IntoIterator<Item = EvidenceBody>,
    ) -> Evidence {
        let mut evidence = Evidence::for_plan(plan);
        for body in bodies {
            evidence.append(body);
        }
        evidence
    }

    #[test]
    fn complete_status_rejects_an_unpinned_execution_image() {
        let step = Step {
            id: "build".to_owned(),
            image: "sha256:unresolved".to_owned(),
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
            environment: BTreeMap::new(),
            working_directory: "/workspace".to_owned(),
            supported: true,
        };
        let runtime = RuntimeProfile {
            kind: "linux-capsule".to_owned(),
            runner_platform: "linux-x86_64".to_owned(),
            workload_digest: step.image.clone(),
            rootfs_digest: Some(step.image.clone()),
            helper_digest: None,
            boot_digest: None,
            capability_fingerprint: None,
        };
        assert!(
            validate_status(
                &PlanStatus::Complete,
                "linux-native",
                &runtime,
                &[],
                &[step]
            )
            .is_err()
        );
    }

    #[test]
    fn native_run_arguments_require_an_explicit_source_root() {
        assert_eq!(
            parse_helper_arguments(&[
                "--run".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
            ]),
            Ok(HelperMode::Run {
                source_root: "/repo".to_owned(),
                trusted_exclusions: Vec::new(),
            })
        );
        assert_eq!(
            parse_helper_arguments(&[
                "--run".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
                "--exclude".to_owned(),
                "generated".to_owned(),
                "--exclude".to_owned(),
                "vendor/cache".to_owned(),
            ]),
            Ok(HelperMode::Run {
                source_root: "/repo".to_owned(),
                trusted_exclusions: vec!["generated".to_owned(), "vendor/cache".to_owned()],
            })
        );
        assert!(parse_helper_arguments(&["--run".to_owned()]).is_err());
        assert!(
            parse_helper_arguments(&[
                "--run".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
                "--exclude".to_owned(),
            ])
            .is_err()
        );
        assert!(parse_helper_arguments(&["--doctor".to_owned(), "unexpected".to_owned()]).is_err());
    }

    #[test]
    fn content_digests_require_lowercase_canonical_hex() {
        assert!(valid_content_digest(&format!(
            "sha256:{}",
            "a".repeat(SHA256_HEX_DIGITS)
        )));
        assert!(!valid_content_digest(&format!(
            "sha256:{}",
            "A".repeat(SHA256_HEX_DIGITS)
        )));
        assert!(!resolved_content_digest(UNRESOLVED_CONTENT_DIGEST));
        assert!(resolved_content_digest(&content_digest('a')));
    }

    #[test]
    fn every_control_name_is_a_total_round_trip() {
        let controls = [
            Control::SourceReadOnly,
            Control::ScratchOverlay,
            Control::NetworkDeny,
            Control::EgressBroker,
            Control::ProcessIsolation,
            Control::ResourceLimits,
            Control::SecretRedaction,
            Control::Namespace,
            Control::Seccomp,
            Control::Landlock,
            Control::CgroupV2,
            Control::AppContainer,
            Control::RestrictedToken,
            Control::JobObject,
            Control::AppSandbox,
            Control::VirtualMachine,
        ];
        for control in controls {
            assert_eq!(
                Control::parse(control.name()),
                Some(control),
                "{}",
                control.name()
            );
        }
        assert_eq!(Control::parse("unknown"), None);
    }

    #[test]
    fn every_evidence_body_round_trips_its_tagged_union() {
        let digest = content_digest('a');
        let bodies = vec![
            EvidenceBody::BackendAttested {
                id: "oci:test".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                platform: "linux-x86_64".to_owned(),
                controls_digest: digest.clone(),
            },
            EvidenceBody::ControlAttested(Control::Namespace.name().to_owned()),
            EvidenceBody::ProcessStarted {
                executable: "/bin/tool".to_owned(),
                argv: vec!["argument".to_owned()],
            },
            EvidenceBody::ProcessExited {
                code: FIXTURE_PROCESS_EXIT,
            },
            EvidenceBody::FilesystemAccess {
                path: "workspace/file".to_owned(),
                operation: "read".to_owned(),
                allowed: true,
            },
            EvidenceBody::NetworkAttempt {
                host: "example.test".to_owned(),
                port: HTTPS_PORT,
                allowed: false,
            },
            EvidenceBody::ArtifactRecorded {
                path: "artifacts/result".to_owned(),
                digest: digest.clone(),
            },
            EvidenceBody::SecretRedacted {
                name: "TOKEN".to_owned(),
            },
            EvidenceBody::ResourceObserved {
                wall_time_ms: 1,
                cpu_time_ms: 2,
                peak_memory_bytes: 3,
                processes: 4,
                output_bytes: 5,
                scratch_bytes: 6,
                scratch_entries: 7,
            },
            EvidenceBody::LogRecorded {
                digest: digest.clone(),
            },
            EvidenceBody::FilesystemFinal {
                digest: digest.clone(),
            },
            EvidenceBody::BackendError("backend unavailable".to_owned()),
        ];
        for body in bodies {
            let encoded = evidence_body_json(&body);
            assert_eq!(parse_evidence_body(&encoded), Ok(body.clone()), "{body:?}");
            assert!(validate_evidence_body(&body).is_ok(), "{body:?}");
        }
    }

    #[test]
    fn evidence_body_identity_and_root_relative_paths_fail_closed() {
        for valid in ["artifact", "directory/artifact"] {
            assert!(root_relative_path(valid), "{valid:?}");
        }
        for invalid in [
            "",
            "/artifact",
            "\\artifact",
            "directory\\artifact",
            "directory//artifact",
            ".",
            "..",
            "directory/./artifact",
            "directory/../artifact",
        ] {
            assert!(!root_relative_path(invalid), "{invalid:?}");
        }

        let digest = content_digest('b');
        let invalid_bodies = [
            EvidenceBody::BackendAttested {
                id: String::new(),
                version: "v".to_owned(),
                platform: "p".to_owned(),
                controls_digest: digest.clone(),
            },
            EvidenceBody::BackendAttested {
                id: "id".to_owned(),
                version: String::new(),
                platform: "p".to_owned(),
                controls_digest: digest.clone(),
            },
            EvidenceBody::BackendAttested {
                id: "id".to_owned(),
                version: "v".to_owned(),
                platform: String::new(),
                controls_digest: digest.clone(),
            },
            EvidenceBody::FilesystemAccess {
                path: String::new(),
                operation: "read".to_owned(),
                allowed: false,
            },
            EvidenceBody::FilesystemAccess {
                path: "path".to_owned(),
                operation: String::new(),
                allowed: false,
            },
            EvidenceBody::NetworkAttempt {
                host: String::new(),
                port: HTTPS_PORT,
                allowed: false,
            },
            EvidenceBody::NetworkAttempt {
                host: "example.test".to_owned(),
                port: 0,
                allowed: false,
            },
            EvidenceBody::ArtifactRecorded {
                path: "/absolute".to_owned(),
                digest: digest.clone(),
            },
            EvidenceBody::SecretRedacted {
                name: String::new(),
            },
            EvidenceBody::LogRecorded {
                digest: "not-a-digest".to_owned(),
            },
            EvidenceBody::BackendError(String::new()),
        ];
        for body in invalid_bodies {
            assert!(validate_evidence_body(&body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn evidence_validation_checks_each_independent_envelope_invariant() {
        let valid = Evidence::new(content_digest('c'));
        assert!(valid.validate().is_ok());

        let mut invalids = Vec::new();
        let mut invalid = valid.clone();
        invalid.plan_digest = "bad".to_owned();
        invalids.push(invalid);
        let mut invalid = valid.clone();
        invalid.bindings.lock_digest = "bad".to_owned();
        invalids.push(invalid);
        let mut invalid = valid.clone();
        invalid.source_digest = content_digest('d');
        invalids.push(invalid);
        let mut invalid = valid.clone();
        invalid.requested_limits.cpu_seconds =
            invalid.requested_limits.cpu_seconds.saturating_sub(1);
        invalids.push(invalid);
        let mut invalid = valid.clone();
        invalid.effective_limits.processes = invalid.effective_limits.processes.saturating_sub(1);
        invalids.push(invalid);
        let mut invalid = valid.clone();
        invalid.forensic_sidecars.push(ForensicSidecar {
            kind: String::new(),
            digest: content_digest('e'),
        });
        invalids.push(invalid);
        let mut invalid = valid;
        invalid.forensic_sidecars.push(ForensicSidecar {
            kind: "trace".to_owned(),
            digest: "bad".to_owned(),
        });
        invalids.push(invalid);

        for evidence in invalids {
            assert!(evidence.validate().is_err(), "{evidence:?}");
        }
    }

    #[test]
    fn evidence_summary_tail_and_sidecars_are_authenticated_data() {
        let plan = fixture_plan();
        let log_digest = content_digest('1');
        let filesystem_digest = content_digest('2');
        let mut evidence = Evidence::for_plan(&plan);
        assert_eq!(evidence.tail_digest(), plan.digest);
        evidence.append(EvidenceBody::ResourceObserved {
            wall_time_ms: 11,
            cpu_time_ms: 12,
            peak_memory_bytes: 13,
            processes: 14,
            output_bytes: 15,
            scratch_bytes: 16,
            scratch_entries: 17,
        });
        evidence.append(EvidenceBody::LogRecorded {
            digest: log_digest.clone(),
        });
        evidence.append(EvidenceBody::FilesystemFinal {
            digest: filesystem_digest.clone(),
        });
        let tail = evidence.tail_digest().to_owned();
        assert_ne!(tail, plan.digest);
        assert!(valid_content_digest(&tail));

        let source = evidence.canonical_json();
        assert!(source.contains(&format!("\"redacted_log_digest\":\"{log_digest}\"")));
        assert!(source.contains(&format!(
            "\"final_filesystem_digest\":\"{filesystem_digest}\""
        )));
        assert!(source.contains("\"wall_time_ms\":11"));
        assert_eq!(Evidence::parse(&source), Ok(evidence));

        let sidecars = json::Value::Array(vec![object([
            ("digest", json::Value::String(content_digest('3'))),
            ("kind", json::Value::String("system-trace".to_owned())),
        ])]);
        assert_eq!(
            parse_forensic_sidecars(&sidecars),
            Ok(vec![ForensicSidecar {
                kind: "system-trace".to_owned(),
                digest: content_digest('3'),
            }])
        );
    }

    #[test]
    fn every_evidence_limit_field_is_independently_constant() {
        let canonical = limits_json(&portable_limits());
        assert_eq!(parse_evidence_limits(&canonical), Ok(portable_limits()));
        let json::Value::Object(fields) = canonical else {
            panic!("limits must serialize as an object")
        };
        for name in [
            "cpu_cores",
            "memory_bytes",
            "output_bytes",
            "processes",
            "scratch_bytes",
            "scratch_entries",
            "wall_time_seconds",
        ] {
            let mut changed = fields.clone();
            changed.insert(name.to_owned(), json::Value::Integer(0));
            assert!(
                parse_evidence_limits(&json::Value::Object(changed)).is_err(),
                "changed evidence limit {name}"
            );
        }
    }

    #[test]
    fn complete_evidence_checks_attestations_required_records_and_lifecycle() {
        let plan = fixture_plan();
        let standard = standard_evidence_bodies(&plan);
        let evidence = evidence_from_bodies(&plan, standard.clone());
        evidence
            .validate_for_plan(&plan)
            .expect("complete evidence must bind to the plan");

        let mut wrong_binding = Evidence::for_plan(&plan);
        wrong_binding.bindings.lock_digest = content_digest('4');
        assert!(wrong_binding.validate_for_plan(&plan).is_err());
        let wrong_plan = Evidence::new(content_digest('5'));
        assert!(wrong_plan.validate_for_plan(&plan).is_err());

        let backend_index = standard
            .iter()
            .position(|body| matches!(body, EvidenceBody::BackendAttested { .. }))
            .expect("backend attestation");
        let mut missing_backend = standard.clone();
        missing_backend.remove(backend_index);
        assert!(
            evidence_from_bodies(&plan, missing_backend)
                .validate_for_plan(&plan)
                .is_err()
        );
        let mut duplicate_backend = standard.clone();
        duplicate_backend.insert(backend_index, standard[backend_index].clone());
        assert!(
            evidence_from_bodies(&plan, duplicate_backend)
                .validate_for_plan(&plan)
                .is_err()
        );

        for mutation in ["id", "controls"] {
            let mut bodies = standard.clone();
            let EvidenceBody::BackendAttested {
                id,
                controls_digest: attested_controls,
                ..
            } = &mut bodies[backend_index]
            else {
                unreachable!()
            };
            match mutation {
                "id" => *id = "oci:other".to_owned(),
                "controls" => *attested_controls = content_digest('6'),
                _ => unreachable!(),
            }
            assert!(
                evidence_from_bodies(&plan, bodies)
                    .validate_for_plan(&plan)
                    .is_err(),
                "backend {mutation} mismatch"
            );
        }

        let mut missing_control = standard.clone();
        let control_index = missing_control
            .iter()
            .position(|body| matches!(body, EvidenceBody::ControlAttested(_)))
            .expect("control attestation");
        missing_control.remove(control_index);
        assert!(
            evidence_from_bodies(&plan, missing_control)
                .validate_for_plan(&plan)
                .is_err()
        );

        for kind in [
            EvidenceBodyKind::Resource,
            EvidenceBodyKind::Log,
            EvidenceBodyKind::FilesystemFinal,
        ] {
            let mut missing = standard.clone();
            missing.retain(|body| !kind.matches(body));
            assert!(
                evidence_from_bodies(&plan, missing)
                    .validate_for_plan(&plan)
                    .is_err()
            );

            let mut duplicate = standard.clone();
            let body = duplicate
                .iter()
                .find(|body| kind.matches(body))
                .expect("required evidence body")
                .clone();
            duplicate.push(body);
            assert!(
                evidence_from_bodies(&plan, duplicate)
                    .validate_for_plan(&plan)
                    .is_err()
            );
        }

        let mut no_exit = standard.clone();
        no_exit.retain(|body| !matches!(body, EvidenceBody::ProcessExited { .. }));
        assert!(
            evidence_from_bodies(&plan, no_exit)
                .validate_for_plan(&plan)
                .is_err()
        );
    }

    #[test]
    fn process_lifecycle_accepts_a_failed_prefix_but_rejects_identity_drift() {
        let plan = fixture_plan();
        let standard = standard_evidence_bodies(&plan);
        let start_index = standard
            .iter()
            .position(|body| matches!(body, EvidenceBody::ProcessStarted { .. }))
            .expect("process start");

        for mutation in ["executable", "argv"] {
            let mut bodies = standard.clone();
            let EvidenceBody::ProcessStarted { executable, argv } = &mut bodies[start_index] else {
                unreachable!()
            };
            match mutation {
                "executable" => *executable = "/bin/other".to_owned(),
                "argv" => argv.push("other".to_owned()),
                _ => unreachable!(),
            }
            assert!(
                evidence_from_bodies(&plan, bodies)
                    .validate_for_plan(&plan)
                    .is_err(),
                "process {mutation} mismatch"
            );
        }

        let mut two_step_plan = plan.clone();
        let mut second = two_step_plan.steps[0].clone();
        second.id = "build:step2".to_owned();
        two_step_plan.steps.push(second);
        evidence_from_bodies(&two_step_plan, standard.clone())
            .validate_for_plan(&two_step_plan)
            .expect("a balanced ordered prefix records a failed run");

        let mut empty_plan = plan;
        empty_plan.steps.clear();
        empty_plan.runtime.workload_digest = UNRESOLVED_CONTENT_DIGEST.to_owned();
        empty_plan.runtime.rootfs_digest = Some(UNRESOLVED_CONTENT_DIGEST.to_owned());
        empty_plan.status = PlanStatus::Incomplete(vec!["no executable steps".to_owned()]);
        let no_processes = standard_evidence_bodies(&empty_plan);
        evidence_from_bodies(&empty_plan, no_processes)
            .validate_for_plan(&empty_plan)
            .expect("an empty plan has no process lifecycle");
    }

    #[test]
    fn sandbox_outcomes_preserve_nullable_codes_and_nonempty_step_ids() {
        for (source, expected) in [
            (r#"{"state":"completed"}"#, Outcome::Completed),
            (
                r#"{"code":null,"state":"step_failed","step":"build"}"#,
                Outcome::StepFailed {
                    step: "build".to_owned(),
                    code: None,
                },
            ),
            (
                r#"{"code":17,"state":"step_failed","step":"build"}"#,
                Outcome::StepFailed {
                    step: "build".to_owned(),
                    code: Some(FIXTURE_PROCESS_EXIT),
                },
            ),
            (
                r#"{"state":"timed_out","step":"build"}"#,
                Outcome::TimedOut {
                    step: "build".to_owned(),
                },
            ),
            (
                r#"{"state":"output_limit_exceeded","step":"build"}"#,
                Outcome::OutputLimitExceeded {
                    step: "build".to_owned(),
                },
            ),
        ] {
            let value = json::parse(source).expect("outcome JSON");
            assert_eq!(parse_outcome(&value), Ok(expected));
        }
        for source in [
            r#"{"code":"bad","state":"step_failed","step":"build"}"#,
            r#"{"code":null,"state":"step_failed","step":" "}"#,
            r#"{"state":"timed_out","step":""}"#,
            r#"{"state":"unknown"}"#,
        ] {
            let value = json::parse(source).expect("invalid outcome JSON remains valid JSON");
            assert!(parse_outcome(&value).is_err(), "{source}");
        }
    }

    #[test]
    fn private_json_field_and_descriptor_helpers_are_exact() {
        let fields =
            BTreeMap::from([("name".to_owned(), json::Value::String(" value ".to_owned()))]);
        assert_eq!(
            nonempty_string_field(&fields, "name"),
            Ok(" value ".to_owned())
        );
        let empty = BTreeMap::from([("name".to_owned(), json::Value::String(" \t".to_owned()))]);
        assert!(nonempty_string_field(&empty, "name").is_err());
        assert_eq!(
            quote_json("quote \" and newline\n"),
            "\"quote \\\" and newline\\n\""
        );

        assert!(exact_fields(&fields, &["name"], "fixture").is_ok());
        assert!(exact_fields(&fields, &[], "fixture").is_err());
        let extra = BTreeMap::from([
            ("name".to_owned(), json::Value::Null),
            ("other".to_owned(), json::Value::Null),
        ]);
        assert!(exact_fields(&extra, &["name"], "fixture").is_err());

        let descriptor = Descriptor {
            id: "test-backend",
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            available: true,
            controls: vec![Control::Namespace],
            reasons: vec!["reason \"quoted\"".to_owned()],
        };
        let descriptor_json = descriptor.canonical_json();
        assert!(descriptor_json.ends_with('\n'));
        assert!(descriptor_json.contains("\"schema\":\"backend-attestation-v1\""));
        assert!(descriptor_json.contains("\"controls\":[\"namespace\"]"));
        assert!(descriptor_json.contains("reason \\\"quoted\\\""));

        let display = LaunchError::BackendMismatch {
            expected: "expected".to_owned(),
            actual: "actual".to_owned(),
        }
        .to_string();
        assert!(display.contains("expected"));
        assert!(display.contains("actual"));
    }

    #[test]
    // Keeping the complete parser matrix together makes independent schema
    // fields and policy operators reviewable as one contract.
    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive table independently mutates every runner-v2 parser field"
    )]
    fn backend_limits_runtime_network_and_dependencies_parse_independently() {
        for backend in [
            "linux-native",
            "windows-native",
            "macos-vm",
            "oci:docker_1.0",
        ] {
            let fields = BTreeMap::from([(
                "backend".to_owned(),
                json::Value::String(backend.to_owned()),
            )]);
            assert_eq!(parse_backend(&fields), Ok(backend.to_owned()));
        }
        for backend in ["", "native", "oci:", "oci:bad/name"] {
            let fields = BTreeMap::from([(
                "backend".to_owned(),
                json::Value::String(backend.to_owned()),
            )]);
            assert!(parse_backend(&fields).is_err(), "{backend:?}");
        }

        let root = json::parse(PLAN_SOURCE).expect("runner fixture");
        let fields = root.object().expect("runner object");
        assert_eq!(parse_limits(fields), Ok(portable_limits()));
        for name in [
            "cpu_cores",
            "memory_bytes",
            "output_bytes",
            "processes",
            "scratch_bytes",
            "scratch_entries",
            "wall_time_seconds",
        ] {
            let mut changed = fields.clone();
            nested_object_mut(&mut changed, "limits")
                .insert(name.to_owned(), json::Value::Integer(0));
            assert!(
                parse_limits(&changed).is_err(),
                "changed runner limit {name}"
            );
        }

        assert!(parse_runtime(fields).is_ok());
        let mut invalid_workload = fields.clone();
        nested_object_mut(&mut invalid_workload, "runtime").insert(
            "workload_digest".to_owned(),
            json::Value::String("bad".to_owned()),
        );
        assert!(parse_runtime(&invalid_workload).is_err());
        let mut invalid_optional = fields.clone();
        nested_object_mut(&mut invalid_optional, "runtime").insert(
            "helper_digest".to_owned(),
            json::Value::String("bad".to_owned()),
        );
        assert!(parse_runtime(&invalid_optional).is_err());

        assert_eq!(
            parse_network(fields, &[Control::NetworkDeny]),
            Ok(Vec::new())
        );
        let enabled = BTreeMap::from([(
            "network".to_owned(),
            object([
                (
                    "destinations",
                    json::Value::Array(vec![json::Value::String(
                        "https://example.test/path".to_owned(),
                    )]),
                ),
                ("mode", json::Value::String("allowlist".to_owned())),
            ]),
        )]);
        assert_eq!(
            parse_network(&enabled, &[]),
            Ok(vec!["https://example.test/path".to_owned()])
        );
        for invalid_destination in [
            "http://example.test",
            "https://user@example.test",
            "https://example.test\\path",
            "https://example.test?query",
            "https://example.test#fragment",
            "https://example..test",
            "https://example.test/%2f",
        ] {
            let invalid = BTreeMap::from([(
                "network".to_owned(),
                object([
                    (
                        "destinations",
                        json::Value::Array(vec![json::Value::String(
                            invalid_destination.to_owned(),
                        )]),
                    ),
                    ("mode", json::Value::String("allowlist".to_owned())),
                ]),
            )]);
            assert!(
                parse_network(&invalid, &[]).is_err(),
                "{invalid_destination:?}"
            );
        }
        let deny_with_destination = BTreeMap::from([(
            "network".to_owned(),
            object([
                (
                    "destinations",
                    json::Value::Array(vec![json::Value::String(
                        "https://example.test".to_owned(),
                    )]),
                ),
                ("mode", json::Value::String("deny".to_owned())),
            ]),
        )]);
        assert!(parse_network(&deny_with_destination, &[Control::NetworkDeny]).is_err());
        let allowlist_without_destination = BTreeMap::from([(
            "network".to_owned(),
            object([
                ("destinations", json::Value::Array(Vec::new())),
                ("mode", json::Value::String("allowlist".to_owned())),
            ]),
        )]);
        assert!(parse_network(&allowlist_without_destination, &[]).is_err());
        assert!(parse_network(&enabled, &[Control::NetworkDeny]).is_err());
        let denied_but_allowlist_mode = BTreeMap::from([(
            "network".to_owned(),
            object([
                ("destinations", json::Value::Array(Vec::new())),
                ("mode", json::Value::String("allowlist".to_owned())),
            ]),
        )]);
        assert!(parse_network(&denied_but_allowlist_mode, &[Control::NetworkDeny]).is_err());
        let enabled_but_deny_mode = BTreeMap::from([(
            "network".to_owned(),
            object([
                (
                    "destinations",
                    json::Value::Array(vec![json::Value::String(
                        "https://example.test".to_owned(),
                    )]),
                ),
                ("mode", json::Value::String("deny".to_owned())),
            ]),
        )]);
        assert!(parse_network(&enabled_but_deny_mode, &[]).is_err());

        let dependency = Dependency {
            reference: "owner/repository".to_owned(),
            digest: Some(content_digest('7')),
            available: true,
        };
        let dependency_fields = BTreeMap::from([(
            "dependencies".to_owned(),
            json::Value::Array(vec![object([
                ("available", json::Value::Bool(dependency.available)),
                (
                    "digest",
                    json::Value::String(dependency.digest.clone().expect("digest")),
                ),
                (
                    "reference",
                    json::Value::String(dependency.reference.clone()),
                ),
            ])]),
        )]);
        assert_eq!(parse_dependencies(&dependency_fields), Ok(vec![dependency]));
    }

    #[test]
    fn plan_status_derives_each_incomplete_reason_from_semantic_state() {
        let plan = fixture_plan();
        assert!(
            validate_status(
                &PlanStatus::Complete,
                &plan.backend,
                &plan.runtime,
                &plan.dependencies,
                &plan.steps,
            )
            .is_ok()
        );

        let resolved_dependency = Dependency {
            reference: "dependency".to_owned(),
            digest: Some(content_digest('8')),
            available: true,
        };
        let mut unavailable = resolved_dependency.clone();
        unavailable.available = false;
        let mut unpinned = resolved_dependency;
        unpinned.digest = None;
        for dependency in [unavailable, unpinned] {
            assert!(
                validate_status(
                    &PlanStatus::Complete,
                    &plan.backend,
                    &plan.runtime,
                    &[dependency],
                    &plan.steps,
                )
                .is_err()
            );
        }

        let mut unsupported = plan.steps[0].clone();
        unsupported.supported = false;
        assert!(
            validate_status(
                &PlanStatus::Complete,
                &plan.backend,
                &plan.runtime,
                &[],
                &[unsupported],
            )
            .is_err()
        );

        let mut native_runtime = plan.runtime.clone();
        native_runtime.kind = "linux-capsule".to_owned();
        native_runtime.helper_digest = None;
        assert!(
            validate_status(
                &PlanStatus::Complete,
                "linux-native",
                &native_runtime,
                &[],
                &plan.steps,
            )
            .is_err()
        );
        native_runtime.helper_digest = Some(content_digest('9'));
        native_runtime.boot_digest = None;
        assert!(
            validate_status(
                &PlanStatus::Complete,
                "macos-vm",
                &native_runtime,
                &[],
                &plan.steps,
            )
            .is_err()
        );

        assert!(
            validate_status(
                &PlanStatus::Incomplete(vec!["explicitly incomplete".to_owned()]),
                &plan.backend,
                &plan.runtime,
                &[],
                &plan.steps,
            )
            .is_ok()
        );
    }

    #[test]
    // This is one cross-backend matrix; splitting it would hide shared
    // runner/runtime binding invariants.
    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive cross-backend table verifies every signed runner binding"
    )]
    fn signed_runner_variants_cover_every_backend_and_cross_field_binding() {
        let oci = fixture_plan();
        assert_eq!(oci.backend, "oci:docker");

        let linux = signed_plan(|fields| {
            fields.insert(
                "backend".to_owned(),
                json::Value::String("linux-native".to_owned()),
            );
            let runtime = nested_object_mut(fields, "runtime");
            runtime.insert(
                "kind".to_owned(),
                json::Value::String("linux-capsule".to_owned()),
            );
            runtime.insert(
                "helper_digest".to_owned(),
                json::Value::String(content_digest('1')),
            );
        });
        assert_eq!(
            validate_plan(&linux).expect("linux-native plan").backend,
            "linux-native"
        );

        let windows = signed_plan(|fields| {
            fields.insert(
                "backend".to_owned(),
                json::Value::String("windows-native".to_owned()),
            );
            let runtime = nested_object_mut(fields, "runtime");
            runtime.insert(
                "kind".to_owned(),
                json::Value::String("windows-runtime-profile".to_owned()),
            );
            runtime.insert(
                "runner_platform".to_owned(),
                json::Value::String("windows-x86_64".to_owned()),
            );
            runtime.insert("rootfs_digest".to_owned(), json::Value::Null);
            runtime.insert(
                "helper_digest".to_owned(),
                json::Value::String(content_digest('2')),
            );
        });
        assert_eq!(
            validate_plan(&windows)
                .expect("windows-native plan")
                .backend,
            "windows-native"
        );

        let macos = signed_plan(|fields| {
            fields.insert(
                "backend".to_owned(),
                json::Value::String("macos-vm".to_owned()),
            );
            let runtime = nested_object_mut(fields, "runtime");
            runtime.insert(
                "kind".to_owned(),
                json::Value::String("macos-vm".to_owned()),
            );
            runtime.insert(
                "runner_platform".to_owned(),
                json::Value::String("macos-arm64".to_owned()),
            );
            runtime.insert(
                "helper_digest".to_owned(),
                json::Value::String(content_digest('3')),
            );
            runtime.insert(
                "boot_digest".to_owned(),
                json::Value::String(content_digest('4')),
            );
        });
        assert_eq!(
            validate_plan(&macos).expect("macos-vm plan").backend,
            "macos-vm"
        );

        for field_name in ["scenario_digest", "source_digest", "lock_digest"] {
            let invalid = signed_plan(|fields| {
                fields.insert(
                    field_name.to_owned(),
                    json::Value::String("invalid".to_owned()),
                );
            });
            assert!(validate_plan(&invalid).is_err(), "invalid {field_name}");
        }
        let empty_profile = signed_plan(|fields| {
            fields.insert(
                "provider_profile".to_owned(),
                json::Value::String(" ".to_owned()),
            );
        });
        assert!(validate_plan(&empty_profile).is_err());
        let empty_jobs = signed_plan(|fields| {
            fields.insert("selected_jobs".to_owned(), json::Value::Array(Vec::new()));
        });
        assert!(validate_plan(&empty_jobs).is_err());

        for field_name in ["runner_platform", "kind"] {
            let invalid = signed_plan(|fields| {
                nested_object_mut(fields, "runtime").insert(
                    field_name.to_owned(),
                    json::Value::String("wrong".to_owned()),
                );
            });
            assert!(
                validate_plan(&invalid).is_err(),
                "invalid runtime {field_name}"
            );
        }
        let wrong_workload = signed_plan(|fields| {
            nested_object_mut(fields, "runtime").insert(
                "workload_digest".to_owned(),
                json::Value::String(content_digest('5')),
            );
        });
        assert!(validate_plan(&wrong_workload).is_err());

        for invalid_binding in ["rootfs_digest", "boot_digest"] {
            let invalid_windows = signed_plan(|fields| {
                fields.insert(
                    "backend".to_owned(),
                    json::Value::String("windows-native".to_owned()),
                );
                let runtime = nested_object_mut(fields, "runtime");
                runtime.insert(
                    "kind".to_owned(),
                    json::Value::String("windows-runtime-profile".to_owned()),
                );
                runtime.insert(
                    "runner_platform".to_owned(),
                    json::Value::String("windows-x86_64".to_owned()),
                );
                runtime.insert("rootfs_digest".to_owned(), json::Value::Null);
                runtime.insert(
                    "helper_digest".to_owned(),
                    json::Value::String(content_digest('6')),
                );
                runtime.insert(
                    invalid_binding.to_owned(),
                    json::Value::String(content_digest('7')),
                );
            });
            assert!(
                validate_plan(&invalid_windows).is_err(),
                "windows {invalid_binding} must be absent"
            );
        }

        let root = json::parse(PLAN_SOURCE).expect("fixture JSON");
        let supplied =
            string_field(root.object().expect("fixture object"), "digest").expect("fixture digest");
        assert!(validate_digest(&root, &supplied).is_ok());
        assert!(validate_digest(&root, &content_digest('8')).is_err());
    }

    #[test]
    fn launch_validation_checks_status_backend_platform_availability_and_controls() {
        let plan = fixture_plan();
        let descriptor = Descriptor {
            id: "oci:docker",
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            available: true,
            controls: plan.controls.clone(),
            reasons: Vec::new(),
        };
        assert_eq!(validate_launch(&descriptor, &plan), Ok(()));

        let mut incomplete = plan.clone();
        incomplete.status = PlanStatus::Incomplete(vec!["unresolved".to_owned()]);
        assert!(matches!(
            validate_launch(&descriptor, &incomplete),
            Err(LaunchError::IncompletePlan(_))
        ));

        let wrong_backend = Descriptor {
            id: "oci:other",
            ..descriptor.clone()
        };
        assert!(matches!(
            validate_launch(&wrong_backend, &plan),
            Err(LaunchError::BackendMismatch { .. })
        ));
        let wrong_platform = Descriptor {
            platform: "unsupported-test-platform",
            ..descriptor.clone()
        };
        assert!(matches!(
            validate_launch(&wrong_platform, &plan),
            Err(LaunchError::UnsupportedPlatform { .. })
        ));
        let unavailable = Descriptor {
            available: false,
            ..descriptor.clone()
        };
        assert!(matches!(
            validate_launch(&unavailable, &plan),
            Err(LaunchError::UnsupportedPlatform { .. })
        ));
        let missing_control = Descriptor {
            controls: Vec::new(),
            ..descriptor
        };
        assert!(matches!(
            validate_launch(&missing_control, &plan),
            Err(LaunchError::MissingControls(_))
        ));
    }

    #[test]
    fn helper_argument_grammar_rejects_every_reordered_or_partial_form() {
        assert_eq!(parse_helper_arguments(&[]), Ok(HelperMode::Doctor));
        assert_eq!(
            parse_helper_arguments(&["--doctor".to_owned()]),
            Ok(HelperMode::Doctor)
        );
        assert_eq!(
            parse_helper_arguments(&["--validate".to_owned()]),
            Ok(HelperMode::Validate)
        );
        for invalid in [
            vec!["--unknown".to_owned()],
            vec!["--run".to_owned(), "--wrong".to_owned(), "/repo".to_owned()],
            vec!["--run".to_owned(), "--source".to_owned(), String::new()],
            vec![
                "--unknown".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
            ],
            vec![
                "--run".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
                "--wrong".to_owned(),
                "value".to_owned(),
            ],
            vec![
                "--run".to_owned(),
                "--source".to_owned(),
                "/repo".to_owned(),
                "--exclude".to_owned(),
                String::new(),
            ],
        ] {
            assert!(parse_helper_arguments(&invalid).is_err(), "{invalid:?}");
        }
    }
}
