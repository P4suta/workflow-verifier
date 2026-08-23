#![forbid(unsafe_code)]

mod json;
mod sha256;
pub mod vm;

pub use sha256::Sha256;

use std::collections::BTreeMap;

pub const BACKEND_ATTESTATION_SCHEMA: &str = "backend-attestation-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Control {
    SourceReadOnly,
    ScratchOverlay,
    NetworkDeny,
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
    events: Vec<EvidenceEvent>,
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
        Self {
            plan_digest: plan_digest.into(),
            events: Vec::new(),
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

    fn json(&self) -> json::Value {
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
        object([
            ("events", json::Value::Array(events)),
            ("plan_digest", json::Value::String(self.plan_digest.clone())),
            ("schema", json::Value::String("evidence-v1".to_owned())),
        ])
    }

    #[must_use]
    pub fn canonical_json(&self) -> String {
        json::canonical(&self.json())
    }
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
            ("schema", json::Value::String("sandbox-run-v1".to_owned())),
        ]);
        format!("{}\n", json::canonical(&value))
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
    pub controls: Vec<Control>,
    pub status: PlanStatus,
    pub source_digest: String,
    pub lock_digest: String,
    pub limits: Limits,
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
    let exact = object.len() == expected.len()
        && object.keys().all(|name| expected.contains(&name.as_str()));
    if exact {
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
        &["cpu_seconds", "memory_mb", "output_bytes", "processes"],
        "limits",
    )?;
    let limits = Limits {
        cpu_seconds: integer_field(fields, "cpu_seconds")?,
        memory_mb: integer_field(fields, "memory_mb")?,
        processes: integer_field(fields, "processes")?,
        output_bytes: integer_field(fields, "output_bytes")?,
    };
    if [
        limits.cpu_seconds,
        limits.memory_mb,
        limits.processes,
        limits.output_bytes,
    ]
    .contains(&0)
    {
        Err("runner limits must be positive".to_owned())
    } else {
        Ok(limits)
    }
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
                .filter(|step| !valid_content_digest(&step.image))
                .map(|step| format!("unresolved image: {}", step.id)),
        )
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    match status {
        PlanStatus::Complete if !reasons.is_empty() => {
            Err("complete plan contains unresolved or unsupported work".to_owned())
        }
        PlanStatus::Incomplete(declared) if declared != &reasons => {
            Err("incomplete status reasons do not match plan contents".to_owned())
        }
        PlanStatus::Complete | PlanStatus::Incomplete(_) => Ok(()),
    }
}

fn valid_content_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Parses canonical runner-v1 JSON and verifies its content digest.
///
/// # Errors
///
/// Returns a descriptive error for malformed JSON, schema/type violations,
/// unknown controls, or a digest mismatch.
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
            "schema",
            "secret_names",
            "source_digest",
            "status",
            "steps",
        ],
        "runner plan",
    )?;
    let digest = string_field(object, "digest")?;
    let schema = string_field(object, "schema")?;
    if schema != "runner-v1" {
        return Err(format!("unsupported runner schema {schema}"));
    }
    validate_digest(&root, &digest)?;
    let backend = parse_backend(object)?;
    let source_digest = string_field(object, "source_digest")?;
    let lock_digest = string_field(object, "lock_digest")?;
    let controls = parse_controls(object)?;
    let secret_names = string_array(field(object, "secret_names")?, "secret_names")?;
    let status = parse_status(object)?;
    let limits = parse_limits(object)?;
    let dependencies = parse_dependencies(object)?;
    let steps = parse_steps(object)?;
    validate_status(&status, &dependencies, &steps)?;
    Ok(ValidatedPlan {
        digest,
        backend,
        controls,
        status,
        source_digest,
        lock_digest,
        limits,
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
    Run { source_root: String },
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
        [mode, source_option, source_root]
            if mode == "--run" && source_option == "--source" && !source_root.is_empty() =>
        {
            Ok(HelperMode::Run {
                source_root: source_root.clone(),
            })
        }
        [mode, ..] if mode == "--run" => Err("--run requires --source SOURCE_ROOT".to_owned()),
        _ => Err("usage: helper --doctor|--validate|--run --source SOURCE_ROOT".to_owned()),
    }
}

pub fn helper_main(
    descriptor: &Descriptor,
    launch: fn(&ValidatedPlan, &str) -> Result<RunResult, LaunchError>,
) -> i32 {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = match parse_helper_arguments(&arguments) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    if mode == HelperMode::Doctor {
        print!("{}", descriptor.canonical_json());
        return 0;
    }
    let mut source = String::new();
    if let Err(error) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut source) {
        eprintln!("failed to read runner plan: {error}");
        return 2;
    }
    let plan = match validate_plan(&source) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("invalid runner plan: {error}");
            return 2;
        }
    };
    if mode == HelperMode::Validate {
        println!("{{\"digest\":\"{}\",\"valid\":true}}", plan.digest);
        return 0;
    }
    let HelperMode::Run { source_root } = mode else {
        unreachable!("doctor and validate modes returned above")
    };
    match launch(&plan, &source_root) {
        Ok(result) => {
            print!("{}", result.canonical_json());
            0
        }
        Err(LaunchError::IncompletePlan(reasons)) => {
            eprintln!("incomplete plan: {}", reasons.join("; "));
            3
        }
        Err(
            error @ (LaunchError::BackendMismatch { .. }
            | LaunchError::MissingControls(_)
            | LaunchError::InvalidPlan(_)),
        ) => {
            eprintln!("invalid sandbox input: {error}");
            2
        }
        Err(error) => {
            eprintln!("sandbox infrastructure failure: {error}");
            5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HelperMode, PlanStatus, Step, parse_helper_arguments, validate_status};
    use std::collections::BTreeMap;

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
        assert!(validate_status(&PlanStatus::Complete, &[], &[step]).is_err());
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
                source_root: "/repo".to_owned()
            })
        );
        assert!(parse_helper_arguments(&["--run".to_owned()]).is_err());
        assert!(parse_helper_arguments(&["--doctor".to_owned(), "unexpected".to_owned()]).is_err());
    }
}
