use crate::Scenario;
use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, content_digest, valid_content_digest};
use workflow_verifier_runner_protocol::{
    Control, Dependency, Limits, PlanStatus, RUNNER_V2_CPU_CORES, RUNNER_V2_MEMORY_BYTES,
    RUNNER_V2_MEMORY_MIB, RUNNER_V2_OUTPUT_BYTES, RUNNER_V2_PROCESSES, RUNNER_V2_SCRATCH_BYTES,
    RUNNER_V2_SCRATCH_ENTRIES, RUNNER_V2_WALL_TIME_SECONDS, Step, UNRESOLVED_CONTENT_DIGEST,
    ValidatedPlan, validate_plan,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Backend {
    Oci(String),
    LinuxNative,
    WindowsNative,
    MacosVm,
}

impl Backend {
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Oci(engine) => format!("oci:{engine}"),
            Self::LinuxNative => "linux-native".to_owned(),
            Self::WindowsNative => "windows-native".to_owned(),
            Self::MacosVm => "macos-vm".to_owned(),
        }
    }

    fn runtime_kind(&self) -> &'static str {
        match self {
            Self::Oci(_) => "oci-capsule",
            Self::LinuxNative => "linux-capsule",
            Self::WindowsNative => "windows-runtime-profile",
            Self::MacosVm => "macos-vm",
        }
    }

    fn compatible_os(&self) -> &'static str {
        match self {
            Self::Oci(_) | Self::LinuxNative => "linux",
            Self::WindowsNative => "windows",
            Self::MacosVm => "macos",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerPlanRequest {
    pub backend: Backend,
    pub scenario: Scenario,
    pub provider_profile: String,
    pub selected_jobs: Vec<String>,
    pub source_digest: String,
    pub lock_digest: String,
    pub controls: Vec<Control>,
    pub network_destinations: Vec<String>,
    pub dependencies: Vec<Dependency>,
    pub steps: Vec<Step>,
    pub incomplete_reasons: Vec<String>,
    pub runtime_helper_digest: Option<String>,
    pub runtime_boot_digest: Option<String>,
    pub capability_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerPlan {
    canonical: String,
    validated: ValidatedPlan,
}

impl RunnerPlan {
    /// Build, authenticate, and independently validate a runner-v2 plan.
    ///
    /// # Errors
    /// Rejects contradictory backends, unsafe policies, duplicate identities,
    /// invalid digests, or any plan the shared helper protocol will not accept.
    #[allow(clippy::too_many_lines)]
    pub fn build(mut request: RunnerPlanRequest) -> Result<Self, String> {
        validate_request(&request)?;
        request.controls.sort_unstable();
        request.selected_jobs.sort();
        request
            .dependencies
            .sort_by(|left, right| left.reference.cmp(&right.reference));
        request.network_destinations.sort();
        let secret_names = request.scenario.secret_names.clone();
        for step in &mut request.steps {
            if !resolved_digest(&step.image) {
                UNRESOLVED_CONTENT_DIGEST.clone_into(&mut step.image);
            }
            for (name, value) in &mut step.environment {
                if secret_names.contains(name) {
                    *value = format!("${{SECRET:{name}}}");
                }
            }
        }
        let mut images: Vec<_> = request
            .steps
            .iter()
            .map(|step| step.image.clone())
            .collect();
        images.sort();
        images.dedup();
        let workload_digest = if images.len() == 1 {
            images.remove(0)
        } else {
            UNRESOLVED_CONTENT_DIGEST.to_owned()
        };
        let mut reasons = std::mem::take(&mut request.incomplete_reasons);
        reasons.extend(request.dependencies.iter().filter_map(|dependency| {
            if dependency.available && dependency.digest.as_deref().is_some_and(resolved_digest) {
                None
            } else {
                Some(format!(
                    "Incomplete.Unresolved_dependency: {}",
                    dependency.reference
                ))
            }
        }));
        reasons.extend(
            request
                .steps
                .iter()
                .filter(|step| !step.supported)
                .map(|step| format!("Incomplete.Unsupported_step: {}", step.id)),
        );
        reasons.extend(
            request
                .steps
                .iter()
                .filter(|step| !resolved_digest(&step.image))
                .map(|step| format!("Incomplete.Unresolved_capsule: {}", step.id)),
        );
        if !resolved_digest(&workload_digest) {
            reasons.push("Incomplete.Unresolved_runtime_workload".to_owned());
        }
        if matches!(
            request.backend,
            Backend::LinuxNative | Backend::WindowsNative | Backend::MacosVm
        ) && request
            .runtime_helper_digest
            .as_deref()
            .is_none_or(|digest| !resolved_digest(digest))
        {
            reasons.push("Incomplete.Unresolved_runtime_helper".to_owned());
        }
        if request.backend == Backend::MacosVm
            && request
                .runtime_boot_digest
                .as_deref()
                .is_none_or(|digest| !resolved_digest(digest))
        {
            reasons.push("Incomplete.Unresolved_macos_boot_bundle".to_owned());
        }
        reasons.sort();
        reasons.dedup();
        for reason in &mut reasons {
            if !reason.starts_with("Incomplete.") {
                *reason = format!("Incomplete.Planner: {reason}");
            }
        }
        let status = if reasons.is_empty() {
            JsonValue::Object(BTreeMap::from([(
                "state".to_owned(),
                JsonValue::String("complete".to_owned()),
            )]))
        } else {
            JsonValue::Object(BTreeMap::from([
                (
                    "reasons".to_owned(),
                    JsonValue::Array(reasons.into_iter().map(JsonValue::String).collect()),
                ),
                (
                    "state".to_owned(),
                    JsonValue::String("incomplete".to_owned()),
                ),
            ]))
        };
        let runtime = runtime_json(&request, &workload_digest);
        let unsigned = JsonValue::Object(BTreeMap::from([
            (
                "backend".to_owned(),
                JsonValue::String(request.backend.name()),
            ),
            (
                "controls".to_owned(),
                JsonValue::Array(
                    request
                        .controls
                        .iter()
                        .map(|control| JsonValue::String(control.name().to_owned()))
                        .collect(),
                ),
            ),
            (
                "dependencies".to_owned(),
                JsonValue::Array(request.dependencies.iter().map(dependency_json).collect()),
            ),
            ("limits".to_owned(), limits_json()),
            (
                "lock_digest".to_owned(),
                JsonValue::String(request.lock_digest),
            ),
            (
                "network".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "destinations".to_owned(),
                        JsonValue::Array(
                            request
                                .network_destinations
                                .into_iter()
                                .map(JsonValue::String)
                                .collect(),
                        ),
                    ),
                    (
                        "mode".to_owned(),
                        JsonValue::String(
                            if request.controls.contains(&Control::NetworkDeny) {
                                "deny"
                            } else {
                                "allowlist"
                            }
                            .to_owned(),
                        ),
                    ),
                ])),
            ),
            (
                "provider_profile".to_owned(),
                JsonValue::String(request.provider_profile),
            ),
            ("runtime".to_owned(), runtime),
            (
                "scenario_digest".to_owned(),
                JsonValue::String(request.scenario.digest),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("runner-v2".to_owned()),
            ),
            (
                "secret_names".to_owned(),
                JsonValue::Array(secret_names.into_iter().map(JsonValue::String).collect()),
            ),
            (
                "selected_jobs".to_owned(),
                JsonValue::Array(
                    request
                        .selected_jobs
                        .into_iter()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            (
                "source_digest".to_owned(),
                JsonValue::String(request.source_digest),
            ),
            ("status".to_owned(), status),
            (
                "steps".to_owned(),
                JsonValue::Array(request.steps.iter().map(step_json).collect()),
            ),
        ]));
        let digest = content_digest(unsigned.canonical());
        let JsonValue::Object(mut fields) = unsigned else {
            return Err("runner plan construction did not produce an object".to_owned());
        };
        fields.insert("digest".to_owned(), JsonValue::String(digest));
        let canonical = JsonValue::Object(fields).canonical_line();
        let validated = validate_plan(&canonical)?;
        Ok(Self {
            canonical,
            validated,
        })
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.canonical.clone()
    }

    #[must_use]
    pub fn validated(&self) -> &ValidatedPlan {
        &self.validated
    }

    #[must_use]
    pub fn status(&self) -> &PlanStatus {
        &self.validated.status
    }
}

fn validate_request(request: &RunnerPlanRequest) -> Result<(), String> {
    if let Backend::Oci(engine) = &request.backend
        && (engine.is_empty()
            || !engine
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
    {
        return Err("OCI backend name is invalid".to_owned());
    }
    if request.backend.compatible_os() != request.scenario.runner_platform.os() {
        return Err("runner platform contradicts the selected backend".to_owned());
    }
    if !request.scenario.verify_digest()
        || !valid_content_digest(&request.source_digest)
        || !valid_content_digest(&request.lock_digest)
    {
        return Err("runner-v2 scenario/source/lock digests must be SHA-256".to_owned());
    }
    if request.provider_profile.trim().is_empty()
        || request.selected_jobs.is_empty()
        || request
            .selected_jobs
            .iter()
            .any(|job| job.trim().is_empty())
    {
        return Err("runner-v2 requires a provider profile and selected job".to_owned());
    }
    unique(&request.selected_jobs, "selected jobs")?;
    unique(&request.controls, "controls")?;
    unique(&request.network_destinations, "network destinations")?;
    let denied = request.controls.contains(&Control::NetworkDeny);
    if denied && !request.network_destinations.is_empty() {
        return Err("network-deny plans cannot contain destination grants".to_owned());
    }
    if !denied && request.network_destinations.is_empty() {
        return Err("network-enabled plans require at least one destination policy".to_owned());
    }
    if request
        .network_destinations
        .iter()
        .any(|destination| !valid_destination(destination))
    {
        return Err("network destinations must be normalized HTTPS policies".to_owned());
    }
    let mut dependency_names = BTreeSet::new();
    for dependency in &request.dependencies {
        if dependency.reference.trim().is_empty()
            || !dependency_names.insert(dependency.reference.as_str())
        {
            return Err("dependency references must be non-empty and unique".to_owned());
        }
        if dependency
            .digest
            .as_deref()
            .is_some_and(|digest| !valid_content_digest(digest))
        {
            return Err(format!(
                "dependency {} has an invalid digest",
                dependency.reference
            ));
        }
    }
    let mut step_ids = BTreeSet::new();
    for step in &request.steps {
        if step.id.is_empty()
            || step.argv.is_empty()
            || !(step.working_directory == "/workspace"
                || step.working_directory.starts_with("/workspace/"))
            || !step_ids.insert(step.id.as_str())
        {
            return Err("steps need unique IDs, argv, and a confined working directory".to_owned());
        }
        if step.environment.keys().any(|name| !environment_name(name)) {
            return Err("step environment names must be portable identifiers".to_owned());
        }
    }
    for digest in [
        request.runtime_helper_digest.as_deref(),
        request.runtime_boot_digest.as_deref(),
        request.capability_fingerprint.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !valid_content_digest(digest) {
            return Err("runtime identities must be SHA-256 content digests".to_owned());
        }
    }
    Ok(())
}

fn unique<T: Ord + Clone>(values: &[T], context: &str) -> Result<(), String> {
    let unique: BTreeSet<_> = values.iter().cloned().collect();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(format!("{context} must be unique"))
    }
}

fn valid_destination(value: &str) -> bool {
    let Some(origin_and_path) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = origin_and_path.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && !value.contains(['@', '\\', '?', '#', '%', '\0', '\r', '\n'])
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        && !value.contains("..")
}

fn environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn resolved_digest(value: &str) -> bool {
    valid_content_digest(value) && value != UNRESOLVED_CONTENT_DIGEST
}

fn limits_json() -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "cpu_cores".to_owned(),
            JsonValue::Integer(i64::try_from(RUNNER_V2_CPU_CORES).expect("schema limit fits i64")),
        ),
        (
            "memory_bytes".to_owned(),
            JsonValue::Integer(
                i64::try_from(RUNNER_V2_MEMORY_BYTES).expect("schema limit fits i64"),
            ),
        ),
        (
            "output_bytes".to_owned(),
            JsonValue::Integer(
                i64::try_from(RUNNER_V2_OUTPUT_BYTES).expect("schema limit fits i64"),
            ),
        ),
        (
            "processes".to_owned(),
            JsonValue::Integer(i64::try_from(RUNNER_V2_PROCESSES).expect("schema limit fits i64")),
        ),
        (
            "scratch_bytes".to_owned(),
            JsonValue::Integer(
                i64::try_from(RUNNER_V2_SCRATCH_BYTES).expect("schema limit fits i64"),
            ),
        ),
        (
            "scratch_entries".to_owned(),
            JsonValue::Integer(
                i64::try_from(RUNNER_V2_SCRATCH_ENTRIES).expect("schema limit fits i64"),
            ),
        ),
        (
            "wall_time_seconds".to_owned(),
            JsonValue::Integer(
                i64::try_from(RUNNER_V2_WALL_TIME_SECONDS).expect("schema limit fits i64"),
            ),
        ),
    ]))
}

fn runtime_json(request: &RunnerPlanRequest, workload_digest: &str) -> JsonValue {
    let rootfs = match request.backend {
        Backend::Oci(_) | Backend::LinuxNative | Backend::MacosVm => {
            JsonValue::String(workload_digest.to_owned())
        }
        Backend::WindowsNative => JsonValue::Null,
    };
    JsonValue::Object(BTreeMap::from([
        (
            "boot_digest".to_owned(),
            optional_string(request.runtime_boot_digest.as_ref()),
        ),
        (
            "capability_fingerprint".to_owned(),
            optional_string(request.capability_fingerprint.as_ref()),
        ),
        (
            "helper_digest".to_owned(),
            optional_string(request.runtime_helper_digest.as_ref()),
        ),
        (
            "kind".to_owned(),
            JsonValue::String(request.backend.runtime_kind().to_owned()),
        ),
        ("rootfs_digest".to_owned(), rootfs),
        (
            "runner_platform".to_owned(),
            JsonValue::String(request.scenario.runner_platform.name().to_owned()),
        ),
        (
            "workload_digest".to_owned(),
            JsonValue::String(workload_digest.to_owned()),
        ),
    ]))
}

fn optional_string(value: Option<&String>) -> JsonValue {
    value.map_or(JsonValue::Null, |value| JsonValue::String(value.clone()))
}

fn dependency_json(dependency: &Dependency) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "available".to_owned(),
            JsonValue::Boolean(dependency.available),
        ),
        (
            "digest".to_owned(),
            optional_string(dependency.digest.as_ref()),
        ),
        (
            "reference".to_owned(),
            JsonValue::String(dependency.reference.clone()),
        ),
    ]))
}

fn step_json(step: &Step) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "argv".to_owned(),
            JsonValue::Array(step.argv.iter().cloned().map(JsonValue::String).collect()),
        ),
        (
            "environment".to_owned(),
            JsonValue::Object(
                step.environment
                    .iter()
                    .map(|(name, value)| (name.clone(), JsonValue::String(value.clone())))
                    .collect(),
            ),
        ),
        ("id".to_owned(), JsonValue::String(step.id.clone())),
        ("image".to_owned(), JsonValue::String(step.image.clone())),
        ("supported".to_owned(), JsonValue::Boolean(step.supported)),
        (
            "working_directory".to_owned(),
            JsonValue::String(step.working_directory.clone()),
        ),
    ]))
}

#[must_use]
pub fn portable_limits() -> Limits {
    Limits {
        cpu_seconds: RUNNER_V2_WALL_TIME_SECONDS,
        memory_mb: RUNNER_V2_MEMORY_MIB,
        processes: RUNNER_V2_PROCESSES,
        output_bytes: RUNNER_V2_OUTPUT_BYTES,
    }
}
