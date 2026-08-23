//! Canonical protocol shared by the macOS controller, Swift VM shim, and
//! Linux guest agent. Every parser rejects unknown fields and unsafe widening.

use std::collections::BTreeMap;

use super::{
    boolean_field, exact_fields, field, integer_field, json, object, string_array, string_field,
    strings, valid_content_digest,
};

pub const REQUEST_SCHEMA: &str = "vm-shim-request-v1";
pub const OBSERVATION_SCHEMA: &str = "vm-observation-v1";
pub const IMAGE_MANIFEST_SCHEMA: &str = "vm-image-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmImage {
    pub architecture: String,
    pub kernel_path: String,
    pub kernel_digest: String,
    pub initrd_path: String,
    pub initrd_digest: String,
    pub rootfs_path: String,
    pub rootfs_digest: String,
    pub manifest_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub plan_digest: String,
    pub image: VmImage,
    pub source_root: String,
    pub scratch_root: String,
    pub control_root: String,
    pub working_directory: String,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub cpu_count: u64,
    pub memory_mb: u64,
    pub processes: u64,
    pub timeout_seconds: u64,
    pub output_bytes: u64,
    pub network: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub output_exceeded: bool,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageManifest {
    pub architecture: String,
    pub kernel_digest: String,
    pub initrd_digest: String,
    pub rootfs_digest: String,
    pub agent_digest: String,
    pub version: String,
}

fn number(value: u64) -> json::Value {
    json::Value::Integer(i64::try_from(value).expect("VM limit fits signed JSON"))
}

fn environment(value: &BTreeMap<String, String>) -> json::Value {
    json::Value::Object(
        value
            .iter()
            .map(|(name, value)| (name.clone(), json::Value::String(value.clone())))
            .collect(),
    )
}

fn image_json(image: &VmImage) -> json::Value {
    object([
        (
            "architecture",
            json::Value::String(image.architecture.clone()),
        ),
        (
            "initrd_digest",
            json::Value::String(image.initrd_digest.clone()),
        ),
        (
            "initrd_path",
            json::Value::String(image.initrd_path.clone()),
        ),
        (
            "kernel_digest",
            json::Value::String(image.kernel_digest.clone()),
        ),
        (
            "kernel_path",
            json::Value::String(image.kernel_path.clone()),
        ),
        (
            "manifest_digest",
            json::Value::String(image.manifest_digest.clone()),
        ),
        (
            "rootfs_digest",
            json::Value::String(image.rootfs_digest.clone()),
        ),
        (
            "rootfs_path",
            json::Value::String(image.rootfs_path.clone()),
        ),
    ])
}

impl Request {
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let value = object([
            ("argv", strings(&self.argv)),
            (
                "control_root",
                json::Value::String(self.control_root.clone()),
            ),
            ("cpu_count", number(self.cpu_count)),
            ("environment", environment(&self.environment)),
            ("image", image_json(&self.image)),
            ("memory_mb", number(self.memory_mb)),
            ("network", json::Value::Bool(self.network)),
            ("output_bytes", number(self.output_bytes)),
            ("plan_digest", json::Value::String(self.plan_digest.clone())),
            ("processes", number(self.processes)),
            ("schema", json::Value::String(REQUEST_SCHEMA.to_owned())),
            (
                "scratch_root",
                json::Value::String(self.scratch_root.clone()),
            ),
            ("source_root", json::Value::String(self.source_root.clone())),
            ("timeout_seconds", number(self.timeout_seconds)),
            (
                "working_directory",
                json::Value::String(self.working_directory.clone()),
            ),
        ]);
        format!("{}\n", json::canonical(&value))
    }
}

fn hex_encode(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() & 1 != 0 {
        return Err("output_hex must contain complete bytes".to_owned());
    }
    let bytes = value.as_bytes();
    bytes
        .iter()
        .step_by(2)
        .zip(bytes.iter().skip(1).step_by(2))
        .map(|(high, low)| {
            let high = char::from(*high)
                .to_digit(16)
                .ok_or_else(|| "output_hex contains a non-hex character".to_owned())?;
            let low = char::from(*low)
                .to_digit(16)
                .ok_or_else(|| "output_hex contains a non-hex character".to_owned())?;
            u8::try_from((high << 4) | low).map_err(|error| error.to_string())
        })
        .collect()
}

impl Observation {
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let value = object([
            (
                "code",
                self.code.map_or(json::Value::Null, |code| {
                    json::Value::Integer(i64::from(code))
                }),
            ),
            ("output_exceeded", json::Value::Bool(self.output_exceeded)),
            ("output_hex", json::Value::String(hex_encode(&self.output))),
            ("schema", json::Value::String(OBSERVATION_SCHEMA.to_owned())),
            ("timed_out", json::Value::Bool(self.timed_out)),
        ]);
        format!("{}\n", json::canonical(&value))
    }
}

impl ImageManifest {
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let value = object([
            (
                "agent_digest",
                json::Value::String(self.agent_digest.clone()),
            ),
            (
                "architecture",
                json::Value::String(self.architecture.clone()),
            ),
            (
                "initrd_digest",
                json::Value::String(self.initrd_digest.clone()),
            ),
            (
                "kernel_digest",
                json::Value::String(self.kernel_digest.clone()),
            ),
            (
                "rootfs_digest",
                json::Value::String(self.rootfs_digest.clone()),
            ),
            (
                "schema",
                json::Value::String(IMAGE_MANIFEST_SCHEMA.to_owned()),
            ),
            ("version", json::Value::String(self.version.clone())),
        ]);
        format!("{}\n", json::canonical(&value))
    }
}

fn schema(object: &BTreeMap<String, json::Value>, expected: &str) -> Result<(), String> {
    let actual = string_field(object, "schema")?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("schema is {actual}, expected {expected}"))
    }
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "arm64" | "x86_64")
}

fn digest(value: String, name: &str) -> Result<String, String> {
    if valid_content_digest(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be a sha256 content digest"))
    }
}

fn absolute_path(value: String, name: &str) -> Result<String, String> {
    let safe = value.starts_with('/')
        && value.len() > 1
        && !value.contains('\0')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    if safe {
        Ok(value)
    } else {
        Err(format!("{name} must be an absolute path without NUL"))
    }
}

fn parse_image(value: &json::Value) -> Result<VmImage, String> {
    let image = value
        .object()
        .ok_or_else(|| "image must be an object".to_owned())?;
    exact_fields(
        image,
        &[
            "architecture",
            "initrd_digest",
            "initrd_path",
            "kernel_digest",
            "kernel_path",
            "manifest_digest",
            "rootfs_digest",
            "rootfs_path",
        ],
        "VM image",
    )?;
    let architecture = string_field(image, "architecture")?;
    if !valid_architecture(&architecture) {
        return Err(format!("unsupported VM architecture {architecture}"));
    }
    Ok(VmImage {
        architecture,
        kernel_path: absolute_path(string_field(image, "kernel_path")?, "kernel_path")?,
        kernel_digest: digest(string_field(image, "kernel_digest")?, "kernel_digest")?,
        initrd_path: absolute_path(string_field(image, "initrd_path")?, "initrd_path")?,
        initrd_digest: digest(string_field(image, "initrd_digest")?, "initrd_digest")?,
        rootfs_path: absolute_path(string_field(image, "rootfs_path")?, "rootfs_path")?,
        rootfs_digest: digest(string_field(image, "rootfs_digest")?, "rootfs_digest")?,
        manifest_digest: digest(string_field(image, "manifest_digest")?, "manifest_digest")?,
    })
}

fn parse_environment(value: &json::Value) -> Result<BTreeMap<String, String>, String> {
    value
        .object()
        .ok_or_else(|| "environment must be an object".to_owned())?
        .iter()
        .map(|(name, value)| {
            let text = value
                .string()
                .ok_or_else(|| format!("environment {name} must be a string"))?;
            if name.is_empty() || name.contains(['=', '\0']) || text.contains('\0') {
                Err(format!("invalid environment entry {name:?}"))
            } else {
                Ok((name.clone(), text.to_owned()))
            }
        })
        .collect()
}

/// Parses and validates an exact `vm-shim-request-v1` document.
///
/// # Errors
///
/// Rejects malformed JSON, unknown fields, unsafe paths, mutable network
/// requests, invalid digests, empty commands, and invalid limits.
pub fn parse_request(source: &str) -> Result<Request, String> {
    let root = json::parse(source)?;
    let value = root
        .object()
        .ok_or_else(|| "VM request must be an object".to_owned())?;
    exact_fields(
        value,
        &[
            "argv",
            "control_root",
            "cpu_count",
            "environment",
            "image",
            "memory_mb",
            "network",
            "output_bytes",
            "plan_digest",
            "processes",
            "schema",
            "scratch_root",
            "source_root",
            "timeout_seconds",
            "working_directory",
        ],
        "VM request",
    )?;
    schema(value, REQUEST_SCHEMA)?;
    let network = boolean_field(value, "network")?;
    if network {
        return Err("VM request cannot enable network".to_owned());
    }
    let argv = string_array(field(value, "argv")?, "argv")?;
    if argv.is_empty() || argv.iter().any(|item| item.contains('\0')) {
        return Err("VM argv must be nonempty and NUL-free".to_owned());
    }
    let working_directory = string_field(value, "working_directory")?;
    let safe_working_directory = working_directory == "/workspace"
        || (working_directory.starts_with("/workspace/")
            && working_directory
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && !matches!(component, "." | "..")));
    if !safe_working_directory {
        return Err("VM working_directory must stay below /workspace".to_owned());
    }
    let request = Request {
        plan_digest: digest(string_field(value, "plan_digest")?, "plan_digest")?,
        image: parse_image(field(value, "image")?)?,
        source_root: absolute_path(string_field(value, "source_root")?, "source_root")?,
        scratch_root: absolute_path(string_field(value, "scratch_root")?, "scratch_root")?,
        control_root: absolute_path(string_field(value, "control_root")?, "control_root")?,
        working_directory,
        argv,
        environment: parse_environment(field(value, "environment")?)?,
        cpu_count: integer_field(value, "cpu_count")?,
        memory_mb: integer_field(value, "memory_mb")?,
        processes: integer_field(value, "processes")?,
        timeout_seconds: integer_field(value, "timeout_seconds")?,
        output_bytes: integer_field(value, "output_bytes")?,
        network,
    };
    if [
        request.cpu_count,
        request.memory_mb,
        request.processes,
        request.timeout_seconds,
        request.output_bytes,
    ]
    .contains(&0)
    {
        return Err("VM resource limits must be positive".to_owned());
    }
    if request.source_root == request.scratch_root
        || request.source_root == request.control_root
        || request.scratch_root == request.control_root
    {
        return Err("VM source, scratch, and control roots must be distinct".to_owned());
    }
    Ok(request)
}

/// Parses an exact guest observation and decodes its binary output.
///
/// # Errors
///
/// Rejects malformed JSON, unknown fields, out-of-range exit codes, and
/// malformed hexadecimal output.
pub fn parse_observation(source: &str) -> Result<Observation, String> {
    let root = json::parse(source)?;
    let value = root
        .object()
        .ok_or_else(|| "VM observation must be an object".to_owned())?;
    exact_fields(
        value,
        &[
            "code",
            "output_exceeded",
            "output_hex",
            "schema",
            "timed_out",
        ],
        "VM observation",
    )?;
    schema(value, OBSERVATION_SCHEMA)?;
    let code = match field(value, "code")? {
        json::Value::Null => None,
        json::Value::Integer(value) => {
            Some(i32::try_from(*value).map_err(|_| "VM exit code is outside i32".to_owned())?)
        }
        _ => return Err("code must be an integer or null".to_owned()),
    };
    Ok(Observation {
        code,
        timed_out: boolean_field(value, "timed_out")?,
        output_exceeded: boolean_field(value, "output_exceeded")?,
        output: hex_decode(&string_field(value, "output_hex")?)?,
    })
}

/// Parses an exact, content-addressed VM image manifest.
///
/// # Errors
///
/// Rejects malformed JSON, unknown fields, unsupported architectures, empty
/// versions, or malformed digests.
pub fn parse_image_manifest(source: &str) -> Result<ImageManifest, String> {
    let root = json::parse(source)?;
    let value = root
        .object()
        .ok_or_else(|| "VM image manifest must be an object".to_owned())?;
    exact_fields(
        value,
        &[
            "agent_digest",
            "architecture",
            "initrd_digest",
            "kernel_digest",
            "rootfs_digest",
            "schema",
            "version",
        ],
        "VM image manifest",
    )?;
    schema(value, IMAGE_MANIFEST_SCHEMA)?;
    let architecture = string_field(value, "architecture")?;
    if !valid_architecture(&architecture) {
        return Err(format!("unsupported VM architecture {architecture}"));
    }
    let version = string_field(value, "version")?;
    if version.is_empty() || version.contains('\0') {
        return Err("VM image version must be nonempty and NUL-free".to_owned());
    }
    Ok(ImageManifest {
        architecture,
        kernel_digest: digest(string_field(value, "kernel_digest")?, "kernel_digest")?,
        initrd_digest: digest(string_field(value, "initrd_digest")?, "initrd_digest")?,
        rootfs_digest: digest(string_field(value, "rootfs_digest")?, "rootfs_digest")?,
        agent_digest: digest(string_field(value, "agent_digest")?, "agent_digest")?,
        version,
    })
}
