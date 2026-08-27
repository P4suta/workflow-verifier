use std::collections::BTreeMap;
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::{JsonValue, PublicPath, content_digest};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RunnerPlatform {
    LinuxX86_64,
    LinuxArm64,
    WindowsX86_64,
    WindowsArm64,
    MacosX86_64,
    MacosArm64,
}

impl RunnerPlatform {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::LinuxArm64 => "linux-arm64",
            Self::WindowsX86_64 => "windows-x86_64",
            Self::WindowsArm64 => "windows-arm64",
            Self::MacosX86_64 => "macos-x86_64",
            Self::MacosArm64 => "macos-arm64",
        }
    }

    #[must_use]
    pub fn os(self) -> &'static str {
        match self {
            Self::LinuxX86_64 | Self::LinuxArm64 => "linux",
            Self::WindowsX86_64 | Self::WindowsArm64 => "windows",
            Self::MacosX86_64 | Self::MacosArm64 => "macos",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "linux-x86_64" => Self::LinuxX86_64,
            "linux-arm64" => Self::LinuxArm64,
            "windows-x86_64" => Self::WindowsX86_64,
            "windows-arm64" => Self::WindowsArm64,
            "macos-x86_64" => Self::MacosX86_64,
            "macos-arm64" => Self::MacosArm64,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    pub digest: String,
    pub provider: Provider,
    pub workflow_entrypoint: String,
    pub job: String,
    pub event: String,
    pub inputs: BTreeMap<String, String>,
    pub matrix: BTreeMap<String, JsonValue>,
    pub variables: BTreeMap<String, String>,
    pub runner_platform: RunnerPlatform,
    pub secret_names: Vec<String>,
}

impl Scenario {
    /// Create a concrete scenario-v1 value with empty bindings.
    ///
    /// # Errors
    /// Rejects unsafe entrypoints and empty job or event selectors.
    pub fn new(
        provider: Provider,
        workflow_entrypoint: impl Into<String>,
        job: impl Into<String>,
        event: impl Into<String>,
        runner_platform: RunnerPlatform,
    ) -> Result<Self, String> {
        let mut scenario = Self {
            digest: String::new(),
            provider,
            workflow_entrypoint: workflow_entrypoint.into().replace('\\', "/"),
            job: job.into(),
            event: event.into(),
            inputs: BTreeMap::new(),
            matrix: BTreeMap::new(),
            variables: BTreeMap::new(),
            runner_platform,
            secret_names: Vec::new(),
        };
        scenario.validate()?;
        scenario.refresh_digest();
        Ok(scenario)
    }

    /// Add a portable string input and refresh the semantic digest.
    ///
    /// # Errors
    /// Rejects invalid or duplicate binding names.
    pub fn with_input(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, String> {
        let name = name.into();
        if !portable_name(&name) || self.inputs.insert(name, value.into()).is_some() {
            return Err("scenario input names must be unique and portable".to_owned());
        }
        self.refresh_digest();
        Ok(self)
    }

    /// Add a portable string variable and refresh the semantic digest.
    ///
    /// # Errors
    /// Rejects invalid or duplicate binding names.
    pub fn with_variable(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, String> {
        let name = name.into();
        if !portable_name(&name) || self.variables.insert(name, value.into()).is_some() {
            return Err("scenario variable names must be unique and portable".to_owned());
        }
        self.refresh_digest();
        Ok(self)
    }

    /// Add a scalar matrix value and refresh the semantic digest.
    ///
    /// # Errors
    /// Rejects invalid names, duplicates, and non-scalar values.
    pub fn with_matrix(
        mut self,
        name: impl Into<String>,
        value: JsonValue,
    ) -> Result<Self, String> {
        let name = name.into();
        if !matches!(
            value,
            JsonValue::String(_) | JsonValue::Boolean(_) | JsonValue::Integer(_)
        ) {
            return Err("scenario matrix values must be scalar".to_owned());
        }
        if !portable_name(&name) || self.matrix.insert(name, value).is_some() {
            return Err("scenario matrix names must be unique and portable".to_owned());
        }
        self.refresh_digest();
        Ok(self)
    }

    /// Declare a secret name without embedding its value.
    ///
    /// # Errors
    /// Rejects invalid or duplicate environment identifiers.
    pub fn with_secret(mut self, name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        if !secret_name(&name) || self.secret_names.contains(&name) {
            return Err("scenario secret_names must be unique portable identifiers".to_owned());
        }
        self.secret_names.push(name);
        self.secret_names.sort();
        self.refresh_digest();
        Ok(self)
    }

    fn validate(&self) -> Result<(), String> {
        PublicPath::new(self.workflow_entrypoint.clone()).map_err(|_| {
            "scenario workflow_entrypoint must be a root-relative UTF-8 path".to_owned()
        })?;
        if self.job.trim().is_empty() {
            return Err("scenario job must not be empty".to_owned());
        }
        if self.event.trim().is_empty() {
            return Err("scenario event must not be empty".to_owned());
        }
        if !self
            .inputs
            .keys()
            .chain(self.variables.keys())
            .all(|name| portable_name(name))
            || !self.matrix.keys().all(|name| portable_name(name))
        {
            return Err("scenario input, matrix, and variable names must be portable".to_owned());
        }
        if !self.secret_names.iter().all(|name| secret_name(name)) {
            return Err("scenario secret_names must be portable identifiers".to_owned());
        }
        Ok(())
    }

    fn unsigned_fields(&self) -> BTreeMap<String, JsonValue> {
        BTreeMap::from([
            ("event".to_owned(), JsonValue::String(self.event.clone())),
            ("inputs".to_owned(), string_map(&self.inputs)),
            ("job".to_owned(), JsonValue::String(self.job.clone())),
            ("matrix".to_owned(), JsonValue::Object(self.matrix.clone())),
            (
                "provider".to_owned(),
                JsonValue::String(self.provider.name().to_owned()),
            ),
            (
                "runner_platform".to_owned(),
                JsonValue::String(self.runner_platform.name().to_owned()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("scenario-v1".to_owned()),
            ),
            (
                "secret_names".to_owned(),
                JsonValue::Array(
                    self.secret_names
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            ("variables".to_owned(), string_map(&self.variables)),
            (
                "workflow_entrypoint".to_owned(),
                JsonValue::String(self.workflow_entrypoint.clone()),
            ),
        ])
    }

    fn unsigned_json(&self) -> JsonValue {
        JsonValue::Object(self.unsigned_fields())
    }

    fn refresh_digest(&mut self) {
        self.digest = content_digest(self.unsigned_json().canonical());
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.digest == content_digest(self.unsigned_json().canonical())
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut fields = self.unsigned_fields();
        fields.insert("digest".to_owned(), JsonValue::String(self.digest.clone()));
        JsonValue::Object(fields).canonical_line()
    }

    /// Parse and authenticate strict scenario-v1 product JSON.
    ///
    /// # Errors
    /// Rejects malformed JSON, unknown fields, invalid values, and digest tampering.
    pub fn parse(source: &str) -> Result<Self, String> {
        let root = JsonValue::parse(source).map_err(|error| error.to_string())?;
        let fields = root.exact_object(
            "scenario-v1",
            &[
                "digest",
                "event",
                "inputs",
                "job",
                "matrix",
                "provider",
                "runner_platform",
                "schema",
                "secret_names",
                "variables",
                "workflow_entrypoint",
            ],
        )?;
        for name in [
            "digest",
            "event",
            "inputs",
            "job",
            "matrix",
            "provider",
            "runner_platform",
            "schema",
            "secret_names",
            "variables",
            "workflow_entrypoint",
        ] {
            if !fields.contains_key(name) {
                return Err(format!("scenario-v1 needs field {name}"));
            }
        }
        if string(fields, "schema")? != "scenario-v1" {
            return Err("unsupported scenario schema".to_owned());
        }
        let supplied_digest = string(fields, "digest")?.to_owned();
        let provider = match string(fields, "provider")? {
            "github" => Provider::Github,
            "gitlab" => Provider::Gitlab,
            "azure" => Provider::Azure,
            "circleci" => Provider::Circleci,
            value => return Err(format!("unknown scenario provider {value}")),
        };
        let runner_name = string(fields, "runner_platform")?;
        let runner_platform = RunnerPlatform::parse(runner_name)
            .ok_or_else(|| format!("unknown runner platform {runner_name}"))?;
        let mut scenario = Self::new(
            provider,
            string(fields, "workflow_entrypoint")?,
            string(fields, "job")?,
            string(fields, "event")?,
            runner_platform,
        )?;
        scenario.inputs = parse_string_map(fields, "inputs")?;
        scenario.variables = parse_string_map(fields, "variables")?;
        scenario.matrix = parse_matrix(fields)?;
        scenario.secret_names = fields
            .get("secret_names")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "secret_names must be an array".to_owned())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "secret_names must contain strings".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique = scenario.secret_names.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != scenario.secret_names.len() {
            return Err("scenario secret_names must be unique".to_owned());
        }
        scenario.secret_names.sort();
        scenario.validate()?;
        scenario.refresh_digest();
        if scenario.digest != supplied_digest {
            return Err("scenario digest mismatch".to_owned());
        }
        Ok(scenario)
    }
}

fn portable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn secret_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn string_map(values: &BTreeMap<String, String>) -> JsonValue {
    JsonValue::Object(
        values
            .iter()
            .map(|(name, value)| (name.clone(), JsonValue::String(value.clone())))
            .collect(),
    )
}

fn string<'a>(fields: &'a BTreeMap<String, JsonValue>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("scenario-v1 needs string field {name}"))
}

fn parse_string_map(
    fields: &BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<BTreeMap<String, String>, String> {
    let JsonValue::Object(values) = fields
        .get(name)
        .ok_or_else(|| format!("scenario-v1 needs field {name}"))?
    else {
        return Err(format!("scenario {name} must be an object"));
    };
    values
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| format!("scenario {name}.{key} must be a string"))
        })
        .collect()
}

fn parse_matrix(
    fields: &BTreeMap<String, JsonValue>,
) -> Result<BTreeMap<String, JsonValue>, String> {
    let JsonValue::Object(values) = fields
        .get("matrix")
        .ok_or_else(|| "scenario-v1 needs field matrix".to_owned())?
    else {
        return Err("scenario matrix must be an object".to_owned());
    };
    if values.values().all(|value| {
        matches!(
            value,
            JsonValue::String(_) | JsonValue::Boolean(_) | JsonValue::Integer(_)
        )
    }) {
        Ok(values.clone())
    } else {
        Err("scenario matrix values must be scalar strings, booleans, or integers".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> Scenario {
        Scenario::new(
            Provider::Github,
            ".github/workflows/ci.yml",
            "build",
            "push",
            RunnerPlatform::LinuxX86_64,
        )
        .unwrap()
    }

    #[test]
    fn validation_checks_binding_and_matrix_names_independently() {
        let mut invalid_input = scenario();
        invalid_input
            .inputs
            .insert("9input".to_owned(), "value".to_owned());
        assert_eq!(
            invalid_input.validate().unwrap_err(),
            "scenario input, matrix, and variable names must be portable"
        );

        let mut invalid_matrix = scenario();
        invalid_matrix
            .matrix
            .insert("9matrix".to_owned(), JsonValue::Boolean(true));
        assert_eq!(
            invalid_matrix.validate().unwrap_err(),
            "scenario input, matrix, and variable names must be portable"
        );
    }
}
