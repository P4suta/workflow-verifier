use crate::domain::{Program, Provider};
use crate::foundation::{
    JsonValue, PublicPath, content_digest, normalize_slashes, portable_path_key,
    valid_content_digest,
};
use crate::product::policy::{
    PolicyRule, PolicyRuleKind, PolicySelector, policy_predicate, rule_json,
};
use crate::verifier::{Diagnostic, Persona, Severity};
use std::collections::{BTreeMap, BTreeSet};
use toml::Value as TomlValue;

type TomlTable = toml::map::Map<String, TomlValue>;

// The serialized limits are owned by schema/config-v2.schema.json and
// schema/runner-v2.schema.json. Defaults below are the built-in v0.1 analysis
// profile; validation floors and portable sandbox values are schema constants.
pub(crate) const CONFIG_V2_SCHEMA_VERSION: u64 = 2;
pub(crate) const ANALYSIS_MIN_FILE_BYTES: u64 = 16_777_216;
pub(crate) const ANALYSIS_MIN_ENTRIES: u64 = 100_000;
pub(crate) const ANALYSIS_MIN_SNAPSHOT_BYTES: u64 = 4_294_967_296;
pub(crate) const ANALYSIS_DEFAULT_YAML_DEPTH: u64 = 256;
pub(crate) const ANALYSIS_DEFAULT_YAML_ALIASES: u64 = 10_000;
pub(crate) const ANALYSIS_DEFAULT_EXPANSION_DEPTH: u64 = 64;
pub(crate) const ANALYSIS_DEFAULT_GRAPH_NODES: u64 = 1_000_000;
pub(crate) const ANALYSIS_DEFAULT_BDD_NODES: u64 = 2_000_000;
pub(crate) const ANALYSIS_DEFAULT_RESOLVER_BYTES: u64 = 16_777_216;
pub(crate) const ANALYSIS_DEFAULT_REPORT_BYTES: u64 = 268_435_456;
pub(crate) const SANDBOX_WALL_TIME_SECONDS: u64 = 900;
pub(crate) const SANDBOX_CPU_CORES: u64 = 1;
pub(crate) const SANDBOX_MEMORY_BYTES: u64 = 2_147_483_648;
pub(crate) const SANDBOX_PROCESSES: u64 = 128;
pub(crate) const SANDBOX_OUTPUT_BYTES: u64 = 16_777_216;
pub(crate) const SANDBOX_SCRATCH_BYTES: u64 = 4_294_967_296;
pub(crate) const SANDBOX_SCRATCH_ENTRIES: u64 = 100_000;
/// Text suffix for IANA's registered default HTTPS port.
pub(crate) const HTTPS_DEFAULT_PORT_SUFFIX: &str = ":443";

// ISO 8601 calendar-date layout and proleptic Gregorian calendar rules.
const DATE_TEXT_LENGTH: usize = "YYYY-MM-DD".len();
const DATE_YEAR_END: usize = "YYYY".len();
const DATE_MONTH_START: usize = "YYYY-".len();
const DATE_MONTH_END: usize = "YYYY-MM".len();
const DATE_DAY_START: usize = "YYYY-MM-".len();
const GREGORIAN_EPOCH_YEAR: u32 = 1970;
const GREGORIAN_LEAP_CYCLE_YEARS: u32 = 400;
const GREGORIAN_LEAP_INTERVAL_YEARS: u32 = 4;
const GREGORIAN_CENTURY_YEARS: u32 = 100;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConfigTrust {
    BuiltIn,
    #[default]
    TrustedPolicy,
    Repository,
}

impl ConfigTrust {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::TrustedPolicy => "trusted-policy",
            Self::Repository => "repository",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigProvenance {
    pub origin: String,
    pub trust: ConfigTrust,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Suppression {
    pub rule: String,
    pub path: String,
    pub reason: String,
    pub owner: String,
    pub expiry: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverOrigin {
    pub origin: String,
    pub path_prefixes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverConfig {
    pub require_immutable: bool,
    pub allowed_origins: Vec<ResolverOrigin>,
    pub allowed_sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisBudget {
    pub max_file_bytes: u64,
    pub max_entries: u64,
    pub max_snapshot_bytes: u64,
    pub max_yaml_depth: u64,
    pub max_yaml_aliases: u64,
    pub max_expansion_depth: u64,
    pub max_graph_nodes: u64,
    pub max_bdd_nodes: u64,
    pub max_resolver_bytes: u64,
    pub max_report_bytes: u64,
}

impl Default for AnalysisBudget {
    fn default() -> Self {
        Self {
            max_file_bytes: ANALYSIS_MIN_FILE_BYTES,
            max_entries: ANALYSIS_MIN_ENTRIES,
            max_snapshot_bytes: ANALYSIS_MIN_SNAPSHOT_BYTES,
            max_yaml_depth: ANALYSIS_DEFAULT_YAML_DEPTH,
            max_yaml_aliases: ANALYSIS_DEFAULT_YAML_ALIASES,
            max_expansion_depth: ANALYSIS_DEFAULT_EXPANSION_DEPTH,
            max_graph_nodes: ANALYSIS_DEFAULT_GRAPH_NODES,
            max_bdd_nodes: ANALYSIS_DEFAULT_BDD_NODES,
            max_resolver_bytes: ANALYSIS_DEFAULT_RESOLVER_BYTES,
            max_report_bytes: ANALYSIS_DEFAULT_REPORT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxConfig {
    pub backend: String,
    pub capsule_digest: String,
    pub network: String,
    pub wall_time_seconds: u64,
    pub cpu_cores: u64,
    pub memory_bytes: u64,
    pub processes: u64,
    pub output_bytes: u64,
    pub scratch_bytes: u64,
    pub scratch_entries: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: "oci:docker".to_owned(),
            capsule_digest: "sha256:unresolved".to_owned(),
            network: "deny".to_owned(),
            wall_time_seconds: SANDBOX_WALL_TIME_SECONDS,
            cpu_cores: SANDBOX_CPU_CORES,
            memory_bytes: SANDBOX_MEMORY_BYTES,
            processes: SANDBOX_PROCESSES,
            output_bytes: SANDBOX_OUTPUT_BYTES,
            scratch_bytes: SANDBOX_SCRATCH_BYTES,
            scratch_entries: SANDBOX_SCRATCH_ENTRIES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistEntry {
    pub kind: String,
    pub value: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub version: u64,
    pub persona: Persona,
    pub frontends: Vec<Provider>,
    pub offline: bool,
    pub source_exclusions: Vec<String>,
    pub resolver: ResolverConfig,
    pub analysis: AnalysisBudget,
    pub sandbox: SandboxConfig,
    pub allowlist: Vec<AllowlistEntry>,
    pub rules: Vec<PolicyRule>,
    pub suppressions: Vec<Suppression>,
    pub provenance: ConfigProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigParseOptions {
    pub origin: String,
    pub trust: ConfigTrust,
    pub today: Option<String>,
}

impl Default for ConfigParseOptions {
    fn default() -> Self {
        Self {
            origin: "explicit".to_owned(),
            trust: ConfigTrust::TrustedPolicy,
            today: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_V2_SCHEMA_VERSION,
            persona: Persona::Gate,
            frontends: all_providers(),
            offline: true,
            source_exclusions: Vec::new(),
            resolver: ResolverConfig {
                require_immutable: true,
                allowed_origins: Vec::new(),
                allowed_sources: Vec::new(),
            },
            analysis: AnalysisBudget::default(),
            sandbox: SandboxConfig::default(),
            allowlist: Vec::new(),
            rules: Vec::new(),
            suppressions: Vec::new(),
            provenance: ConfigProvenance {
                origin: "built-in".to_owned(),
                trust: ConfigTrust::BuiltIn,
                digest: content_digest("config-v2:built-in"),
            },
        }
    }
}

impl Config {
    /// Parse config-v2 TOML under an explicit trust classification.
    ///
    /// # Errors
    /// Returns all known schema, type, trust, origin, and budget violations.
    pub fn parse(source: &str, options: ConfigParseOptions) -> Result<Self, Vec<String>> {
        let ConfigParseOptions {
            origin,
            trust,
            today,
        } = options;
        let document = source
            .parse::<toml::Table>()
            .map_err(|error| vec![format!("config-v2 TOML: {error}")])?;
        let root = &document;
        exact(
            root,
            &[
                "version",
                "persona",
                "frontends",
                "offline",
                "source_exclusions",
                "analysis",
                "resolver",
                "sandbox",
                "allowlist",
                "rules",
                "suppressions",
            ],
            "config-v2",
        )
        .map_err(|error| vec![error])?;
        let version = required_integer(root, "version", "configuration")?;
        if version != CONFIG_V2_SCHEMA_VERSION {
            return Err(vec!["configuration version must be 2".to_owned()]);
        }
        let persona = match optional_string(root, "persona")?.unwrap_or("gate") {
            "gate" => Persona::Gate,
            "audit" => Persona::Audit,
            "paranoid" => Persona::Paranoid,
            _ => return Err(vec!["persona must be gate, audit, or paranoid".to_owned()]),
        };
        let frontend_names = optional_strings(root, "frontends")?
            .unwrap_or_else(|| vec!["github", "gitlab", "azure", "circleci"]);
        let frontends = frontend_names
            .iter()
            .map(|name| provider(name).ok_or_else(|| vec![format!("unknown frontend: {name}")]))
            .collect::<Result<Vec<_>, _>>()?;
        if frontends.iter().collect::<BTreeSet<_>>().len() != frontends.len() {
            return Err(vec!["frontends must be unique".to_owned()]);
        }
        let offline = optional_bool(root, "offline")?.unwrap_or(true);
        if !offline {
            return Err(vec![
                "offline must remain true; network requires a per-command grant".to_owned(),
            ]);
        }
        let source_exclusions = parse_exclusions(root)?;
        let analysis = root
            .get("analysis")
            .map_or_else(|| Ok(AnalysisBudget::default()), parse_analysis)?;
        validate_analysis(&analysis)?;
        let resolver = root
            .get("resolver")
            .map_or_else(|| Ok(default_resolver()), parse_resolver)?;
        let sandbox = root
            .get("sandbox")
            .map_or_else(|| Ok(SandboxConfig::default()), parse_sandbox)?;
        validate_sandbox(&sandbox)?;
        let allowlist = parse_table_array(root, "allowlist", parse_allowlist)?;
        let rules = parse_table_array(root, "rules", parse_rule)?;
        let suppressions = parse_table_array(root, "suppressions", |table| {
            parse_suppression(table, today.as_deref())
        })?;
        let config = Self {
            version,
            persona,
            frontends,
            offline,
            source_exclusions,
            resolver,
            analysis,
            sandbox,
            allowlist,
            rules,
            suppressions,
            provenance: ConfigProvenance {
                origin: normalize_slashes(&origin),
                trust,
                digest: content_digest(source),
            },
        };
        if trust == ConfigTrust::Repository {
            validate_repository(&config)?;
        }
        Ok(config)
    }

    #[must_use]
    pub fn suppressed(&self, diagnostic: &Diagnostic, program: &Program) -> bool {
        let path = program
            .source_path_for(diagnostic.span.source)
            .map_or("<unknown>".to_owned(), normalize_slashes);
        self.suppressions.iter().any(|suppression| {
            suppression.rule == diagnostic.rule_id
                && (suppression.path == "**" || suppression.path == path)
        })
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "allowlist".to_owned(),
                JsonValue::Array(self.allowlist.iter().map(allowlist_json).collect()),
            ),
            ("analysis".to_owned(), analysis_json(self.analysis)),
            (
                "frontends".to_owned(),
                JsonValue::Array(
                    self.frontends
                        .iter()
                        .map(|provider| JsonValue::String(provider.name().to_owned()))
                        .collect(),
                ),
            ),
            ("offline".to_owned(), JsonValue::Boolean(self.offline)),
            (
                "persona".to_owned(),
                JsonValue::String(self.persona.name().to_owned()),
            ),
            (
                "provenance".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "digest".to_owned(),
                        JsonValue::String(self.provenance.digest.clone()),
                    ),
                    (
                        "origin".to_owned(),
                        JsonValue::String(self.provenance.origin.clone()),
                    ),
                    (
                        "trust".to_owned(),
                        JsonValue::String(self.provenance.trust.name().to_owned()),
                    ),
                ])),
            ),
            (
                "resolver".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "allowed_origins".to_owned(),
                        JsonValue::Array(
                            self.resolver
                                .allowed_origins
                                .iter()
                                .map(resolver_origin_json)
                                .collect(),
                        ),
                    ),
                    (
                        "require_immutable".to_owned(),
                        JsonValue::Boolean(self.resolver.require_immutable),
                    ),
                ])),
            ),
            (
                "rules".to_owned(),
                JsonValue::Array(self.rules.iter().map(rule_json).collect()),
            ),
            ("sandbox".to_owned(), sandbox_json(&self.sandbox)),
            (
                "source_exclusions".to_owned(),
                JsonValue::Array(
                    self.source_exclusions
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            (
                "suppressions".to_owned(),
                JsonValue::Array(self.suppressions.iter().map(suppression_json).collect()),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::try_from(self.version).unwrap_or(i64::MAX)),
            ),
        ]))
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }
}

fn exact(table: &TomlTable, allowed: &[&str], context: &str) -> Result<(), String> {
    if let Some(name) = table.keys().find(|name| !allowed.contains(&name.as_str())) {
        Err(format!("{context} has unknown key {name}"))
    } else {
        Ok(())
    }
}

fn required_integer(table: &TomlTable, name: &str, context: &str) -> Result<u64, Vec<String>> {
    let value = table
        .get(name)
        .and_then(TomlValue::as_integer)
        .ok_or_else(|| vec![format!("{context} must declare integer {name}")])?;
    u64::try_from(value).map_err(|_| vec![format!("{context}.{name} cannot be negative")])
}

fn optional_integer(table: &TomlTable, name: &str) -> Result<Option<u64>, Vec<String>> {
    table
        .get(name)
        .map(|value| {
            value
                .as_integer()
                .ok_or_else(|| vec![format!("{name} must be an integer")])
                .and_then(|value| {
                    u64::try_from(value).map_err(|_| vec![format!("{name} cannot be negative")])
                })
        })
        .transpose()
}

fn optional_string<'a>(table: &'a TomlTable, name: &str) -> Result<Option<&'a str>, Vec<String>> {
    table
        .get(name)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| vec![format!("{name} must be a string")])
        })
        .transpose()
}

fn optional_bool(table: &TomlTable, name: &str) -> Result<Option<bool>, Vec<String>> {
    table
        .get(name)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| vec![format!("{name} must be boolean")])
        })
        .transpose()
}

fn optional_strings<'a>(
    table: &'a TomlTable,
    name: &str,
) -> Result<Option<Vec<&'a str>>, Vec<String>> {
    table
        .get(name)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| vec![format!("{name} must be an array")])?
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or_else(|| vec![format!("{name} must contain strings")])
                })
                .collect()
        })
        .transpose()
}

fn parse_exclusions(root: &TomlTable) -> Result<Vec<String>, Vec<String>> {
    let values = optional_strings(root, "source_exclusions")?.unwrap_or_default();
    let mut paths = Vec::new();
    let mut portable = BTreeSet::new();
    for value in values {
        if value.contains('\\')
            || value.contains(':')
            || PublicPath::new(value.to_owned()).is_err()
            || matches!(value, ".workflow-verifier.toml" | "workflow-verifier.lock")
        {
            return Err(vec![format!(
                "source_exclusions entries must be portable relative path prefixes: {value}"
            )]);
        }
        if !portable.insert(portable_path_key(value)) {
            return Err(vec![
                "source_exclusions must be unique under portable case folding".to_owned(),
            ]);
        }
        paths.push(value.to_owned());
    }
    Ok(paths)
}

fn parse_analysis(value: &TomlValue) -> Result<AnalysisBudget, Vec<String>> {
    let table = value
        .as_table()
        .ok_or_else(|| vec!["analysis must be a table".to_owned()])?;
    exact(
        table,
        &[
            "max_file_bytes",
            "max_entries",
            "max_snapshot_bytes",
            "max_yaml_depth",
            "max_yaml_aliases",
            "max_expansion_depth",
            "max_graph_nodes",
            "max_bdd_nodes",
            "max_resolver_bytes",
            "max_report_bytes",
        ],
        "analysis",
    )
    .map_err(|error| vec![error])?;
    let default = AnalysisBudget::default();
    Ok(AnalysisBudget {
        max_file_bytes: optional_integer(table, "max_file_bytes")?
            .unwrap_or(default.max_file_bytes),
        max_entries: optional_integer(table, "max_entries")?.unwrap_or(default.max_entries),
        max_snapshot_bytes: optional_integer(table, "max_snapshot_bytes")?
            .unwrap_or(default.max_snapshot_bytes),
        max_yaml_depth: optional_integer(table, "max_yaml_depth")?
            .unwrap_or(default.max_yaml_depth),
        max_yaml_aliases: optional_integer(table, "max_yaml_aliases")?
            .unwrap_or(default.max_yaml_aliases),
        max_expansion_depth: optional_integer(table, "max_expansion_depth")?
            .unwrap_or(default.max_expansion_depth),
        max_graph_nodes: optional_integer(table, "max_graph_nodes")?
            .unwrap_or(default.max_graph_nodes),
        max_bdd_nodes: optional_integer(table, "max_bdd_nodes")?.unwrap_or(default.max_bdd_nodes),
        max_resolver_bytes: optional_integer(table, "max_resolver_bytes")?
            .unwrap_or(default.max_resolver_bytes),
        max_report_bytes: optional_integer(table, "max_report_bytes")?
            .unwrap_or(default.max_report_bytes),
    })
}

fn validate_analysis(value: &AnalysisBudget) -> Result<(), Vec<String>> {
    if value.max_file_bytes < ANALYSIS_MIN_FILE_BYTES
        || value.max_entries < ANALYSIS_MIN_ENTRIES
        || value.max_snapshot_bytes < ANALYSIS_MIN_SNAPSHOT_BYTES
    {
        return Err(vec![
            "analysis snapshot budgets must meet the published 16 MiB/file, 100000-entry, 4 GiB floor"
                .to_owned(),
        ]);
    }
    if [
        value.max_yaml_depth,
        value.max_yaml_aliases,
        value.max_expansion_depth,
        value.max_graph_nodes,
        value.max_bdd_nodes,
        value.max_resolver_bytes,
        value.max_report_bytes,
    ]
    .contains(&0)
    {
        return Err(vec!["analysis budgets must be positive".to_owned()]);
    }
    Ok(())
}

fn default_resolver() -> ResolverConfig {
    ResolverConfig {
        require_immutable: true,
        allowed_origins: Vec::new(),
        allowed_sources: Vec::new(),
    }
}

fn parse_resolver(value: &TomlValue) -> Result<ResolverConfig, Vec<String>> {
    let table = value
        .as_table()
        .ok_or_else(|| vec!["resolver must be a table".to_owned()])?;
    exact(table, &["require_immutable", "allowed_origins"], "resolver")
        .map_err(|error| vec![error])?;
    let require_immutable = optional_bool(table, "require_immutable")?.unwrap_or(true);
    if !require_immutable {
        return Err(vec![
            "resolver.require_immutable must remain true".to_owned(),
        ]);
    }
    let allowed_origins = table
        .get("allowed_origins")
        .map(|origins| {
            origins
                .as_array()
                .ok_or_else(|| vec!["resolver.allowed_origins must be an array".to_owned()])?
                .iter()
                .map(parse_origin)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut allowed_sources = BTreeSet::new();
    for origin in &allowed_origins {
        if origin.path_prefixes.is_empty() {
            allowed_sources.insert(format!("{}/", origin.origin));
        } else {
            for prefix in &origin.path_prefixes {
                allowed_sources.insert(format!("{}{}", origin.origin, prefix));
            }
        }
    }
    Ok(ResolverConfig {
        require_immutable,
        allowed_origins,
        allowed_sources: allowed_sources.into_iter().collect(),
    })
}

fn parse_origin(value: &TomlValue) -> Result<ResolverOrigin, Vec<String>> {
    let table = value
        .as_table()
        .ok_or_else(|| vec!["resolver.allowed_origins[] must be a table".to_owned()])?;
    exact(
        table,
        &["origin", "path_prefixes"],
        "resolver.allowed_origins[]",
    )
    .map_err(|error| vec![error])?;
    let raw = optional_string(table, "origin")?
        .ok_or_else(|| vec!["resolver origin is required".to_owned()])?;
    let origin = normalize_origin(raw)?;
    let mut path_prefixes = optional_strings(table, "path_prefixes")?
        .unwrap_or_default()
        .into_iter()
        .map(normalize_prefix)
        .collect::<Result<Vec<_>, _>>()?;
    path_prefixes.sort();
    path_prefixes.dedup();
    Ok(ResolverOrigin {
        origin,
        path_prefixes,
    })
}

fn normalize_origin(value: &str) -> Result<String, Vec<String>> {
    let authority = value
        .strip_prefix("https://")
        .ok_or_else(|| vec!["origin must use https".to_owned()])?;
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\', '%'])
        || authority.eq_ignore_ascii_case("localhost")
        || authority.to_ascii_lowercase().ends_with(".localhost")
    {
        return Err(vec![
            "origin contains a forbidden authority component".to_owned(),
        ]);
    }
    let lower = authority.to_ascii_lowercase();
    let host = lower
        .strip_suffix(HTTPS_DEFAULT_PORT_SUFFIX)
        .unwrap_or(&lower);
    if host.contains(':')
        || host.is_empty()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(vec![
            "literal, empty, or non-443 resolver hosts are forbidden".to_owned(),
        ]);
    }
    Ok(format!("https://{host}"))
}

fn normalize_prefix(value: &str) -> Result<String, Vec<String>> {
    if !value.starts_with('/')
        || value.contains(['\\', '?', '#', '%'])
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(vec![
            "path prefix contains an unsafe segment or delimiter".to_owned(),
        ]);
    }
    Ok(if value.ends_with('/') {
        value.to_owned()
    } else {
        format!("{value}/")
    })
}

fn parse_sandbox(value: &TomlValue) -> Result<SandboxConfig, Vec<String>> {
    let table = value
        .as_table()
        .ok_or_else(|| vec!["sandbox must be a table".to_owned()])?;
    exact(
        table,
        &[
            "backend",
            "capsule_digest",
            "network",
            "wall_time_seconds",
            "cpu_cores",
            "memory_bytes",
            "processes",
            "output_bytes",
            "scratch_bytes",
            "scratch_entries",
        ],
        "sandbox",
    )
    .map_err(|error| vec![error])?;
    let default = SandboxConfig::default();
    Ok(SandboxConfig {
        backend: optional_string(table, "backend")?
            .unwrap_or(&default.backend)
            .to_owned(),
        capsule_digest: optional_string(table, "capsule_digest")?
            .unwrap_or(&default.capsule_digest)
            .to_owned(),
        network: optional_string(table, "network")?
            .unwrap_or(&default.network)
            .to_owned(),
        wall_time_seconds: optional_integer(table, "wall_time_seconds")?
            .unwrap_or(default.wall_time_seconds),
        cpu_cores: optional_integer(table, "cpu_cores")?.unwrap_or(default.cpu_cores),
        memory_bytes: optional_integer(table, "memory_bytes")?.unwrap_or(default.memory_bytes),
        processes: optional_integer(table, "processes")?.unwrap_or(default.processes),
        output_bytes: optional_integer(table, "output_bytes")?.unwrap_or(default.output_bytes),
        scratch_bytes: optional_integer(table, "scratch_bytes")?.unwrap_or(default.scratch_bytes),
        scratch_entries: optional_integer(table, "scratch_entries")?
            .unwrap_or(default.scratch_entries),
    })
}

fn validate_sandbox(value: &SandboxConfig) -> Result<(), Vec<String>> {
    let backend = matches!(
        value.backend.as_str(),
        "linux-native" | "windows-native" | "macos-vm"
    ) || value.backend.strip_prefix("oci:").is_some_and(|engine| {
        !engine.is_empty()
            && engine
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    });
    if !backend {
        return Err(vec![
            "sandbox.backend is not a supported typed backend".to_owned(),
        ]);
    }
    if value.capsule_digest != "sha256:unresolved" && !valid_content_digest(&value.capsule_digest) {
        return Err(vec!["sandbox.capsule_digest must be sha256".to_owned()]);
    }
    if value.network != "deny" {
        return Err(vec![
            "sandbox.network must be deny; egress is a scenario grant".to_owned(),
        ]);
    }
    let default = SandboxConfig::default();
    if value.wall_time_seconds != default.wall_time_seconds
        || value.cpu_cores != default.cpu_cores
        || value.memory_bytes != default.memory_bytes
        || value.processes != default.processes
        || value.output_bytes != default.output_bytes
        || value.scratch_bytes != default.scratch_bytes
        || value.scratch_entries != default.scratch_entries
    {
        return Err(vec![
            "sandbox portable limits are fixed by runner-v2".to_owned(),
        ]);
    }
    Ok(())
}

fn parse_table_array<T>(
    root: &TomlTable,
    name: &str,
    parse: impl Fn(&TomlTable) -> Result<T, Vec<String>>,
) -> Result<Vec<T>, Vec<String>> {
    root.get(name)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| vec![format!("{name} must be a table array")])?
                .iter()
                .map(|item| {
                    item.as_table()
                        .ok_or_else(|| vec![format!("{name}[] must be a table")])
                        .and_then(&parse)
                })
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn parse_allowlist(table: &TomlTable) -> Result<AllowlistEntry, Vec<String>> {
    exact(table, &["kind", "value", "reason"], "allowlist[]").map_err(|error| vec![error])?;
    let kind = required_string(table, "kind", "allowlist[]")?;
    let value = required_string(table, "value", "allowlist[]")?;
    let reason = required_string(table, "reason", "allowlist[]")?;
    if !matches!(kind.as_str(), "dependency" | "network_host" | "source") {
        return Err(vec![format!("unknown allowlist kind: {kind}")]);
    }
    if value.trim().is_empty() || reason.trim().is_empty() {
        return Err(vec![
            "allowlist value and reason must not be empty".to_owned(),
        ]);
    }
    Ok(AllowlistEntry {
        kind,
        value,
        reason,
    })
}

fn parse_rule(table: &TomlTable) -> Result<PolicyRule, Vec<String>> {
    exact(
        table,
        &["id", "kind", "limit", "message", "severity", "selector"],
        "rules[]",
    )
    .map_err(|error| vec![error])?;
    let id = required_string(table, "id", "rules[]")?;
    if id.trim().is_empty() {
        return Err(vec!["rules[].id must not be empty".to_owned()]);
    }
    let kind = match required_string(table, "kind", "rules[]")?
        .to_ascii_lowercase()
        .as_str()
    {
        "forbid" => PolicyRuleKind::Forbid,
        "require" => PolicyRuleKind::Require,
        "forbid_path" => PolicyRuleKind::ForbidPath,
        "limit" => PolicyRuleKind::Limit(
            optional_integer(table, "limit")?
                .ok_or_else(|| vec![format!("{id}: limit rule requires limit")])?
                .try_into()
                .map_err(|_| vec![format!("{id}: limit is out of range")])?,
        ),
        _ => return Err(vec![format!("{id}: unknown rule kind")]),
    };
    let severity = match optional_string(table, "severity")?.unwrap_or("error") {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "note" => Severity::Note,
        _ => return Err(vec![format!("{id}: unknown severity")]),
    };
    let selector = table.get("selector").map_or_else(
        || Ok(PolicySelector::All(Vec::new())),
        |value| parse_selector(&id, value),
    )?;
    Ok(PolicyRule {
        id: id.clone(),
        kind,
        selector,
        message: optional_string(table, "message")?
            .map_or_else(|| format!("policy {id} failed"), str::to_owned),
        severity,
    })
}

fn parse_selector(id: &str, value: &TomlValue) -> Result<PolicySelector, Vec<String>> {
    let table = value
        .as_table()
        .ok_or_else(|| vec![format!("{id}: selector must be a table")])?;
    let mode = optional_string(table, "mode")?.unwrap_or("all");
    let predicates = table
        .iter()
        .filter(|(name, _)| name.as_str() != "mode")
        .map(|(name, value)| {
            let value = value
                .as_str()
                .ok_or_else(|| vec![format!("{id}: selector.{name} must be a string")])?;
            policy_predicate(name, value).map_err(|error| vec![format!("{id}: {error}")])
        })
        .collect::<Result<Vec<_>, _>>()?;
    match mode {
        "all" => Ok(PolicySelector::All(predicates)),
        "any" => Ok(PolicySelector::Any(predicates)),
        "none" => Ok(PolicySelector::NoneOf(predicates)),
        _ => Err(vec![format!(
            "{id}: selector.mode must be all, any, or none"
        )]),
    }
}

fn parse_suppression(table: &TomlTable, today: Option<&str>) -> Result<Suppression, Vec<String>> {
    exact(
        table,
        &["rule", "path", "reason", "owner", "expiry"],
        "suppressions[]",
    )
    .map_err(|error| vec![error])?;
    let suppression = Suppression {
        rule: required_string(table, "rule", "suppressions[]")?,
        path: normalize_slashes(&required_string(table, "path", "suppressions[]")?),
        reason: required_string(table, "reason", "suppressions[]")?,
        owner: required_string(table, "owner", "suppressions[]")?,
        expiry: required_string(table, "expiry", "suppressions[]")?,
    };
    if [
        suppression.rule.as_str(),
        suppression.path.as_str(),
        suppression.reason.as_str(),
        suppression.owner.as_str(),
        suppression.expiry.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(vec!["suppression fields must not be empty".to_owned()]);
    }
    if !portable_identifier(&suppression.owner) || !valid_date(&suppression.expiry) {
        return Err(vec!["suppression owner or expiry is invalid".to_owned()]);
    }
    if today.is_some_and(|today| valid_date(today) && suppression.expiry.as_str() < today) {
        return Err(vec![format!(
            "suppression {} expired on {}",
            suppression.rule, suppression.expiry
        )]);
    }
    Ok(suppression)
}

fn required_string(table: &TomlTable, name: &str, context: &str) -> Result<String, Vec<String>> {
    optional_string(table, name)?
        .map(str::to_owned)
        .ok_or_else(|| vec![format!("{context}.{name} is required")])
}

fn validate_repository(config: &Config) -> Result<(), Vec<String>> {
    let default = Config::default();
    if config.persona == Persona::Audit {
        return Err(vec![
            "repository config cannot weaken persona to audit".to_owned(),
        ]);
    }
    if config.frontends != default.frontends
        || !config.resolver.allowed_origins.is_empty()
        || !config.suppressions.is_empty()
        || !config.allowlist.is_empty()
        || !config.source_exclusions.is_empty()
        || config.sandbox != default.sandbox
    {
        return Err(vec![
            "repository config cannot disable evidence or grant policy/network/sandbox privileges"
                .to_owned(),
        ]);
    }
    Ok(())
}

fn all_providers() -> Vec<Provider> {
    vec![
        Provider::Github,
        Provider::Gitlab,
        Provider::Azure,
        Provider::Circleci,
    ]
}

fn provider(value: &str) -> Option<Provider> {
    Some(match value {
        "github" => Provider::Github,
        "gitlab" => Provider::Gitlab,
        "azure" => Provider::Azure,
        "circleci" => Provider::Circleci,
        _ => return None,
    })
}

fn portable_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_date(value: &str) -> bool {
    if value.len() != DATE_TEXT_LENGTH
        || value.as_bytes().get(DATE_YEAR_END) != Some(&b'-')
        || value.as_bytes().get(DATE_MONTH_END) != Some(&b'-')
    {
        return false;
    }
    let year = value[..DATE_YEAR_END].parse::<u32>().ok();
    let month = value[DATE_MONTH_START..DATE_MONTH_END].parse::<u32>().ok();
    let day = value[DATE_DAY_START..].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % GREGORIAN_LEAP_CYCLE_YEARS == 0
        || (year % GREGORIAN_LEAP_INTERVAL_YEARS == 0 && year % GREGORIAN_CENTURY_YEARS != 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year >= GREGORIAN_EPOCH_YEAR && day >= 1 && day <= days
}

fn resolver_origin_json(value: &ResolverOrigin) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("origin".to_owned(), JsonValue::String(value.origin.clone())),
        (
            "path_prefixes".to_owned(),
            JsonValue::Array(
                value
                    .path_prefixes
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
    ]))
}

fn analysis_json(value: AnalysisBudget) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("max_bdd_nodes".to_owned(), integer(value.max_bdd_nodes)),
        ("max_entries".to_owned(), integer(value.max_entries)),
        (
            "max_expansion_depth".to_owned(),
            integer(value.max_expansion_depth),
        ),
        ("max_file_bytes".to_owned(), integer(value.max_file_bytes)),
        ("max_graph_nodes".to_owned(), integer(value.max_graph_nodes)),
        (
            "max_report_bytes".to_owned(),
            integer(value.max_report_bytes),
        ),
        (
            "max_resolver_bytes".to_owned(),
            integer(value.max_resolver_bytes),
        ),
        (
            "max_snapshot_bytes".to_owned(),
            integer(value.max_snapshot_bytes),
        ),
        (
            "max_yaml_aliases".to_owned(),
            integer(value.max_yaml_aliases),
        ),
        ("max_yaml_depth".to_owned(), integer(value.max_yaml_depth)),
    ]))
}

fn sandbox_json(value: &SandboxConfig) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "backend".to_owned(),
            JsonValue::String(value.backend.clone()),
        ),
        (
            "capsule_digest".to_owned(),
            JsonValue::String(value.capsule_digest.clone()),
        ),
        ("cpu_cores".to_owned(), integer(value.cpu_cores)),
        ("memory_bytes".to_owned(), integer(value.memory_bytes)),
        (
            "network".to_owned(),
            JsonValue::String(value.network.clone()),
        ),
        ("output_bytes".to_owned(), integer(value.output_bytes)),
        ("processes".to_owned(), integer(value.processes)),
        ("scratch_bytes".to_owned(), integer(value.scratch_bytes)),
        ("scratch_entries".to_owned(), integer(value.scratch_entries)),
        (
            "wall_time_seconds".to_owned(),
            integer(value.wall_time_seconds),
        ),
    ]))
}

fn allowlist_json(value: &AllowlistEntry) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("kind".to_owned(), JsonValue::String(value.kind.clone())),
        ("reason".to_owned(), JsonValue::String(value.reason.clone())),
        ("value".to_owned(), JsonValue::String(value.value.clone())),
    ]))
}

fn suppression_json(value: &Suppression) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("expiry".to_owned(), JsonValue::String(value.expiry.clone())),
        ("owner".to_owned(), JsonValue::String(value.owner.clone())),
        ("path".to_owned(), JsonValue::String(value.path.clone())),
        ("reason".to_owned(), JsonValue::String(value.reason.clone())),
        ("rule".to_owned(), JsonValue::String(value.rule.clone())),
    ]))
}

fn integer(value: u64) -> JsonValue {
    JsonValue::Integer(i64::try_from(value).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(source: &str) -> TomlTable {
        source.parse::<TomlTable>().expect("valid test TOML")
    }

    #[test]
    fn calendar_dates_and_portable_owners_cover_gregorian_boundaries() {
        for value in [
            "1970-01-01",
            "2000-02-29",
            "2024-02-29",
            "2025-02-28",
            "2025-04-30",
            "2025-12-31",
        ] {
            assert!(valid_date(value), "valid date {value:?}");
        }
        for value in [
            "1969-12-31",
            "1900-02-29",
            "2023-02-29",
            "2100-02-29",
            "2025-00-01",
            "2025-01-00",
            "2025-04-31",
            "2025-13-01",
            "2025/01/01",
            "2025/01-01",
            "2025-01/01",
            "2025-01-001",
            "2025-1-01",
            "not-a-date",
        ] {
            assert!(!valid_date(value), "invalid date {value:?}");
        }

        for value in ["platform", "platform_team", "Team-1", "team.owner"] {
            assert!(portable_identifier(value), "valid owner {value:?}");
        }
        for value in ["", "9team", "team/name", "team owner", "team@owner"] {
            assert!(!portable_identifier(value), "invalid owner {value:?}");
        }
    }

    #[test]
    fn trusted_origin_and_prefix_normalization_rejects_each_unsafe_component() {
        assert_eq!(
            normalize_origin("https://Git.Example.test:443"),
            Ok("https://git.example.test".to_owned())
        );
        assert_eq!(
            normalize_origin("https://git.example.test"),
            Ok("https://git.example.test".to_owned())
        );
        for value in [
            "http://git.example.test",
            "https://",
            "https://git.example.test/path",
            "https://git.example.test?query",
            "https://git.example.test#fragment",
            "https://user@git.example.test",
            "https://git\\example.test",
            "https://git%2eexample.test",
            "https://localhost",
            "https://service.localhost",
            "https://git.example.test:444",
            "https://127.0.0.1",
        ] {
            assert!(normalize_origin(value).is_err(), "unsafe origin {value:?}");
        }

        assert_eq!(normalize_prefix("/"), Ok("/".to_owned()));
        assert_eq!(normalize_prefix("/org"), Ok("/org/".to_owned()));
        assert_eq!(
            normalize_prefix("/org/project/"),
            Ok("/org/project/".to_owned())
        );
        for value in [
            "org",
            "/org\\project",
            "/org?query",
            "/org#fragment",
            "/org%2fproject",
            "/org/./project",
            "/org/../project",
        ] {
            assert!(normalize_prefix(value).is_err(), "unsafe prefix {value:?}");
        }
    }

    #[test]
    // Analysis and sandbox limits are two complete schema matrices whose
    // independent field boundaries are clearest when reviewed together.
    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive table verifies every published analysis and sandbox limit"
    )]
    fn analysis_and_sandbox_schema_boundaries_are_independently_enforced() {
        assert_eq!(validate_analysis(&AnalysisBudget::default()), Ok(()));
        for invalid in [
            AnalysisBudget {
                max_file_bytes: ANALYSIS_MIN_FILE_BYTES.saturating_sub(1),
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_entries: ANALYSIS_MIN_ENTRIES.saturating_sub(1),
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_snapshot_bytes: ANALYSIS_MIN_SNAPSHOT_BYTES.saturating_sub(1),
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_yaml_depth: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_yaml_aliases: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_expansion_depth: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_graph_nodes: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_bdd_nodes: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_resolver_bytes: 0,
                ..AnalysisBudget::default()
            },
            AnalysisBudget {
                max_report_bytes: 0,
                ..AnalysisBudget::default()
            },
        ] {
            assert!(validate_analysis(&invalid).is_err(), "{invalid:?}");
        }

        for backend in ["linux-native", "windows-native", "macos-vm", "oci:docker"] {
            let sandbox = SandboxConfig {
                backend: backend.to_owned(),
                ..SandboxConfig::default()
            };
            assert_eq!(validate_sandbox(&sandbox), Ok(()), "{backend:?}");
        }
        let resolved = SandboxConfig {
            capsule_digest: content_digest("capsule"),
            ..SandboxConfig::default()
        };
        assert_eq!(validate_sandbox(&resolved), Ok(()));
        for backend in ["", "oci:", "oci:bad/engine", "native", "OCI:docker"] {
            let sandbox = SandboxConfig {
                backend: backend.to_owned(),
                ..SandboxConfig::default()
            };
            assert!(validate_sandbox(&sandbox).is_err(), "{backend:?}");
        }
        let default = SandboxConfig::default();
        let invalid_limits = [
            SandboxConfig {
                wall_time_seconds: default.wall_time_seconds.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                cpu_cores: default.cpu_cores.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                memory_bytes: default.memory_bytes.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                processes: default.processes.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                output_bytes: default.output_bytes.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                scratch_bytes: default.scratch_bytes.saturating_add(1),
                ..default.clone()
            },
            SandboxConfig {
                scratch_entries: default.scratch_entries.saturating_add(1),
                ..default
            },
        ];
        for invalid in invalid_limits {
            assert!(validate_sandbox(&invalid).is_err(), "{invalid:?}");
        }
        assert!(
            validate_sandbox(&SandboxConfig {
                network: "allow".to_owned(),
                ..SandboxConfig::default()
            })
            .is_err()
        );
        assert!(
            validate_sandbox(&SandboxConfig {
                capsule_digest: "not-a-digest".to_owned(),
                ..SandboxConfig::default()
            })
            .is_err()
        );
    }

    #[test]
    fn every_policy_rule_selector_severity_and_allowlist_variant_parses() {
        for (kind, expected) in [
            ("forbid", PolicyRuleKind::Forbid),
            ("require", PolicyRuleKind::Require),
            ("forbid_path", PolicyRuleKind::ForbidPath),
            ("limit", PolicyRuleKind::Limit(1)),
        ] {
            let limit = if kind == "limit" { "limit = 1" } else { "" };
            let rule = parse_rule(&table(&format!(
                "id = \"RULE\"\nkind = \"{kind}\"\n{limit}\n"
            )))
            .expect("rule kind");
            assert_eq!(rule.kind, expected, "{kind:?}");
        }
        for (severity, expected) in [
            ("critical", Severity::Critical),
            ("error", Severity::Error),
            ("warning", Severity::Warning),
            ("note", Severity::Note),
        ] {
            let rule = parse_rule(&table(&format!(
                "id = \"RULE\"\nkind = \"forbid\"\nseverity = \"{severity}\"\n"
            )))
            .expect("rule severity");
            assert_eq!(rule.severity, expected, "{severity:?}");
        }
        for (mode, expected) in [
            ("all", PolicySelector::All(Vec::new())),
            ("any", PolicySelector::Any(Vec::new())),
            ("none", PolicySelector::NoneOf(Vec::new())),
        ] {
            let selector = parse_selector(
                "RULE",
                &TomlValue::Table(table(&format!("mode = \"{mode}\"\n"))),
            )
            .expect("selector mode");
            assert_eq!(selector, expected, "{mode:?}");
        }
        for kind in ["dependency", "network_host", "source"] {
            let entry = parse_allowlist(&table(&format!(
                "kind = \"{kind}\"\nvalue = \"owned\"\nreason = \"reviewed\"\n"
            )))
            .expect("allowlist kind");
            assert_eq!(entry.kind, kind);
        }
        for source in [
            "kind = \"unknown\"\nvalue = \"owned\"\nreason = \"reviewed\"\n",
            "kind = \"source\"\nvalue = \"\"\nreason = \"reviewed\"\n",
            "kind = \"source\"\nvalue = \"owned\"\nreason = \" \"\n",
        ] {
            assert!(parse_allowlist(&table(source)).is_err());
        }
    }

    #[test]
    fn repository_trust_and_suppression_expiry_each_fail_closed() {
        let mut repository = Config::default();
        assert_eq!(validate_repository(&repository), Ok(()));
        repository.persona = Persona::Audit;
        assert!(validate_repository(&repository).is_err());

        let variants = vec![
            Config {
                frontends: vec![Provider::Github],
                ..Config::default()
            },
            Config {
                resolver: ResolverConfig {
                    allowed_origins: vec![ResolverOrigin {
                        origin: "https://git.example.test".to_owned(),
                        path_prefixes: Vec::new(),
                    }],
                    ..default_resolver()
                },
                ..Config::default()
            },
            Config {
                suppressions: vec![Suppression {
                    rule: "RULE".to_owned(),
                    path: "**".to_owned(),
                    reason: "reviewed".to_owned(),
                    owner: "platform".to_owned(),
                    expiry: "2027-01-01".to_owned(),
                }],
                ..Config::default()
            },
            Config {
                allowlist: vec![AllowlistEntry {
                    kind: "source".to_owned(),
                    value: "owned".to_owned(),
                    reason: "reviewed".to_owned(),
                }],
                ..Config::default()
            },
            Config {
                source_exclusions: vec!["generated".to_owned()],
                ..Config::default()
            },
            Config {
                sandbox: SandboxConfig {
                    backend: "linux-native".to_owned(),
                    ..SandboxConfig::default()
                },
                ..Config::default()
            },
        ];
        for variant in variants {
            assert!(validate_repository(&variant).is_err(), "{variant:?}");
        }

        let suppression = |expiry: &str| {
            table(&format!(
                "rule = \"RULE\"\npath = \"**\"\nreason = \"reviewed\"\nowner = \"platform\"\nexpiry = \"{expiry}\"\n"
            ))
        };
        assert!(parse_suppression(&suppression("2027-01-01"), Some("2026-12-31")).is_ok());
        assert!(parse_suppression(&suppression("2027-01-01"), Some("2027-01-01")).is_ok());
        assert!(parse_suppression(&suppression("2027-01-01"), Some("2027-01-02")).is_err());
        assert!(parse_suppression(&suppression("invalid"), None).is_err());
        let invalid_owner = table(
            "rule = \"RULE\"\npath = \"**\"\nreason = \"reviewed\"\nowner = \"not portable\"\nexpiry = \"2027-01-01\"\n",
        );
        assert!(parse_suppression(&invalid_owner, None).is_err());
    }

    #[test]
    fn primitive_options_exclusions_and_analysis_parsing_preserve_explicit_values() {
        assert_eq!(optional_bool(&table(""), "flag"), Ok(None));
        assert_eq!(
            optional_bool(&table("flag = true\n"), "flag"),
            Ok(Some(true))
        );
        assert_eq!(
            optional_bool(&table("flag = false\n"), "flag"),
            Ok(Some(false))
        );
        assert!(optional_bool(&table("flag = \"false\"\n"), "flag").is_err());

        assert_eq!(
            parse_exclusions(&table("source_exclusions = [\"generated\", \"vendor\"]\n")),
            Ok(vec!["generated".to_owned(), "vendor".to_owned()])
        );
        for value in [
            "windows\\path",
            "drive:path",
            "../escape",
            ".workflow-verifier.toml",
            "workflow-verifier.lock",
        ] {
            let exclusions = TomlTable::from_iter([(
                "source_exclusions".to_owned(),
                TomlValue::Array(vec![TomlValue::String(value.to_owned())]),
            )]);
            assert!(
                parse_exclusions(&exclusions).is_err(),
                "excluded path {value:?}"
            );
        }
        assert!(
            parse_exclusions(&table(
                "source_exclusions = [\"Generated\", \"generated\"]\n"
            ))
            .is_err()
        );

        let defaults = AnalysisBudget::default();
        let custom_yaml_depth = defaults.max_yaml_depth.saturating_add(1);
        let parsed = parse_analysis(&TomlValue::Table(table(&format!(
            "max_yaml_depth = {custom_yaml_depth}\n"
        ))))
        .expect("custom analysis budget");
        assert_eq!(parsed.max_yaml_depth, custom_yaml_depth);
        assert_eq!(parsed.max_file_bytes, defaults.max_file_bytes);
        assert_eq!(parsed.max_entries, defaults.max_entries);
        assert_eq!(parsed.max_snapshot_bytes, defaults.max_snapshot_bytes);
        assert_eq!(parsed.max_yaml_aliases, defaults.max_yaml_aliases);
        assert_eq!(parsed.max_expansion_depth, defaults.max_expansion_depth);
        assert_eq!(parsed.max_graph_nodes, defaults.max_graph_nodes);
        assert_eq!(parsed.max_bdd_nodes, defaults.max_bdd_nodes);
        assert_eq!(parsed.max_resolver_bytes, defaults.max_resolver_bytes);
        assert_eq!(parsed.max_report_bytes, defaults.max_report_bytes);
        assert!(parse_analysis(&TomlValue::String("not a table".to_owned())).is_err());
    }
}
