use crate::policy::{PolicyRule, PolicyRuleKind, PolicySelector, policy_predicate, rule_json};
use std::collections::{BTreeMap, BTreeSet};
use toml::Value as TomlValue;
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::{
    JsonValue, PublicPath, content_digest, normalize_slashes, portable_path_key,
    valid_content_digest,
};
use workflow_verifier_verifier::{Diagnostic, Persona, Severity};

type TomlTable = toml::map::Map<String, TomlValue>;

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
            max_file_bytes: 16 * 1024 * 1024,
            max_entries: 100_000,
            max_snapshot_bytes: 4_294_967_296,
            max_yaml_depth: 256,
            max_yaml_aliases: 10_000,
            max_expansion_depth: 64,
            max_graph_nodes: 1_000_000,
            max_bdd_nodes: 2_000_000,
            max_resolver_bytes: 16 * 1024 * 1024,
            max_report_bytes: 256 * 1024 * 1024,
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
            wall_time_seconds: 900,
            cpu_cores: 1,
            memory_bytes: 2_147_483_648,
            processes: 128,
            output_bytes: 16 * 1024 * 1024,
            scratch_bytes: 4_294_967_296,
            scratch_entries: 100_000,
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
            version: 2,
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
    #[allow(clippy::too_many_lines)]
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
        if version != 2 {
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
    pub fn suppressed(&self, diagnostic: &Diagnostic) -> bool {
        let path = normalize_slashes(&diagnostic.span.file);
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
    if value.max_file_bytes < 16 * 1024 * 1024
        || value.max_entries < 100_000
        || value.max_snapshot_bytes < 4_294_967_296
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
    let host = lower.strip_suffix(":443").unwrap_or(&lower);
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
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return false;
    }
    let year = value[..4].parse::<u32>().ok();
    let month = value[5..7].parse::<u32>().ok();
    let day = value[8..].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year >= 1970 && day >= 1 && day <= days
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
