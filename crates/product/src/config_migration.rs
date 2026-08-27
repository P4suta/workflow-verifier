use crate::config::{
    ANALYSIS_DEFAULT_BDD_NODES, ANALYSIS_DEFAULT_EXPANSION_DEPTH, ANALYSIS_DEFAULT_GRAPH_NODES,
    ANALYSIS_DEFAULT_REPORT_BYTES, ANALYSIS_DEFAULT_RESOLVER_BYTES, ANALYSIS_DEFAULT_YAML_ALIASES,
    ANALYSIS_DEFAULT_YAML_DEPTH, ANALYSIS_MIN_ENTRIES, ANALYSIS_MIN_FILE_BYTES,
    ANALYSIS_MIN_SNAPSHOT_BYTES, CONFIG_V2_SCHEMA_VERSION, HTTPS_DEFAULT_PORT_SUFFIX,
    SANDBOX_CPU_CORES, SANDBOX_MEMORY_BYTES, SANDBOX_OUTPUT_BYTES, SANDBOX_PROCESSES,
    SANDBOX_SCRATCH_BYTES, SANDBOX_SCRATCH_ENTRIES, SANDBOX_WALL_TIME_SECONDS,
};
use crate::{Config, ConfigParseOptions, ConfigTrust};
use toml::Value;

type Table = toml::Table;
const CONFIG_V1_SCHEMA_VERSION: i64 = 1;

/// Migrate a typed config-v1 document to a revalidated config-v2 document.
///
/// # Errors
/// Rejects malformed TOML, non-v1 input, unsafe legacy resolver URLs,
/// suppressions without explicit ownership/expiry, and any result which does
/// not satisfy the current strict config-v2 contract.
pub fn migrate_config_v1(
    source: &str,
    suppression_owner: Option<&str>,
    suppression_expiry: Option<&str>,
    today: Option<&str>,
) -> Result<String, Vec<String>> {
    let mut document = source
        .parse::<Table>()
        .map_err(|error| vec![format!("config-v1 TOML: {error}")])?;
    match document.get("version").and_then(Value::as_integer) {
        Some(CONFIG_V1_SCHEMA_VERSION) => {}
        Some(version) if version == schema_integer(CONFIG_V2_SCHEMA_VERSION) => {
            return Err(vec!["input is already config-v2".to_owned()]);
        }
        _ => {
            return Err(vec![
                "legacy configuration must declare version = 1".to_owned(),
            ]);
        }
    }
    document.insert(
        "version".to_owned(),
        Value::Integer(schema_integer(CONFIG_V2_SCHEMA_VERSION)),
    );
    if let Some(resolver) = document.get_mut("resolver") {
        migrate_resolver(resolver)?;
    }
    if let Some(sandbox) = document.get_mut("sandbox") {
        migrate_sandbox(sandbox)?;
    }
    if let Some(suppressions) = document.get_mut("suppressions") {
        migrate_suppressions(suppressions, suppression_owner, suppression_expiry)?;
    }
    if !document.contains_key("analysis") {
        document.insert("analysis".to_owned(), Value::Table(default_analysis()));
    }
    let output = toml::to_string(&document)
        .map_err(|error| vec![format!("cannot serialize config-v2: {error}")])?;
    let output = format!("{}\n", output.trim_end_matches('\n'));
    Config::parse(
        &output,
        ConfigParseOptions {
            origin: "migration:config-v1".to_owned(),
            trust: ConfigTrust::TrustedPolicy,
            today: today.map(str::to_owned),
        },
    )?;
    Ok(output)
}

fn migrate_resolver(value: &mut Value) -> Result<(), Vec<String>> {
    let fields = value
        .as_table_mut()
        .ok_or_else(|| vec!["resolver: expected a TOML table".to_owned()])?;
    let sources = fields.remove("allowed_sources");
    fields.remove("allowed_origins");
    let mut origins = Vec::new();
    if let Some(sources) = sources {
        let sources = sources.as_array().ok_or_else(|| {
            vec!["resolver.allowed_sources: expected an array of strings".to_owned()]
        })?;
        for source in sources {
            let source = source.as_str().ok_or_else(|| {
                vec!["resolver.allowed_sources: expected an array of strings".to_owned()]
            })?;
            let (origin, prefix) = split_https_url(source).map_err(|error| vec![error])?;
            origins.push(Value::Table(Table::from_iter([
                ("origin".to_owned(), Value::String(origin)),
                (
                    "path_prefixes".to_owned(),
                    Value::Array(vec![Value::String(prefix)]),
                ),
            ])));
        }
    }
    fields.insert("require_immutable".to_owned(), Value::Boolean(true));
    fields.insert("allowed_origins".to_owned(), Value::Array(origins));
    Ok(())
}

fn split_https_url(value: &str) -> Result<(String, String), String> {
    let rest = value
        .strip_prefix("https://")
        .ok_or_else(|| format!("legacy resolver source must be an HTTPS URL: {value}"))?;
    let (authority, raw_path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(authority, path)| {
            (authority, &value[value.len() - path.len() - 1..])
        });
    if authority.is_empty()
        || value.contains(['@', '?', '#', '\\', '%'])
        || raw_path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || authority.eq_ignore_ascii_case("localhost")
        || authority.to_ascii_lowercase().ends_with(".localhost")
    {
        return Err(format!("unsafe legacy resolver source: {value}"));
    }
    let authority = authority.to_ascii_lowercase();
    let authority = authority
        .strip_suffix(HTTPS_DEFAULT_PORT_SUFFIX)
        .unwrap_or(&authority);
    if authority.contains(':')
        || authority
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(format!("unsafe legacy resolver source: {value}"));
    }
    let prefix = if raw_path.ends_with('/') {
        raw_path.to_owned()
    } else {
        format!("{raw_path}/")
    };
    Ok((format!("https://{authority}"), prefix))
}

fn migrate_sandbox(value: &mut Value) -> Result<(), Vec<String>> {
    let fields = value
        .as_table_mut()
        .ok_or_else(|| vec!["sandbox: expected a TOML table".to_owned()])?;
    let capsule = fields
        .remove("capsule_digest")
        .or_else(|| fields.remove("image"))
        .unwrap_or_else(|| Value::String("sha256:unresolved".to_owned()));
    for name in [
        "image",
        "cpu_seconds",
        "memory_mb",
        "wall_time_seconds",
        "cpu_cores",
        "memory_bytes",
        "processes",
        "output_bytes",
        "scratch_bytes",
        "scratch_entries",
    ] {
        fields.remove(name);
    }
    fields.insert("capsule_digest".to_owned(), capsule);
    fields.insert("network".to_owned(), Value::String("deny".to_owned()));
    for (name, value) in [
        ("wall_time_seconds", SANDBOX_WALL_TIME_SECONDS),
        ("cpu_cores", SANDBOX_CPU_CORES),
        ("memory_bytes", SANDBOX_MEMORY_BYTES),
        ("processes", SANDBOX_PROCESSES),
        ("output_bytes", SANDBOX_OUTPUT_BYTES),
        ("scratch_bytes", SANDBOX_SCRATCH_BYTES),
        ("scratch_entries", SANDBOX_SCRATCH_ENTRIES),
    ] {
        fields.insert(name.to_owned(), Value::Integer(schema_integer(value)));
    }
    Ok(())
}

fn migrate_suppressions(
    value: &mut Value,
    owner: Option<&str>,
    expiry: Option<&str>,
) -> Result<(), Vec<String>> {
    let suppressions = value
        .as_array_mut()
        .ok_or_else(|| vec!["suppressions must be an array of tables".to_owned()])?;
    if !suppressions.is_empty() && (owner.is_none() || expiry.is_none()) {
        return Err(vec![
            "legacy suppressions require --suppression-owner and --suppression-expiry".to_owned(),
        ]);
    }
    for suppression in suppressions {
        let fields = suppression
            .as_table_mut()
            .ok_or_else(|| vec!["suppressions[]: expected a TOML table".to_owned()])?;
        if let Some(owner) = owner {
            fields.insert("owner".to_owned(), Value::String(owner.to_owned()));
        }
        if let Some(expiry) = expiry {
            fields.insert("expiry".to_owned(), Value::String(expiry.to_owned()));
        }
    }
    Ok(())
}

fn default_analysis() -> Table {
    Table::from_iter([
        (
            "max_file_bytes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_MIN_FILE_BYTES)),
        ),
        (
            "max_entries".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_MIN_ENTRIES)),
        ),
        (
            "max_snapshot_bytes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_MIN_SNAPSHOT_BYTES)),
        ),
        (
            "max_yaml_depth".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_YAML_DEPTH)),
        ),
        (
            "max_yaml_aliases".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_YAML_ALIASES)),
        ),
        (
            "max_expansion_depth".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_EXPANSION_DEPTH)),
        ),
        (
            "max_graph_nodes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_GRAPH_NODES)),
        ),
        (
            "max_bdd_nodes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_BDD_NODES)),
        ),
        (
            "max_resolver_bytes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_RESOLVER_BYTES)),
        ),
        (
            "max_report_bytes".to_owned(),
            Value::Integer(schema_integer(ANALYSIS_DEFAULT_REPORT_BYTES)),
        ),
    ])
}

fn schema_integer(value: u64) -> i64 {
    i64::try_from(value).expect("config-v2 schema limits fit TOML integers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalysisBudget;

    #[test]
    fn migration_version_and_optional_section_boundaries_are_explicit() {
        assert_eq!(
            migrate_config_v1("version = 2\n", None, None, None),
            Err(vec!["input is already config-v2".to_owned()])
        );
        for source in ["", "version = 0\n", "version = \"1\"\n"] {
            assert_eq!(
                migrate_config_v1(source, None, None, None),
                Err(vec![
                    "legacy configuration must declare version = 1".to_owned()
                ])
            );
        }
        assert!(migrate_config_v1("not = [\n", None, None, None).is_err());
        let minimal =
            migrate_config_v1("version = 1\n", None, None, None).expect("minimal config-v1");
        assert!(minimal.contains("version = 2"));
        assert!(minimal.contains("[analysis]"));
        assert!(minimal.ends_with('\n'));

        let custom = r"
version = 1

[analysis]
max_file_bytes = 16777216
max_entries = 100000
max_snapshot_bytes = 4294967296
max_yaml_depth = 257
max_yaml_aliases = 10000
max_expansion_depth = 64
max_graph_nodes = 1000000
max_bdd_nodes = 2000000
max_resolver_bytes = 16777216
max_report_bytes = 268435456
";
        let migrated = migrate_config_v1(custom, None, None, None).expect("custom analysis");
        assert!(migrated.contains("max_yaml_depth = 257"));
    }

    #[test]
    fn legacy_https_source_split_accepts_only_public_origin_shapes() {
        assert_eq!(
            split_https_url("https://CI.Example.test"),
            Ok(("https://ci.example.test".to_owned(), "/".to_owned()))
        );
        assert_eq!(
            split_https_url("https://CI.Example.test:443/group/project"),
            Ok((
                "https://ci.example.test".to_owned(),
                "/group/project/".to_owned(),
            ))
        );
        assert_eq!(
            split_https_url("https://ci.example.test/group/"),
            Ok(("https://ci.example.test".to_owned(), "/group/".to_owned(),))
        );
        for unsafe_source in [
            "http://ci.example.test/path",
            "https:///path",
            "https://user@ci.example.test/path",
            "https://ci.example.test/path?query",
            "https://ci.example.test/path#fragment",
            "https://ci.example.test\\path",
            "https://ci.example.test/%2e%2e/path",
            "https://ci.example.test/./path",
            "https://ci.example.test/../path",
            "https://localhost/path",
            "https://ci.localhost/path",
            "https://ci.example.test:8443/path",
            "https://127.0.0.1/path",
        ] {
            assert!(
                split_https_url(unsafe_source).is_err(),
                "unsafe URL {unsafe_source:?}"
            );
        }
    }

    #[test]
    fn section_migrators_reject_wrong_types_and_require_suppression_metadata() {
        let mut resolver = Value::String("not a table".to_owned());
        assert!(migrate_resolver(&mut resolver).is_err());
        for source in ["allowed_sources = \"url\"", "allowed_sources = [1]"] {
            let mut value = source.parse::<Table>().expect("resolver fixture").into();
            assert!(migrate_resolver(&mut value).is_err());
        }
        let mut resolver = r#"
allowed_sources = ["https://ci.example.test/path"]
allowed_origins = [{ origin = "https://obsolete.example.test" }]
require_immutable = false
"#
        .parse::<Table>()
        .expect("resolver table")
        .into();
        migrate_resolver(&mut resolver).expect("resolver migration");
        let fields = resolver.as_table().expect("migrated resolver table");
        assert_eq!(fields.get("require_immutable"), Some(&Value::Boolean(true)));
        assert_eq!(
            fields
                .get("allowed_origins")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        let mut sandbox = Value::String("not a table".to_owned());
        assert!(migrate_sandbox(&mut sandbox).is_err());
        let mut sandbox = r#"
image = "sha256:image"
capsule_digest = "sha256:capsule"
cpu_seconds = 1
"#
        .parse::<Table>()
        .expect("sandbox table")
        .into();
        migrate_sandbox(&mut sandbox).expect("sandbox migration");
        let fields = sandbox.as_table().expect("migrated sandbox table");
        assert_eq!(
            fields.get("capsule_digest").and_then(Value::as_str),
            Some("sha256:capsule")
        );
        assert!(!fields.contains_key("image"));
        assert!(!fields.contains_key("cpu_seconds"));
        assert_eq!(fields.get("network").and_then(Value::as_str), Some("deny"));

        let mut not_array = Value::String("not an array".to_owned());
        assert!(migrate_suppressions(&mut not_array, None, None).is_err());
        let mut empty = Value::Array(Vec::new());
        assert!(migrate_suppressions(&mut empty, None, None).is_ok());
        let suppression = || Value::Array(vec![Value::Table(Table::new())]);
        assert!(migrate_suppressions(&mut suppression(), None, Some("expiry")).is_err());
        assert!(migrate_suppressions(&mut suppression(), Some("owner"), None).is_err());
        let mut wrong_item = Value::Array(vec![Value::String("not a table".to_owned())]);
        assert!(migrate_suppressions(&mut wrong_item, Some("owner"), Some("expiry")).is_err());
        let mut valid = suppression();
        migrate_suppressions(&mut valid, Some("owner"), Some("expiry"))
            .expect("suppression migration");
        let fields = valid
            .as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_table)
            .expect("migrated suppression");
        assert_eq!(fields.get("owner").and_then(Value::as_str), Some("owner"));
        assert_eq!(fields.get("expiry").and_then(Value::as_str), Some("expiry"));
    }

    #[test]
    fn migration_defaults_are_the_config_v2_schema_profile() {
        let defaults = default_analysis();
        let expected = AnalysisBudget::default();
        let value = |name: &str| {
            defaults
                .get(name)
                .and_then(Value::as_integer)
                .and_then(|value| u64::try_from(value).ok())
        };
        assert_eq!(value("max_file_bytes"), Some(expected.max_file_bytes));
        assert_eq!(value("max_entries"), Some(expected.max_entries));
        assert_eq!(
            value("max_snapshot_bytes"),
            Some(expected.max_snapshot_bytes)
        );
        assert_eq!(value("max_yaml_depth"), Some(expected.max_yaml_depth));
        assert_eq!(value("max_yaml_aliases"), Some(expected.max_yaml_aliases));
        assert_eq!(
            value("max_expansion_depth"),
            Some(expected.max_expansion_depth)
        );
        assert_eq!(value("max_graph_nodes"), Some(expected.max_graph_nodes));
        assert_eq!(value("max_bdd_nodes"), Some(expected.max_bdd_nodes));
        assert_eq!(
            value("max_resolver_bytes"),
            Some(expected.max_resolver_bytes)
        );
        assert_eq!(value("max_report_bytes"), Some(expected.max_report_bytes));
    }
}
