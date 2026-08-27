use crate::{Config, ConfigParseOptions, ConfigTrust};
use toml::Value;

type Table = toml::Table;

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
        Some(1) => {}
        Some(2) => return Err(vec!["input is already config-v2".to_owned()]),
        _ => {
            return Err(vec![
                "legacy configuration must declare version = 1".to_owned(),
            ]);
        }
    }
    document.insert("version".to_owned(), Value::Integer(2));
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
    let mut output = toml::to_string(&document)
        .map_err(|error| vec![format!("cannot serialize config-v2: {error}")])?;
    if !output.ends_with('\n') {
        output.push('\n');
    }
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
    let authority = authority.strip_suffix(":443").unwrap_or(&authority);
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
        ("wall_time_seconds", 900),
        ("cpu_cores", 1),
        ("memory_bytes", 2_147_483_648),
        ("processes", 128),
        ("output_bytes", 16_777_216),
        ("scratch_bytes", 4_294_967_296),
        ("scratch_entries", 100_000),
    ] {
        fields.insert(name.to_owned(), Value::Integer(value));
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
        ("max_file_bytes".to_owned(), Value::Integer(16_777_216)),
        ("max_entries".to_owned(), Value::Integer(100_000)),
        (
            "max_snapshot_bytes".to_owned(),
            Value::Integer(4_294_967_296),
        ),
        ("max_yaml_depth".to_owned(), Value::Integer(256)),
        ("max_yaml_aliases".to_owned(), Value::Integer(10_000)),
        ("max_expansion_depth".to_owned(), Value::Integer(64)),
        ("max_graph_nodes".to_owned(), Value::Integer(1_000_000)),
        ("max_bdd_nodes".to_owned(), Value::Integer(2_000_000)),
        ("max_resolver_bytes".to_owned(), Value::Integer(16_777_216)),
        ("max_report_bytes".to_owned(), Value::Integer(268_435_456)),
    ])
}
