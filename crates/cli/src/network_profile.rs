use crate::network::ProxyEndpoint;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};
use toml::Value;

// network-profile-v1 deliberately permits only a small, user-owned trust
// bundle: one MiB per file, eight MiB total, and sixteen roots. These limits
// are security-contract boundaries exercised by the profile attack fixtures.
const NETWORK_PROFILE_SCHEMA_VERSION: i64 = 1;
const BYTES_PER_MEBIBYTE: u64 = 1_048_576;
const BYTES_PER_MEBIBYTE_USIZE: usize = 1_048_576;
const MAX_PROFILE_BYTES: u64 = BYTES_PER_MEBIBYTE;
const MAX_CA_BYTES: u64 = BYTES_PER_MEBIBYTE;
const MAX_CA_FILES: usize = 16;
const MAX_CA_TOTAL_BYTES: usize = 8 * BYTES_PER_MEBIBYTE_USIZE;

#[derive(Clone, Debug, Default)]
pub(crate) struct TrustedNetworkProfile {
    pub(crate) proxy: Option<ProxyEndpoint>,
    pub(crate) additional_der_roots: Vec<Vec<u8>>,
}

impl TrustedNetworkProfile {
    pub(crate) fn load(path: &Path, repository_root: &Path) -> Result<Self, String> {
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("cannot inspect trusted network profile: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("trusted network profile must be a regular non-symlink file".to_owned());
        }
        if metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES {
            return Err("trusted network profile size is outside 1..1048576 bytes".to_owned());
        }
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("cannot resolve trusted network profile: {error}"))?;
        let repository = repository_root
            .canonicalize()
            .map_err(|error| format!("cannot resolve repository root: {error}"))?;
        if canonical.starts_with(&repository) {
            return Err(
                "trusted network profile must be outside the analyzed repository".to_owned(),
            );
        }
        let source = fs::read_to_string(&canonical)
            .map_err(|error| format!("cannot read trusted network profile: {error}"))?;
        let table = source
            .parse::<toml::Table>()
            .map_err(|error| format!("network-profile-v1 TOML: {error}"))?;
        let (proxy, ca_names) = parse_fields(&table)?;
        let additional_der_roots = load_ca_files(&canonical, ca_names)?;
        Ok(Self {
            proxy,
            additional_der_roots,
        })
    }
}

fn parse_fields(table: &toml::Table) -> Result<(Option<ProxyEndpoint>, Vec<String>), String> {
    let expected = BTreeSet::from(["custom_ca_der", "proxy", "version"]);
    let actual: BTreeSet<_> = table.keys().map(String::as_str).collect();
    if !actual.is_subset(&expected) {
        return Err(format!(
            "network-profile-v1 has unknown fields {:?}",
            actual.difference(&expected).collect::<Vec<_>>()
        ));
    }
    if table.get("version").and_then(Value::as_integer) != Some(NETWORK_PROFILE_SCHEMA_VERSION) {
        return Err("trusted network profile version must be 1".to_owned());
    }
    let proxy = table
        .get("proxy")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "network profile proxy must be a string".to_owned())
                .and_then(ProxyEndpoint::parse)
        })
        .transpose()?;
    let ca_names = table
        .get("custom_ca_der")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "network profile custom_ca_der must be an array".to_owned())?
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_owned).ok_or_else(|| {
                        "network profile custom_ca_der entries must be strings".to_owned()
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if ca_names.len() > MAX_CA_FILES {
        return Err(format!(
            "network profile exceeds {MAX_CA_FILES} custom CA files"
        ));
    }
    Ok((proxy, ca_names))
}

fn load_ca_files(profile: &Path, ca_names: Vec<String>) -> Result<Vec<Vec<u8>>, String> {
    let parent = profile
        .parent()
        .ok_or_else(|| "trusted network profile has no parent directory".to_owned())?
        .canonicalize()
        .map_err(|error| format!("cannot resolve trusted profile directory: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();
    let mut total = 0usize;
    for name in ca_names {
        let relative = Path::new(&name);
        if relative.is_absolute()
            || name.contains('\\')
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("custom CA path must be a safe relative path".to_owned());
        }
        let candidate = parent.join(relative);
        let metadata = candidate
            .symlink_metadata()
            .map_err(|error| format!("cannot inspect custom CA {name}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CA_BYTES
        {
            return Err(format!(
                "custom CA {name} must be a nonempty regular non-symlink file at most 1 MiB"
            ));
        }
        let resolved = candidate
            .canonicalize()
            .map_err(|error| format!("cannot resolve custom CA {name}: {error}"))?;
        if !resolved.starts_with(&parent) || !seen.insert(resolved.clone()) {
            return Err(format!(
                "custom CA {name} escapes or duplicates the trusted profile"
            ));
        }
        let bytes = fs::read(&resolved)
            .map_err(|error| format!("cannot read custom CA {name}: {error}"))?;
        total = total.saturating_add(bytes.len());
        if total > MAX_CA_TOTAL_BYTES {
            return Err("network profile custom CA bytes exceed 8 MiB".to_owned());
        }
        roots.push(bytes);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::TrustedNetworkProfile;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn profile_must_be_outside_repository_and_loads_only_bounded_der_files() {
        let root = std::env::temp_dir().join(format!(
            "workflow-verifier-network-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let repository = root.join("repository");
        let profile_root = root.join("user-config");
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir_all(&profile_root).unwrap();
        fs::write(profile_root.join("enterprise.der"), b"DER fixture").unwrap();
        let profile_path = profile_root.join("network-v1.toml");
        fs::write(
            &profile_path,
            "version = 1\nproxy = \"http://proxy.enterprise.example:8080\"\ncustom_ca_der = [\"enterprise.der\"]\n",
        )
        .unwrap();

        let profile = TrustedNetworkProfile::load(&profile_path, &repository).unwrap();
        assert_eq!(profile.proxy.unwrap().host(), "proxy.enterprise.example");
        assert_eq!(profile.additional_der_roots, vec![b"DER fixture".to_vec()]);

        let inside = repository.join("network-v1.toml");
        fs::write(&inside, "version = 1\n").unwrap();
        assert!(TrustedNetworkProfile::load(&inside, &repository).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
