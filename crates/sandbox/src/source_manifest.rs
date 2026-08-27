use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{
    JsonValue, PublicPath, content_digest, normalize_slashes, portable_path_key,
};

const GENERATED_DIRECTORIES: [&str; 4] = [
    ".git",
    ".workflow-verifier",
    ".workflow-verifier-cache",
    ".workflow-verifier-output",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestBudget {
    pub max_file_bytes: u64,
    pub max_entries: usize,
    pub max_snapshot_bytes: u64,
}

impl Default for ManifestBudget {
    fn default() -> Self {
        Self {
            max_file_bytes: 16 * 1024 * 1024,
            max_entries: 100_000,
            max_snapshot_bytes: 4_294_967_296,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceKind {
    Regular { contents: Vec<u8>, executable: bool },
    Symlink { target: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFile {
    path: String,
    kind: SourceKind,
    identity: Option<String>,
}

impl SourceFile {
    #[must_use]
    pub fn regular(path: impl Into<String>, contents: impl AsRef<[u8]>) -> Self {
        Self {
            path: path.into(),
            kind: SourceKind::Regular {
                contents: contents.as_ref().to_vec(),
                executable: false,
            },
            identity: None,
        }
    }

    #[must_use]
    pub fn executable(path: impl Into<String>, contents: impl AsRef<[u8]>) -> Self {
        Self {
            path: path.into(),
            kind: SourceKind::Regular {
                contents: contents.as_ref().to_vec(),
                executable: true,
            },
            identity: None,
        }
    }

    #[must_use]
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: SourceKind::Symlink {
                target: target.into(),
            },
            identity: None,
        }
    }

    #[must_use]
    pub fn with_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestEntryKind {
    Regular,
    Symlink,
}

impl ManifestEntryKind {
    fn name(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: ManifestEntryKind,
    pub executable: bool,
    pub size: u64,
    pub digest: String,
    pub target: Option<String>,
    pub identity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestExclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceManifest {
    pub entries: Vec<ManifestEntry>,
    pub exclusions: Vec<ManifestExclusion>,
    pub exclusion_policy_digest: String,
    pub total_size: u64,
    pub digest: String,
}

impl SourceManifest {
    /// Create the immutable source-manifest-v2 protocol object.
    ///
    /// # Errors
    /// Rejects unsafe paths and links, collisions, hardlink aliases, and resource excess.
    pub fn create(
        root: &str,
        files: impl IntoIterator<Item = SourceFile>,
        trusted_exclusions: &[String],
    ) -> Result<Self, String> {
        Self::create_with_budget(root, files, trusted_exclusions, ManifestBudget::default())
    }

    /// Create a manifest under an explicit, non-widening resource envelope.
    ///
    /// # Errors
    /// Returns a stable incomplete or validation reason for the first violation.
    #[allow(clippy::too_many_lines)]
    pub fn create_with_budget(
        root: &str,
        files: impl IntoIterator<Item = SourceFile>,
        trusted_exclusions: &[String],
        budget: ManifestBudget,
    ) -> Result<Self, String> {
        let published = ManifestBudget::default();
        if budget.max_file_bytes < published.max_file_bytes
            || budget.max_entries < published.max_entries
            || budget.max_snapshot_bytes < published.max_snapshot_bytes
        {
            return Err("source-manifest-v2 budgets are below the published floor".to_owned());
        }
        let root = normalize_root(root);
        let mut files: Vec<_> = files.into_iter().collect();
        files.sort_by(|left, right| {
            normalize_slashes(&left.path).cmp(&normalize_slashes(&right.path))
        });
        let trusted: BTreeSet<String> = trusted_exclusions
            .iter()
            .map(|path| normalize_slashes(path))
            .collect();
        let exclusion_policy = JsonValue::Object(BTreeMap::from([
            (
                "default".to_owned(),
                JsonValue::Array(
                    GENERATED_DIRECTORIES
                        .iter()
                        .map(|path| JsonValue::String((*path).to_owned()))
                        .collect(),
                ),
            ),
            (
                "trusted".to_owned(),
                JsonValue::Array(trusted.iter().cloned().map(JsonValue::String).collect()),
            ),
        ]));
        let exclusion_policy_digest = content_digest(exclusion_policy.canonical());
        let mut entries = Vec::new();
        let mut exclusions = Vec::new();
        let mut exact_paths = BTreeSet::new();
        let mut portable_paths = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut total_size = 0u64;
        for file in files {
            let relative = relative_to(&root, &file.path)?;
            if generated(&relative) {
                exclusions.push(ManifestExclusion {
                    path: relative,
                    reason: "product-default".to_owned(),
                });
                continue;
            }
            if trusted.iter().any(|prefix| path_below(&relative, prefix)) {
                exclusions.push(ManifestExclusion {
                    path: relative,
                    reason: "trusted-policy".to_owned(),
                });
                continue;
            }
            if !exact_paths.insert(relative.clone()) {
                return Err(format!("duplicate source manifest path: {relative}"));
            }
            if !portable_paths.insert(portable_path_key(&relative)) {
                return Err(format!("portable case-fold path collision: {relative}"));
            }
            if entries.len() >= budget.max_entries {
                return Err("Incomplete.Resource_limit: source entry budget exceeded".to_owned());
            }
            if let Some(identity) = &file.identity
                && !identities.insert(identity.clone())
            {
                return Err(format!("hardlink/file identity collision: {relative}"));
            }
            let (kind, executable, bytes, target) = match file.kind {
                SourceKind::Regular {
                    contents,
                    executable,
                } => (ManifestEntryKind::Regular, executable, contents, None),
                SourceKind::Symlink { target } => {
                    let normalized = resolve_target(&relative, &target)?;
                    (
                        ManifestEntryKind::Symlink,
                        false,
                        target.as_bytes().to_vec(),
                        Some(normalized),
                    )
                }
            };
            let size = u64::try_from(bytes.len()).map_err(|_| "source file is too large")?;
            if size > budget.max_file_bytes {
                return Err(format!(
                    "Incomplete.Resource_limit: file exceeds 16 MiB: {relative}"
                ));
            }
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| "Incomplete.Resource_limit: snapshot size overflow".to_owned())?;
            if total_size > budget.max_snapshot_bytes {
                return Err("Incomplete.Resource_limit: snapshot exceeds 4 GiB".to_owned());
            }
            entries.push(ManifestEntry {
                path: relative,
                kind,
                executable,
                size,
                digest: content_digest(bytes),
                target,
                identity: file.identity,
            });
        }
        validate_symlinks(&entries)?;
        let mut manifest = Self {
            entries,
            exclusions,
            exclusion_policy_digest,
            total_size,
            digest: String::new(),
        };
        manifest.digest = content_digest(manifest.body_json().canonical());
        Ok(manifest)
    }

    fn body_fields(&self) -> BTreeMap<String, JsonValue> {
        BTreeMap::from([
            (
                "entries".to_owned(),
                JsonValue::Array(self.entries.iter().map(entry_json).collect()),
            ),
            (
                "exclusion_policy_digest".to_owned(),
                JsonValue::String(self.exclusion_policy_digest.clone()),
            ),
            (
                "exclusions".to_owned(),
                JsonValue::Array(self.exclusions.iter().map(exclusion_json).collect()),
            ),
            ("limits".to_owned(), limits_json()),
            (
                "schema".to_owned(),
                JsonValue::String("source-manifest-v2".to_owned()),
            ),
            (
                "total_size".to_owned(),
                JsonValue::Integer(i64::try_from(self.total_size).unwrap_or(i64::MAX)),
            ),
        ])
    }

    fn body_json(&self) -> JsonValue {
        JsonValue::Object(self.body_fields())
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.digest == content_digest(self.body_json().canonical())
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut fields = self.body_fields();
        fields.insert("digest".to_owned(), JsonValue::String(self.digest.clone()));
        JsonValue::Object(fields).canonical_line()
    }
}

fn entry_json(entry: &ManifestEntry) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("digest".to_owned(), JsonValue::String(entry.digest.clone())),
        (
            "executable".to_owned(),
            JsonValue::Boolean(entry.executable),
        ),
        (
            "kind".to_owned(),
            JsonValue::String(entry.kind.name().to_owned()),
        ),
        ("path".to_owned(), JsonValue::String(entry.path.clone())),
        (
            "size".to_owned(),
            JsonValue::Integer(i64::try_from(entry.size).unwrap_or(i64::MAX)),
        ),
        (
            "target".to_owned(),
            entry
                .target
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
    ]))
}

fn exclusion_json(exclusion: &ManifestExclusion) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("path".to_owned(), JsonValue::String(exclusion.path.clone())),
        (
            "reason".to_owned(),
            JsonValue::String(exclusion.reason.clone()),
        ),
    ]))
}

fn limits_json() -> JsonValue {
    let limits = ManifestBudget::default();
    JsonValue::Object(BTreeMap::from([
        (
            "max_entries".to_owned(),
            JsonValue::Integer(i64::try_from(limits.max_entries).unwrap_or(i64::MAX)),
        ),
        (
            "max_file_bytes".to_owned(),
            JsonValue::Integer(i64::try_from(limits.max_file_bytes).unwrap_or(i64::MAX)),
        ),
        (
            "max_snapshot_bytes".to_owned(),
            JsonValue::Integer(i64::try_from(limits.max_snapshot_bytes).unwrap_or(i64::MAX)),
        ),
    ]))
}

fn normalize_root(root: &str) -> String {
    let root = normalize_slashes(root);
    root.trim_end_matches('/').to_owned()
}

fn relative_to(root: &str, path: &str) -> Result<String, String> {
    let path = normalize_slashes(path);
    let path = path.trim_start_matches("./").to_owned();
    let relative = if matches!(root, "" | ".") {
        path
    } else if let Some(relative) = path.strip_prefix(&format!("{root}/")) {
        relative.to_owned()
    } else {
        return Err(format!(
            "source path escapes or equals manifest root: {path}"
        ));
    };
    PublicPath::new(relative.clone())
        .map_err(|_| format!("source path is not a safe relative path: {relative}"))?;
    Ok(relative)
}

fn generated(path: &str) -> bool {
    path.split('/').any(|segment| {
        GENERATED_DIRECTORIES
            .iter()
            .any(|generated| segment.eq_ignore_ascii_case(generated))
    })
}

fn path_below(path: &str, prefix: &str) -> bool {
    path.eq_ignore_ascii_case(prefix)
        || path
            .to_ascii_lowercase()
            .starts_with(&format!("{}/", prefix.to_ascii_lowercase()))
}

fn resolve_target(path: &str, target: &str) -> Result<String, String> {
    let target = normalize_slashes(target);
    if target.starts_with('/') || target.as_bytes().get(1) == Some(&b':') || target.contains('\0') {
        return Err(format!("{path}: absolute symlink target is forbidden"));
    }
    let mut segments: Vec<&str> = path
        .rsplit_once('/')
        .map_or(Vec::new(), |(base, _)| base.split('/').collect());
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(format!("{path}: symlink target escapes snapshot root"));
                }
            }
            other => segments.push(other),
        }
    }
    let resolved = segments.join("/");
    PublicPath::new(resolved.clone())
        .map_err(|_| format!("{path}: symlink target is not a safe relative path"))?;
    Ok(resolved)
}

fn validate_symlinks(entries: &[ManifestEntry]) -> Result<(), String> {
    let targets: BTreeMap<&str, &str> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .target
                .as_deref()
                .map(|target| (entry.path.as_str(), target))
        })
        .collect();
    for start in targets.keys() {
        let mut visiting = BTreeSet::new();
        let mut cursor = *start;
        while let Some(target) = targets.get(cursor) {
            if !visiting.insert(cursor) {
                return Err(format!("symlink cycle at {cursor}"));
            }
            cursor = target;
        }
    }
    Ok(())
}
