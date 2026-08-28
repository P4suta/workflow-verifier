use crate::DependencySummary;
use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::{JsonValue, valid_content_digest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockEntry {
    pub provider: Provider,
    pub reference: String,
    pub revision: String,
    pub digest: String,
    pub source: String,
    pub summary: Option<DependencySummary>,
}

impl LockEntry {
    #[must_use]
    pub fn new(
        provider: Provider,
        reference: impl Into<String>,
        revision: impl Into<String>,
        digest: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            reference: reference.into(),
            revision: revision.into(),
            digest: digest.into(),
            source: source.into(),
            summary: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.reference.trim().is_empty() {
            Err("lock reference must not be empty".to_owned())
        } else if self.revision.trim().is_empty() {
            Err("lock revision must not be empty".to_owned())
        } else if !valid_content_digest(&self.digest) {
            Err(format!("invalid SHA-256 digest for {}", self.reference))
        } else if self.source.trim().is_empty() {
            Err("lock source must not be empty".to_owned())
        } else {
            Ok(())
        }
    }

    fn to_json(&self) -> JsonValue {
        let mut fields = BTreeMap::from([
            ("digest".to_owned(), JsonValue::String(self.digest.clone())),
            (
                "provider".to_owned(),
                JsonValue::String(self.provider.name().to_owned()),
            ),
            (
                "reference".to_owned(),
                JsonValue::String(self.reference.clone()),
            ),
            (
                "revision".to_owned(),
                JsonValue::String(self.revision.clone()),
            ),
            ("source".to_owned(), JsonValue::String(self.source.clone())),
        ]);
        if let Some(summary) = &self.summary {
            fields.insert("summary".to_owned(), summary.to_json());
        }
        JsonValue::Object(fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub schema: String,
    entries: Vec<LockEntry>,
    pub integrity: String,
}

impl Lockfile {
    /// Build a canonical lock-v2 value.
    ///
    /// # Errors
    /// Rejects invalid or conflicting provider/reference entries.
    pub fn new(entries: impl IntoIterator<Item = LockEntry>) -> Result<Self, String> {
        Self::new_with_schema("lock-v2", entries)
    }

    fn new_with_schema(
        schema: &str,
        entries: impl IntoIterator<Item = LockEntry>,
    ) -> Result<Self, String> {
        if !matches!(schema, "lock-v1" | "lock-v2") {
            return Err(format!("unsupported lock schema {schema}"));
        }
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_by(|left, right| {
            (left.provider, left.reference.as_str())
                .cmp(&(right.provider, right.reference.as_str()))
        });
        for entry in &entries {
            entry.validate()?;
            if schema == "lock-v1" && entry.summary.is_some() {
                return Err("lock-v1 entries cannot contain semantic summaries".to_owned());
            }
        }
        let mut unique = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(previous) = unique.last() {
                let previous: &LockEntry = previous;
                if previous.provider == entry.provider && previous.reference == entry.reference {
                    if previous == &entry {
                        continue;
                    }
                    return Err(format!(
                        "conflicting lock entries for {}:{}",
                        entry.provider.name(),
                        entry.reference
                    ));
                }
            }
            unique.push(entry);
        }
        let unsigned = Self::unsigned_json(schema, &unique);
        Ok(Self {
            schema: schema.to_owned(),
            entries: unique,
            integrity: unsigned.canonical_digest(),
        })
    }

    fn unsigned_json(schema: &str, entries: &[LockEntry]) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "entries".to_owned(),
                JsonValue::Array(entries.iter().map(LockEntry::to_json).collect()),
            ),
            ("schema".to_owned(), JsonValue::String(schema.to_owned())),
        ]))
    }

    #[must_use]
    pub fn entries(&self) -> &[LockEntry] {
        &self.entries
    }

    #[must_use]
    pub fn find(&self, provider: Provider, reference: &str) -> Option<&LockEntry> {
        self.entries
            .iter()
            .find(|entry| entry.provider == provider && entry.reference == reference)
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.integrity == Self::unsigned_json(&self.schema, &self.entries).canonical_digest()
    }

    fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "entries".to_owned(),
                JsonValue::Array(self.entries.iter().map(LockEntry::to_json).collect()),
            ),
            (
                "integrity".to_owned(),
                JsonValue::String(self.integrity.clone()),
            ),
            ("schema".to_owned(), JsonValue::String(self.schema.clone())),
        ]))
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }

    /// Parse and authenticate strict lock-v1 or lock-v2 product JSON.
    ///
    /// # Errors
    /// Rejects malformed JSON, unknown fields, invalid entries, and integrity mismatch.
    pub fn parse(source: &str) -> Result<Self, String> {
        let root = JsonValue::parse(source).map_err(|error| error.to_string())?;
        let fields = root.exact_object("lockfile", &["entries", "integrity", "schema"])?;
        require_exact(fields, &["entries", "integrity", "schema"], "lockfile")?;
        let schema = string(fields, "schema")?;
        if !matches!(schema, "lock-v1" | "lock-v2") {
            return Err(format!("unsupported lock schema {schema}"));
        }
        let integrity = string(fields, "integrity")?;
        let values = fields
            .get("entries")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "lockfile entries must be an array".to_owned())?;
        let mut entries = Vec::with_capacity(values.len());
        for value in values {
            let allowed = if schema == "lock-v1" {
                &["digest", "provider", "reference", "revision", "source"][..]
            } else {
                &[
                    "digest",
                    "provider",
                    "reference",
                    "revision",
                    "source",
                    "summary",
                ][..]
            };
            let item = value.exact_object("lock entry", allowed)?;
            let required: BTreeSet<_> = ["digest", "provider", "reference", "revision", "source"]
                .into_iter()
                .collect();
            if !required.iter().all(|name| item.contains_key(*name)) {
                return Err("lock entry is missing a required field".to_owned());
            }
            let provider = match string(item, "provider")? {
                "github" => Provider::Github,
                "gitlab" => Provider::Gitlab,
                "azure" => Provider::Azure,
                "circleci" => Provider::Circleci,
                value => return Err(format!("unknown lock provider {value}")),
            };
            entries.push(LockEntry {
                provider,
                reference: string(item, "reference")?.to_owned(),
                revision: string(item, "revision")?.to_owned(),
                digest: string(item, "digest")?.to_owned(),
                source: string(item, "source")?.to_owned(),
                summary: item
                    .get("summary")
                    .map(DependencySummary::parse)
                    .transpose()?,
            });
        }
        let rebuilt = Self::new_with_schema(schema, entries)?;
        if rebuilt.integrity != integrity {
            return Err("lockfile integrity digest mismatch".to_owned());
        }
        Ok(rebuilt)
    }
}

fn string<'a>(fields: &'a BTreeMap<String, JsonValue>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("lockfile needs string field {name}"))
}

fn require_exact(
    fields: &BTreeMap<String, JsonValue>,
    expected: &[&str],
    context: &str,
) -> Result<(), String> {
    if fields.len() == expected.len() && expected.iter().all(|name| fields.contains_key(*name)) {
        Ok(())
    } else {
        Err(format!("{context} has missing fields"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workflow_verifier_foundation::content_digest;

    fn valid_entry(provider: Provider, reference: &str) -> LockEntry {
        LockEntry::new(
            provider,
            reference,
            "immutable-revision",
            content_digest("locked content"),
            "https://example.test/source",
        )
    }

    #[test]
    fn entry_validation_and_lookup_require_every_identity_field() {
        let valid = valid_entry(Provider::Github, "owner/action@main");
        assert!(valid.validate().is_ok());
        for invalid in [
            LockEntry {
                reference: " ".to_owned(),
                ..valid.clone()
            },
            LockEntry {
                revision: " ".to_owned(),
                ..valid.clone()
            },
            LockEntry {
                digest: "invalid".to_owned(),
                ..valid.clone()
            },
            LockEntry {
                source: " ".to_owned(),
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
            assert!(Lockfile::new([invalid]).is_err());
        }

        let gitlab = valid_entry(Provider::Gitlab, "owner/action@main");
        let other = valid_entry(Provider::Github, "owner/other@main");
        let lock = Lockfile::new([valid.clone(), gitlab, other]).expect("lockfile");
        assert_eq!(lock.find(Provider::Github, &valid.reference), Some(&valid));
        assert_eq!(lock.find(Provider::Gitlab, "owner/other@main"), None);
        assert_eq!(lock.find(Provider::Github, "missing"), None);
    }

    #[test]
    fn integrity_and_exact_field_contracts_reject_independent_tampering() {
        let lock =
            Lockfile::new([valid_entry(Provider::Github, "owner/action@main")]).expect("lockfile");
        assert!(lock.verify_integrity());
        let mut tampered = lock.clone();
        tampered.entries[0].revision = "other-revision".to_owned();
        assert!(!tampered.verify_integrity());

        let exact = BTreeMap::from([
            ("first".to_owned(), JsonValue::Null),
            ("second".to_owned(), JsonValue::Null),
        ]);
        assert!(require_exact(&exact, &["first", "second"], "fixture").is_ok());
        assert!(require_exact(&exact, &["first"], "fixture").is_err());
        assert!(require_exact(&exact, &["first", "other"], "fixture").is_err());
    }
}
