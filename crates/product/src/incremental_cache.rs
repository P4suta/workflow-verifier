use std::collections::BTreeMap;
use workflow_verifier_foundation::{JsonValue, content_digest, normalize_slashes};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheKeyInput {
    pub path: String,
    pub digest: String,
}

#[must_use]
pub fn cache_key(
    tool_version: &str,
    config_digest: &str,
    lock_digest: &str,
    inputs: &[CacheKeyInput],
) -> String {
    let mut inputs: Vec<_> = inputs
        .iter()
        .map(|input| CacheKeyInput {
            path: normalize_slashes(&input.path),
            digest: input.digest.clone(),
        })
        .collect();
    inputs.sort_by(|left, right| left.path.cmp(&right.path));
    let material = JsonValue::Object(BTreeMap::from([
        (
            "config_digest".to_owned(),
            JsonValue::String(config_digest.to_owned()),
        ),
        (
            "inputs".to_owned(),
            JsonValue::Array(
                inputs
                    .iter()
                    .map(|input| {
                        JsonValue::Object(BTreeMap::from([
                            ("digest".to_owned(), JsonValue::String(input.digest.clone())),
                            ("path".to_owned(), JsonValue::String(input.path.clone())),
                        ]))
                    })
                    .collect(),
            ),
        ),
        (
            "lock_digest".to_owned(),
            JsonValue::String(lock_digest.to_owned()),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("analysis-cache-key-v1".to_owned()),
        ),
        (
            "tool_version".to_owned(),
            JsonValue::String(tool_version.to_owned()),
        ),
    ]));
    content_digest(material.canonical())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisCacheEntry {
    pub key: String,
    pub exit_code: i64,
    pub report: String,
    pub integrity: String,
}

impl AnalysisCacheEntry {
    /// Construct an authenticated analysis-cache-v1 entry.
    ///
    /// # Errors
    /// Rejects exit codes outside the public 0..=5 protocol range.
    pub fn new(
        key: impl Into<String>,
        exit_code: i64,
        report: impl Into<String>,
    ) -> Result<Self, String> {
        if !(0..=5).contains(&exit_code) {
            return Err("cache exit code must be 0..5".to_owned());
        }
        let mut entry = Self {
            key: key.into(),
            exit_code,
            report: report.into(),
            integrity: String::new(),
        };
        entry.integrity = content_digest(entry.unsigned_json().canonical());
        Ok(entry)
    }

    fn unsigned_fields(&self) -> BTreeMap<String, JsonValue> {
        BTreeMap::from([
            ("exit_code".to_owned(), JsonValue::Integer(self.exit_code)),
            ("key".to_owned(), JsonValue::String(self.key.clone())),
            ("report".to_owned(), JsonValue::String(self.report.clone())),
            (
                "schema".to_owned(),
                JsonValue::String("analysis-cache-v1".to_owned()),
            ),
        ])
    }

    fn unsigned_json(&self) -> JsonValue {
        JsonValue::Object(self.unsigned_fields())
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.integrity == content_digest(self.unsigned_json().canonical())
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut fields = self.unsigned_fields();
        fields.insert(
            "integrity".to_owned(),
            JsonValue::String(self.integrity.clone()),
        );
        JsonValue::Object(fields).canonical_line()
    }

    /// Parse and authenticate strict analysis-cache-v1 product JSON.
    ///
    /// # Errors
    /// Rejects malformed/unknown fields, invalid exits, and integrity tampering.
    pub fn parse(source: &str) -> Result<Self, String> {
        let root = JsonValue::parse(source).map_err(|error| error.to_string())?;
        let fields = root.exact_object(
            "analysis cache",
            &["exit_code", "integrity", "key", "report", "schema"],
        )?;
        if fields.len() != 5 {
            return Err("analysis cache is missing a required field".to_owned());
        }
        let string = |name: &str| {
            fields
                .get(name)
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("analysis cache needs string field {name}"))
        };
        if string("schema")? != "analysis-cache-v1" {
            return Err("unsupported analysis cache schema".to_owned());
        }
        let exit_code = fields
            .get("exit_code")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| "analysis cache needs integer field exit_code".to_owned())?;
        let supplied = string("integrity")?;
        let rebuilt = Self::new(string("key")?, exit_code, string("report")?)?;
        if rebuilt.integrity != supplied {
            return Err("analysis cache integrity mismatch".to_owned());
        }
        Ok(rebuilt)
    }
}
