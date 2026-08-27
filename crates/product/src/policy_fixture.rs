use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, normalize_slashes};
use workflow_verifier_verifier::Diagnostic;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExpectation {
    schema: String,
    expected_rules: Vec<String>,
}

impl PolicyExpectation {
    /// Parse the language-independent `policy-fixture-v1` sidecar.
    ///
    /// # Errors
    /// Rejects malformed or duplicate-key JSON, unknown fields, unsupported
    /// schemas, non-string rule IDs, empty IDs, and duplicate IDs.
    pub fn parse(source: &str) -> Result<Self, String> {
        let value = JsonValue::parse(source).map_err(|error| error.to_string())?;
        let fields = value.exact_object("policy fixture", &["expected_rules", "schema"])?;
        let schema = fields
            .get("schema")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "policy fixture needs schema".to_owned())?;
        if schema != "policy-fixture-v1" {
            return Err(format!("unsupported policy fixture schema {schema}"));
        }
        let values = fields
            .get("expected_rules")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "policy fixture expected_rules must be an array".to_owned())?;
        let mut expected_rules = Vec::with_capacity(values.len());
        for value in values {
            let rule = value
                .as_str()
                .filter(|rule| !rule.trim().is_empty())
                .ok_or_else(|| "policy fixture rule IDs must be non-empty strings".to_owned())?;
            expected_rules.push(rule.to_owned());
        }
        let unique: BTreeSet<_> = expected_rules.iter().collect();
        if unique.len() != expected_rules.len() {
            return Err("policy fixture rule IDs must be unique".to_owned());
        }
        expected_rules.sort();
        Ok(Self {
            schema: schema.to_owned(),
            expected_rules,
        })
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn expected_rules(&self) -> &[String] {
        &self.expected_rules
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFixtureResult {
    fixture: String,
    expected_rules: Vec<String>,
    actual_rules: Vec<String>,
    missing_rules: Vec<String>,
    unexpected_rules: Vec<String>,
    passed: bool,
}

impl PolicyFixtureResult {
    #[must_use]
    pub fn fixture(&self) -> &str {
        &self.fixture
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.passed
    }

    #[must_use]
    pub fn missing_rules(&self) -> &[String] {
        &self.missing_rules
    }

    #[must_use]
    pub fn unexpected_rules(&self) -> &[String] {
        &self.unexpected_rules
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            ("actual_rules".to_owned(), strings(&self.actual_rules)),
            ("expected_rules".to_owned(), strings(&self.expected_rules)),
            (
                "fixture".to_owned(),
                JsonValue::String(self.fixture.clone()),
            ),
            ("missing_rules".to_owned(), strings(&self.missing_rules)),
            ("passed".to_owned(), JsonValue::Boolean(self.passed)),
            (
                "unexpected_rules".to_owned(),
                strings(&self.unexpected_rules),
            ),
        ]))
    }
}

#[must_use]
pub fn evaluate_policy_fixture(
    fixture: &str,
    expectation: &PolicyExpectation,
    diagnostics: &[Diagnostic],
) -> PolicyFixtureResult {
    let actual_rules: Vec<_> = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.rule_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let expected: BTreeSet<_> = expectation.expected_rules.iter().cloned().collect();
    let actual: BTreeSet<_> = actual_rules.iter().cloned().collect();
    let missing_rules = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected_rules = actual.difference(&expected).cloned().collect::<Vec<_>>();
    let passed = missing_rules.is_empty() && unexpected_rules.is_empty();
    PolicyFixtureResult {
        fixture: normalize_slashes(fixture),
        expected_rules: expectation.expected_rules.clone(),
        actual_rules,
        missing_rules,
        unexpected_rules,
        passed,
    }
}

fn strings(values: &[String]) -> JsonValue {
    JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect())
}
