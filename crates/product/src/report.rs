use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::Graph;
use workflow_verifier_foundation::{JsonValue, normalize_slashes};
use workflow_verifier_verifier::{Diagnostic, Persona, Property, VerificationResult};

pub const TOOL_NAME: &str = "workflow-verifier";
pub const TOOL_VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportInput {
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateResult {
    Pass,
    Finding,
    Incomplete,
}

impl GateResult {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Finding => "finding",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    pub implementation: String,
    pub compiler: String,
    pub target: String,
    pub source_commit: Option<String>,
    pub binary_digest: String,
}

impl BuildInfo {
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "binary_digest".to_owned(),
                JsonValue::String(self.binary_digest.clone()),
            ),
            (
                "compiler".to_owned(),
                JsonValue::String(self.compiler.clone()),
            ),
            (
                "implementation".to_owned(),
                JsonValue::String(self.implementation.clone()),
            ),
            (
                "source_commit".to_owned(),
                self.source_commit
                    .clone()
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
            ("target".to_owned(), JsonValue::String(self.target.clone())),
        ]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportProvenance {
    pub config_origin: String,
    pub config_trust: String,
    pub config_digest: String,
    pub lock_digest: String,
    pub source_manifest_digest: String,
    pub provider_profiles: Vec<String>,
    pub completeness_reasons: Vec<String>,
    pub gate_result: GateResult,
    pub exit_code: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub schema: String,
    pub tool_version: String,
    pub persona: Persona,
    pub inputs: Vec<ReportInput>,
    pub graphs: Vec<Graph>,
    pub verifications: Vec<VerificationResult>,
    pub policy_diagnostics: Vec<Diagnostic>,
    pub build: BuildInfo,
    pub provenance: ReportProvenance,
    pub semantic_digest: String,
    pub digest: String,
}

fn public_origin(origin: &str) -> String {
    let normalized = normalize_slashes(origin);
    let drive = normalized.as_bytes().get(1) == Some(&b':');
    let safe = !normalized.starts_with('/')
        && !drive
        && normalized.split('/').all(|segment| segment != "..");
    if safe {
        normalized
    } else {
        let basename = normalized.rsplit('/').next().unwrap_or("external");
        format!("external:{basename}")
    }
}

impl Report {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        persona: Persona,
        inputs: Vec<ReportInput>,
        graphs: Vec<Graph>,
        verifications: Vec<VerificationResult>,
        policy_diagnostics: Vec<Diagnostic>,
        build: BuildInfo,
        mut provenance: ReportProvenance,
    ) -> Self {
        let mut inputs: Vec<_> = inputs
            .into_iter()
            .map(|input| ReportInput {
                path: normalize_slashes(&input.path),
                digest: input.digest,
            })
            .collect();
        inputs.sort_by(|left, right| left.path.cmp(&right.path));
        let mut graphs = graphs;
        graphs.sort_by(|left, right| left.source.cmp(&right.source));
        provenance.config_origin = public_origin(&provenance.config_origin);
        provenance.provider_profiles = provenance
            .provider_profiles
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        provenance.completeness_reasons = provenance
            .completeness_reasons
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut report = Self {
            schema: "report-v3".to_owned(),
            tool_version: TOOL_VERSION.to_owned(),
            persona,
            inputs,
            graphs,
            verifications,
            policy_diagnostics,
            build,
            provenance,
            semantic_digest: String::new(),
            digest: String::new(),
        };
        let mut digest_projection = report.semantic_projection();
        report.semantic_digest = digest_projection.canonical_digest();
        Self::promote_to_full_digest_projection(
            &mut digest_projection,
            &report.build,
            &report.semantic_digest,
        );
        report.digest = digest_projection.canonical_digest();
        report
    }

    fn promote_to_full_digest_projection(
        projection: &mut JsonValue,
        build: &BuildInfo,
        semantic_digest: &str,
    ) {
        let JsonValue::Object(fields) = projection else {
            return;
        };
        fields.insert(
            "semantic_digest".to_owned(),
            JsonValue::String(semantic_digest.to_owned()),
        );
        if let Some(JsonValue::Object(tool)) = fields.get_mut("tool") {
            tool.insert("build".to_owned(), build.to_json());
        }
    }

    #[must_use]
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut diagnostics: Vec<_> = self
            .verifications
            .iter()
            .flat_map(|verification| verification.diagnostics.iter().cloned())
            .chain(self.policy_diagnostics.iter().cloned())
            .collect();
        diagnostics.sort();
        diagnostics
    }

    #[must_use]
    pub fn properties(&self) -> Vec<Property> {
        let mut properties: Vec<_> = self
            .verifications
            .iter()
            .flat_map(|verification| verification.properties.iter().cloned())
            .collect();
        properties.sort();
        properties
    }

    #[allow(clippy::too_many_lines)]
    fn json_with(
        &self,
        include_digest: bool,
        include_semantic: bool,
        include_build: bool,
    ) -> JsonValue {
        let diagnostics = self.diagnostics();
        let properties = self.properties();
        let unknown_properties = properties
            .iter()
            .filter(|property| {
                matches!(
                    property.state,
                    workflow_verifier_verifier::PropertyState::Unknown(_)
                )
            })
            .count();
        let complete = self.provenance.completeness_reasons.is_empty();
        let mut tool = BTreeMap::from([
            ("name".to_owned(), JsonValue::String(TOOL_NAME.to_owned())),
            (
                "version".to_owned(),
                JsonValue::String(self.tool_version.clone()),
            ),
        ]);
        if include_build {
            tool.insert("build".to_owned(), self.build.to_json());
        }
        let mut fields = BTreeMap::from([
            (
                "completeness".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "reasons".to_owned(),
                        JsonValue::Array(
                            self.provenance
                                .completeness_reasons
                                .iter()
                                .cloned()
                                .map(JsonValue::String)
                                .collect(),
                        ),
                    ),
                    (
                        "state".to_owned(),
                        JsonValue::String(
                            if complete { "complete" } else { "incomplete" }.to_owned(),
                        ),
                    ),
                ])),
            ),
            (
                "configuration".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "digest".to_owned(),
                        JsonValue::String(self.provenance.config_digest.clone()),
                    ),
                    (
                        "origin".to_owned(),
                        JsonValue::String(self.provenance.config_origin.clone()),
                    ),
                    (
                        "trust".to_owned(),
                        JsonValue::String(self.provenance.config_trust.clone()),
                    ),
                ])),
            ),
            (
                "diagnostics".to_owned(),
                JsonValue::Array(diagnostics.iter().map(Diagnostic::to_json).collect()),
            ),
            (
                "gate".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "exit_code".to_owned(),
                        JsonValue::Integer(self.provenance.exit_code),
                    ),
                    (
                        "result".to_owned(),
                        JsonValue::String(self.provenance.gate_result.name().to_owned()),
                    ),
                ])),
            ),
            (
                "graphs".to_owned(),
                JsonValue::Array(self.graphs.iter().map(Graph::to_json).collect()),
            ),
            (
                "inputs".to_owned(),
                JsonValue::Array(
                    self.inputs
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
                "lock".to_owned(),
                JsonValue::Object(BTreeMap::from([(
                    "digest".to_owned(),
                    JsonValue::String(self.provenance.lock_digest.clone()),
                )])),
            ),
            (
                "persona".to_owned(),
                JsonValue::String(self.persona.name().to_owned()),
            ),
            (
                "properties".to_owned(),
                JsonValue::Array(properties.iter().map(Property::to_json).collect()),
            ),
            (
                "provider_profiles".to_owned(),
                JsonValue::Array(
                    self.provenance
                        .provider_profiles
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            ("schema".to_owned(), JsonValue::String(self.schema.clone())),
            (
                "snapshot".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "digest".to_owned(),
                        JsonValue::String(self.provenance.source_manifest_digest.clone()),
                    ),
                    (
                        "schema".to_owned(),
                        JsonValue::String("source-manifest-v2".to_owned()),
                    ),
                ])),
            ),
            (
                "summary".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "diagnostics".to_owned(),
                        JsonValue::Integer(i64::try_from(diagnostics.len()).unwrap_or(i64::MAX)),
                    ),
                    (
                        "graphs".to_owned(),
                        JsonValue::Integer(i64::try_from(self.graphs.len()).unwrap_or(i64::MAX)),
                    ),
                    (
                        "inputs".to_owned(),
                        JsonValue::Integer(i64::try_from(self.inputs.len()).unwrap_or(i64::MAX)),
                    ),
                    (
                        "unknown_properties".to_owned(),
                        JsonValue::Integer(i64::try_from(unknown_properties).unwrap_or(i64::MAX)),
                    ),
                ])),
            ),
            ("tool".to_owned(), JsonValue::Object(tool)),
        ]);
        if include_digest {
            fields.insert("digest".to_owned(), JsonValue::String(self.digest.clone()));
        }
        if include_semantic {
            fields.insert(
                "semantic_digest".to_owned(),
                JsonValue::String(self.semantic_digest.clone()),
            );
        }
        JsonValue::Object(fields)
    }

    fn semantic_projection(&self) -> JsonValue {
        self.json_with(false, false, false)
    }

    fn full_digest_projection(&self) -> JsonValue {
        self.json_with(false, true, true)
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        self.json_with(true, true, true)
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        self.to_json().canonical_line()
    }

    #[must_use]
    pub fn verify_digests(&self) -> bool {
        self.semantic_digest == self.semantic_projection().canonical_digest()
            && self.digest == self.full_digest_projection().canonical_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workflow_verifier_foundation::content_digest;
    use workflow_verifier_verifier::{PropertyState, VerificationResult};

    fn report() -> Report {
        Report::new(
            Persona::Gate,
            Vec::new(),
            Vec::new(),
            vec![VerificationResult {
                properties: vec![
                    Property {
                        id: "RULE-B".to_owned(),
                        state: PropertyState::Proved,
                        subject: None,
                        explanation: "second".to_owned(),
                    },
                    Property {
                        id: "RULE-A".to_owned(),
                        state: PropertyState::Proved,
                        subject: None,
                        explanation: "first".to_owned(),
                    },
                ],
                diagnostics: Vec::new(),
                complete: true,
                analyzed_nodes: 0,
                analyzed_edges: 0,
            }],
            Vec::new(),
            BuildInfo {
                implementation: "rust".to_owned(),
                compiler: "rustc".to_owned(),
                target: "test-target".to_owned(),
                source_commit: None,
                binary_digest: content_digest("binary"),
            },
            ReportProvenance {
                config_origin: "policy.toml".to_owned(),
                config_trust: "trusted-policy".to_owned(),
                config_digest: content_digest("config"),
                lock_digest: content_digest("lock"),
                source_manifest_digest: content_digest("manifest"),
                provider_profiles: Vec::new(),
                completeness_reasons: Vec::new(),
                gate_result: GateResult::Pass,
                exit_code: crate::EXIT_CODE_PASS,
            },
        )
    }

    #[test]
    fn gate_names_and_public_config_origins_are_exact() {
        assert_eq!(
            [
                GateResult::Pass,
                GateResult::Finding,
                GateResult::Incomplete
            ]
            .map(GateResult::name),
            ["pass", "finding", "incomplete"]
        );
        for safe in [
            "policy.toml",
            "config/policy.toml",
            ".config/policy.toml",
            "C",
        ] {
            assert_eq!(public_origin(safe), safe.replace('\\', "/"));
        }
        for (private, expected) in [
            ("/private/policy.toml", "external:policy.toml"),
            ("C:\\private\\policy.toml", "external:policy.toml"),
            ("config/../policy.toml", "external:policy.toml"),
        ] {
            assert_eq!(public_origin(private), expected);
        }
    }

    #[test]
    fn properties_are_sorted_and_both_report_digests_authenticate_independently() {
        let report = report();
        assert_eq!(
            report
                .properties()
                .iter()
                .map(|property| property.id.as_str())
                .collect::<Vec<_>>(),
            ["RULE-A", "RULE-B"]
        );
        assert!(report.verify_digests());

        let mut semantic_tamper = report.clone();
        semantic_tamper.semantic_digest = content_digest("other semantics");
        assert!(!semantic_tamper.verify_digests());
        let mut full_tamper = report;
        full_tamper.digest = content_digest("other build");
        assert!(!full_tamper.verify_digests());
    }
}
