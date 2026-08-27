use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::{Capability, ObservableEffect, Provider};
use workflow_verifier_foundation::{Budget, JsonValue};
use workflow_verifier_frontend::{Dependency, DependencyKind, DependencyStatus, compile};
use workflow_verifier_verifier::inferred_effects;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencySummary {
    pub complete: bool,
    pub reasons: Vec<String>,
    pub capabilities: Vec<Capability>,
    pub effects: Vec<ObservableEffect>,
}

impl DependencySummary {
    #[must_use]
    pub fn new(
        complete: bool,
        reasons: impl IntoIterator<Item = String>,
        capabilities: impl IntoIterator<Item = Capability>,
        effects: impl IntoIterator<Item = ObservableEffect>,
    ) -> Self {
        let mut reasons: Vec<_> = reasons
            .into_iter()
            .filter(|reason| !reason.trim().is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if complete {
            reasons.clear();
        } else if reasons.is_empty() {
            reasons.push("semantic evidence is incomplete".to_owned());
        }
        Self {
            complete,
            reasons,
            capabilities: capabilities
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            effects: effects
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }

    /// Infer a conservative capability/effect summary from exact semantic
    /// source bytes retained by the resolver.
    #[must_use]
    pub fn infer(dependency: &Dependency, path: &str, source: &[u8]) -> Self {
        let Ok(source) = std::str::from_utf8(source) else {
            return Self::new(false, ["semantic source is not UTF-8".to_owned()], [], []);
        };
        if dependency.provider == Provider::Azure && dependency.kind == DependencyKind::Task {
            return infer_azure_task(source);
        }
        infer_graph(dependency, path, source)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.exact_object(
            "dependency summary",
            &["capabilities", "complete", "effects", "reasons"],
        )?;
        for name in ["capabilities", "complete", "effects", "reasons"] {
            if !fields.contains_key(name) {
                return Err(format!("dependency summary needs field {name}"));
            }
        }
        let complete = fields
            .get("complete")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "dependency summary complete must be a boolean".to_owned())?;
        let reasons = strings(fields, "reasons")?;
        if reasons.iter().any(|reason| reason.trim().is_empty()) {
            return Err("dependency summary reasons must not be empty".to_owned());
        }
        unique(&reasons, "reasons")?;
        if complete && !reasons.is_empty() {
            return Err(
                "complete dependency summaries cannot contain incomplete reasons".to_owned(),
            );
        }
        if !complete && reasons.is_empty() {
            return Err("incomplete dependency summaries need a reason".to_owned());
        }
        let capability_names = strings(fields, "capabilities")?;
        unique(&capability_names, "capabilities")?;
        let capabilities = capability_names
            .iter()
            .map(|name| {
                capability(name)
                    .ok_or_else(|| format!("unknown dependency summary capabilities value {name}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let effect_names = strings(fields, "effects")?;
        unique(&effect_names, "effects")?;
        let effects = effect_names
            .iter()
            .map(|name| {
                effect(name)
                    .ok_or_else(|| format!("unknown dependency summary effects value {name}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(complete, reasons, capabilities, effects))
    }

    pub(crate) fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "capabilities".to_owned(),
                JsonValue::Array(
                    self.capabilities
                        .iter()
                        .map(|capability| JsonValue::String(capability.name().to_owned()))
                        .collect(),
                ),
            ),
            ("complete".to_owned(), JsonValue::Boolean(self.complete)),
            (
                "effects".to_owned(),
                JsonValue::Array(
                    self.effects
                        .iter()
                        .map(|effect| JsonValue::String(effect.name().to_owned()))
                        .collect(),
                ),
            ),
            (
                "reasons".to_owned(),
                JsonValue::Array(
                    self.reasons
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
        ]))
    }
}

fn infer_graph(dependency: &Dependency, path: &str, source: &str) -> DependencySummary {
    let compilation = match compile(dependency.provider, path, source, Budget::default()) {
        Ok(compilation) => compilation,
        Err(problems) => {
            return DependencySummary::new(
                false,
                [problems
                    .iter()
                    .map(|problem| format!("{}: {}", problem.code, problem.message))
                    .collect::<Vec<_>>()
                    .join("; ")],
                [],
                [],
            );
        }
    };
    let mut reasons = compilation
        .problems
        .iter()
        .map(|problem| format!("{}: {}", problem.code, problem.message))
        .collect::<Vec<_>>();
    reasons.extend(
        compilation
            .graph
            .nodes
            .iter()
            .filter_map(|node| node.unknown.as_ref().map(ToString::to_string)),
    );
    reasons.extend(compilation.dependencies.iter().filter_map(|dependency| {
        if let DependencyStatus::Unresolved(reason) = &dependency.status {
            Some(reason.to_string())
        } else {
            None
        }
    }));
    if dependency.provider == Provider::Github && dependency.kind == DependencyKind::Action {
        reasons.extend(github_runtime_reasons(&compilation.cst));
    }
    let effects = compilation
        .graph
        .nodes
        .iter()
        .flat_map(inferred_effects)
        .collect::<Vec<_>>();
    let mut capabilities = compilation
        .graph
        .nodes
        .iter()
        .flat_map(|node| node.capabilities.iter().copied())
        .collect::<Vec<_>>();
    capabilities.extend(effects.iter().copied().flat_map(required_by_effect));
    DependencySummary::new(reasons.is_empty(), reasons, capabilities, effects)
}

fn github_runtime_reasons(document: &workflow_verifier_syntax::YamlDocument) -> Vec<String> {
    let runtime = document
        .root()
        .and_then(|root| root.field("runs"))
        .and_then(|runs| runs.field("using"))
        .and_then(workflow_verifier_syntax::YamlNode::scalar);
    match runtime {
        None | Some("composite") => Vec::new(),
        Some("docker") => {
            vec!["Docker action implementation is unavailable beyond locked metadata".to_owned()]
        }
        Some(runtime) => vec![format!(
            "{runtime} action implementation is unavailable beyond locked metadata"
        )],
    }
}

fn infer_azure_task(source: &str) -> DependencySummary {
    let parsed = match JsonValue::parse(source) {
        Ok(value) => value,
        Err(error) => {
            return DependencySummary::new(
                false,
                [format!(
                    "Azure task metadata JSON byte {}: {}",
                    error.offset, error.message
                )],
                [],
                [],
            );
        }
    };
    let has_execution = matches!(
        parsed.member("execution"),
        Some(JsonValue::Object(fields)) if !fields.is_empty()
    );
    if has_execution {
        DependencySummary::new(
            false,
            ["Azure task implementation is unavailable beyond locked task.json".to_owned()],
            [Capability::Shell, Capability::FilesystemRead],
            [ObservableEffect::CommandExecution],
        )
    } else {
        DependencySummary::new(
            false,
            ["Azure task metadata has no declared execution handler".to_owned()],
            [],
            [],
        )
    }
}

fn required_by_effect(effect: ObservableEffect) -> Vec<Capability> {
    match effect {
        ObservableEffect::RepositoryChange => {
            vec![Capability::RepositoryWrite, Capability::TokenWrite]
        }
        ObservableEffect::NetworkRequest => vec![Capability::Network],
        ObservableEffect::FileWrite | ObservableEffect::WorkflowChange => {
            vec![Capability::FilesystemWrite]
        }
        ObservableEffect::ArtifactPublish => vec![Capability::ArtifactWrite],
        ObservableEffect::CachePublish => vec![Capability::CacheWrite],
        ObservableEffect::DeploymentChange => vec![Capability::Deployment],
        ObservableEffect::CredentialUse => vec![Capability::SecretAccess],
        ObservableEffect::AiAgentExecution => vec![Capability::AiTool],
        ObservableEffect::FileRead | ObservableEffect::CommandExecution => Vec::new(),
    }
}

fn strings(fields: &BTreeMap<String, JsonValue>, name: &str) -> Result<Vec<String>, String> {
    fields
        .get(name)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| format!("dependency summary {name} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("dependency summary {name} must contain strings"))
        })
        .collect()
}

fn unique(values: &[String], name: &str) -> Result<(), String> {
    if values.iter().collect::<BTreeSet<_>>().len() == values.len() {
        Ok(())
    } else {
        Err(format!("dependency summary {name} must be unique"))
    }
}

fn capability(value: &str) -> Option<Capability> {
    Some(match value {
        "repository_read" => Capability::RepositoryRead,
        "repository_write" => Capability::RepositoryWrite,
        "token_read" => Capability::TokenRead,
        "token_write" => Capability::TokenWrite,
        "oidc" => Capability::Oidc,
        "cloud_credential" => Capability::CloudCredential,
        "secret_access" => Capability::SecretAccess,
        "network" => Capability::Network,
        "filesystem_read" => Capability::FilesystemRead,
        "filesystem_write" => Capability::FilesystemWrite,
        "shell" => Capability::Shell,
        "artifact_read" => Capability::ArtifactRead,
        "artifact_write" => Capability::ArtifactWrite,
        "cache_read" => Capability::CacheRead,
        "cache_write" => Capability::CacheWrite,
        "deployment" => Capability::Deployment,
        "self_hosted_persistence" => Capability::SelfHostedPersistence,
        "ai_tool" => Capability::AiTool,
        _ => return None,
    })
}

fn effect(value: &str) -> Option<ObservableEffect> {
    Some(match value {
        "repository_change" => ObservableEffect::RepositoryChange,
        "network_request" => ObservableEffect::NetworkRequest,
        "file_read" => ObservableEffect::FileRead,
        "file_write" => ObservableEffect::FileWrite,
        "command_execution" => ObservableEffect::CommandExecution,
        "artifact_publish" => ObservableEffect::ArtifactPublish,
        "cache_publish" => ObservableEffect::CachePublish,
        "deployment_change" => ObservableEffect::DeploymentChange,
        "credential_use" => ObservableEffect::CredentialUse,
        "workflow_change" => ObservableEffect::WorkflowChange,
        "ai_agent_execution" => ObservableEffect::AiAgentExecution,
        _ => return None,
    })
}
