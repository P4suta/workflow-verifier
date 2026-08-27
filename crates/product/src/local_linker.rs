use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::{
    AbstractValue, Node, NodeKind, Provenance, Provider, Secrecy, Trust,
};
use workflow_verifier_foundation::{Budget, Span, content_digest, normalize_slashes};
use workflow_verifier_frontend::{
    Compilation, Dependency, DependencyKind, DependencyStatus, Mutability, compile,
};

type ResolutionKey = (Provider, String, DependencyKind, String);

/// Recursively compile and content-address local dependencies without touching
/// the filesystem. Every candidate must already be present in `sources`.
///
/// # Errors
/// Rejects paths that escape the snapshot, ambiguous action metadata, and
/// malformed local documents.
pub fn link_local(
    sources: &BTreeMap<String, String>,
    roots: Vec<Compilation>,
    budget: Budget,
) -> Result<Vec<Compilation>, Vec<String>> {
    let sources = normalized_sources(sources)?;
    let mut compilations = roots;
    let mut seen: BTreeSet<(Provider, String)> = compilations
        .iter()
        .map(|compilation| (compilation.provider, normalize(&compilation.graph.source)))
        .collect();
    let mut resolutions: BTreeMap<ResolutionKey, String> = BTreeMap::new();
    let mut local_intents = BTreeSet::new();
    let mut index = 0;
    while index < compilations.len() {
        let compilation = compilations[index].clone();
        let caller = normalize(&compilation.graph.source);
        for dependency in &compilation.dependencies {
            let Some(candidates) = local_candidates(&caller, dependency)? else {
                continue;
            };
            let key = resolution_key(compilation.provider, &caller, dependency);
            local_intents.insert(key.clone());
            let matches: Vec<_> = candidates
                .into_iter()
                .filter(|candidate| sources.contains_key(candidate))
                .collect();
            if matches.len() > 1 {
                return Err(vec![format!(
                    "local dependency is ambiguous: {}",
                    dependency.reference
                )]);
            }
            let Some(target) = matches.first() else {
                continue;
            };
            resolutions.insert(key, target.clone());
            let target_key = (compilation.provider, target.clone());
            if seen.insert(target_key) {
                let Some(source) = sources.get(target) else {
                    return Err(vec!["local source index changed during linking".to_owned()]);
                };
                let target_compilation = compile(compilation.provider, target, source, budget)
                    .map_err(|problems| {
                        problems
                            .into_iter()
                            .map(|problem| format!("{}: {}", problem.code, problem.message))
                            .collect::<Vec<_>>()
                    })?;
                compilations.push(target_compilation);
            }
        }
        index += 1;
    }
    for compilation in &mut compilations {
        apply_resolutions(compilation, &sources, &resolutions, &local_intents)?;
    }
    compilations.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.graph.source.cmp(&right.graph.source))
    });
    Ok(compilations)
}

fn normalized_sources(
    sources: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Vec<String>> {
    let mut output = BTreeMap::new();
    for (path, source) in sources {
        let normalized = normalize_relative(path)
            .ok_or_else(|| vec![format!("workspace source path escapes the root: {path}")])?;
        if output.insert(normalized.clone(), source.clone()).is_some() {
            return Err(vec![format!(
                "duplicate normalized source path: {normalized}"
            )]);
        }
    }
    Ok(output)
}

fn normalize(value: &str) -> String {
    normalize_slashes(value).trim_start_matches("./").to_owned()
}

fn normalize_relative(value: &str) -> Option<String> {
    let normalized = normalize_slashes(value);
    let mut stack = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop()?;
            }
            value => stack.push(value),
        }
    }
    Some(stack.join("/"))
}

fn dirname(value: &str) -> &str {
    value.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn yaml_extension(value: &str) -> bool {
    std::path::Path::new(value)
        .extension()
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
        })
}

fn local_candidates(
    caller: &str,
    dependency: &Dependency,
) -> Result<Option<Vec<String>>, Vec<String>> {
    let reference = normalize_slashes(&dependency.reference);
    let raw = match (dependency.provider, dependency.kind) {
        (Provider::Github, DependencyKind::Action)
            if reference.starts_with("./") || reference.starts_with("../") =>
        {
            let value = reference.trim_start_matches("./");
            if yaml_extension(value) {
                Some(vec![value.to_owned()])
            } else {
                Some(vec![
                    format!("{value}/action.yml"),
                    format!("{value}/action.yaml"),
                ])
            }
        }
        (Provider::Gitlab, DependencyKind::Include)
            if !reference.contains("://")
                && !reference.contains('@')
                && (yaml_extension(&reference)
                    || reference.starts_with('/')
                    || reference.starts_with("./")
                    || reference.starts_with("../")) =>
        {
            Some(vec![reference.trim_start_matches('/').to_owned()])
        }
        (Provider::Azure, DependencyKind::Template) => {
            let template = match reference.rsplit_once('@') {
                Some((path, alias)) if alias.eq_ignore_ascii_case("self") => path,
                Some(_) => return Ok(None),
                None => reference.as_str(),
            };
            if template.contains("${{") {
                return Ok(None);
            }
            if template.starts_with('/') {
                Some(vec![template.trim_start_matches('/').to_owned()])
            } else {
                let parent = dirname(caller);
                Some(vec![if parent.is_empty() {
                    template.to_owned()
                } else {
                    format!("{parent}/{template}")
                }])
            }
        }
        _ => None,
    };
    raw.map(|values| {
        values
            .into_iter()
            .map(|candidate| {
                normalize_relative(&candidate).ok_or_else(|| {
                    vec![format!(
                        "local dependency escapes the workspace: {}",
                        dependency.reference
                    )]
                })
            })
            .collect()
    })
    .transpose()
}

fn resolution_key(provider: Provider, caller: &str, dependency: &Dependency) -> ResolutionKey {
    (
        provider,
        caller.to_owned(),
        dependency.kind,
        dependency.reference.clone(),
    )
}

fn local_evidence(operation: &str, value: &str) -> AbstractValue {
    AbstractValue::string_constant(
        value,
        Trust::Trusted,
        Secrecy::Public,
        vec![Provenance {
            origin: "workspace source".to_owned(),
            span: Span::default(),
            operation: operation.to_owned(),
        }],
    )
}

fn call_matches(node: &Node, reference: &str) -> bool {
    node.name == reference || node.name == format!("child:{reference}")
}

fn apply_resolutions(
    compilation: &mut Compilation,
    sources: &BTreeMap<String, String>,
    resolutions: &BTreeMap<ResolutionKey, String>,
    local_intents: &BTreeSet<ResolutionKey>,
) -> Result<(), Vec<String>> {
    let caller = normalize(&compilation.graph.source);
    for dependency in &mut compilation.dependencies {
        let key = resolution_key(compilation.provider, &caller, dependency);
        if let Some(target) = resolutions.get(&key) {
            let Some(source) = sources.get(target) else {
                return Err(vec!["local source index changed during linking".to_owned()]);
            };
            dependency.mutability = Mutability::Local;
            dependency.status = DependencyStatus::Locked {
                revision: format!("local:{target}"),
                digest: content_digest(source),
            };
        } else if local_intents.contains(&key) {
            dependency.mutability = Mutability::Local;
        }
    }
    for node in &mut compilation.graph.nodes {
        if node.kind != NodeKind::Call {
            continue;
        }
        let Some((_, target)) = resolutions
            .iter()
            .find(|((provider, owner, _, reference), _)| {
                *provider == compilation.provider
                    && owner == &caller
                    && call_matches(node, reference)
            })
        else {
            continue;
        };
        let Some(source) = sources.get(target) else {
            return Err(vec!["local source index changed during linking".to_owned()]);
        };
        let revision = format!("local:{target}");
        node.attributes.insert(
            "dependency.source".to_owned(),
            local_evidence("local source", &revision),
        );
        node.attributes.insert(
            "dependency.revision".to_owned(),
            local_evidence("local revision", &revision),
        );
        node.attributes.insert(
            "dependency.digest".to_owned(),
            local_evidence("local digest", &content_digest(source)),
        );
        node.unknown = None;
    }
    compilation.graph.finalize();
    Ok(())
}
