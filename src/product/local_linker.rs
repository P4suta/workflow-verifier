use crate::domain::{AbstractValue, Node, NodeKind, Provenance, Provider, Secrecy, Trust};
use crate::foundation::{Budget, Span, content_digest, normalize_slashes};
use crate::frontend::{
    Compilation, Dependency, DependencyKind, DependencyStatus, Mutability, compile,
};
use std::collections::{BTreeMap, BTreeSet};

type ResolutionKey = (Provider, String, DependencyKind, String);

/// Recursively compile and content-address local dependencies without touching
/// the filesystem. Every candidate must already be present in `sources`.
///
/// # Errors
/// Rejects paths that escape the snapshot, ambiguous action metadata, and
/// malformed local documents.
pub fn link_local<S: AsRef<str>>(
    sources: &BTreeMap<String, S>,
    roots: Vec<Compilation>,
    budget: Budget,
) -> Result<Vec<Compilation>, Vec<String>> {
    let sources = normalized_sources(sources)?;
    let mut compilations = roots;
    let mut seen: BTreeSet<(Provider, String)> = compilations
        .iter()
        .map(|compilation| {
            (
                compilation.provider,
                normalize(compilation.graph.source_path()),
            )
        })
        .collect();
    let mut resolutions: BTreeMap<ResolutionKey, String> = BTreeMap::new();
    let mut local_intents = BTreeSet::new();
    let mut index = 0;
    while index < compilations.len() {
        let provider = compilations[index].provider;
        let caller = normalize(compilations[index].graph.source_path());
        let dependencies = compilations[index].dependencies.clone();
        for dependency in &dependencies {
            let Some(candidates) = local_candidates(&caller, dependency)? else {
                continue;
            };
            let key = resolution_key(provider, &caller, dependency);
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
            let target_key = (provider, target.clone());
            if seen.insert(target_key) {
                let Some(source) = sources.get(target) else {
                    return Err(vec!["local source index changed during linking".to_owned()]);
                };
                let target_compilation =
                    compile(provider, target, source, budget).map_err(|problems| {
                        problems
                            .into_iter()
                            .map(|problem| format!("{}: {}", problem.code, problem.message))
                            .collect::<Vec<_>>()
                    })?;
                compilations.push(target_compilation);
            }
        }
        index = index.saturating_add(1);
    }
    for compilation in &mut compilations {
        apply_resolutions(compilation, &sources, &resolutions, &local_intents)?;
    }
    compilations.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.graph.source_path().cmp(right.graph.source_path()))
    });
    Ok(compilations)
}

fn normalized_sources<S: AsRef<str>>(
    sources: &BTreeMap<String, S>,
) -> Result<BTreeMap<String, &str>, Vec<String>> {
    let mut output = BTreeMap::new();
    for (path, source) in sources {
        let normalized = normalize_relative(path)
            .ok_or_else(|| vec![format!("workspace source path escapes the root: {path}")])?;
        if output.insert(normalized.clone(), source.as_ref()).is_some() {
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

fn apply_resolutions<S: AsRef<str>>(
    compilation: &mut Compilation,
    sources: &BTreeMap<String, S>,
    resolutions: &BTreeMap<ResolutionKey, String>,
    local_intents: &BTreeSet<ResolutionKey>,
) -> Result<(), Vec<String>> {
    let caller = normalize(compilation.graph.source_path());
    for dependency in &mut compilation.dependencies {
        let key = resolution_key(compilation.provider, &caller, dependency);
        if let Some(target) = resolutions.get(&key) {
            let Some(source) = sources.get(target) else {
                return Err(vec!["local source index changed during linking".to_owned()]);
            };
            dependency.mutability = Mutability::Local;
            dependency.status = DependencyStatus::Locked {
                revision: format!("local:{target}"),
                digest: content_digest(source.as_ref()),
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
            local_evidence("local digest", &content_digest(source.as_ref())),
        );
        node.unknown = None;
    }
    compilation.graph.finalize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::DependencyLocator;

    fn dependency(provider: Provider, kind: DependencyKind, reference: &str) -> Dependency {
        Dependency::unresolved(
            provider,
            kind,
            reference,
            DependencyLocator::Direct,
            Span::default(),
        )
    }

    #[test]
    fn workspace_path_helpers_are_platform_neutral_and_fail_closed() {
        assert_eq!(normalize("./a\\b.yml"), "a/b.yml");
        assert_eq!(normalize("././a.yml"), "a.yml");
        assert_eq!(
            normalize_relative("./a//b/../c.yml"),
            Some("a/c.yml".to_owned())
        );
        assert_eq!(normalize_relative("a/../../escape.yml"), None);
        assert_eq!(normalize_relative("../escape.yml"), None);
        assert_eq!(dirname("a/b/file.yml"), "a/b");
        assert_eq!(dirname("file.yml"), "");
        for path in ["a.yml", "a.YML", "a.yaml", "a.YaMl"] {
            assert!(yaml_extension(path), "YAML extension {path:?}");
        }
        for path in ["a", "a.json", "a.yml.txt"] {
            assert!(!yaml_extension(path), "non-YAML extension {path:?}");
        }

        let sources = BTreeMap::from([
            ("a/./b.yml".to_owned(), "first".to_owned()),
            ("a/b.yml".to_owned(), "second".to_owned()),
        ]);
        assert!(normalized_sources(&sources).is_err());
        assert!(
            normalized_sources(&BTreeMap::from([(
                "../escape.yml".to_owned(),
                "source".to_owned(),
            )]))
            .is_err()
        );
    }

    #[test]
    fn provider_local_candidates_cover_every_accepted_and_remote_shape() {
        let github_directory = dependency(Provider::Github, DependencyKind::Action, "./action");
        assert_eq!(
            local_candidates(".github/workflows/ci.yml", &github_directory),
            Ok(Some(vec![
                "action/action.yml".to_owned(),
                "action/action.yaml".to_owned(),
            ]))
        );
        let github_file = dependency(Provider::Github, DependencyKind::Action, "./action.YML");
        assert_eq!(
            local_candidates(".github/workflows/ci.yml", &github_file),
            Ok(Some(vec!["action.YML".to_owned()]))
        );
        for reference in ["owner/action@main", "action", "https://example.test/action"] {
            assert_eq!(
                local_candidates(
                    ".github/workflows/ci.yml",
                    &dependency(Provider::Github, DependencyKind::Action, reference),
                ),
                Ok(None)
            );
        }
        assert!(
            local_candidates(
                ".github/workflows/ci.yml",
                &dependency(Provider::Github, DependencyKind::Action, "../../../escape"),
            )
            .is_err()
        );

        for (reference, expected) in [
            ("include.yml", "include.yml"),
            ("/root", "root"),
            ("./relative", "relative"),
        ] {
            assert_eq!(
                local_candidates(
                    ".gitlab-ci.yml",
                    &dependency(Provider::Gitlab, DependencyKind::Include, reference),
                ),
                Ok(Some(vec![expected.to_owned()]))
            );
        }
        for reference in [
            "plain",
            "https://example.test/include.yml",
            "component@example",
        ] {
            assert_eq!(
                local_candidates(
                    ".gitlab-ci.yml",
                    &dependency(Provider::Gitlab, DependencyKind::Include, reference),
                ),
                Ok(None)
            );
        }
        assert!(
            local_candidates(
                ".gitlab-ci.yml",
                &dependency(Provider::Gitlab, DependencyKind::Include, "../parent"),
            )
            .is_err()
        );

        let azure = |reference| {
            local_candidates(
                "pipelines/root.yml",
                &dependency(Provider::Azure, DependencyKind::Template, reference),
            )
        };
        assert_eq!(
            azure("steps.yml"),
            Ok(Some(vec!["pipelines/steps.yml".to_owned()]))
        );
        assert_eq!(
            azure("/shared/steps.yml"),
            Ok(Some(vec!["shared/steps.yml".to_owned()]))
        );
        assert_eq!(
            azure("steps.yml@SELF"),
            Ok(Some(vec!["pipelines/steps.yml".to_owned()]))
        );
        assert_eq!(azure("steps.yml@external"), Ok(None));
        assert_eq!(azure("${{ parameters.template }}"), Ok(None));
        assert_eq!(
            local_candidates(
                "pipelines/root.yml",
                &dependency(Provider::Azure, DependencyKind::Task, "steps.yml"),
            ),
            Ok(None)
        );
    }

    #[test]
    fn evidence_and_call_matching_do_not_cross_semantic_identity() {
        let evidence = local_evidence("local digest", "sha256:value");
        assert_eq!(evidence.trust, Trust::Trusted);
        assert_eq!(evidence.secrecy, Secrecy::Public);
        assert_eq!(evidence.constants(), Some(&["sha256:value".to_owned()][..]));
        assert_eq!(evidence.provenance.len(), 1);
        assert_eq!(evidence.provenance[0].origin, "workspace source");
        assert_eq!(evidence.provenance[0].operation, "local digest");

        let direct = Node::simple(
            Provider::Github,
            NodeKind::Call,
            "./action",
            crate::domain::Phase::Run,
            Span::default(),
        );
        let child = Node::simple(
            Provider::Gitlab,
            NodeKind::Call,
            "child:include.yml",
            crate::domain::Phase::Run,
            Span::default(),
        );
        assert!(call_matches(&direct, "./action"));
        assert!(call_matches(&child, "include.yml"));
        assert!(!call_matches(&direct, "include.yml"));
        assert!(!call_matches(&child, "./action"));
    }

    #[test]
    fn ambiguous_action_metadata_is_rejected_and_missing_local_source_stays_explicit() {
        let workflow = "on: push\njobs:\n  build:\n    steps:\n      - uses: ./action\n";
        let root = compile(
            Provider::Github,
            ".github/workflows/ci.yml",
            workflow,
            Budget::default(),
        )
        .expect("root workflow");
        let ambiguous = BTreeMap::from([
            (".github/workflows/ci.yml".to_owned(), workflow.to_owned()),
            (
                "action/action.yml".to_owned(),
                "name: first\nruns:\n  using: composite\n  steps: []\n".to_owned(),
            ),
            (
                "action/action.yaml".to_owned(),
                "name: second\nruns:\n  using: composite\n  steps: []\n".to_owned(),
            ),
        ]);
        assert!(link_local(&ambiguous, vec![root.clone()], Budget::default()).is_err());

        let linked = link_local(
            &BTreeMap::<String, String>::new(),
            vec![root],
            Budget::default(),
        )
        .expect("missing source remains unresolved");
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].dependencies[0].mutability, Mutability::Local);
        assert!(matches!(
            linked[0].dependencies[0].status,
            DependencyStatus::Unresolved(_)
        ));
        let call = linked[0]
            .graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Call)
            .expect("local call");
        assert!(call.unknown.is_some());
        assert!(!call.attributes.contains_key("dependency.digest"));
    }

    #[test]
    fn resolution_application_requires_both_provider_and_owner_identity() {
        let workflow = "on: push\njobs:\n  build:\n    steps:\n      - uses: ./action.yml\n";
        let original = compile(
            Provider::Github,
            ".github/workflows/ci.yml",
            workflow,
            Budget::default(),
        )
        .expect("root workflow");
        let sources = BTreeMap::from([(
            "action.yml".to_owned(),
            "name: action\nruns:\n  using: composite\n  steps: []\n".to_owned(),
        )]);
        let dependency = original.dependencies.first().expect("local dependency");
        let wrong_keys = [
            resolution_key(Provider::Gitlab, ".github/workflows/ci.yml", dependency),
            resolution_key(Provider::Github, "other/workflow.yml", dependency),
        ];
        for wrong_key in wrong_keys {
            let mut compilation = original.clone();
            apply_resolutions(
                &mut compilation,
                &sources,
                &BTreeMap::from([(wrong_key, "action.yml".to_owned())]),
                &BTreeSet::new(),
            )
            .expect("unrelated resolution is ignored");
            let call = compilation
                .graph
                .nodes
                .iter()
                .find(|node| node.kind == NodeKind::Call)
                .expect("call node");
            assert!(call.unknown.is_some());
            assert!(!call.attributes.contains_key("dependency.digest"));
        }
    }
}
