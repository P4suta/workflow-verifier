use workflow_verifier_cli::resolver_transport::{ResolverRequest, resolve_dependency};
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::Span;
use workflow_verifier_frontend::{Dependency, DependencyKind, DependencyLocator};

fn dependency(provider: Provider, kind: DependencyKind, reference: &str) -> Dependency {
    Dependency::unresolved(
        provider,
        kind,
        reference,
        DependencyLocator::Direct,
        Span::default(),
    )
}

fn located_dependency(
    provider: Provider,
    kind: DependencyKind,
    reference: &str,
    locator: DependencyLocator,
) -> Dependency {
    Dependency::unresolved(provider, kind, reference, locator, Span::default())
}

#[test]
fn github_action_resolves_commit_archive_and_exact_metadata() {
    let revision = "a".repeat(40);
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        requests.push(request.clone());
        if request.url.contains("/repos/actions/checkout/commits/v4") {
            Ok(format!("{revision}\n").into_bytes())
        } else if request
            .url
            .ends_with(&format!("/actions/checkout/tar.gz/{revision}"))
        {
            Ok(b"immutable archive".to_vec())
        } else if request
            .url
            .ends_with(&format!("/actions/checkout/{revision}/action.yml"))
        {
            Ok(b"name: checkout\nruns:\n  using: node20\n  main: dist/index.js\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };

    let fetched = resolve_dependency(
        &dependency(
            Provider::Github,
            DependencyKind::Action,
            "actions/checkout@v4",
        ),
        &mut get,
    )
    .expect("resolve GitHub action");

    assert_eq!(fetched.revision, revision);
    assert_eq!(fetched.content, b"immutable archive");
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|value| value.0.as_str()),
        Some("action.yml")
    );
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "Accept" && value == "application/vnd.github.sha")
    );
}

#[test]
fn gitlab_component_resolves_project_archive_and_template() {
    let revision = "b".repeat(40);
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        requests.push(request.url.clone());
        if request.url.contains("/repository/commits/1.2.3") {
            Ok(format!("{{\"id\":\"{revision}\"}}").into_bytes())
        } else if request.url.contains("/repository/archive.tar.gz?sha=") {
            Ok(b"gitlab archive".to_vec())
        } else if request.url.contains("templates%2Faws%2Ftemplate.yml/raw") {
            Ok(b"deploy:\n  script: echo exact\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };

    let fetched = resolve_dependency(
        &dependency(
            Provider::Gitlab,
            DependencyKind::Component,
            "gitlab.com/acme/components/deploy/aws@1.2.3",
        ),
        &mut get,
    )
    .expect("resolve GitLab component");

    assert_eq!(fetched.revision, revision);
    assert_eq!(fetched.content, b"gitlab archive");
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|value| value.0.as_str()),
        Some("templates/aws/template.yml")
    );
    assert_eq!(requests.len(), 3);
}

#[test]
fn azure_task_resolves_official_task_tree_and_metadata() {
    let revision = "c".repeat(40);
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        requests.push(request.url.clone());
        if request
            .url
            .contains("/repos/microsoft/azure-pipelines-tasks/commits/main")
        {
            Ok(revision.clone().into_bytes())
        } else if request.url.ends_with(&format!("/tar.gz/{revision}")) {
            Ok(b"azure task archive".to_vec())
        } else if request
            .url
            .ends_with(&format!("/{revision}/Tasks/UsePythonVersionV0/task.json"))
        {
            Ok(b"{\"execution\":{\"Node20_1\":{\"target\":\"main.js\"}}}".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };

    let fetched = resolve_dependency(
        &dependency(Provider::Azure, DependencyKind::Task, "UsePythonVersion@0"),
        &mut get,
    )
    .expect("resolve Azure task");

    assert_eq!(fetched.revision, revision);
    assert!(fetched.source.ends_with("/Tasks/UsePythonVersionV0"));
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|value| value.0.as_str()),
        Some("Tasks/UsePythonVersionV0/task.json")
    );
    assert_eq!(requests.len(), 3);
}

#[test]
fn circleci_orb_requires_an_exact_production_version_and_fetches_source() {
    let version_id = "7a09fb7b-4415-4aee-bc0f-a2f7f8395824";
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        requests.push(request.url.clone());
        if request.url.contains("/api/v3/orb/versions?") {
            Ok(format!(
                "{{\"data\":[{{\"attributes\":{{\"version\":\"5.0.3\"}},\"id\":\"{version_id}\"}}]}}"
            )
            .into_bytes())
        } else if request.url.ends_with(&format!("/{version_id}/source")) {
            Ok(b"version: 2.1\ncommands: {}\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };

    let fetched = resolve_dependency(
        &dependency(
            Provider::Circleci,
            DependencyKind::Orb,
            "circleci/node@5.0.3",
        ),
        &mut get,
    )
    .expect("resolve CircleCI orb");

    assert_eq!(fetched.revision, "5.0.3");
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|value| value.0.as_str()),
        Some(".circleci/config.yml")
    );
    assert!(
        resolve_dependency(
            &dependency(Provider::Circleci, DependencyKind::Orb, "circleci/node@5",),
            &mut get,
        )
        .is_err()
    );
    assert_eq!(requests.len(), 2);
}

#[test]
fn gitlab_repository_file_uses_the_declared_project_revision_and_path() {
    let revision = "d".repeat(40);
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        requests.push(request.url.clone());
        if request
            .url
            .contains(&format!("/repository/commits/{revision}"))
        {
            Ok(format!("{{\"id\":\"{revision}\"}}").into_bytes())
        } else if request.url.contains("archive.tar.gz?sha=") {
            Ok(b"project include archive".to_vec())
        } else if request
            .url
            .contains("repository/files/templates%2Fbuild.yml/raw")
        {
            Ok(b"build:\n  script: echo exact\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };
    let dependency = located_dependency(
        Provider::Gitlab,
        DependencyKind::Repository,
        &format!("acme/ci:/templates/build.yml@{revision}"),
        DependencyLocator::RepositoryFile {
            repository: "acme/ci".to_owned(),
            revision: Some(revision.clone()),
            path: "/templates/build.yml".to_owned(),
            repository_type: None,
        },
    );

    let fetched = resolve_dependency(&dependency, &mut get).expect("resolve GitLab include");

    assert_eq!(fetched.revision, revision);
    assert!(
        fetched
            .source
            .ends_with(&format!("/{}/templates/build.yml", fetched.revision))
    );
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|source| source.0.as_str()),
        Some("templates/build.yml")
    );
    assert_eq!(requests.len(), 3);
}

#[test]
fn azure_repository_locators_support_github_and_native_repositories() {
    let github_revision = "e".repeat(40);
    let mut github_requests = Vec::new();
    let mut github_get = |request: &ResolverRequest| {
        github_requests.push(request.url.clone());
        if request
            .url
            .contains("/repos/org/templates/commits/refs%2Ftags%2Fv1")
        {
            Ok(github_revision.clone().into_bytes())
        } else if request.url.ends_with(&format!("/tar.gz/{github_revision}")) {
            Ok(b"GitHub template archive".to_vec())
        } else if request
            .url
            .ends_with(&format!("/{github_revision}/shared.yml"))
        {
            Ok(b"steps:\n  - script: echo exact\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };
    let github = located_dependency(
        Provider::Azure,
        DependencyKind::Template,
        "shared.yml@shared",
        DependencyLocator::RepositoryFile {
            repository: "org/templates".to_owned(),
            revision: Some("refs/tags/v1".to_owned()),
            path: "shared.yml".to_owned(),
            repository_type: Some("github".to_owned()),
        },
    );
    let fetched = resolve_dependency(&github, &mut github_get).expect("resolve GitHub alias");
    assert_eq!(fetched.revision, github_revision);
    assert_eq!(github_requests.len(), 3);

    let native_revision = "f".repeat(40);
    let mut native_requests = Vec::new();
    let mut native_get = |request: &ResolverRequest| {
        native_requests.push(request.url.clone());
        if request.url.contains("/commits?") {
            Ok(format!("{{\"value\":[{{\"commitId\":\"{native_revision}\"}}]}}").into_bytes())
        } else if request.url.contains("recursionLevel=Full") {
            Ok(b"Azure Repos archive".to_vec())
        } else if request.url.contains("path=%2Fshared.yml") {
            Ok(b"steps:\n  - script: echo exact\n".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };
    let native = located_dependency(
        Provider::Azure,
        DependencyKind::Template,
        "shared.yml@templates",
        DependencyLocator::RepositoryFile {
            repository: "org/project/templates".to_owned(),
            revision: Some("refs/tags/v1".to_owned()),
            path: "shared.yml".to_owned(),
            repository_type: Some("azurereposgit".to_owned()),
        },
    );
    let fetched = resolve_dependency(&native, &mut native_get).expect("resolve Azure Repos alias");
    assert_eq!(fetched.revision, native_revision);
    assert_eq!(
        fetched
            .semantic_source
            .as_ref()
            .map(|source| source.0.as_str()),
        Some("shared.yml")
    );
    assert_eq!(native_requests.len(), 3);
}

#[test]
fn container_images_resolve_tags_and_redact_registry_tokens_from_debug_output() {
    let token = "registry-secret-value";
    let mut requests = Vec::new();
    let mut get = |request: &ResolverRequest| {
        assert!(!format!("{request:?}").contains(token));
        requests.push(request.clone());
        if request.url.starts_with("https://auth.docker.io/token?") {
            Ok(format!("{{\"token\":\"{token}\"}}").into_bytes())
        } else if request
            .url
            .starts_with("https://registry-1.docker.io/v2/library/alpine/manifests/")
        {
            assert!(request.headers.iter().any(
                |(name, value)| name == "Authorization" && value == &format!("Bearer {token}")
            ));
            Ok(b"immutable manifest".to_vec())
        } else {
            Err(format!("unexpected URL {}", request.url))
        }
    };
    let tagged = dependency(
        Provider::Circleci,
        DependencyKind::ContainerImage,
        "alpine:3.20",
    );

    let fetched = resolve_dependency(&tagged, &mut get).expect("resolve image tag");

    assert!(fetched.revision.starts_with("sha256:"));
    assert_eq!(fetched.content, b"immutable manifest");
    assert!(
        fetched
            .source
            .starts_with("oci://registry-1.docker.io/library/alpine@sha256:")
    );
    let digest = format!("sha256:{}", "1".repeat(64));
    let pinned = dependency(
        Provider::Github,
        DependencyKind::ContainerImage,
        &format!("docker://alpine@{digest}"),
    );
    let fetched = resolve_dependency(&pinned, &mut get).expect("accept pinned image");
    assert_eq!(fetched.revision, digest);
    assert_eq!(requests.len(), 2, "pinned image must stay offline");
}
