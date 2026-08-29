//! Deterministic provider request composition for immutable dependency resolution.

use crate::domain::Provider;
use crate::foundation::{GIT_SHA1_HEX_DIGITS, JsonValue, SHA256_HEX_DIGITS, content_digest};
use crate::frontend::{Dependency, DependencyKind, DependencyLocator};
use crate::product::FetchedDependency;

#[derive(Clone, Eq, PartialEq)]
pub struct ResolverRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub credential_provider: Option<Provider>,
}

impl std::fmt::Debug for ResolverRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "authorization" | "cookie" | "private-token"
                ) {
                    (name.as_str(), "[REDACTED]")
                } else {
                    (name.as_str(), value.as_str())
                }
            })
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ResolverRequest")
            .field("url", &self.url)
            .field("headers", &headers)
            .field("credential_provider", &self.credential_provider)
            .finish()
    }
}

pub trait ResolverGet {
    /// Fetch one already-policy-checked HTTPS resource.
    ///
    /// # Errors
    /// Returns a redacted transport or protocol failure.
    fn get(&mut self, request: &ResolverRequest) -> Result<Vec<u8>, String>;
}

impl<F> ResolverGet for F
where
    F: FnMut(&ResolverRequest) -> Result<Vec<u8>, String>,
{
    fn get(&mut self, request: &ResolverRequest) -> Result<Vec<u8>, String> {
        self(request)
    }
}

/// Resolve one typed provider dependency to immutable bytes.
///
/// # Errors
/// Rejects malformed identities, mutable provider responses, invalid strict
/// JSON, empty bodies, and dependency kinds without a safe resolver.
pub fn resolve_dependency(
    dependency: &Dependency,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    match (dependency.provider, dependency.kind, &dependency.locator) {
        (_, DependencyKind::ContainerImage, _) => container_image(&dependency.reference, get),
        (
            Provider::Gitlab,
            _,
            DependencyLocator::RepositoryFile {
                repository,
                revision,
                path,
                ..
            },
        ) => gitlab_repository_file(repository, revision.as_deref(), path, get),
        (
            Provider::Azure,
            _,
            DependencyLocator::RepositoryFile {
                repository,
                revision,
                path,
                repository_type,
            },
        ) => azure_repository_locator(
            repository,
            revision.as_deref(),
            path,
            repository_type.as_deref(),
            get,
        ),
        (
            Provider::Azure,
            _,
            DependencyLocator::RepositorySource {
                repository,
                revision,
                repository_type,
            },
        ) => azure_repository_locator(
            repository,
            revision.as_deref(),
            "",
            repository_type.as_deref(),
            get,
        ),
        (
            Provider::Github,
            DependencyKind::Action | DependencyKind::Repository | DependencyKind::Template,
            _,
        ) => github_action(&dependency.reference, get),
        (Provider::Gitlab, DependencyKind::Component, _) => {
            gitlab_component(&dependency.reference, get)
        }
        (Provider::Azure, DependencyKind::Task, _) => azure_task(&dependency.reference, get),
        (Provider::Circleci, DependencyKind::Orb, _) => circleci_orb(&dependency.reference, get),
        (_, _, _) if dependency.reference.starts_with("https://") => direct_https(dependency, get),
        _ => Err(format!(
            "no safe resolver for {} dependency {}",
            dependency.kind.name(),
            dependency.reference
        )),
    }
}

fn request(
    get: &mut dyn ResolverGet,
    provider: Provider,
    url: String,
    headers: Vec<(String, String)>,
) -> Result<Vec<u8>, String> {
    request_scoped(get, Some(provider), url, headers)
}

fn request_scoped(
    get: &mut dyn ResolverGet,
    credential_provider: Option<Provider>,
    url: String,
    headers: Vec<(String, String)>,
) -> Result<Vec<u8>, String> {
    let request = ResolverRequest {
        url,
        headers,
        credential_provider,
    };
    let response = get.get(&request)?;
    if response.is_empty() {
        Err(format!(
            "resolver returned empty content for {}",
            request.url
        ))
    } else {
        Ok(response)
    }
}

fn split_revision(reference: &str) -> Result<(&str, &str), String> {
    let Some(index) = reference.rfind('@') else {
        return Err(format!("dependency has no revision: {reference}"));
    };
    let identity = &reference[..index];
    let revision = &reference[index + 1..];
    if identity.is_empty() || revision.is_empty() {
        Err(format!(
            "dependency has an empty identity or revision: {reference}"
        ))
    } else {
        Ok((identity, revision))
    }
}

fn url_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .filter(|part| !part.is_empty())
        .map(url_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn components(value: &str) -> Vec<&str> {
    value.split('/').filter(|part| !part.is_empty()).collect()
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn commit_digest(source: &[u8]) -> Result<String, String> {
    let source = std::str::from_utf8(source)
        .map_err(|_| "resolver returned a non-UTF-8 commit digest".to_owned())?
        .trim();
    let candidate = if source.starts_with('{') {
        let parsed = JsonValue::parse(source).map_err(|error| error.to_string())?;
        member_string(&parsed, "sha")?.to_owned()
    } else {
        source.to_owned()
    };
    if matches!(candidate.len(), GIT_SHA1_HEX_DIGITS | SHA256_HEX_DIGITS)
        && candidate.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(candidate.to_ascii_lowercase())
    } else {
        Err("resolver returned an invalid commit digest".to_owned())
    }
}

fn member_string<'a>(value: &'a JsonValue, name: &str) -> Result<&'a str, String> {
    value
        .member(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("resolver response has no string field {name}"))
}

fn github_action(reference: &str, get: &mut dyn ResolverGet) -> Result<FetchedDependency, String> {
    let (identity, requested) = split_revision(reference)?;
    let parts = components(identity);
    let [owner, repository, path @ ..] = parts.as_slice() else {
        return Err(format!("invalid GitHub dependency reference: {reference}"));
    };
    if !valid_component(owner)
        || !valid_component(repository)
        || !path.iter().all(|value| valid_component(value))
    {
        return Err(format!("invalid GitHub dependency reference: {reference}"));
    }
    let path = path.join("/");
    let semantic_paths = if yaml_path(&path) {
        vec![path.clone()]
    } else {
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        vec![
            format!("{prefix}action.yml"),
            format!("{prefix}action.yaml"),
        ]
    };
    resolve_github_repository(owner, repository, &path, requested, &semantic_paths, get)
}

fn resolve_github_repository(
    owner: &str,
    repository: &str,
    path: &str,
    requested: &str,
    semantic_paths: &[String],
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let api = format!(
        "https://api.github.com/repos/{}/{}/commits/{}",
        url_encode(owner),
        url_encode(repository),
        url_encode(requested)
    );
    let commit = commit_digest(&request(
        get,
        Provider::Github,
        api,
        vec![
            ("Accept".to_owned(), "application/vnd.github.sha".to_owned()),
            ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
        ],
    )?)?;
    let archive_url = format!(
        "https://codeload.github.com/{}/{}/tar.gz/{commit}",
        url_encode(owner),
        url_encode(repository)
    );
    let archive = request(get, Provider::Github, archive_url, Vec::new())?;
    let semantic_source = semantic_paths.iter().find_map(|candidate| {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{commit}/{}",
            url_encode(owner),
            url_encode(repository),
            encode_path(candidate)
        );
        request(get, Provider::Github, url, Vec::new())
            .ok()
            .map(|source| (candidate.clone(), source))
    });
    let suffix = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    Ok(FetchedDependency {
        revision: commit.clone(),
        content: archive,
        source: format!("https://github.com/{owner}/{repository}/tree/{commit}{suffix}"),
        semantic_source,
    })
}

fn gitlab_component(
    reference: &str,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let (identity, requested) = split_revision(reference)?;
    let parts = components(identity);
    let Some((component, project_parts)) = parts.split_last() else {
        return Err(format!("invalid GitLab component reference: {reference}"));
    };
    let Some((host, project_parts)) = project_parts.split_first() else {
        return Err(format!("invalid GitLab component reference: {reference}"));
    };
    if project_parts.len() < 2
        || !valid_component(host)
        || !valid_component(component)
        || !project_parts.iter().all(|value| valid_component(value))
    {
        return Err(format!("invalid GitLab component reference: {reference}"));
    }
    gitlab_project(
        host,
        &project_parts.join("/"),
        requested,
        &format!("templates/{component}"),
        get,
    )
}

fn gitlab_project(
    host: &str,
    project: &str,
    requested: &str,
    path: &str,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    if !valid_component(host)
        || components(project).len() < 2
        || !components(project)
            .iter()
            .all(|value| valid_component(value))
    {
        return Err("invalid GitLab project locator".to_owned());
    }
    let base = format!("https://{host}/api/v4/projects/{}", url_encode(project));
    let commit_url = format!("{base}/repository/commits/{}", url_encode(requested));
    let response = request(get, Provider::Gitlab, commit_url, Vec::new())?;
    let parsed = JsonValue::parse_bytes(&response).map_err(|error| error.to_string())?;
    let revision = member_string(&parsed, "id")?;
    if revision.len() != GIT_SHA1_HEX_DIGITS
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("GitLab returned an invalid commit digest".to_owned());
    }
    let revision = revision.to_ascii_lowercase();
    let archive = request(
        get,
        Provider::Gitlab,
        format!("{base}/repository/archive.tar.gz?sha={revision}"),
        Vec::new(),
    )?;
    let normalized_path = path.trim_start_matches('/');
    let candidates = if normalized_path.is_empty() {
        Vec::new()
    } else if yaml_path(normalized_path) {
        vec![normalized_path.to_owned()]
    } else {
        vec![
            format!("{normalized_path}/template.yml"),
            format!("{normalized_path}.yml"),
        ]
    };
    let semantic_source = candidates.iter().find_map(|candidate| {
        request(
            get,
            Provider::Gitlab,
            format!(
                "{base}/repository/files/{}/raw?ref={}",
                url_encode(candidate),
                url_encode(&revision)
            ),
            Vec::new(),
        )
        .ok()
        .map(|source| (candidate.clone(), source))
    });
    let suffix = if normalized_path.is_empty() {
        String::new()
    } else {
        format!("/{normalized_path}")
    };
    Ok(FetchedDependency {
        revision: revision.clone(),
        content: archive,
        source: format!("https://{host}/{project}/-/tree/{revision}{suffix}"),
        semantic_source,
    })
}

fn gitlab_repository_file(
    repository: &str,
    revision: Option<&str>,
    path: &str,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let requested =
        revision.ok_or_else(|| "GitLab project include has no immutable revision".to_owned())?;
    let parts = components(repository);
    let (host, project) = match parts.split_first() {
        Some((host, rest)) if host.contains('.') => (*host, rest.join("/")),
        _ => ("gitlab.com", repository.to_owned()),
    };
    gitlab_project(host, &project, requested, path, get)
}

fn yaml_path(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
        })
}

fn azure_repository_parts(repository: &str) -> Option<(String, String, String)> {
    let parts = components(repository);
    match parts.as_slice() {
        [
            "https:",
            "dev.azure.com",
            organization,
            project,
            "_git",
            repository,
        ]
        | [organization, project, repository] => Some((
            (*organization).to_owned(),
            (*project).to_owned(),
            (*repository).to_owned(),
        )),
        _ => None,
    }
}

fn azure_repository(
    repository: &str,
    requested: &str,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let (organization, project, name) = azure_repository_parts(repository)
        .ok_or_else(|| format!("invalid Azure repository reference: {repository}@{requested}"))?;
    let base = format!(
        "https://dev.azure.com/{}/{}/_apis/git/repositories/{}",
        url_encode(&organization),
        url_encode(&project),
        url_encode(&name)
    );
    let commits = format!(
        "{base}/commits?searchCriteria.itemVersion.version={}&searchCriteria.%24top=1&api-version=7.1",
        url_encode(requested)
    );
    let response = request(get, Provider::Azure, commits, Vec::new())?;
    let parsed = JsonValue::parse_bytes(&response).map_err(|error| error.to_string())?;
    let values = parsed
        .member("value")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "Azure repository response contains no commit".to_owned())?;
    let commit = values
        .first()
        .ok_or_else(|| "Azure repository response contains no commit".to_owned())?;
    let revision = member_string(commit, "commitId")?;
    if revision.len() != GIT_SHA1_HEX_DIGITS
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Azure returned an invalid commit digest".to_owned());
    }
    let revision = revision.to_ascii_lowercase();
    let content = request(
        get,
        Provider::Azure,
        format!(
            "{base}/items?scopePath=%2F&recursionLevel=Full&download=true&%24format=zip&versionDescriptor.version={revision}&api-version=7.1"
        ),
        Vec::new(),
    )?;
    Ok(FetchedDependency {
        revision: revision.clone(),
        content,
        source: format!(
            "https://dev.azure.com/{organization}/{project}/_git/{name}?version=GC{revision}"
        ),
        semantic_source: None,
    })
}

fn azure_repository_locator(
    repository: &str,
    revision: Option<&str>,
    path: &str,
    repository_type: Option<&str>,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    match repository_type.map(str::to_ascii_lowercase).as_deref() {
        Some("github") => {
            let requested = revision
                .ok_or_else(|| "repository resource has no immutable revision".to_owned())?;
            let repository_parts = components(repository);
            let [owner, name] = repository_parts.as_slice() else {
                return Err(format!("invalid GitHub repository locator: {repository}"));
            };
            if !valid_component(owner) || !valid_component(name) {
                return Err(format!("invalid GitHub repository locator: {repository}"));
            }
            let semantic_paths = if path.is_empty() {
                Vec::new()
            } else {
                vec![path.to_owned()]
            };
            resolve_github_repository(owner, name, path, requested, &semantic_paths, get)
        }
        None | Some("git" | "azurereposgit") => {
            let requested = revision
                .ok_or_else(|| "Azure repository resource has no immutable revision".to_owned())?;
            let mut fetched = azure_repository(repository, requested, get)?;
            if !path.is_empty() {
                let (organization, project, name) = azure_repository_parts(repository)
                    .ok_or_else(|| "invalid Azure repository locator".to_owned())?;
                let normalized = path.trim_start_matches('/');
                let base = format!(
                    "https://dev.azure.com/{}/{}/_apis/git/repositories/{}",
                    url_encode(&organization),
                    url_encode(&project),
                    url_encode(&name)
                );
                let url = format!(
                    "{base}/items?path={}&includeContent=true&versionDescriptor.versionType=commit&versionDescriptor.version={}&api-version=7.1",
                    url_encode(&format!("/{normalized}")),
                    url_encode(&fetched.revision)
                );
                if let Ok(content) = request(get, Provider::Azure, url, Vec::new()) {
                    fetched.semantic_source = Some((normalized.to_owned(), content));
                }
                fetched.source = format!("{}#path={}", fetched.source, url_encode(path));
            }
            Ok(fetched)
        }
        Some(kind) => Err(format!("unsupported Azure repository type {kind}")),
    }
}

fn azure_task(reference: &str, get: &mut dyn ResolverGet) -> Result<FetchedDependency, String> {
    let (name, major) = split_revision(reference)?;
    if !valid_component(name)
        || major.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("invalid Azure task reference: {reference}"));
    }
    let task_path = format!("Tasks/{name}V{major}");
    let mut fetched = resolve_github_repository(
        "microsoft",
        "azure-pipelines-tasks",
        "",
        "main",
        &[format!("{task_path}/task.json")],
        get,
    )?;
    fetched.source = format!("{}/{task_path}", fetched.source);
    Ok(fetched)
}

fn exact_semver(value: &str) -> bool {
    let core = value.split(['-', '+']).next().unwrap_or_default();
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn circleci_orb(reference: &str, get: &mut dyn ResolverGet) -> Result<FetchedDependency, String> {
    let (identity, version) = split_revision(reference)?;
    if components(identity).len() != 2 || !exact_semver(version) {
        return Err(format!(
            "CircleCI orb must use an exact production SemVer: {reference}"
        ));
    }
    let versions = request(
        get,
        Provider::Circleci,
        format!(
            "https://circleci.com/api/v3/orb/versions?filter%5Bref%5D={}",
            url_encode(reference)
        ),
        Vec::new(),
    )?;
    let parsed = JsonValue::parse_bytes(&versions).map_err(|error| error.to_string())?;
    let values = parsed
        .member("data")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "CircleCI orb response is missing one exact version".to_owned())?;
    let [item] = values else {
        return Err("CircleCI orb response is missing one exact version".to_owned());
    };
    let id = member_string(item, "id")?;
    let actual = item
        .member("attributes")
        .and_then(|value| value.member("version"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "CircleCI orb response has no version".to_owned())?;
    if actual != version {
        return Err("CircleCI returned a different orb version".to_owned());
    }
    let content = request(
        get,
        Provider::Circleci,
        format!(
            "https://circleci.com/api/v3/orb/versions/{}/source",
            url_encode(id)
        ),
        Vec::new(),
    )?;
    Ok(FetchedDependency {
        revision: version.to_owned(),
        content: content.clone(),
        source: format!("https://circleci.com/developer/orbs/orb/{identity}/{version}"),
        semantic_source: Some((".circleci/config.yml".to_owned(), content)),
    })
}

fn direct_https(
    dependency: &Dependency,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let content = request(
        get,
        dependency.provider,
        dependency.reference.clone(),
        Vec::new(),
    )?;
    Ok(FetchedDependency {
        revision: content_digest(&content),
        content: content.clone(),
        source: dependency.reference.clone(),
        semantic_source: Some((dependency.reference.clone(), content)),
    })
}

fn container_image(
    reference: &str,
    get: &mut dyn ResolverGet,
) -> Result<FetchedDependency, String> {
    let reference = reference.strip_prefix("docker://").unwrap_or(reference);
    if let Some((name, digest)) = reference.rsplit_once('@') {
        if valid_image_name(name) && valid_sha256(digest) {
            let digest = digest.to_ascii_lowercase();
            return Ok(FetchedDependency {
                revision: digest.clone(),
                content: format!("{name}@{digest}").into_bytes(),
                source: format!("oci://{name}@{digest}"),
                semantic_source: None,
            });
        }
        return Err(format!("invalid OCI image digest: {reference}"));
    }
    let slash = reference.rfind('/');
    let colon = reference.rfind(':');
    let (name, tag) = match colon {
        Some(index) if slash.is_none_or(|slash| index > slash) => {
            (&reference[..index], &reference[index + 1..])
        }
        _ => (reference, "latest"),
    };
    if !valid_image_name(name) || tag.is_empty() {
        return Err(format!("invalid OCI image: {reference}"));
    }
    let parts = components(name);
    let first = parts
        .first()
        .ok_or_else(|| format!("invalid OCI image: {reference}"))?;
    let explicit_registry = first.contains('.') || first.contains(':');
    let (registry, repository) = if explicit_registry {
        if parts.len() < 2 {
            return Err(format!("invalid OCI image: {reference}"));
        }
        (*first, parts[1..].join("/"))
    } else {
        (
            "registry-1.docker.io",
            if parts.len() == 1 {
                format!("library/{name}")
            } else {
                name.to_owned()
            },
        )
    };
    let mut headers = vec![(
        "Accept".to_owned(),
        "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json".to_owned(),
    )];
    if registry == "registry-1.docker.io" {
        let token_response = request_scoped(
            get,
            None,
            format!(
                "https://auth.docker.io/token?service=registry.docker.io&scope={}",
                url_encode(&format!("repository:{repository}:pull"))
            ),
            Vec::new(),
        )?;
        let parsed = JsonValue::parse_bytes(&token_response).map_err(|error| error.to_string())?;
        let token = parsed
            .member("token")
            .and_then(JsonValue::as_str)
            .or_else(|| parsed.member("access_token").and_then(JsonValue::as_str))
            .ok_or_else(|| "resolver response has no registry token".to_owned())?;
        headers.push(("Authorization".to_owned(), format!("Bearer {token}")));
    }
    let content = request_scoped(
        get,
        None,
        format!(
            "https://{registry}/v2/{repository}/manifests/{}",
            url_encode(tag)
        ),
        headers,
    )?;
    let digest = content_digest(&content);
    Ok(FetchedDependency {
        revision: digest.clone(),
        content,
        source: format!("oci://{registry}/{repository}@{digest}"),
        semantic_source: None,
    })
}

fn valid_image_name(value: &str) -> bool {
    !components(value).is_empty()
        && components(value).iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
                })
        })
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == SHA256_HEX_DIGITS && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
