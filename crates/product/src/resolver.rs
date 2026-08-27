use crate::{DependencySummary, LockEntry, Lockfile};
use workflow_verifier_domain::Provider;
use workflow_verifier_foundation::{content_digest, valid_content_digest};
use workflow_verifier_frontend::{Dependency, DependencyStatus, Mutability};

pub type SemanticSource = (String, Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedDependency {
    pub revision: String,
    pub content: Vec<u8>,
    pub source: String,
    pub semantic_source: Option<SemanticSource>,
}

pub trait DependencyFetcher {
    /// Fetch an immutable snapshot for one non-local dependency.
    ///
    /// # Errors
    /// Returns a redacted resolver failure suitable for deterministic CLI
    /// diagnostics.
    fn fetch(&mut self, dependency: &Dependency) -> Result<FetchedDependency, String>;
}

impl<F> DependencyFetcher for F
where
    F: FnMut(&Dependency) -> Result<FetchedDependency, String>,
{
    fn fetch(&mut self, dependency: &Dependency) -> Result<FetchedDependency, String> {
        self(dependency)
    }
}

#[derive(Clone, Debug)]
pub struct ResolutionResult {
    pub locked: Vec<(Dependency, LockEntry)>,
    pub unresolved: Vec<Dependency>,
    pub errors: Vec<String>,
    pub lockfile: Lockfile,
}

#[must_use]
pub fn immutable_revision(provider: Provider, revision: &str) -> bool {
    let hexadecimal =
        |length| revision.len() == length && revision.bytes().all(|byte| byte.is_ascii_hexdigit());
    if hexadecimal(40) || hexadecimal(64) || valid_content_digest(revision) {
        return true;
    }
    match provider {
        Provider::Circleci => {
            !revision.is_empty()
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'+'))
        }
        Provider::Azure => {
            let compact = revision.replace('-', "");
            compact.len() == 32 && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        Provider::Github | Provider::Gitlab => false,
    }
}

#[must_use]
pub fn resolve_dependencies(
    dependencies: &[Dependency],
    lock: &Lockfile,
    refresh: bool,
    allowed_sources: &[String],
    mut network: Option<&mut dyn DependencyFetcher>,
) -> ResolutionResult {
    let mut ordered = dependencies.to_vec();
    ordered.sort_by(|left, right| {
        (left.provider, left.reference.as_str()).cmp(&(right.provider, right.reference.as_str()))
    });
    let mut locked = Vec::new();
    let mut unresolved = Vec::new();
    let mut errors = Vec::new();
    let mut current = lock.clone();
    for dependency in ordered {
        if dependency.mutability == Mutability::Local {
            if !matches!(dependency.status, DependencyStatus::Locked { .. }) {
                unresolved.push(dependency);
            }
            continue;
        }
        if !refresh
            && let Some(entry) = current
                .find(dependency.provider, &dependency.reference)
                .cloned()
        {
            locked.push((dependency, entry));
            continue;
        }
        let Some(fetcher) = network.as_deref_mut() else {
            unresolved.push(dependency);
            continue;
        };
        match fetcher.fetch(&dependency) {
            Ok(snapshot) => match lock_fetched(&dependency, snapshot, allowed_sources, &current) {
                Ok((next, entry)) => {
                    current = next;
                    locked.push((dependency, entry));
                }
                Err(error) => {
                    errors.push(format!("{}: {error}", dependency.reference));
                    unresolved.push(dependency);
                }
            },
            Err(error) => {
                errors.push(format!("{}: {error}", dependency.reference));
                unresolved.push(dependency);
            }
        }
    }
    ResolutionResult {
        locked,
        unresolved,
        errors,
        lockfile: current,
    }
}

fn lock_fetched(
    dependency: &Dependency,
    fetched: FetchedDependency,
    allowed_sources: &[String],
    current: &Lockfile,
) -> Result<(Lockfile, LockEntry), String> {
    if !immutable_revision(dependency.provider, &fetched.revision) {
        return Err(format!(
            "resolver returned a mutable revision {}",
            fetched.revision
        ));
    }
    if !allowed_sources.is_empty()
        && !allowed_sources
            .iter()
            .any(|prefix| fetched.source.starts_with(prefix))
    {
        return Err("resolved source is outside the allowlist".to_owned());
    }
    let mut entry = LockEntry::new(
        dependency.provider,
        dependency.reference.clone(),
        fetched.revision,
        content_digest(&fetched.content),
        fetched.source,
    );
    entry.summary = fetched
        .semantic_source
        .map(|(path, source)| DependencySummary::infer(dependency, &path, &source));
    let mut entries = current
        .entries()
        .iter()
        .filter(|existing| {
            existing.provider != entry.provider || existing.reference != entry.reference
        })
        .cloned()
        .collect::<Vec<_>>();
    entries.push(entry.clone());
    let lock = Lockfile::new(entries)?;
    Ok((lock, entry))
}
