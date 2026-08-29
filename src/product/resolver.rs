use crate::domain::Provider;
use crate::foundation::{
    GIT_SHA1_HEX_DIGITS, SHA256_HEX_DIGITS, content_digest, valid_content_digest,
};
use crate::frontend::{Dependency, DependencyStatus, Mutability};
use crate::product::{DependencySummary, LockEntry, Lockfile};

// Immutable revision widths are provider protocol formats: Git object IDs
// (SHA-1/SHA-256) and Azure task GUIDs after removing hyphens.
const AZURE_GUID_HEX_DIGITS: usize = 32;

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
    if hexadecimal(GIT_SHA1_HEX_DIGITS)
        || hexadecimal(SHA256_HEX_DIGITS)
        || valid_content_digest(revision)
    {
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
            compact.len() == AZURE_GUID_HEX_DIGITS
                && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{Span, content_digest};
    use crate::frontend::{DependencyKind, DependencyLocator};

    fn dependency(provider: Provider) -> Dependency {
        Dependency::unresolved(
            provider,
            DependencyKind::Action,
            "owner/unit@main",
            DependencyLocator::Direct,
            Span::default(),
        )
    }

    #[test]
    fn immutable_revision_formats_cover_every_provider_boundary() {
        for provider in [
            Provider::Github,
            Provider::Gitlab,
            Provider::Azure,
            Provider::Circleci,
        ] {
            assert!(immutable_revision(
                provider,
                &"a".repeat(GIT_SHA1_HEX_DIGITS)
            ));
            assert!(immutable_revision(provider, &"b".repeat(SHA256_HEX_DIGITS)));
            assert!(immutable_revision(provider, &content_digest("revision")));
        }
        for length in [
            GIT_SHA1_HEX_DIGITS.saturating_sub(1),
            GIT_SHA1_HEX_DIGITS.saturating_add(1),
            SHA256_HEX_DIGITS.saturating_sub(1),
            SHA256_HEX_DIGITS.saturating_add(1),
        ] {
            assert!(!immutable_revision(Provider::Github, &"a".repeat(length)));
        }
        assert!(!immutable_revision(
            Provider::Github,
            &"z".repeat(GIT_SHA1_HEX_DIGITS)
        ));
        assert!(!immutable_revision(Provider::Gitlab, "main"));

        for revision in ["1", "1.2.3", "2026-08-27", "1.2.3+4"] {
            assert!(immutable_revision(Provider::Circleci, revision));
        }
        for revision in ["", "release", "1_2"] {
            assert!(!immutable_revision(Provider::Circleci, revision));
        }

        assert!(immutable_revision(
            Provider::Azure,
            "01234567-89ab-cdef-0123-456789abcdef"
        ));
        assert!(immutable_revision(
            Provider::Azure,
            &"a".repeat(AZURE_GUID_HEX_DIGITS)
        ));
        assert!(!immutable_revision(
            Provider::Azure,
            &"a".repeat(AZURE_GUID_HEX_DIGITS.saturating_sub(1))
        ));
        assert!(!immutable_revision(
            Provider::Azure,
            &"z".repeat(AZURE_GUID_HEX_DIGITS)
        ));
    }

    #[test]
    fn fetched_lock_allows_empty_or_matching_allowlists_and_replaces_only_identity() {
        let dependency = dependency(Provider::Github);
        let fetched = || FetchedDependency {
            revision: "a".repeat(GIT_SHA1_HEX_DIGITS),
            content: b"content".to_vec(),
            source: "https://example.test/owner/unit".to_owned(),
            semantic_source: None,
        };
        let other = LockEntry::new(
            Provider::Gitlab,
            dependency.reference.clone(),
            "b".repeat(GIT_SHA1_HEX_DIGITS),
            content_digest("other"),
            "https://gitlab.example.test/owner/unit",
        );
        let current = Lockfile::new([other.clone()]).expect("current lock");
        let (empty_allowed, entry) = lock_fetched(&dependency, fetched(), &[], &current)
            .expect("empty allowlist permits resolver-owned transport policy");
        assert_eq!(entry.source, "https://example.test/owner/unit");
        assert!(
            empty_allowed
                .find(Provider::Gitlab, &dependency.reference)
                .is_some()
        );
        assert!(
            empty_allowed
                .find(Provider::Github, &dependency.reference)
                .is_some()
        );

        assert!(
            lock_fetched(
                &dependency,
                fetched(),
                &[
                    "https://unrelated.test/".to_owned(),
                    "https://example.test/".to_owned()
                ],
                &current,
            )
            .is_ok()
        );
        assert!(
            lock_fetched(
                &dependency,
                fetched(),
                &["https://unrelated.test/".to_owned()],
                &current,
            )
            .is_err()
        );

        let mut mutable = fetched();
        mutable.revision = "main".to_owned();
        assert!(lock_fetched(&dependency, mutable, &[], &current).is_err());
    }
}
