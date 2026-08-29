use workflow_verifier::internal::conformance::domain::Provider;
use workflow_verifier::internal::conformance::foundation::Span;
use workflow_verifier::internal::conformance::frontend::{
    Dependency, DependencyKind, DependencyLocator,
};
use workflow_verifier::internal::conformance::product::{
    FetchedDependency, LockEntry, Lockfile, resolve_dependencies,
};

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
fn offline_resolution_reuses_authenticated_locks_without_network() {
    let dependency = dependency(Provider::Github, DependencyKind::Action, "owner/action@v1");
    let entry = LockEntry::new(
        Provider::Github,
        "owner/action@v1",
        "a".repeat(40),
        format!("sha256:{}", "b".repeat(64)),
        format!("https://github.com/owner/action/tree/{}", "a".repeat(40)),
    );
    let lock = Lockfile::new([entry.clone()]).expect("lock");

    let result = resolve_dependencies(&[dependency], &lock, false, &[], None);

    assert!(result.errors.is_empty());
    assert!(result.unresolved.is_empty());
    assert_eq!(result.locked.len(), 1);
    assert_eq!(result.locked[0].1, entry);
    assert_eq!(
        result.lockfile.to_canonical_json(),
        lock.to_canonical_json()
    );
}

#[test]
fn refresh_fetches_immutable_content_and_replaces_the_matching_entry() {
    let dependency = dependency(Provider::Github, DependencyKind::Action, "owner/action@v1");
    let old = LockEntry::new(
        Provider::Github,
        "owner/action@v1",
        "a".repeat(40),
        format!("sha256:{}", "b".repeat(64)),
        format!("https://github.com/owner/action/tree/{}", "a".repeat(40)),
    );
    let lock = Lockfile::new([old]).expect("lock");
    let revision = "c".repeat(40);
    let mut calls = 0;
    let mut fetch = |_: &Dependency| {
        calls += 1;
        Ok(FetchedDependency {
            revision: revision.clone(),
            content: b"immutable archive".to_vec(),
            source: format!("https://github.com/owner/action/tree/{revision}"),
            semantic_source: Some((
                "action.yml".to_owned(),
                b"name: composite\nruns:\n  using: composite\n  steps:\n    - run: echo exact\n"
                    .to_vec(),
            )),
        })
    };

    let result = resolve_dependencies(
        &[dependency],
        &lock,
        true,
        &["https://github.com/owner/".to_owned()],
        Some(&mut fetch),
    );

    assert_eq!(calls, 1);
    assert!(result.errors.is_empty());
    assert!(result.unresolved.is_empty());
    let entry = &result.locked[0].1;
    assert_eq!(entry.revision, revision);
    assert_eq!(
        entry.digest,
        "sha256:61ae07798abb4ecc73a3152d9cd3277a57cef725a28ae051f429b22e0590dec2"
    );
    assert!(
        entry
            .summary
            .as_ref()
            .is_some_and(|summary| summary.complete)
    );
    assert_eq!(
        result.lockfile.find(Provider::Github, "owner/action@v1"),
        Some(entry)
    );
}

#[test]
fn resolver_rejects_mutable_revisions_and_sources_outside_the_allowlist() {
    let first = dependency(Provider::Github, DependencyKind::Action, "owner/action@v1");
    let second = dependency(
        Provider::Gitlab,
        DependencyKind::Include,
        "https://ci.test/base.yml",
    );
    let lock = Lockfile::new([]).expect("empty lock");
    let mut fetch = |dependency: &Dependency| {
        Ok(FetchedDependency {
            revision: if dependency.provider == Provider::Github {
                "still-a-tag".to_owned()
            } else {
                format!("sha256:{}", "d".repeat(64))
            },
            content: b"content".to_vec(),
            source: if dependency.provider == Provider::Github {
                "https://github.com/owner/action/tree/tag".to_owned()
            } else {
                "https://untrusted.test/base.yml".to_owned()
            },
            semantic_source: None,
        })
    };

    let result = resolve_dependencies(
        &[first, second],
        &lock,
        false,
        &["https://ci.test/".to_owned()],
        Some(&mut fetch),
    );

    assert_eq!(result.unresolved.len(), 2);
    assert_eq!(result.errors.len(), 2);
    assert!(result.errors[0].contains("mutable revision"));
    assert!(result.errors[1].contains("outside the allowlist"));
    assert!(result.lockfile.entries().is_empty());
}

#[test]
fn local_dependencies_never_cross_the_network_boundary() {
    let local = dependency(Provider::Github, DependencyKind::Action, "./local-action");
    let lock = Lockfile::new([]).expect("empty lock");
    let mut calls = 0;
    let mut fetch = |_: &Dependency| -> Result<FetchedDependency, String> {
        calls += 1;
        Err("must not be called".to_owned())
    };

    let result = resolve_dependencies(&[local], &lock, false, &[], Some(&mut fetch));

    assert_eq!(calls, 0);
    assert_eq!(result.unresolved.len(), 1);
    assert!(result.errors.is_empty());
}
