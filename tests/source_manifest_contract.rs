use workflow_verifier::internal::conformance::foundation::{JsonValue, content_digest};
use workflow_verifier::internal::conformance::sandbox::{
    ManifestBudget, SourceFile, SourceManifest,
};

#[test]
fn canonical_body_distinguishes_regular_executable_and_symlink_entries() {
    let manifest = SourceManifest::create(
        ".",
        [
            SourceFile::regular("target.txt", b"target"),
            SourceFile::executable("bin/check", b"#!/bin/sh\n"),
            SourceFile::symlink("nested/link", "../target.txt"),
        ],
        &[],
    )
    .unwrap();
    assert!(manifest.verify_digest());
    assert_eq!(
        manifest.total_size,
        b"target".len() as u64 + b"#!/bin/sh\n".len() as u64 + b"../target.txt".len() as u64
    );
    let canonical = manifest.to_canonical_json();
    assert!(canonical.contains("\"kind\":\"regular\""));
    assert!(canonical.contains("\"kind\":\"symlink\""));
    assert!(canonical.contains("\"executable\":true"));
    assert!(canonical.contains("\"target\":\"target.txt\""));
    assert_eq!(
        JsonValue::parse(&canonical)
            .unwrap()
            .member("schema")
            .and_then(JsonValue::as_str),
        Some("source-manifest-v2")
    );
}

#[test]
fn root_normalization_accepts_only_files_strictly_below_the_root() {
    for root in ["repository/", "repository\\"] {
        let manifest = SourceManifest::create(
            root,
            [SourceFile::regular("repository/src/lib.rs", b"source")],
            &[],
        )
        .unwrap();
        assert_eq!(manifest.entries[0].path, "src/lib.rs");
    }
    assert!(
        SourceManifest::create(
            "repository",
            [SourceFile::regular("other/src/lib.rs", b"source")],
            &[],
        )
        .is_err()
    );
    assert!(
        SourceManifest::create(
            "repository",
            [SourceFile::regular("repository", b"source")],
            &[],
        )
        .is_err()
    );
}

#[test]
fn trusted_exclusions_match_exact_paths_and_descendants_not_siblings() {
    let trusted = vec!["vendor/cache".to_owned()];
    let manifest = SourceManifest::create(
        ".",
        [
            SourceFile::regular("vendor/cache", b"exact"),
            SourceFile::regular("vendor/cache/nested", b"nested"),
            SourceFile::regular("vendor/cache-sibling", b"kept"),
            SourceFile::regular("src/main.rs", b"kept"),
        ],
        &trusted,
    )
    .unwrap();
    let paths: Vec<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(paths, ["src/main.rs", "vendor/cache-sibling"]);
    assert_eq!(manifest.exclusions.len(), trusted.len() + 1);
    assert!(
        manifest
            .exclusions
            .iter()
            .all(|entry| entry.reason == "trusted-policy")
    );
}

#[test]
fn file_identity_aliases_and_both_path_collision_forms_are_rejected() {
    assert!(
        SourceManifest::create(
            ".",
            [SourceFile::regular("single", b"one").with_identity("device:file")],
            &[],
        )
        .is_ok()
    );
    assert!(
        SourceManifest::create(
            ".",
            [
                SourceFile::regular("same", b"one"),
                SourceFile::regular("same", b"two"),
            ],
            &[],
        )
        .is_err()
    );
    assert!(
        SourceManifest::create(
            ".",
            [
                SourceFile::regular("Readme", b"one"),
                SourceFile::regular("README", b"two"),
            ],
            &[],
        )
        .is_err()
    );
    assert!(
        SourceManifest::create(
            ".",
            [
                SourceFile::regular("first", b"one").with_identity("device:file"),
                SourceFile::regular("second", b"two").with_identity("device:file"),
            ],
            &[],
        )
        .is_err()
    );
}

#[test]
fn each_published_budget_floor_is_checked_independently() {
    let published = ManifestBudget::default();
    for below_floor in [
        ManifestBudget {
            max_file_bytes: published.max_file_bytes - 1,
            ..published
        },
        ManifestBudget {
            max_entries: published.max_entries - 1,
            ..published
        },
        ManifestBudget {
            max_snapshot_bytes: published.max_snapshot_bytes - 1,
            ..published
        },
    ] {
        assert!(
            SourceManifest::create_with_budget(".", [], &[], below_floor).is_err(),
            "every source-manifest-v2 schema floor is mandatory"
        );
    }
    assert!(SourceManifest::create_with_budget(".", [], &[], published).is_ok());
}

#[test]
fn per_file_limit_accepts_the_boundary_and_rejects_the_next_byte() {
    let published = ManifestBudget::default();
    let at_limit = vec![0_u8; usize::try_from(published.max_file_bytes).unwrap()];
    assert!(
        SourceManifest::create_with_budget(
            ".",
            [SourceFile::regular("boundary", &at_limit)],
            &[],
            published,
        )
        .is_ok()
    );
    let mut over_limit = at_limit;
    over_limit.push(0);
    assert!(
        SourceManifest::create_with_budget(
            ".",
            [SourceFile::regular("over", &over_limit)],
            &[],
            published,
        )
        .is_err()
    );
}

#[test]
fn symlink_targets_reject_each_absolute_or_escaping_form_and_cycles() {
    for target in ["/absolute", "C:/absolute", "../escape", "nul\0target"] {
        let error =
            SourceManifest::create(".", [SourceFile::symlink("link", target)], &[]).unwrap_err();
        assert!(
            if target == "../escape" {
                error.contains("escapes snapshot root")
            } else {
                error.contains("absolute symlink target is forbidden")
            },
            "unexpected error for {target:?}: {error}"
        );
    }
    assert!(
        SourceManifest::create(
            ".",
            [
                SourceFile::symlink("first", "second"),
                SourceFile::symlink("second", "first"),
            ],
            &[],
        )
        .is_err()
    );
    assert!(
        SourceManifest::create(
            ".",
            [
                SourceFile::regular("target", b"target"),
                SourceFile::symlink("link", "./target"),
            ],
            &[],
        )
        .is_ok()
    );
}

#[test]
fn digest_authenticates_the_complete_manifest_body() {
    let mut manifest =
        SourceManifest::create(".", [SourceFile::regular("source", b"contents")], &[]).unwrap();
    let original = manifest.digest.clone();
    manifest.total_size += 1;
    assert!(!manifest.verify_digest());
    manifest.total_size -= 1;
    manifest.digest = content_digest(b"different manifest");
    assert_ne!(manifest.digest, original);
    assert!(!manifest.verify_digest());
}
