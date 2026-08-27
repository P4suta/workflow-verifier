use std::path::PathBuf;

use workflow_verifier_helper_runtime::{
    ChangeKind, ScratchTree, reserve_temp_directory, source_snapshot,
    source_snapshot_with_exclusions,
};

#[test]
fn source_snapshot_matches_the_shared_ocaml_fixture() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repository.join("test/fixtures/protocol/source-tree");
    let expected =
        std::fs::read_to_string(repository.join("test/fixtures/protocol/source-manifest-v2.json"))
            .expect("shared source manifest fixture")
            .trim()
            .to_owned();
    let snapshot = source_snapshot(&root).expect("source snapshot");
    assert_eq!(snapshot.manifest.canonical_json, expected);
    assert_eq!(
        snapshot.manifest.digest,
        "sha256:d70c409989907fb9194417d737ec25d8dd56e7ab36911dbf5b43db5d620b3594"
    );
}

#[test]
fn scratch_diff_records_add_modify_and_delete() {
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-runtime-test-{}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale test directory");
    }
    std::fs::create_dir(&root).expect("create source");
    std::fs::write(root.join("modify.txt"), b"before").expect("write source");
    std::fs::write(root.join("delete.txt"), b"delete").expect("write source");
    let snapshot = source_snapshot(&root).expect("source snapshot");
    let scratch = ScratchTree::prepare(&root, snapshot).expect("scratch tree");
    std::fs::write(scratch.path().join("modify.txt"), b"after").expect("modify");
    std::fs::write(scratch.path().join("added.txt"), b"added").expect("add");
    std::fs::remove_file(scratch.path().join("delete.txt")).expect("delete");
    let changes = scratch.changes().expect("changes");
    assert!(
        changes
            .iter()
            .any(|change| { change.path == "added.txt" && change.kind == ChangeKind::Added })
    );
    assert!(
        changes
            .iter()
            .any(|change| { change.path == "modify.txt" && change.kind == ChangeKind::Modified })
    );
    assert!(
        changes
            .iter()
            .any(|change| { change.path == "delete.txt" && change.kind == ChangeKind::Deleted })
    );
    drop(scratch);
    std::fs::remove_dir_all(&root).expect("remove source");
}

#[test]
fn trusted_exclusions_are_authenticated_and_remove_the_excluded_bytes() {
    let root = reserve_temp_directory("trusted-exclusion-test").expect("temporary source");
    std::fs::create_dir(root.join("generated")).expect("generated directory");
    std::fs::write(root.join("workflow.yml"), b"jobs: {}\n").expect("workflow");
    std::fs::write(root.join("generated/ignored.yml"), b"secret build output\n")
        .expect("excluded output");

    let included = source_snapshot(&root).expect("unfiltered snapshot");
    let excluded = source_snapshot_with_exclusions(&root, &["generated".to_owned()])
        .expect("trusted filtered snapshot");

    assert!(included.regular_file("generated/ignored.yml").is_some());
    assert!(excluded.regular_file("generated/ignored.yml").is_none());
    assert_eq!(
        excluded
            .regular_file("workflow.yml")
            .expect("included workflow"),
        b"jobs: {}\n"
    );
    assert_eq!(excluded.trusted_exclusions(), ["generated"]);
    assert!(
        excluded
            .manifest
            .canonical_json
            .contains("\"exclusion_policy_digest\":\"sha256:")
    );
    assert!(
        excluded
            .manifest
            .canonical_json
            .contains("\"exclusions\":[{\"path\":\"generated\",\"reason\":\"trusted-policy\"}]")
    );
    assert_ne!(included.manifest.digest, excluded.manifest.digest);

    std::fs::remove_dir_all(root).expect("remove source");
}
