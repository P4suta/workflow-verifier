use std::path::PathBuf;

use workflow_verifier_helper_runtime::{ChangeKind, ScratchTree, source_snapshot};

#[test]
fn source_snapshot_matches_the_shared_ocaml_fixture() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repository.join("test/fixtures/protocol/source-tree");
    let expected =
        std::fs::read_to_string(repository.join("test/fixtures/protocol/source-manifest-v1.json"))
            .expect("shared source manifest fixture")
            .trim()
            .to_owned();
    let snapshot = source_snapshot(&root).expect("source snapshot");
    assert_eq!(snapshot.manifest.canonical_json, expected);
    assert_eq!(
        snapshot.manifest.digest,
        "sha256:6d8438471c06fc1f4199de690117a6c60da9bee4c8d9421ad2333a7847033b48"
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
