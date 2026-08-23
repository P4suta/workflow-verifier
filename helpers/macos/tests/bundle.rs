use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use workflow_verifier_macos_helper::VmBundle;
use workflow_verifier_runner_protocol::sha256_hex;
use workflow_verifier_runner_protocol::vm::ImageManifest;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn fixture() -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-vm-bundle-test-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale bundle");
    }
    std::fs::create_dir(&root).expect("create bundle");
    root
}

fn write_bundle(root: &Path) -> String {
    let artifacts = [
        ("vmlinuz", b"kernel".as_slice()),
        ("initrd.img", b"initrd".as_slice()),
        ("rootfs.raw", b"root filesystem".as_slice()),
        ("workflow-verifier-vm-agent", b"agent".as_slice()),
    ];
    for (name, contents) in artifacts {
        std::fs::write(root.join(name), contents).expect("write VM artifact");
    }
    let manifest = ImageManifest {
        architecture: "arm64".to_owned(),
        kernel_digest: format!("sha256:{}", sha256_hex(b"kernel")),
        initrd_digest: format!("sha256:{}", sha256_hex(b"initrd")),
        rootfs_digest: format!("sha256:{}", sha256_hex(b"root filesystem")),
        agent_digest: format!("sha256:{}", sha256_hex(b"agent")),
        version: "2026.08.1".to_owned(),
    };
    let encoded = manifest.canonical_json();
    std::fs::write(root.join("manifest.json"), &encoded).expect("write manifest");
    format!("sha256:{}", sha256_hex(encoded.as_bytes()))
}

#[test]
fn content_addressed_bundle_loads_only_when_every_digest_matches() {
    let root = fixture();
    let manifest_digest = write_bundle(&root);
    let bundle = VmBundle::load(&root, &manifest_digest, "arm64").expect("load bundle");
    assert_eq!(bundle.manifest().version, "2026.08.1");
    assert_eq!(bundle.manifest_digest(), manifest_digest);
    assert_eq!(
        bundle.kernel(),
        root.canonicalize()
            .expect("canonical bundle")
            .join("vmlinuz")
    );
    std::fs::remove_dir_all(root).expect("remove bundle");
}

#[test]
fn bundle_rejects_manifest_pin_architecture_and_artifact_tampering() {
    let root = fixture();
    let manifest_digest = write_bundle(&root);
    assert!(VmBundle::load(&root, &format!("sha256:{}", "0".repeat(64)), "arm64").is_err());
    assert!(VmBundle::load(&root, &manifest_digest, "x86_64").is_err());
    std::fs::write(root.join("rootfs.raw"), b"tampered").expect("tamper rootfs");
    assert!(VmBundle::load(&root, &manifest_digest, "arm64").is_err());
    std::fs::remove_dir_all(root).expect("remove bundle");
}

#[cfg(unix)]
#[test]
fn bundle_rejects_symlinked_artifacts() {
    use std::os::unix::fs::symlink;

    let root = fixture();
    let manifest_digest = write_bundle(&root);
    std::fs::remove_file(root.join("vmlinuz")).expect("remove kernel");
    symlink(root.join("rootfs.raw"), root.join("vmlinuz")).expect("link kernel");
    assert!(VmBundle::load(&root, &manifest_digest, "arm64").is_err());
    std::fs::remove_dir_all(root).expect("remove bundle");
}
