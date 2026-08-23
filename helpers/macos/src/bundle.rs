use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use workflow_verifier_runner_protocol::Sha256;
use workflow_verifier_runner_protocol::vm::{ImageManifest, VmImage, parse_image_manifest};

const MANIFEST: &str = "manifest.json";
const KERNEL: &str = "vmlinuz";
const INITRD: &str = "initrd.img";
const ROOTFS: &str = "rootfs.raw";
const AGENT: &str = "workflow-verifier-vm-agent";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// Verified, immutable input bundle for the macOS Linux VM backend.
pub struct VmBundle {
    root: PathBuf,
    manifest: ImageManifest,
    manifest_digest: String,
}

fn regular_file(path: &Path) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect VM artifact {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        Err(format!(
            "VM artifact must be a regular non-symlink file: {}",
            path.display()
        ))
    } else if metadata.len() == 0 {
        Err(format!("VM artifact is empty: {}", path.display()))
    } else {
        Ok(metadata)
    }
}

fn digest_file(path: &Path) -> Result<String, String> {
    regular_file(path)?;
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("hash {}: {error}", path.display()))?;
        if count == 0 {
            return Ok(format!("sha256:{}", digest.finalize_hex()));
        }
        digest.update(&buffer[..count]);
    }
}

fn verify_digest(path: &Path, expected: &str) -> Result<(), String> {
    let actual = digest_file(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "VM artifact digest mismatch for {}: expected {expected}, actual {actual}",
            path.display()
        ))
    }
}

impl VmBundle {
    /// Loads a bundle only after its canonical manifest pin, architecture, and
    /// every artifact digest have been verified.
    ///
    /// # Errors
    ///
    /// Rejects missing, empty, symlinked, noncanonical, unpinned, wrong-
    /// architecture, or content-mismatched bundles.
    pub fn load(
        root: &Path,
        expected_manifest_digest: &str,
        expected_architecture: &str,
    ) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(root)
            .map_err(|error| format!("inspect VM bundle {}: {error}", root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("VM bundle root must be a non-symlink directory".to_owned());
        }
        let root = root
            .canonicalize()
            .map_err(|error| format!("canonicalize VM bundle: {error}"))?;
        let manifest_path = root.join(MANIFEST);
        let manifest_metadata = regular_file(&manifest_path)?;
        if manifest_metadata.len() > MAX_MANIFEST_BYTES {
            return Err("VM image manifest exceeds 64 KiB".to_owned());
        }
        let source = std::fs::read_to_string(&manifest_path)
            .map_err(|error| format!("read VM image manifest: {error}"))?;
        let manifest = parse_image_manifest(&source)?;
        if source != manifest.canonical_json() {
            return Err("VM image manifest is not canonical JSON".to_owned());
        }
        let manifest_digest = digest_file(&manifest_path)?;
        if manifest_digest != expected_manifest_digest {
            return Err(format!(
                "VM manifest digest mismatch: expected {expected_manifest_digest}, actual {manifest_digest}"
            ));
        }
        if manifest.architecture != expected_architecture {
            return Err(format!(
                "VM architecture is {}, host requires {expected_architecture}",
                manifest.architecture
            ));
        }
        for (name, expected) in [
            (KERNEL, manifest.kernel_digest.as_str()),
            (INITRD, manifest.initrd_digest.as_str()),
            (ROOTFS, manifest.rootfs_digest.as_str()),
            (AGENT, manifest.agent_digest.as_str()),
        ] {
            verify_digest(&root.join(name), expected)?;
        }
        Ok(Self {
            root,
            manifest,
            manifest_digest,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &ImageManifest {
        &self.manifest
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    #[must_use]
    pub fn kernel(&self) -> PathBuf {
        self.root.join(KERNEL)
    }

    #[must_use]
    pub fn initrd(&self) -> PathBuf {
        self.root.join(INITRD)
    }

    #[must_use]
    pub fn rootfs(&self) -> PathBuf {
        self.root.join(ROOTFS)
    }

    #[must_use]
    pub fn image(&self) -> VmImage {
        VmImage {
            architecture: self.manifest.architecture.clone(),
            kernel_path: self.kernel().to_string_lossy().into_owned(),
            kernel_digest: self.manifest.kernel_digest.clone(),
            initrd_path: self.initrd().to_string_lossy().into_owned(),
            initrd_digest: self.manifest.initrd_digest.clone(),
            rootfs_path: self.rootfs().to_string_lossy().into_owned(),
            rootfs_digest: self.manifest.rootfs_digest.clone(),
            manifest_digest: self.manifest_digest.clone(),
        }
    }
}
