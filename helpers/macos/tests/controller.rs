#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use workflow_verifier_helper_runtime::ProcessObservation;
use workflow_verifier_macos_helper::{VmBundle, VmExecution, VmTransport, execute_vm_step};
use workflow_verifier_runner_protocol::vm::{Observation, parse_request};
use workflow_verifier_runner_protocol::{Limits, sha256_hex};

mod fixture {
    use std::sync::atomic::{AtomicU64, Ordering};

    use workflow_verifier_runner_protocol::vm::ImageManifest;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub fn directory(name: &str) -> PathBuf {
        let value = std::env::temp_dir().join(format!(
            "workflow-verifier-vm-controller-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&value).expect("create fixture");
        value
    }

    pub fn bundle() -> (PathBuf, String) {
        let root = directory("bundle");
        for (name, contents) in [
            ("vmlinuz", b"kernel".as_slice()),
            ("initrd.img", b"initrd".as_slice()),
            ("rootfs.raw", b"rootfs".as_slice()),
            ("workflow-verifier-vm-agent", b"agent".as_slice()),
        ] {
            std::fs::write(root.join(name), contents).expect("write artifact");
        }
        let manifest = ImageManifest {
            architecture: "arm64".to_owned(),
            kernel_digest: format!("sha256:{}", sha256_hex(b"kernel")),
            initrd_digest: format!("sha256:{}", sha256_hex(b"initrd")),
            rootfs_digest: format!("sha256:{}", sha256_hex(b"rootfs")),
            agent_digest: format!("sha256:{}", sha256_hex(b"agent")),
            version: "test".to_owned(),
        }
        .canonical_json();
        std::fs::write(root.join("manifest.json"), &manifest).expect("write manifest");
        let digest = format!("sha256:{}", sha256_hex(manifest.as_bytes()));
        (root, digest)
    }
}

struct FakeTransport {
    response: String,
    control_root: Option<PathBuf>,
}

impl VmTransport for FakeTransport {
    fn invoke(
        &mut self,
        request_path: &Path,
        _timeout: Duration,
        _output_limit: u64,
    ) -> Result<ProcessObservation, String> {
        let encoded = std::fs::read_to_string(request_path).expect("read request");
        let request = parse_request(&encoded).expect("strict request");
        assert!(!request.network);
        assert_ne!(request.source_root, request.scratch_root);
        self.control_root = Some(PathBuf::from(&request.control_root));
        Ok(ProcessObservation {
            code: Some(0),
            timed_out: false,
            output_exceeded: false,
            output: self.response.as_bytes().to_vec(),
            output_bytes: u64::try_from(self.response.len()).unwrap_or(u64::MAX),
            wall_time_ms: 1,
        })
    }
}

fn limits() -> Limits {
    Limits {
        cpu_seconds: 5,
        memory_mb: 512,
        processes: 4,
        output_bytes: 4096,
    }
}

#[test]
fn controller_round_trips_guest_observation_and_removes_control_data() {
    let (bundle_root, manifest_digest) = fixture::bundle();
    let bundle = VmBundle::load(&bundle_root, &manifest_digest, "arm64").expect("bundle");
    let source = fixture::directory("source");
    let scratch = fixture::directory("scratch");
    let guest = Observation {
        code: Some(0),
        timed_out: false,
        output_exceeded: false,
        output: b"binary\0secret".to_vec(),
    };
    let mut transport = FakeTransport {
        response: guest.canonical_json(),
        control_root: None,
    };
    let observed = execute_vm_step(
        &VmExecution {
            plan_digest: &format!("sha256:{}", "0".repeat(64)),
            bundle: &bundle,
            source_root: &source,
            scratch_root: &scratch,
            working_directory: "/workspace",
            argv: &["/bin/true".to_owned()],
            environment: &BTreeMap::new(),
            limits: &limits(),
        },
        &mut transport,
    )
    .expect("execute VM step");
    assert_eq!(observed.output, b"binary\0secret");
    assert_eq!(observed.code, Some(0));
    assert!(!transport.control_root.expect("control root").exists());
    std::fs::remove_dir_all(bundle_root).expect("remove bundle");
    std::fs::remove_dir_all(source).expect("remove source");
    std::fs::remove_dir_all(scratch).expect("remove scratch");
}

#[test]
fn controller_rejects_noncanonical_or_oversized_guest_responses() {
    let (bundle_root, manifest_digest) = fixture::bundle();
    let bundle = VmBundle::load(&bundle_root, &manifest_digest, "arm64").expect("bundle");
    let source = fixture::directory("source-invalid");
    let scratch = fixture::directory("scratch-invalid");
    let mut transport = FakeTransport {
        response: "{\"schema\":\"vm-observation-v1\"}".to_owned(),
        control_root: None,
    };
    let result = execute_vm_step(
        &VmExecution {
            plan_digest: &format!("sha256:{}", "0".repeat(64)),
            bundle: &bundle,
            source_root: &source,
            scratch_root: &scratch,
            working_directory: "/workspace",
            argv: &["/bin/true".to_owned()],
            environment: &BTreeMap::new(),
            limits: &limits(),
        },
        &mut transport,
    );
    assert!(result.is_err());
    assert!(!transport.control_root.expect("control root").exists());
    std::fs::remove_dir_all(bundle_root).expect("remove bundle");
    std::fs::remove_dir_all(source).expect("remove source");
    std::fs::remove_dir_all(scratch).expect("remove scratch");
}
