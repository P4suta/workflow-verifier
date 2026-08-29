use std::collections::BTreeMap;

use workflow_verifier::internal::runner_protocol::vm::{
    ImageManifest, Observation, Request, VmImage, parse_image_manifest, parse_observation,
    parse_request,
};

fn request() -> Request {
    Request {
        plan_digest: format!("sha256:{}", "0".repeat(64)),
        image: VmImage {
            architecture: "arm64".to_owned(),
            kernel_path: "/bundle/vmlinuz".to_owned(),
            kernel_digest: format!("sha256:{}", "1".repeat(64)),
            initrd_path: "/bundle/initrd.img".to_owned(),
            initrd_digest: format!("sha256:{}", "2".repeat(64)),
            rootfs_path: "/bundle/rootfs.raw".to_owned(),
            rootfs_digest: format!("sha256:{}", "3".repeat(64)),
            manifest_digest: format!("sha256:{}", "4".repeat(64)),
        },
        source_root: "/private/source".to_owned(),
        scratch_root: "/private/scratch".to_owned(),
        control_root: "/private/control".to_owned(),
        working_directory: "/workspace".to_owned(),
        argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
        environment: BTreeMap::from([("MODE".to_owned(), "test".to_owned())]),
        cpu_count: 2,
        memory_mb: 512,
        processes: 8,
        timeout_seconds: 30,
        output_bytes: 4096,
        network: false,
    }
}

#[test]
fn vm_request_is_canonical_and_round_trips_exactly() {
    let value = request();
    let encoded = value.canonical_json();
    assert!(encoded.starts_with("{\"argv\":"));
    assert!(encoded.contains("\"network\":false"));
    assert_eq!(parse_request(&encoded).expect("parse request"), value);
    assert!(parse_request(&encoded.replace("\"network\":false", "\"network\":true")).is_err());
    assert!(parse_request(&encoded.replacen('{', "{\"extra\":0,", 1)).is_err());
}

#[test]
fn vm_observation_round_trips_binary_output_without_ambiguity() {
    let value = Observation {
        code: Some(7),
        timed_out: false,
        output_exceeded: false,
        output: vec![0, 1, 0x7f, 0xff],
    };
    let encoded = value.canonical_json();
    assert!(encoded.contains("\"output_hex\":\"00017fff\""));
    assert_eq!(
        parse_observation(&encoded).expect("parse observation"),
        value
    );
    assert!(parse_observation(&encoded.replace("00017fff", "00017ffz")).is_err());
}

#[test]
fn vm_image_manifest_is_content_addressable_and_architecture_bound() {
    let value = ImageManifest {
        architecture: "x86_64".to_owned(),
        kernel_digest: format!("sha256:{}", "a".repeat(64)),
        initrd_digest: format!("sha256:{}", "b".repeat(64)),
        rootfs_digest: format!("sha256:{}", "c".repeat(64)),
        agent_digest: format!("sha256:{}", "d".repeat(64)),
        version: "2026.08.1".to_owned(),
    };
    let encoded = value.canonical_json();
    assert_eq!(
        parse_image_manifest(&encoded).expect("parse manifest"),
        value
    );
    assert!(parse_image_manifest(&encoded.replace("x86_64", "universal")).is_err());
}
