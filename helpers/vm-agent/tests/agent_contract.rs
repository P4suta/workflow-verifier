use std::sync::atomic::{AtomicU64, Ordering};

use workflow_verifier_internal::internal::runner_protocol::vm::{Observation, parse_observation};
use workflow_verifier_vm_agent::{guest_working_directory, write_observation};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn guest_working_directory_is_confined_below_workspace() {
    assert_eq!(
        guest_working_directory("/workspace").expect("workspace"),
        std::path::PathBuf::from("/workspace")
    );
    assert_eq!(
        guest_working_directory("/workspace/nested").expect("nested"),
        std::path::PathBuf::from("/workspace/nested")
    );
    assert!(guest_working_directory("/workspace/../control").is_err());
    assert!(guest_working_directory("/source").is_err());
}

#[test]
fn observation_is_published_atomically_as_canonical_json() {
    let root = std::env::temp_dir().join(format!(
        "workflow-verifier-agent-response-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).expect("create response fixture");
    let path = root.join("response.json");
    let observation = Observation {
        code: Some(0),
        timed_out: false,
        output_exceeded: false,
        output: b"result\0bytes".to_vec(),
    };
    write_observation(&path, &observation).expect("write observation");
    let encoded = std::fs::read_to_string(&path).expect("read observation");
    assert_eq!(encoded, observation.canonical_json());
    assert_eq!(
        parse_observation(&encoded).expect("parse response"),
        observation
    );
    assert!(!root.join("response.json.tmp").exists());
    std::fs::remove_dir_all(root).expect("remove response fixture");
}
