use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use workflow_verifier::internal::helper_runtime::run_command_with_termination;

fn sleeping_command() -> Command {
    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 10",
        ]);
        command
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        command
    }
}

#[test]
fn supervisor_invokes_backend_termination_before_collecting_output() {
    let terminated = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&terminated);
    let observation = run_command_with_termination(
        &mut sleeping_command(),
        Duration::from_millis(25),
        1024,
        move |child: &mut Child| {
            observed.store(true, Ordering::Release);
            child.kill().map_err(|error| error.to_string())
        },
    )
    .expect("supervise process");
    assert!(observation.timed_out);
    assert!(terminated.load(Ordering::Acquire));
}
