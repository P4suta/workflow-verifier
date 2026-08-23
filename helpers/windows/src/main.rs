fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(code) = workflow_verifier_windows_helper::broker_main(&arguments) {
        std::process::exit(code);
    }
    std::process::exit(workflow_verifier_runner_protocol::helper_main(
        &workflow_verifier_windows_helper::descriptor(),
        workflow_verifier_windows_helper::launch,
    ));
}
