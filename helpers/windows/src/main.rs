fn main() {
    std::process::exit(workflow_verifier_runner_protocol::helper_main(
        &workflow_verifier_windows_helper::descriptor(),
        workflow_verifier_windows_helper::launch_with_exclusions,
    ));
}
