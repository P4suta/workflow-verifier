fn main() {
    std::process::exit(workflow_verifier_runner_protocol::helper_main(
        &workflow_verifier_macos_helper::descriptor(),
        workflow_verifier_macos_helper::launch_with_exclusions,
    ));
}
