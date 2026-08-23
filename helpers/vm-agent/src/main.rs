fn main() {
    match workflow_verifier_vm_agent::run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("workflow-verifier VM agent failure: {error}");
            std::process::exit(5);
        }
    }
}
