use std::collections::BTreeSet;

use workflow_verifier::internal::helper_runtime::{reserve_temp_directory, reserve_temp_file};

#[test]
fn temporary_resources_are_atomically_unique_under_parallel_callers() {
    let callers = (0..32)
        .map(|_| {
            std::thread::spawn(|| {
                let directory = reserve_temp_directory("reservation-test")
                    .expect("reserve temporary directory");
                let (file, handle) =
                    reserve_temp_file("reservation-test", ".bin").expect("reserve temporary file");
                drop(handle);
                (directory, file)
            })
        })
        .collect::<Vec<_>>();

    let resources = callers
        .into_iter()
        .map(|caller| caller.join().expect("join temporary resource caller"))
        .collect::<Vec<_>>();
    let directories = resources
        .iter()
        .map(|(directory, _)| directory.clone())
        .collect::<BTreeSet<_>>();
    let files = resources
        .iter()
        .map(|(_, file)| file.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(directories.len(), resources.len());
    assert_eq!(files.len(), resources.len());
    for (directory, file) in resources {
        std::fs::remove_dir(directory).expect("remove temporary directory");
        std::fs::remove_file(file).expect("remove temporary file");
    }
}

#[test]
fn temporary_resource_names_reject_path_syntax() {
    assert!(reserve_temp_directory("../escape").is_err());
    assert!(reserve_temp_file("safe", "/escape").is_err());
}
