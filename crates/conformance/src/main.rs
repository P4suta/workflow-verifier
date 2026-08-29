#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;
use workflow_verifier_conformance::compare_documents;

const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let code = match run(&arguments) {
        Ok((code, output)) => {
            if let Err(error) = std::io::stdout().write_all(output.as_bytes()) {
                eprintln!("workflow-verifier-conformance: write stdout: {error}");
                4
            } else {
                code
            }
        }
        Err(error) => {
            eprintln!("workflow-verifier-conformance: {error}");
            2
        }
    };
    std::process::exit(code);
}

fn run(arguments: &[OsString]) -> Result<(i32, String), String> {
    let [command, left, right] = arguments else {
        return Err("usage: workflow-verifier-conformance compare DOCUMENT DOCUMENT".to_owned());
    };
    if command != "compare" {
        return Err("usage: workflow-verifier-conformance compare DOCUMENT DOCUMENT".to_owned());
    }
    let left = read_document(Path::new(left))?;
    let right = read_document(Path::new(right))?;
    let comparison = compare_documents(&left, &right)?;
    Ok((
        i32::from(!comparison.equivalent()),
        comparison.to_canonical_json(),
    ))
}

fn read_document(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open document {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect document {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "document is not a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(format!("document exceeds 16 MiB: {}", path.display()));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read document {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DOCUMENT_BYTES {
        return Err(format!("document exceeds 16 MiB: {}", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("document is not UTF-8: {}", path.display()))
}
