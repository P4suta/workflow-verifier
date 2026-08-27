#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;
use workflow_verifier_conformance::compare_reports;

const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

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
        return Err("usage: workflow-verifier-conformance compare REPORT REPORT".to_owned());
    };
    if command != "compare" {
        return Err("usage: workflow-verifier-conformance compare REPORT REPORT".to_owned());
    }
    let left = read_report(Path::new(left))?;
    let right = read_report(Path::new(right))?;
    let comparison = compare_reports(&left, &right)?;
    Ok((
        i32::from(!comparison.equivalent()),
        comparison.to_canonical_json(),
    ))
}

fn read_report(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open report {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect report {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("report is not a regular file: {}", path.display()));
    }
    if metadata.len() > MAX_REPORT_BYTES {
        return Err(format!("report exceeds 16 MiB: {}", path.display()));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read report {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REPORT_BYTES {
        return Err(format!("report exceeds 16 MiB: {}", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("report is not UTF-8: {}", path.display()))
}
