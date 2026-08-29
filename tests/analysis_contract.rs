use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use workflow_verifier::internal::conformance::engine::{
    AnalysisInput, AnalysisSession, AnalysisSource, Analyzer, CancellationToken, LoadOptions,
    WorkspaceEntry, WorkspaceFileSystem, WorkspaceLoader,
};
use workflow_verifier::internal::conformance::product::{BuildInfo, GraphKind};

fn source(path: &str, text: &str) -> AnalysisSource {
    AnalysisSource::new(path, Arc::<str>::from(text)).expect("valid analysis source")
}

fn workflow(command: &str) -> String {
    format!(
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {command}\n"
    )
}

fn analyzer() -> Analyzer {
    Analyzer::with_build(BuildInfo {
        compiler: "rustc test".to_owned(),
        target: "test-target".to_owned(),
        source_commit: Some("test-commit".to_owned()),
    })
}

#[test]
fn outcome_is_owned_once_and_formats_are_borrowed_projections() {
    let input = AnalysisInput::new([source(".github/workflows/ci.yml", &workflow("echo safe"))])
        .expect("input");
    let outcome = analyzer().analyze(input).expect("analysis");
    let report = outcome.check_report().to_canonical_json();
    assert!(report.contains("\"schema\":\"workflow-verifier-report/1\""));
    assert!(!report.contains("\"graphs\""));
    assert!(!report.contains("binary_digest"));

    let graph = outcome.graph(GraphKind::All).to_canonical_json();
    assert!(graph.contains("\"schema\":\"workflow-verifier-graph/1\""));
    assert!(graph.contains("\"sources\""));
    assert!(!graph.contains("\"edge_id\""));
    assert!(
        outcome
            .program()
            .nodes
            .iter()
            .enumerate()
            .all(|(index, node)| node.id.0 == u32::try_from(index).expect("fixture fits"))
    );
}

#[test]
fn session_caches_are_mutable_local_state_and_overlay_deletion_invalidates_semantics() {
    let base = AnalysisInput::new([source(".github/workflows/ci.yml", &workflow("echo first"))])
        .expect("input");
    let mut session = AnalysisSession::with_build(BuildInfo {
        compiler: "rustc test".to_owned(),
        target: "test-target".to_owned(),
        source_commit: Some("test-commit".to_owned()),
    });
    let first = session.analyze(base.clone()).expect("first");
    let first_digest = first.check_report().analysis_digest();
    let second = session.analyze(base.clone()).expect("second");
    assert_eq!(first_digest, second.check_report().analysis_digest());
    assert!(session.statistics().parse_hits > 0);
    assert!(session.statistics().lower_hits > 0);

    let mut edited = base.clone();
    edited.overlays.insert(
        ".github/workflows/ci.yml".to_owned(),
        Some(Arc::<str>::from(workflow("echo second"))),
    );
    let changed = session.analyze(edited).expect("edited");
    assert_ne!(first_digest, changed.check_report().analysis_digest());

    let mut deleted = base;
    deleted
        .overlays
        .insert(".github/workflows/ci.yml".to_owned(), None);
    let empty = session.analyze(deleted).expect("deleted overlay");
    assert!(empty.program().nodes.is_empty());
}

#[test]
fn cancellation_is_typed_before_analysis_work() {
    let mut input =
        AnalysisInput::new([source(".github/workflows/ci.yml", &workflow("echo safe"))])
            .expect("input");
    input.cancellation = CancellationToken::new();
    input.cancellation.cancel();
    let error = analyzer().analyze(input).expect_err("cancelled");
    assert_eq!(error.code(), "Cancelled");
}

#[derive(Clone, Default)]
struct CountingFs {
    directories: Arc<BTreeMap<PathBuf, Vec<WorkspaceEntry>>>,
    files: Arc<BTreeMap<PathBuf, Arc<[u8]>>>,
    reads: Arc<Mutex<Vec<PathBuf>>>,
}

impl WorkspaceFileSystem for CountingFs {
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, String> {
        Ok(path.to_path_buf())
    }

    fn is_file(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    fn is_directory(&self, path: &Path) -> bool {
        self.directories.contains_key(path)
    }

    fn read_directory(&self, path: &Path) -> Result<Vec<WorkspaceEntry>, String> {
        self.directories
            .get(path)
            .cloned()
            .ok_or_else(|| "missing directory".to_owned())
    }

    fn read(&self, path: &Path) -> Result<Arc<[u8]>, String> {
        self.reads
            .lock()
            .expect("read lock")
            .push(path.to_path_buf());
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| "missing file".to_owned())
    }
}

#[test]
fn static_loader_never_reads_an_unrelated_large_file() {
    let root = PathBuf::from("/repo");
    let github = root.join(".github");
    let workflows = github.join("workflows");
    let workflow_path = workflows.join("ci.yml");
    let huge = root.join("huge.bin");
    let directories = BTreeMap::from([
        (
            root.clone(),
            vec![
                WorkspaceEntry {
                    path: github.clone(),
                    is_directory: true,
                    is_file: false,
                },
                WorkspaceEntry {
                    path: huge.clone(),
                    is_directory: false,
                    is_file: true,
                },
            ],
        ),
        (
            github.clone(),
            vec![WorkspaceEntry {
                path: workflows.clone(),
                is_directory: true,
                is_file: false,
            }],
        ),
        (
            workflows.clone(),
            vec![WorkspaceEntry {
                path: workflow_path.clone(),
                is_directory: false,
                is_file: true,
            }],
        ),
    ]);
    let files = BTreeMap::from([
        (
            workflow_path.clone(),
            Arc::<[u8]>::from(workflow("echo safe").into_bytes()),
        ),
        (huge.clone(), Arc::<[u8]>::from(vec![0; 1_000_000])),
    ]);
    let filesystem = CountingFs {
        directories: Arc::new(directories),
        files: Arc::new(files),
        reads: Arc::default(),
    };
    let reads = Arc::clone(&filesystem.reads);
    let input = WorkspaceLoader::new(filesystem)
        .load(LoadOptions::new(&root))
        .expect("workspace load");
    assert_eq!(input.sources.len(), 1);
    assert_eq!(*reads.lock().expect("read lock"), vec![workflow_path]);
}
