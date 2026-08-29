set dotenv-load := false
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

bootstrap:
    opam init --bare --no-setup --yes
    opam switch create . ocaml-base-compiler.5.5.0 --yes
    opam install . --deps-only --with-test --locked --yes

build:
    opam exec -- dune build @all

test:
    opam exec -- dune runtest --force

property:
    opam exec -- dune exec test/property_contract.exe

yaml-conformance suite="_build/upstream/yaml-test-suite-data-2022-01-17":
    python -B scripts/fetch_yaml_test_suite.py --destination {{suite}}
    opam exec -- dune exec test/yaml_conformance.exe -- --suite {{suite}}

fetch-yaml-suite:
    python -B scripts/fetch_yaml_test_suite.py --allow-network

helpers:
    cargo test --workspace --all-targets --exclude workflow-verifier --exclude workflow-verifier-conformance

helpers-lint:
    cargo clippy --workspace --all-targets --exclude workflow-verifier --exclude workflow-verifier-conformance -- -D warnings

rust:
    cargo fmt --all -- --check
    cargo test --workspace --all-targets
    cargo clippy --workspace --all-targets -- -D warnings

lsp-performance:
    cargo test --release -p workflow-verifier --lib lsp::performance_tests -- --ignored --nocapture --test-threads=1

differential:
    opam exec -- dune build bin/main.exe
    cargo build -p workflow-verifier -p workflow-verifier-conformance
    mkdir -p _build/rust-conformance
    _build/default/bin/main.exe __semantic-conformance --trust-repository-config test/fixtures/determinism > _build/rust-conformance/reference-determinism.json
    target/debug/workflow-verifier __semantic-conformance --trust-repository-config test/fixtures/determinism > _build/rust-conformance/candidate-determinism.json
    target/debug/workflow-verifier-conformance compare _build/rust-conformance/reference-determinism.json _build/rust-conformance/candidate-determinism.json > _build/rust-conformance/determinism-comparison.json
    _build/default/bin/main.exe __semantic-conformance --trust-repository-config test/fixtures/determinism-exclusions > _build/rust-conformance/reference-exclusions.json
    target/debug/workflow-verifier __semantic-conformance --trust-repository-config test/fixtures/determinism-exclusions > _build/rust-conformance/candidate-exclusions.json
    target/debug/workflow-verifier-conformance compare _build/rust-conformance/reference-exclusions.json _build/rust-conformance/candidate-exclusions.json > _build/rust-conformance/exclusions-comparison.json
    _build/default/bin/main.exe __semantic-conformance test/fixtures/semantic-local > _build/rust-conformance/reference-local-link.json
    target/debug/workflow-verifier __semantic-conformance test/fixtures/semantic-local > _build/rust-conformance/candidate-local-link.json
    target/debug/workflow-verifier-conformance compare _build/rust-conformance/reference-local-link.json _build/rust-conformance/candidate-local-link.json > _build/rust-conformance/local-link-comparison.json

tooling:
    python -B -m unittest discover -s scripts/tests -p "test_*.py" -v

fuzz seconds="60" memory_mb="1024":
    opam exec -- dune build --profile afl test/yaml_fuzz.exe
    python -B scripts/run_afl_fuzz.py --seeds fuzz/corpus/yaml --output _build/afl-results --target _build/default/test/yaml_fuzz.exe --seconds {{seconds}} --memory-mb {{memory_mb}}

mutation-gate report="_build/mutation-report.json" output="_build/mutation-gate-v1.json":
    python -B scripts/verify_mutation_report.py --report {{report}} --output {{output}} --require-prefix lib/foundation/ --require-prefix lib/syntax/ --require-prefix lib/domain/ --require-prefix lib/verifier/ --require-prefix lib/product/

mutation-campaign catalog="_build/mutation-evidence/mutation-catalog.json" evidence="_build/mutation-evidence" output="_build/mutation-evidence/mutation-campaign-v1.json":
    python -B scripts/verify_mutation_campaign.py aggregate --manifest scripts/mutation-shards-v1.json --config .ocaml-mutants.toml --workspace . --catalog {{catalog}} --evidence-dir {{evidence}} --output {{output}}

mutation-rust-list output="_build/rust-mutants-catalog.json":
    mkdir -p _build
    cargo mutants --config .cargo/mutants.toml --package workflow-verifier --list --json > {{output}}

mutation-rust layer output="_build/rust-mutants":
    cargo mutants --config .cargo/mutants.toml --package workflow-verifier --file "src/{{layer}}/**/*.rs" --output {{output}}

mutation-rust-high-value output="_build/rust-mutants-high-value":
    cargo mutants --config .cargo/mutants.toml --package workflow-verifier --output {{output}}

corpus manifest="evaluation/corpus-v1.json" corpus_root="evaluation/corpus" reports_root="evaluation/reports" output="_build/corpus-report-v1.json":
    python -B scripts/corpus_gate.py --manifest {{manifest}} --corpus-root {{corpus_root}} --reports-root {{reports_root}} --output {{output}} --release

corpus-acquire analyzer="target/debug/workflow-verifier" output="evaluation" pages="10" workers="8":
    cargo build --locked -p workflow-verifier
    python -B scripts/prepare_corpus.py acquire --analyzer {{analyzer}} --output {{output}} --per-provider 100 --pages {{pages}} --workers {{workers}}

corpus-refresh evaluation="evaluation" analyzer="target/debug/workflow-verifier" output="_build/evaluation-refreshed" workers="8":
    cargo build --locked -p workflow-verifier
    python -B scripts/prepare_corpus.py refresh --evaluation {{evaluation}} --analyzer {{analyzer}} --output {{output}} --workers {{workers}}

corpus-review review="evaluation/review-v1.json" manifest="evaluation/corpus-v1.json" reports_root="evaluation/reports":
    python -B scripts/prepare_corpus.py apply-review --manifest {{manifest}} --reports-root {{reports_root}} --review {{review}}

official-fetch manifest="official/official-projects-v1.json" destination="_build/official-projects" mode="pinned":
    python -B scripts/fetch_official_projects.py --manifest {{manifest}} --destination {{destination}} --mode {{mode}}

official-compat analyzer="target/debug/workflow-verifier" snapshots="_build/official-projects" output="_build/official-compat-v1.json":
    cargo build --locked -p workflow-verifier
    python -B scripts/official_compat.py --manifest official/official-projects-v1.json --snapshots {{snapshots}} --analyzer {{analyzer}} --output {{output}}

performance-measure revision suite="performance/rust-suite-v2.json" output="_build/performance-current.json" samples="7":
    python -B scripts/measure_performance.py --suite {{suite}} --workspace . --revision {{revision}} --samples {{samples}} --output {{output}}

performance-pair baseline_workspace baseline_revision current_revision suite="performance/rust-suite-v2.json" output_dir="_build/performance-pair" samples="24":
    python -B scripts/measure_performance_pair.py --suite {{suite}} --baseline-workspace {{baseline_workspace}} --baseline-revision {{baseline_revision}} --current-workspace . --current-revision {{current_revision}} --samples {{samples}} --output-dir {{output_dir}}

performance-measure-rust revision output="_build/performance-rust-current.json" samples="7":
    WORKFLOW_VERIFIER_SOURCE_COMMIT={{revision}} cargo build --locked --release -p workflow-verifier
    python -B scripts/measure_performance.py --suite performance/rust-suite-v2.json --workspace . --revision {{revision}} --samples {{samples}} --output {{output}}

performance-pair-rust baseline_workspace baseline_revision current_revision output_dir="_build/performance-rust-pair" samples="24":
    WORKFLOW_VERIFIER_SOURCE_COMMIT={{baseline_revision}} cargo build --locked --release --manifest-path {{baseline_workspace}}/Cargo.toml --bin workflow-verifier
    WORKFLOW_VERIFIER_SOURCE_COMMIT={{current_revision}} cargo build --locked --release -p workflow-verifier
    python -B scripts/measure_performance_pair.py --suite performance/rust-suite-v2.json --baseline-workspace {{baseline_workspace}} --baseline-revision {{baseline_revision}} --current-workspace . --current-revision {{current_revision}} --samples {{samples}} --output-dir {{output_dir}}

performance-gate baseline current="_build/performance-current.json" output="_build/performance-comparison-v2.json":
    python -B scripts/performance_gate.py --baseline {{baseline}} --current {{current}} --output {{output}}

determinism-probe output="_build/determinism/local":
    WORKFLOW_VERIFIER_SOURCE_COMMIT=$(git rev-parse HEAD) cargo build --locked -p workflow-verifier
    python -B scripts/determinism_probe.py --analyzer target/debug/workflow-verifier --fixture test/fixtures/determinism --output {{output}}

determinism-compare linux_x86_64 linux_arm64 windows macos_arm64 macos_x86_64 output="_build/determinism/comparison.json":
    python -B scripts/compare_determinism.py --output {{output}} {{linux_x86_64}} {{linux_arm64}} {{windows}} {{macos_arm64}} {{macos_x86_64}}

version:
    python -B scripts/verify_release_version.py --allow-development

sync-release-version:
    python -B scripts/sync_release_version.py

release-evidence revision tag manifest="release-evidence/release-evidence-v4.json":
    python -B scripts/verify_release_evidence.py --manifest {{manifest}} --revision {{revision}} --tag {{tag}} --repository .

candidate-source revision version output="_candidate/source":
    python -B scripts/candidate_artifacts.py source-assets --repository . --subject-commit {{revision}} --version {{version}} --output-dir {{output}} --fragment {{output}}/reproducibility-source.json

candidate-reproducibility revision output *fragments:
    python -B scripts/candidate_artifacts.py aggregate --subject-commit {{revision}} --output {{output}} {{fragments}}

architecture:
    python -B scripts/verify_architecture.py

lint-policy:
    python -B scripts/verify_lint_policy.py

purity:
    python -B scripts/verify_pure_ocaml.py

licenses:
    python -B scripts/verify_licenses.py

install-check:
    opam exec -- dune build @install
    cargo build -p workflow-verifier
    python -B scripts/verify_install_layout.py _build/install/default target/debug/workflow-verifier

task-surface:
    python -B scripts/verify_task_surface.py

conformance-manifest:
    python -B scripts/verify_conformance_manifest.py --manifest conformance/manifest-v2.json --root .

links:
    python -B scripts/verify_markdown_links.py --root .

sbom version *artifacts:
    python -B scripts/generate_sbom.py --version {{version}} --dependency-manifest release/sbom-components-v1.json --output-dir dist/sbom --cyclonedx dist/workflow-verifier.cdx.json --checksums dist/SBOM-SHA256SUMS {{artifacts}}

linux-compat binary:
    python -B scripts/verify_linux_compat.py {{binary}}

check: task-surface conformance-manifest links build test yaml-conformance tooling architecture lint-policy rust lsp-performance differential purity licenses install-check

dogfood:
    cargo build --locked -p workflow-verifier
    target/debug/workflow-verifier check --config examples/dogfood-policy-v2.toml --trust-repository-config .

dogfood-gate root="_dogfood" output="_build/dogfood-v1.json":
    python -B scripts/dogfood_gate.py verify --root {{root}} --output {{output}}
