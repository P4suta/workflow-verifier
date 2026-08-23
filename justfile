set dotenv-load := false

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
    cargo test --manifest-path helpers/Cargo.toml --workspace --all-targets
    cargo fmt --manifest-path helpers/Cargo.toml --all -- --check
    cargo clippy --manifest-path helpers/Cargo.toml --workspace --all-targets -- -D warnings

tooling:
    python -B -m unittest discover -s scripts/tests -p "test_*.py" -v

fuzz seconds="60" memory_mb="1024":
    opam exec -- dune build --profile afl test/yaml_fuzz.exe
    python -B scripts/run_afl_fuzz.py --seeds fuzz/corpus/yaml --output _build/afl-results --target _build/default/test/yaml_fuzz.exe --seconds {{seconds}} --memory-mb {{memory_mb}}

mutation-gate report="_build/mutation-report.json" output="_build/mutation-gate-v1.json":
    python -B scripts/verify_mutation_report.py --report {{report}} --output {{output}} --require-prefix lib/foundation/ --require-prefix lib/syntax/ --require-prefix lib/domain/ --require-prefix lib/verifier/ --require-prefix lib/product/

corpus manifest="evaluation/corpus-v1.json" corpus_root="evaluation/corpus" reports_root="evaluation/reports" output="_build/corpus-report-v1.json":
    python -B scripts/corpus_gate.py --manifest {{manifest}} --corpus-root {{corpus_root}} --reports-root {{reports_root}} --output {{output}} --release

performance-measure suite="performance/suite-v1.json" revision output="_build/performance-current.json" samples="7":
    python -B scripts/measure_performance.py --suite {{suite}} --workspace . --revision {{revision}} --samples {{samples}} --output {{output}}

performance-pair baseline_workspace baseline_revision current_revision suite="performance/suite-v1.json" output_dir="_build/performance-pair" samples="21":
    python -B scripts/measure_performance_pair.py --suite {{suite}} --baseline-workspace {{baseline_workspace}} --baseline-revision {{baseline_revision}} --current-workspace . --current-revision {{current_revision}} --samples {{samples}} --output-dir {{output_dir}}

performance-gate baseline current="_build/performance-current.json" output="_build/performance-comparison-v1.json":
    python -B scripts/performance_gate.py --baseline {{baseline}} --current {{current}} --output {{output}}

determinism-probe output="_build/determinism/local":
    opam exec -- dune build bin/main.exe
    python -B scripts/determinism_probe.py --analyzer _build/default/bin/main.exe --fixture test/fixtures/determinism --output {{output}}

determinism-compare linux windows macos_arm64 macos_x86_64 output="_build/determinism/comparison.json":
    python -B scripts/compare_determinism.py --output {{output}} {{linux}} {{windows}} {{macos_arm64}} {{macos_x86_64}}

version:
    python -B scripts/verify_release_version.py --allow-development

release-evidence revision tag manifest="release-evidence/release-evidence-v1.json":
    python -B scripts/verify_release_evidence.py --manifest {{manifest}} --revision {{revision}} --tag {{tag}}

architecture:
    python -B scripts/verify_architecture.py

purity:
    python -B scripts/verify_pure_ocaml.py

licenses:
    python -B scripts/verify_licenses.py

install-check:
    opam exec -- dune build @install
    python -B scripts/verify_install_layout.py _build/install/default

sbom version artifact1 artifact2 artifact3 artifact4:
    python -B scripts/generate_sbom.py --version {{version}} --output dist/workflow-verifier.spdx.json --checksums dist/SHA256SUMS {{artifact1}} {{artifact2}} {{artifact3}} {{artifact4}}

check: build test yaml-conformance tooling architecture helpers purity licenses install-check

dogfood:
    opam exec -- dune exec workflow-verifier -- check --persona audit .

dogfood-gate root="_dogfood" output="_build/dogfood-v1.json":
    python -B scripts/dogfood_gate.py verify --root {{root}} --output {{output}}
