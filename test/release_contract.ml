let required =
  [
    "../mise.toml";
    "../justfile";
    "../scripts/verify_pure_ocaml.py";
    "../scripts/verify_architecture.py";
    "../scripts/verify_install_layout.py";
    "../scripts/generate_sbom.py";
    "../scripts/package_release.py";
    "../scripts/verify_release_version.py";
    "../scripts/verify_release_evidence.py";
    "../scripts/fetch_yaml_test_suite.py";
    "../scripts/corpus_gate.py";
    "../scripts/prepare_corpus.py";
    "../scripts/measure_performance.py";
    "../scripts/measure_performance_pair.py";
    "../scripts/performance_gate.py";
    "../scripts/run_afl_fuzz.py";
    "../scripts/verify_mutation_report.py";
    "../scripts/verify_mutation_campaign.py";
    "../scripts/mutation-shards-v1.json";
    "../scripts/determinism_probe.py";
    "../scripts/compare_determinism.py";
    "../scripts/dogfood_gate.py";
    "../.gitattributes";
    "../.ocaml-mutants.toml";
    "../test/upstream/yaml-test-suite.toml";
    "../.github/workflows/ci.yml";
    "../.github/workflows/mutation.yml";
    "../.github/workflows/release.yml";
    "../.gitlab-ci.yml";
    "../azure-pipelines.yml";
    "../.circleci/config.yml";
    "../docs/release.md";
    "../docs/security-review.md";
    "../docs/evaluation.md";
    "../corpus/README.md";
    "../performance/README.md";
    "../performance/suite-v1.json";
    "../schema/dogfood-v1.schema.json";
    "../schema/mutation-campaign-v1.schema.json";
    "../schema/corpus-review-v1.schema.json";
    "../schema/release-evidence-v1.schema.json";
    "../release-evidence/README.md";
  ]

let fail format =
  Printf.ksprintf
    (fun value ->
      prerr_endline value;
      exit 1)
    format

let source_root =
  let cwd = Sys.getcwd () in
  Filename.dirname (Filename.dirname (Filename.dirname cwd))

let read_required relative =
  match Util.read_file (Filename.concat source_root relative) with
  | Ok source -> source
  | Error message -> fail "%s" message

let () =
  List.iter
    (fun relative ->
      let path =
        Filename.concat source_root
          (String.sub relative 3 (String.length relative - 3))
      in
      if not (Sys.file_exists path) then
        fail "missing release artifact %s" relative;
      match Util.read_file path with
      | Error message -> fail "%s" message
      | Ok source when String.trim source = "" ->
          fail "empty release artifact %s" relative
      | Ok _ -> Printf.printf "ok - %s exists\n" relative)
    required;
  let opam =
    match
      Util.read_file (Filename.concat source_root "workflow-verifier.opam")
    with
    | Ok source -> source
    | Error message -> fail "%s" message
  in
  List.iter
    (fun forbidden ->
      if Util.contains ~needle:forbidden opam then
        fail "analyzer dependency surface contains %s" forbidden)
    [ "ctypes"; "yaml"; "unix"; "cmdliner"; "yojson" ];
  let attributes = read_required ".gitattributes" in
  if
    not
      (Util.contains ~needle:"evaluation/corpus/** -text -whitespace" attributes)
  then
    fail "immutable corpus bytes must bypass Git text and whitespace rewriting";
  let github = read_required ".github/workflows/ci.yml" in
  if
    Util.contains ~needle:"actions/checkout@v" github
    || Util.contains ~needle:"ocaml/setup-ocaml@v" github
  then fail "GitHub CI actions must be immutable commit pins";
  List.iter
    (fun command ->
      if not (Util.contains ~needle:command github) then
        fail "GitHub CI omits required gate: %s" command)
    [
      "unittest discover";
      "verify_architecture.py";
      "fetch_yaml_test_suite.py --allow-network";
      "yaml-test-suite-canonical-data-2022-01-17";
      "yaml_conformance.exe";
      "cargo fmt --manifest-path helpers/Cargo.toml --all -- --check";
      "cargo clippy --manifest-path helpers/Cargo.toml --workspace \
       --all-targets -- -D warnings";
      "run_afl_fuzz.py";
      "--profile afl";
      "determinism_probe.py";
      "compare_determinism.py";
      "dogfood_gate.py verify";
      "dogfood_gate.py extract-evidence";
      "sandbox run --backend oci:docker";
      "WORKFLOW_VERIFIER_OCI_HELPER";
      "rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4";
      "Performance ${{ matrix.platform }}";
      "measure_performance_pair.py";
      "Period-balance identical workloads";
      "--samples 24";
      "performance_gate.py";
      "- performance-regression";
    ];
  if not (Util.contains ~needle:"run: sh helpers/macos/build-shim.sh" github)
  then fail "macOS shim build must use an explicit POSIX shell";
  if Util.contains ~needle:"rust:1.85-bookworm sh" github then
    fail "Linux containment image must be pinned by digest";
  let yaml_pin = read_required "test/upstream/yaml-test-suite.toml" in
  List.iter
    (fun evidence ->
      if not (Util.contains ~needle:evidence yaml_pin) then
        fail "yaml-test-suite pin omits immutable export evidence: %s" evidence)
    [
      "cases = 402";
      "export_schema = 1";
      "export_files = 1887";
      "export_tree_sha256 = \
       \"7d4d407d90a557f337770260d31f7e518551921e73aa56681b4516d947587158\"";
    ];
  let yaml_fetch = read_required "scripts/fetch_yaml_test_suite.py" in
  List.iter
    (fun contract ->
      if not (Util.contains ~needle:contract yaml_fetch) then
        fail "yaml-test-suite fetcher omits pin contract: %s" contract)
    [
      "PIN = load_pin(PIN_PATH)";
      "expected_files=PIN.export_files";
      "expected_tree_sha256=PIN.export_tree_sha256";
    ];
  if Util.contains ~needle:"6e6c296ae9c9d2d5c4134b4b64d01b29ac19ff6f" yaml_fetch
  then fail "yaml-test-suite fetcher duplicates the commit pin authority";
  List.iter
    (fun (relative, required) ->
      let source = read_required relative in
      if not (Util.contains ~needle:required source) then
        fail "%s omits period-balanced sample count: %s" relative required)
    [
      ("justfile", "samples=\"24\"");
      ("mise.toml", "--samples 24");
      ("justfile", "prepare_corpus.py acquire");
      ("justfile", "prepare_corpus.py apply-review");
      ("mise.toml", "prepare_corpus.py acquire");
      ("mise.toml", "prepare_corpus.py apply-review");
    ];
  if
    not
      (Util.contains
         ~needle:
           "rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4"
         github)
  then fail "Linux containment image pin is missing";
  List.iter
    (fun relative ->
      let source = read_required relative in
      List.iter
        (fun command ->
          if not (Util.contains ~needle:command source) then
            fail "%s omits required YAML gate: %s" relative command)
        [
          "fetch_yaml_test_suite.py --allow-network";
          "yaml-test-suite-canonical-data-2022-01-17";
          "yaml_conformance.exe";
        ])
    [ ".gitlab-ci.yml"; "azure-pipelines.yml"; ".circleci/config.yml" ];
  let ci = read_required ".github/workflows/ci.yml" in
  if not (Util.contains ~needle:"workflow_call:" ci) then
    fail "CI workflow must be reusable by the release workflow";
  let release = read_required ".github/workflows/release.yml" in
  let mutation = read_required ".github/workflows/mutation.yml" in
  let mutation_config = read_required ".ocaml-mutants.toml" in
  let test_build = read_required "test/dune" in
  List.iter
    (fun mutable_reference ->
      if Util.contains ~needle:mutable_reference mutation then
        fail "mutation workflow contains mutable action reference %s"
          mutable_reference)
    [
      "actions/checkout@v";
      "actions/upload-artifact@v";
      "actions/download-artifact@v";
      "ocaml/setup-ocaml@v";
    ];
  if
    not
      (Util.contains
         ~needle:
           "name: yaml-conformance-oracle\n\
           \          path: \
            _build/upstream/yaml-test-suite-canonical-data-2022-01-17\n\
           \          if-no-files-found: error\n\
           \          include-hidden-files: true"
         mutation)
  then
    fail
      "mutation workflow must retain the hidden canonical YAML export manifest";
  List.iter
    (fun required_surface ->
      if not (Util.contains ~needle:required_surface mutation) then
        fail "mutation workflow omits required surface: %s" required_surface)
    [
      "ff665225c110f8b71a40356bf69574b5c9a67413";
      "mkdir -p _build";
      "ocaml-mutants list --json";
      "ocaml-mutants run --fresh --json";
      "--destination _build/upstream/yaml-test-suite-data-2022-01-17";
      "--export-destination";
      "_build/upstream/yaml-test-suite-canonical-data-2022-01-17";
      "--verify-export-only";
      "WORKFLOW_VERIFIER_YAML_SUITE: ${{ github.workspace \
       }}/_build/upstream/yaml-test-suite-canonical-data-2022-01-17";
      "verify_mutation_campaign.py";
      "mutation-shards-v1.json";
      "fromJSON(needs.catalog.outputs.matrix)";
      "continue-on-error: true";
      "if: always()";
      "--runner-exit";
      "mutation-runner-exit-${{ matrix.shard }}.txt";
      "mutation-report-${{ matrix.shard }}.json";
      "mutation-campaign-v1.json";
    ];
  List.iter
    (fun required_surface ->
      if not (Util.contains ~needle:required_surface mutation_config) then
        fail "mutation configuration omits required surface: %s"
          required_surface)
    [
      "name = \"yaml-conformance\"";
      "@@test/mutation-yaml-conformance";
      "name = \"semantic-fingerprints\"";
      "@@test/mutation-semantic-oracle";
    ];
  if not (Util.contains ~needle:"(alias mutation-yaml-conformance)" test_build)
  then fail "test build omits the mutation YAML conformance alias";
  if
    not
      (Util.contains ~needle:"(env_var WORKFLOW_VERIFIER_YAML_SUITE)" test_build)
  then fail "mutation YAML alias omits its explicit external oracle input";
  if
    not
      (Util.contains ~needle:"%{env:WORKFLOW_VERIFIER_YAML_SUITE=}" test_build)
  then fail "mutation YAML alias does not pass the external oracle path";
  if Util.contains ~needle:"(source_tree upstream/" test_build then
    fail "mutation YAML oracle must stay outside the analyzed source snapshot";
  if not (Util.contains ~needle:"(alias mutation-semantic-oracle)" test_build)
  then fail "test build omits the semantic mutation oracle alias";
  if Util.contains ~needle:"Run all configured analyzer-core mutants" mutation
  then fail "mutation workflow must shard the complete catalog before execution";
  let mutation_campaign = read_required "scripts/verify_mutation_campaign.py" in
  if not (Util.contains ~needle:"verify_mutation_report" mutation_campaign) then
    fail "mutation campaign verifier must retain the strict per-report verifier";
  List.iter
    (fun mutable_reference ->
      if Util.contains ~needle:mutable_reference release then
        fail "release workflow contains mutable action reference %s"
          mutable_reference)
    [
      "actions/checkout@v";
      "actions/upload-artifact@v";
      "actions/download-artifact@v";
      "actions/attest@v";
      "sigstore/cosign-installer@v";
    ];
  List.iter
    (fun required_surface ->
      if not (Util.contains ~needle:required_surface release) then
        fail "release workflow omits required surface: %s" required_surface)
    [
      "verify_release_version.py --tag";
      "package_release.py";
      "generate_sbom.py";
      "cargo build --locked --release";
      "cosign sign-blob --yes --bundle";
      "subject-checksums:";
      "sbom-path:";
      "gh release create";
      "id-token: write";
      "attestations: write";
      "artifact-metadata: write";
      "uses: ./.github/workflows/ci.yml";
      "uses: ./.github/workflows/mutation.yml";
      "verify_release_evidence.py";
      "release-evidence/release-evidence-v1.json";
      "cosign verify-blob";
      "needs: [build, mutation, quality, release_evidence]";
    ];
  let just = read_required "justfile" and mise = read_required "mise.toml" in
  List.iter
    (fun command ->
      if not (Util.contains ~needle:command just) then
        fail "justfile omits required task surface: %s" command;
      if not (Util.contains ~needle:command mise) then
        fail "mise.toml omits required task surface: %s" command)
    [
      "corpus_gate.py";
      "measure_performance.py";
      "measure_performance_pair.py";
      "performance_gate.py";
      "run_afl_fuzz.py";
      "verify_mutation_report.py";
      "verify_mutation_campaign.py";
      "determinism_probe.py";
      "compare_determinism.py";
      "dogfood_gate.py";
      "verify_release_version.py --allow-development";
      "verify_release_evidence.py";
    ];
  let readme =
    match Util.read_file (Filename.concat source_root "README.md") with
    | Ok source -> String.lowercase_ascii source
    | Error message -> fail "%s" message
  in
  if
    Util.contains ~needle:"-dev" opam
    && not (Util.contains ~needle:"not a release candidate" readme)
  then
    fail "development builds must not imply that the publish gates are complete";
  Printf.printf "release surface contract passed\n"
