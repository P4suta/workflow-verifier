type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let controls =
  [
    Sandbox_protocol.Source_read_only;
    Scratch_overlay;
    Network_deny;
    Process_isolation;
    Resource_limits;
    Secret_redaction;
  ]

let step ?(supported = true) id command =
  {
    Sandbox_protocol.id;
    image = "sha256:" ^ String.make 64 'a';
    argv = [ "/bin/sh"; "-c"; command ];
    environment = [ ("CI", "true") ];
    working_directory = "/workspace";
    supported;
  }

let make_plan ~backend ~source_digest ~lock_digest ~controls ~limits
    ~secret_names ~dependencies ~steps =
  let runner_platform =
    match backend with
    | Sandbox_protocol.Oci _ | Linux_native -> "linux-x86_64"
    | Windows_native -> "windows-x86_64"
    | Macos_vm -> "macos-arm64"
  in
  match
    Sandbox_protocol.make_scenario_plan ~backend
      ~scenario_digest:("sha256:" ^ String.make 64 'd')
      ~provider_profile:"test-semantic-v1" ~selected_jobs:[ "build" ]
      ~runner_platform ~source_digest ~lock_digest ~controls ~limits
      ~network_destinations:[] ~secret_names ~dependencies ~steps
      ~incomplete_reasons:[]
  with
  | Ok plan -> plan
  | Error error -> fail "valid test plan was rejected: %s" error

let complete_evidence_with_backend (plan : Sandbox_protocol.plan) backend_id =
  let evidence =
    Evidence.for_plan plan
    |> Evidence.append
         (Evidence.Backend_attested
            {
              id = backend_id;
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
            wall_time_ms = 1;
            cpu_time_ms = 0;
            peak_memory_bytes = 0L;
            processes = 1;
            output_bytes = 0;
            scratch_bytes = 0L;
            scratch_entries = 0;
          })
  |> Evidence.append
       (Evidence.Log_recorded { digest = "sha256:" ^ Sha256.digest_string "" })
  |> Evidence.append (Evidence.Filesystem_final { digest = plan.source_digest })

let fixture_root () =
  let build_tree = Filename.concat (Sys.getcwd ()) "fixtures/protocol" in
  if Sys.file_exists build_tree then build_tree
  else Filename.concat (Sys.getcwd ()) "test/fixtures/protocol"

let fixture name =
  let path = Filename.concat (fixture_root ()) name in
  match Util.read_file path with
  | Ok source -> source
  | Error message -> fail "%s" message

let cross_language_protocol_test () =
  let source = fixture "runner-v2-complete.json" in
  let plan =
    match Sandbox_protocol.parse source with
    | Ok plan -> plan
    | Error error -> fail "OCaml rejected shared runner fixture: %s" error
  in
  let canonical_plan = Sandbox_protocol.to_canonical_json plan in
  let () =
    if canonical_plan = source then ()
    else
      let rec first_difference index =
        if
          index >= String.length source || index >= String.length canonical_plan
        then index
        else if source.[index] <> canonical_plan.[index] then index
        else first_difference (index + 1)
      in
      let difference = first_difference 0 in
      fail
        "shared runner fixture is not OCaml canonical (byte=%d actual=%d/%s \
         fixture=%d/%s):\n\
         actual=%S\n\
         fixture=%S"
        difference
        (String.length canonical_plan)
        (Sha256.digest_string canonical_plan)
        (String.length source)
        (Sha256.digest_string source)
        canonical_plan source
  in
  let invalid = fixture "runner-v2-invalid-complete.json" in
  expect "complete cannot conceal an unresolved dependency"
    (Result.is_error (Sandbox_protocol.parse invalid));
  let run_source = fixture "sandbox-run-v2-complete.json" in
  let run =
    match Sandbox_run.parse run_source with
    | Ok value -> value
    | Error error -> fail "OCaml rejected shared sandbox-run fixture: %s" error
  in
  expect "shared sandbox-run fixture is OCaml canonical"
    (Sandbox_run.to_canonical_json run = run_source)

let cross_language_source_manifest_test () =
  let root = Filename.concat (fixture_root ()) "source-tree" in
  let read relative =
    let path = Filename.concat root relative in
    match Util.read_file path with
    | Ok source -> (path, source)
    | Error message -> fail "%s" message
  in
  let manifest =
    match
      Source_manifest.create ~root ~files:[ read "a.txt"; read "nested/b.txt" ]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "OCaml source manifest matches the shared canonical fixture"
    (manifest.canonical_json = String.trim (fixture "source-manifest-v2.json"));
  expect "shared source manifest has a stable content digest"
    (manifest.digest
   = "sha256:d70c409989907fb9194417d737ec25d8dd56e7ab36911dbf5b43db5d620b3594")

let trusted_source_exclusion_manifest_test () =
  let root = "repository" in
  let source path contents =
    ( Filename.concat root path,
      Source_manifest.Regular_source
        { contents; executable = false; identity = None } )
  in
  let create trusted_exclusions =
    match
      Source_manifest.create_from_sources ~budget:Source_manifest.default_budget
        ~trusted_exclusions ~root
        ~files:
          [ source "workflow.yml" "jobs: {}\n"; source "_build/cache" "bytes" ]
    with
    | Ok manifest -> manifest
    | Error message -> fail "%s" message
  in
  let included = create [] and excluded = create [ "_build" ] in
  expect "trusted exclusions remove only the declared prefix"
    (List.length included.entries = 2
    && List.map
         (fun (entry : Source_manifest.entry) -> entry.path)
         excluded.entries
       = [ "workflow.yml" ]);
  expect "manifest records the exclusion and its trust reason"
    (excluded.exclusions
    = [ { Source_manifest.path = "_build/cache"; reason = "trusted-policy" } ]);
  expect "exclusion policy changes the content-addressed manifest"
    (included.exclusion_policy_digest <> excluded.exclusion_policy_digest
    && included.digest <> excluded.digest)

let canonical_plan_test () =
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 'b')
      ~lock_digest:("sha256:" ^ String.make 64 'c')
      ~controls
      ~limits:
        {
          cpu_seconds = 900;
          memory_mb = 2048;
          processes = 128;
          output_bytes = 16 * 1024 * 1024;
        }
      ~secret_names:[ "TOKEN"; "DEPLOY_KEY" ] ~dependencies:[]
      ~steps:[ step "build" "make test" ]
  in
  expect "fully resolved supported plan is Complete"
    (plan.status = Sandbox_protocol.Complete);
  let first = Sandbox_protocol.to_canonical_json plan
  and second = Sandbox_protocol.to_canonical_json plan in
  expect "plan bytes are deterministic" (first = second);
  expect "secret names are present for injection"
    (Util.contains ~needle:"DEPLOY_KEY" first);
  expect "protocol has no field for secret values"
    (not (Util.contains ~needle:"secret_values" first));
  let parsed =
    match Sandbox_protocol.parse first with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  expect "plan digest validates on round trip" (parsed.digest = plan.digest);
  let tampered =
    Util.replace_all ~needle:"make test" ~replacement:"make publish" first
  in
  match Sandbox_protocol.parse tampered with
  | Error _ -> ()
  | Ok _ -> fail "tampered plan must fail digest validation"

let incomplete_test () =
  let dependency =
    {
      Sandbox_protocol.reference = "owner/action@v4";
      digest = None;
      available = false;
    }
  in
  let plan =
    make_plan ~backend:Linux_native
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls ~limits:Sandbox_protocol.portable_limits ~secret_names:[]
      ~dependencies:[ dependency ]
      ~steps:[ step ~supported:false "opaque" "unknown" ]
  in
  match plan.status with
  | Incomplete reasons ->
      expect "unresolved dependency and unsupported step are retained"
        (List.exists (Util.contains ~needle:"Unresolved_dependency") reasons
        && List.exists (Util.contains ~needle:"Unsupported_step") reasons)
  | Complete -> fail "incomplete plan cannot report success"

let smart_constructor_test () =
  let result =
    Sandbox_protocol.make_plan ~backend:(Oci "docker")
      ~source_digest:"sha256:source" ~lock_digest:"sha256:lock" ~controls
      ~limits:
        { cpu_seconds = 0; memory_mb = 64; processes = 4; output_bytes = 1024 }
      ~secret_names:[ "TOKEN" ] ~dependencies:[]
      ~steps:[ { (step "empty" "ignored") with argv = [] } ]
  in
  expect "schema-invalid plans cannot be constructed" (Result.is_error result)

let backend_fail_closed_test () =
  let requested =
    {
      Sandbox_backend.backend = Sandbox_protocol.Windows_native;
      required_controls =
        controls
        @ [
            Sandbox_protocol.App_container;
            Sandbox_protocol.Restricted_token;
            Sandbox_protocol.Job_object;
          ];
    }
  and weak_windows =
    {
      Sandbox_backend.id = "windows-native";
      version = "1";
      platform = "windows";
      controls =
        controls
        @ [ Sandbox_protocol.Restricted_token; Sandbox_protocol.Job_object ];
    }
  and oci =
    {
      Sandbox_backend.id = "oci:docker";
      version = "1";
      platform = "windows";
      controls;
    }
  in
  match Sandbox_backend.select requested [ weak_windows; oci ] with
  | Error missing ->
      expect "missing AppContainer is explicit"
        (List.mem Sandbox_protocol.App_container missing)
  | Ok selected -> fail "must not fall back to %s" selected.id

let backend_probe_parse_test () =
  let source =
    "{\"available\":true,\"controls\":[\"source_read_only\",\"network_deny\"],\"id\":\"oci:docker\",\"platform\":\"windows\",\"reasons\":[],\"schema\":\"backend-attestation-v1\",\"version\":\"0.1.0\"}\n"
  in
  let probe =
    match Sandbox_backend.parse_probe source with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "backend probe preserves availability and typed controls"
    (probe.available && probe.reasons = []
    && probe.attestation.id = "oci:docker"
    && probe.attestation.controls
       = [ Sandbox_protocol.Source_read_only; Sandbox_protocol.Network_deny ]);
  expect "unknown controls make a helper probe untrusted"
    (Result.is_error
       (Sandbox_backend.parse_probe
          (Util.replace_all ~needle:"network_deny" ~replacement:"magic_bypass"
             source)))

let evidence_chain_test () =
  let genesis = "sha256:" ^ String.make 64 '0' in
  let chain =
    Evidence.empty ~plan_digest:genesis
    |> Evidence.append (Evidence.Control_attested "network_deny")
    |> Evidence.append
         (Evidence.Process_started
            { executable = "/bin/sh"; argv = [ "-c"; "true" ] })
    |> Evidence.append (Evidence.Process_exited { code = 0 })
  in
  expect "valid evidence chain verifies" (Evidence.validate chain = Ok ());
  let events = chain.events in
  let last = List.hd (List.rev events) in
  let tampered_last = { last with Evidence.digest = "sha256:tampered" } in
  let tampered =
    {
      chain with
      events = List.rev (tampered_last :: List.tl (List.rev events));
    }
  in
  expect "tampered evidence chain is rejected"
    (Result.is_error (Evidence.validate tampered));
  expect "chain binds the original plan" (chain.plan_digest = genesis)

let evidence_parse_test () =
  let evidence =
    Evidence.empty ~plan_digest:("sha256:" ^ String.make 64 '9')
    |> Evidence.append (Evidence.Control_attested "network_deny")
    |> Evidence.append
         (Evidence.Network_attempt
            { host = "example.invalid"; port = 443; allowed = false })
  in
  let bytes = Evidence.to_canonical_json evidence in
  let parsed =
    match Evidence.parse bytes with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "evidence parser preserves canonical bytes"
    (Evidence.to_canonical_json parsed = bytes);
  let tampered =
    Util.replace_all ~needle:"example.invalid" ~replacement:"evil.invalid" bytes
  in
  expect "evidence parser rejects a broken hash chain"
    (Result.is_error (Evidence.parse tampered))

let evidence_backend_binding_test () =
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls ~limits:Sandbox_protocol.portable_limits ~secret_names:[]
      ~dependencies:[]
      ~steps:[ step "build" "true" ]
  in
  let evidence = complete_evidence_with_backend plan "oci:podman" in
  expect "evidence backend identity is bound directly to runner-v2"
    (match Evidence.validate_for_plan plan evidence with
    | Error message ->
        Util.contains ~needle:"backend attestation identity" message
    | Ok () -> false)

let sandbox_audit_test () =
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls ~limits:Sandbox_protocol.portable_limits ~secret_names:[]
      ~dependencies:[]
      ~steps:[ step "audit" "true" ]
  in
  let evidence =
    List.fold_left
      (fun evidence control ->
        Evidence.append
          (Evidence.Control_attested (Sandbox_protocol.control_name control))
          evidence)
      (Evidence.empty ~plan_digest:plan.digest)
      controls
  in
  let audit =
    match Sandbox_audit.evaluate ~plan ~evidence with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "controls alone cannot authenticate which backend ran"
    (match audit.status with
    | Sandbox_audit.Incomplete reasons ->
        List.exists (Util.contains ~needle:"backend attestation") reasons
    | Verified -> false);
  let authenticated =
    Evidence.append
      (Evidence.Backend_attested
         {
           id = "oci:docker";
           version = "0.1.0";
           platform = "test";
           controls_digest = Sandbox_protocol.controls_digest plan.controls;
         })
      (Evidence.empty ~plan_digest:plan.digest)
    |> fun initial ->
    List.fold_left
      (fun current control ->
        Evidence.append
          (Evidence.Control_attested (Sandbox_protocol.control_name control))
          current)
      initial controls
  in
  let authenticated_audit =
    match Sandbox_audit.evaluate ~plan ~evidence:authenticated with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "matching backend and controls attestations verify the run"
    (authenticated_audit.status = Sandbox_audit.Verified);
  let incomplete =
    match
      Sandbox_audit.evaluate ~plan
        ~evidence:(Evidence.empty ~plan_digest:plan.digest)
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "missing runtime control attestations remain incomplete"
    (match incomplete.status with
    | Sandbox_audit.Incomplete reasons ->
        List.length reasons = List.length controls + 1
    | Verified -> false)

let oci_runner_test () =
  let calls = ref [] and prepared = ref false in
  let runtime =
    {
      Oci_runner.prepare_scratch =
        (fun ~source_root ~scratch_root ->
          prepared := source_root = "C:/source" && scratch_root = "C:/scratch";
          Ok ());
      finalize_scratch =
        (fun ~scratch_root ->
          expect "OCI finalizes the dedicated scratch"
            (scratch_root = "C:/scratch");
          Ok
            {
              Oci_runner.digest = "sha256:" ^ String.make 64 '1';
              bytes = 8L;
              entries = 1;
            });
      run =
        (fun ~engine ~arguments ~timeout_seconds ~output_bytes ~secret_names ->
          calls :=
            (engine, arguments, timeout_seconds, output_bytes, secret_names)
            :: !calls;
          Ok
            {
              Oci_runner.exit_code = Some 0;
              timed_out = false;
              output_truncated = false;
              redacted_secrets = [ "TOKEN" ];
              redacted_output = "redacted log";
              wall_time_ms = 3;
              output_bytes = 12;
            });
    }
  in
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls ~limits:Sandbox_protocol.portable_limits
      ~secret_names:[ "TOKEN" ] ~dependencies:[]
      ~steps:[ step "build" "make test" ]
  in
  let execution =
    match
      Oci_runner.execute ~runtime ~source_root:"C:/source"
        ~scratch_root:"C:/scratch" plan
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "OCI source is copied into a dedicated scratch overlay" !prepared;
  (match !calls with
  | [ ("docker", arguments, 900, 16_777_216, [ "TOKEN" ]) ] ->
      let joined = String.concat " " arguments in
      expect "OCI argv enforces network rootfs process and memory controls"
        (Util.contains ~needle:"--network none" joined
        && Util.contains ~needle:"--read-only" joined
        && Util.contains ~needle:"--pids-limit 128" joined
        && Util.contains ~needle:"--memory 2048m" joined
        && Util.contains ~needle:"readonly" joined
        && Util.contains ~needle:"C:/scratch" joined)
  | _ -> fail "unexpected OCI runtime calls");
  expect "successful OCI execution has an authenticated evidence chain"
    (execution.Sandbox_run.outcome = Completed
    && Result.is_ok (Evidence.validate execution.evidence)
    && Evidence.observes_effect Ir.Command_execution execution.evidence);
  let execution_bytes = Sandbox_run.to_canonical_json execution in
  expect "sandbox-run envelope authenticates on round trip"
    (match Sandbox_run.parse execution_bytes with
    | Ok parsed -> Sandbox_run.to_canonical_json parsed = execution_bytes
    | Error _ -> false);
  expect "secret values never enter engine argv"
    (not
       (Util.contains ~needle:"secret-value"
          (Evidence.to_canonical_json execution.evidence)))

let reconciliation_test () =
  let static_unknown =
    Property.Unknown [ Unknown.External_state "remote API" ]
  in
  let no_network_observed =
    Reconcile.property ~static:static_unknown
      ~possible_effect:Ir.Network_request
      ~evidence:(Evidence.empty ~plan_digest:"sha256:x")
  in
  expect "absence in one run cannot prove impossibility"
    (no_network_observed = static_unknown);
  let observed =
    Evidence.empty ~plan_digest:"sha256:x"
    |> Evidence.append
         (Evidence.Network_attempt
            { host = "example.invalid"; port = 443; allowed = false })
  in
  expect "runtime observation can corroborate a violation"
    (Reconcile.property ~static:Property.Violated
       ~possible_effect:Ir.Network_request ~evidence:observed
    = Property.Violated)

let runtime_envelope_test () =
  let node observable =
    Ir.make_node ~provider:Ir.Github ~kind:Ir.Command ~phase:Ir.Run
      ~name:"command" ~span:Span.none ~condition:Condition.true_ ~attributes:[]
      ~capabilities:[] ~effects:[ observable ] ()
  in
  let graph observable =
    Ir.empty Ir.Github "workflow.yml"
    |> Ir.add_node (node observable)
    |> Ir.finalize
  in
  let evidence =
    Evidence.empty ~plan_digest:"sha256:plan"
    |> Evidence.append
         (Evidence.Network_attempt
            { host = "example.invalid"; port = 443; allowed = false })
  in
  let expected =
    Reconcile.envelope ~graphs:[ graph Ir.Network_request ] ~evidence
  in
  expect "an observed statically predicted effect stays inside the envelope"
    (expected.Property.state = Property.Proved);
  let unexpected =
    Reconcile.envelope ~graphs:[ graph Ir.File_write ] ~evidence
  in
  expect "an observed effect outside a complete static model is violated"
    (unexpected.Property.state = Property.Violated)

let scratch_artifact_reconciliation_test () =
  let command =
    Ir.make_node ~provider:Ir.Github ~kind:Ir.Command ~phase:Ir.Run
      ~name:"printf 'result\\n' > result.txt" ~span:Span.none
      ~condition:Condition.true_ ~attributes:[] ~capabilities:[]
      ~effects:[ Ir.Command_execution ] ()
  in
  let graph =
    Ir.empty Ir.Github "workflow.yml" |> Ir.add_node command |> Ir.finalize
  in
  let evidence =
    Evidence.empty ~plan_digest:"sha256:plan"
    |> Evidence.append
         (Evidence.Filesystem_access
            { path = "result.txt"; operation = "write"; allowed = true })
    |> Evidence.append
         (Evidence.Artifact_recorded
            { path = "result.txt"; digest = "sha256:" ^ String.make 64 'a' })
  in
  let reconciled = Reconcile.envelope ~graphs:[ graph ] ~evidence in
  expect "a redirected scratch file stays inside the script effect envelope"
    (reconciled.Property.state = Property.Proved);
  expect "recording scratch bytes is not a provider artifact publication"
    (not (Evidence.observes_effect Ir.Artifact_publish evidence))

let scenario_condition_planner_test () =
  let source =
    "on: [push, pull_request]\n\
     jobs:\n\
    \  build:\n\
    \    if: github.event_name == 'push'\n\
    \    steps:\n\
    \      - run: echo selected\n\
    \      - if: github.event_name == 'schedule'\n\
    \        run: echo skipped\n"
  in
  let graph =
    match
      Frontend.compile_string ~provider:Ir.Github
        ~path:".github/workflows/ci.yml" ~source ()
    with
    | Ok compilation -> compilation.Frontend_intf.graph
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  let scenario event =
    match
      Scenario.make ~provider:Ir.Github
        ~workflow_entrypoint:".github/workflows/ci.yml" ~job:"build" ~event
        ~inputs:[] ~matrix:[] ~variables:[]
        ~runner_platform:Scenario.Linux_x86_64 ~secret_names:[]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let plan event =
    match
      Scenario_planner.plan ~scenario:(scenario event)
        ~image:("sha256:" ^ String.make 64 'a')
        ~graphs:[ graph ]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  let push = plan "push" in
  expect "true job and step gates select only the reachable command"
    (match push.steps with
    | [ step ] ->
        List.rev step.Sandbox_protocol.argv |> List.hd = "echo selected"
    | _ -> false);
  expect "known false conditions are complete, not unsupported"
    (push.incomplete_reasons = []);
  let pull_request = plan "pull_request" in
  expect "a false job gate suppresses its entire command subtree"
    (pull_request.steps = [] && pull_request.incomplete_reasons = [])

let tests : test list =
  [
    ( "OCaml and helpers share canonical runner-v2 fixtures",
      cross_language_protocol_test );
    ( "OCaml and OCI helper share canonical source manifests",
      cross_language_source_manifest_test );
    ( "trusted source exclusions are recorded and digest-bound",
      trusted_source_exclusion_manifest_test );
    ( "runner plan is canonical content-addressed and secret-safe",
      canonical_plan_test );
    ("runner plans use a checked smart constructor", smart_constructor_test);
    ("unresolved or unsupported execution is Incomplete", incomplete_test);
    ("backend selection fails closed without fallback", backend_fail_closed_test);
    ("backend probes are versioned and typed", backend_probe_parse_test);
    ("runtime evidence is hash chained to the plan", evidence_chain_test);
    ("runtime evidence parses and authenticates", evidence_parse_test);
    ( "runtime evidence binds the exact backend identity",
      evidence_backend_binding_test );
    ("sandbox audit verifies every requested control", sandbox_audit_test);
    ("OCI runner enforces controls through argv-safe ports", oci_runner_test);
    ("runtime absence never upgrades static proof", reconciliation_test);
    ( "scratch artifacts retain file-write rather than publish semantics",
      scratch_artifact_reconciliation_test );
    ( "scenario planning propagates job and step conditions",
      scenario_condition_planner_test );
    ( "runtime observations are checked against the static effect envelope",
      runtime_envelope_test );
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
