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
  match
    Sandbox_protocol.make_plan ~backend ~source_digest ~lock_digest ~controls
      ~limits ~secret_names ~dependencies ~steps
  with
  | Ok plan -> plan
  | Error error -> fail "valid test plan was rejected: %s" error

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
  let source = fixture "runner-v1-complete.json" in
  let plan =
    match Sandbox_protocol.parse source with
    | Ok plan -> plan
    | Error error -> fail "OCaml rejected shared runner fixture: %s" error
  in
  expect "shared runner fixture is OCaml canonical"
    (Sandbox_protocol.to_canonical_json plan = source);
  let invalid = fixture "runner-v1-invalid-complete.json" in
  expect "complete cannot conceal an unresolved dependency"
    (Result.is_error (Sandbox_protocol.parse invalid));
  let run_source = fixture "sandbox-run-v1-complete.json" in
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
    (manifest.canonical_json = String.trim (fixture "source-manifest-v1.json"));
  expect "shared source manifest has a stable content digest"
    (manifest.digest
   = "sha256:6d8438471c06fc1f4199de690117a6c60da9bee4c8d9421ad2333a7847033b48")

let canonical_plan_test () =
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 'b')
      ~lock_digest:("sha256:" ^ String.make 64 'c')
      ~controls
      ~limits:
        {
          cpu_seconds = 60;
          memory_mb = 512;
          processes = 32;
          output_bytes = 1_000_000;
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
    make_plan ~backend:Linux_native ~source_digest:"sha256:source"
      ~lock_digest:"sha256:lock" ~controls
      ~limits:
        { cpu_seconds = 1; memory_mb = 64; processes = 4; output_bytes = 1024 }
      ~secret_names:[] ~dependencies:[ dependency ]
      ~steps:[ step ~supported:false "opaque" "unknown" ]
  in
  match plan.status with
  | Incomplete reasons ->
      expect "both unresolved dependency and unsupported step are retained"
        (List.length reasons = 2)
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
    "{\"available\":true,\"controls\":[\"source_read_only\",\"network_deny\"],\"id\":\"oci:docker\",\"platform\":\"windows\",\"reasons\":[],\"schema\":\"backend-attestation-v1\",\"version\":\"0.1.0-dev\"}\n"
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

let sandbox_audit_test () =
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls
      ~limits:
        { cpu_seconds = 1; memory_mb = 64; processes = 4; output_bytes = 1024 }
      ~secret_names:[] ~dependencies:[] ~steps:[]
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
           version = "0.1.0-dev";
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
            });
    }
  in
  let plan =
    make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls
      ~limits:
        { cpu_seconds = 7; memory_mb = 128; processes = 5; output_bytes = 4096 }
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
  | [ ("docker", arguments, 7, 4096, [ "TOKEN" ]) ] ->
      let joined = String.concat " " arguments in
      expect "OCI argv enforces network rootfs process and memory controls"
        (Util.contains ~needle:"--network none" joined
        && Util.contains ~needle:"--read-only" joined
        && Util.contains ~needle:"--pids-limit 5" joined
        && Util.contains ~needle:"--memory 128m" joined
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

let tests : test list =
  [
    ( "OCaml and helpers share canonical runner-v1 fixtures",
      cross_language_protocol_test );
    ( "OCaml and OCI helper share canonical source manifests",
      cross_language_source_manifest_test );
    ( "runner plan is canonical content-addressed and secret-safe",
      canonical_plan_test );
    ("runner plans use a checked smart constructor", smart_constructor_test);
    ("unresolved or unsupported execution is Incomplete", incomplete_test);
    ("backend selection fails closed without fallback", backend_fail_closed_test);
    ("backend probes are versioned and typed", backend_probe_parse_test);
    ("runtime evidence is hash chained to the plan", evidence_chain_test);
    ("runtime evidence parses and authenticates", evidence_parse_test);
    ("sandbox audit verifies every requested control", sandbox_audit_test);
    ("OCI runner enforces controls through argv-safe ports", oci_runner_test);
    ("runtime absence never upgrades static proof", reconciliation_test);
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
