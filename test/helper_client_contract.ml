exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let plan () =
  match
    Sandbox_protocol.make_plan ~backend:(Oci "docker")
      ~source_digest:("sha256:" ^ String.make 64 '1')
      ~lock_digest:("sha256:" ^ String.make 64 '2')
      ~controls:
        [
          Source_read_only;
          Scratch_overlay;
          Network_deny;
          Process_isolation;
          Resource_limits;
          Secret_redaction;
        ]
      ~limits:
        { cpu_seconds = 2; memory_mb = 64; processes = 2; output_bytes = 1024 }
      ~secret_names:[] ~dependencies:[] ~steps:[]
  with
  | Ok value -> value
  | Error message -> fail "%s" message

let probe_contract () =
  let observed = ref None in
  let invoke request =
    observed := Some request;
    Ok
      {
        Helper_client.exit_code = 0;
        stdout =
          "{\"available\":true,\"controls\":[\"source_read_only\",\"scratch_overlay\",\"network_deny\",\"process_isolation\",\"resource_limits\",\"secret_redaction\"],\"id\":\"oci:docker\",\"platform\":\"windows\",\"reasons\":[],\"schema\":\"backend-attestation-v1\",\"version\":\"0.1.0\"}\n";
        stderr = "";
      }
  in
  let probe =
    match
      Helper_client.probe ~invoke ~executable:"helper with spaces.exe"
        ~arguments:[ "--doctor"; "--engine"; "docker" ]
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "available typed helper probe is accepted" probe.available;
  expect "helper invocation remains an argv vector"
    (match !observed with
    | Some request ->
        request.executable = "helper with spaces.exe"
        && request.arguments = [ "--doctor"; "--engine"; "docker" ]
        && request.stdin = ""
    | None -> false)

let execution_contract () =
  let plan = plan () in
  let execution =
    {
      Sandbox_run.evidence = Evidence.empty ~plan_digest:plan.digest;
      outcome = Completed;
    }
  in
  let observed = ref None in
  let invoke request =
    observed := Some request;
    Ok
      {
        Helper_client.exit_code = 0;
        stdout = Sandbox_run.to_canonical_json execution;
        stderr = "";
      }
  in
  let actual =
    match
      Helper_client.execute ~invoke ~executable:"helper.exe"
        ~arguments:[ "--run"; "--engine"; "docker"; "--source"; "C:/repo" ]
        plan
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "helper result is authenticated protocol data" (actual = execution);
  expect "only canonical runner-v1 bytes enter helper stdin"
    (match !observed with
    | Some request -> request.stdin = Sandbox_protocol.to_canonical_json plan
    | None -> false);
  let failed _request =
    Ok
      {
        Helper_client.exit_code = 5;
        stdout = "ignored";
        stderr = "engine failed";
      }
  in
  expect "nonzero helper exits remain infrastructure errors"
    (Result.is_error
       (Helper_client.execute ~invoke:failed ~executable:"helper.exe"
          ~arguments:[ "--run" ] plan))

let tests =
  [
    ("helper probes use argv-only typed transport", probe_contract);
    ("helper execution transports canonical protocols", execution_contract);
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
