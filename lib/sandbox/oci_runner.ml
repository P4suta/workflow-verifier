type process_result = {
  exit_code : int option;
  timed_out : bool;
  output_truncated : bool;
  redacted_secrets : string list;
}

type runtime = {
  prepare_scratch :
    source_root:string -> scratch_root:string -> (unit, string) result;
  run :
    engine:string ->
    arguments:string list ->
    timeout_seconds:int ->
    output_bytes:int ->
    secret_names:string list ->
    (process_result, string) result;
}

let required_controls =
  [
    Sandbox_protocol.Source_read_only;
    Scratch_overlay;
    Process_isolation;
    Resource_limits;
    Secret_redaction;
  ]

let mount ~source ~target ~readonly =
  "type=bind,src=" ^ source ^ ",dst=" ^ target
  ^ if readonly then ",readonly" else ""

let arguments plan step ~source_root ~scratch_root =
  let limits = plan.Sandbox_protocol.limits in
  [
    "run";
    "--rm";
    "--read-only";
    "--pids-limit";
    string_of_int limits.processes;
    "--memory";
    string_of_int limits.memory_mb ^ "m";
  ]
  @ (if List.mem Sandbox_protocol.Network_deny plan.controls then
       [ "--network"; "none" ]
     else [])
  @ [ "--mount"; mount ~source:source_root ~target:"/source" ~readonly:true ]
  @ [
      "--mount"; mount ~source:scratch_root ~target:"/workspace" ~readonly:false;
    ]
  @ [ "--tmpfs"; "/tmp:rw,noexec,nosuid,nodev" ]
  @ [ "--workdir"; step.Sandbox_protocol.working_directory ]
  @ List.concat_map (fun name -> [ "--env"; name ]) plan.secret_names
  @ [ step.image ] @ step.argv

let execute ~runtime ~source_root ~scratch_root plan =
  let open Util in
  let* checked =
    Sandbox_protocol.parse (Sandbox_protocol.to_canonical_json plan)
  in
  let* engine =
    match checked.backend with
    | Sandbox_protocol.Oci (("docker" | "podman") as engine) -> Ok engine
    | Oci engine -> Error ("unsupported OCI engine " ^ engine)
    | _ -> Error "OCI runner received a native backend plan"
  in
  let* () =
    match checked.status with
    | Complete -> Ok ()
    | Incomplete reasons ->
        Error ("incomplete plan: " ^ String.concat "; " reasons)
  in
  let missing =
    List.filter
      (fun control -> not (List.mem control checked.controls))
      required_controls
  in
  if missing <> [] then
    Error
      ("OCI plan lacks required controls: "
      ^ String.concat ", " (List.map Sandbox_protocol.control_name missing))
  else if source_root = "" || scratch_root = "" then
    Error "OCI source and scratch roots must be non-empty"
  else if
    Util.normalize_slashes source_root = Util.normalize_slashes scratch_root
  then Error "OCI scratch root must not alias the source root"
  else
    let* () = runtime.prepare_scratch ~source_root ~scratch_root in
    let backend_evidence =
      Evidence.empty ~plan_digest:checked.digest
      |> Evidence.append
           (Evidence.Backend_attested
              {
                id = Sandbox_protocol.backend_name checked.backend;
                version = "injected-runtime";
                platform = "injected-runtime";
                controls_digest =
                  Sandbox_protocol.controls_digest checked.controls;
              })
    in
    let initial =
      List.fold_left
        (fun evidence control ->
          Evidence.append
            (Evidence.Control_attested (Sandbox_protocol.control_name control))
            evidence)
        backend_evidence checked.controls
    in
    let rec run_steps evidence = function
      | [] -> Ok { Sandbox_run.evidence; outcome = Completed }
      | (step : Sandbox_protocol.step) :: rest -> (
          let argv = arguments checked step ~source_root ~scratch_root in
          let evidence =
            Evidence.append
              (Evidence.Process_started { executable = engine; argv })
              evidence
          in
          let* process =
            runtime.run ~engine ~arguments:argv
              ~timeout_seconds:checked.limits.cpu_seconds
              ~output_bytes:checked.limits.output_bytes
              ~secret_names:checked.secret_names
          in
          let evidence =
            process.redacted_secrets |> Util.deduplicate_strings
            |> List.fold_left
                 (fun evidence name ->
                   Evidence.append (Evidence.Secret_redacted { name }) evidence)
                 evidence
          in
          let evidence =
            Evidence.append
              (Evidence.Process_exited
                 { code = Option.value ~default:(-1) process.exit_code })
              evidence
          in
          if process.timed_out then
            Ok { Sandbox_run.evidence; outcome = Timed_out { step = step.id } }
          else if process.output_truncated then
            Ok
              {
                Sandbox_run.evidence;
                outcome = Output_limit_exceeded { step = step.id };
              }
          else
            match process.exit_code with
            | Some 0 -> run_steps evidence rest
            | code ->
                Ok
                  {
                    Sandbox_run.evidence;
                    outcome = Step_failed { step = step.id; code };
                  })
    in
    run_steps initial checked.steps
