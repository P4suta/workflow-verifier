type process_result = {
  exit_code : int option;
  timed_out : bool;
  output_truncated : bool;
  redacted_secrets : string list;
  redacted_output : string;
  wall_time_ms : int;
  output_bytes : int;
}

type scratch_result = { digest : string; bytes : int64; entries : int }

type runtime = {
  prepare_scratch :
    source_root:string -> scratch_root:string -> (unit, string) result;
  finalize_scratch : scratch_root:string -> (scratch_result, string) result;
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
    Network_deny;
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
    "--pull";
    "never";
    "--read-only";
    "--cap-drop";
    "ALL";
    "--security-opt";
    "no-new-privileges";
    "--cpus";
    "1";
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
      Evidence.for_plan checked
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
    let finalize evidence ~processes ~wall_time_ms ~output_bytes ~logs outcome =
      let* scratch = runtime.finalize_scratch ~scratch_root in
      let evidence =
        evidence
        |> Evidence.append
             (Evidence.Resource_observed
                {
                  wall_time_ms;
                  cpu_time_ms = 0;
                  peak_memory_bytes = 0L;
                  processes;
                  output_bytes;
                  scratch_bytes = scratch.bytes;
                  scratch_entries = scratch.entries;
                })
        |> Evidence.append
             (Evidence.Log_recorded
                {
                  digest =
                    "sha256:"
                    ^ Sha256.digest_string (String.concat "" (List.rev logs));
                })
        |> Evidence.append
             (Evidence.Filesystem_final { digest = scratch.digest })
      in
      Ok { Sandbox_run.evidence; outcome }
    in
    let rec run_steps evidence processes wall_time_ms output_bytes logs =
      function
      | [] ->
          finalize evidence ~processes ~wall_time_ms ~output_bytes ~logs
            Completed
      | (step : Sandbox_protocol.step) :: rest -> (
          let argv = arguments checked step ~source_root ~scratch_root in
          let workload_executable, workload_argv =
            match step.argv with
            | executable :: arguments -> (executable, arguments)
            | [] -> ("<invalid>", [])
          in
          let evidence =
            Evidence.append
              (Evidence.Process_started
                 { executable = workload_executable; argv = workload_argv })
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
          let processes = processes + 1
          and wall_time_ms = wall_time_ms + process.wall_time_ms
          and output_bytes = output_bytes + process.output_bytes
          and logs = process.redacted_output :: logs in
          if process.timed_out then
            finalize evidence ~processes ~wall_time_ms ~output_bytes ~logs
              (Timed_out { step = step.id })
          else if process.output_truncated then
            finalize evidence ~processes ~wall_time_ms ~output_bytes ~logs
              (Output_limit_exceeded { step = step.id })
          else
            match process.exit_code with
            | Some 0 ->
                run_steps evidence processes wall_time_ms output_bytes logs rest
            | code ->
                finalize evidence ~processes ~wall_time_ms ~output_bytes ~logs
                  (Step_failed { step = step.id; code }))
    in
    run_steps initial 0 0 0 [] checked.steps
