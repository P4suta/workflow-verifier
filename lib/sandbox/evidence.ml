type body =
  | Backend_attested of {
      id : string;
      version : string;
      platform : string;
      controls_digest : string;
    }
  | Control_attested of string
  | Process_started of { executable : string; argv : string list }
  | Process_exited of { code : int }
  | Filesystem_access of { path : string; operation : string; allowed : bool }
  | Network_attempt of { host : string; port : int; allowed : bool }
  | Artifact_recorded of { path : string; digest : string }
  | Secret_redacted of { name : string }
  | Resource_observed of {
      wall_time_ms : int;
      cpu_time_ms : int;
      peak_memory_bytes : int64;
      processes : int;
      output_bytes : int;
      scratch_bytes : int64;
      scratch_entries : int;
    }
  | Log_recorded of { digest : string }
  | Filesystem_final of { digest : string }
  | Backend_error of string

type event = {
  sequence : int;
  previous_digest : string;
  digest : string;
  body : body;
}

type bindings = {
  scenario_digest : string;
  source_digest : string;
  lock_digest : string;
  runtime_digest : string;
  controls_digest : string;
}

type observed_resources = {
  wall_time_ms : int;
  cpu_time_ms : int;
  peak_memory_bytes : int64;
  processes : int;
  output_bytes : int;
  scratch_bytes : int64;
  scratch_entries : int;
}

type artifact = { path : string; digest : string }
type sidecar = { kind : string; digest : string }

type t = {
  schema : string;
  plan_digest : string;
  bindings : bindings;
  requested_limits : Sandbox_protocol.limits;
  effective_limits : Sandbox_protocol.limits;
  observed_resources : observed_resources;
  redacted_log_digest : string;
  final_filesystem_digest : string;
  artifacts : artifact list;
  forensic_sidecars : sidecar list;
  events : event list;
}

let empty_observation =
  {
    wall_time_ms = 0;
    cpu_time_ms = 0;
    peak_memory_bytes = 0L;
    processes = 0;
    output_bytes = 0;
    scratch_bytes = 0L;
    scratch_entries = 0;
  }

let digest_json value = "sha256:" ^ Sha256.digest_string (Json.to_string value)

let runtime_digest (plan : Sandbox_protocol.plan) =
  match Json.member "runtime" (Sandbox_protocol.to_json plan) with
  | Some value -> digest_json value
  | None -> digest_json Json.Null

let for_plan (plan : Sandbox_protocol.plan) =
  {
    schema = "evidence-v2";
    plan_digest = plan.digest;
    bindings =
      {
        scenario_digest = plan.scenario_digest;
        source_digest = plan.source_digest;
        lock_digest = plan.lock_digest;
        runtime_digest = runtime_digest plan;
        controls_digest = Sandbox_protocol.controls_digest plan.controls;
      };
    requested_limits = plan.limits;
    effective_limits = plan.limits;
    observed_resources = empty_observation;
    redacted_log_digest = "sha256:" ^ Sha256.digest_string "";
    final_filesystem_digest = plan.source_digest;
    artifacts = [];
    forensic_sidecars = [];
    events = [];
  }

let empty ~plan_digest =
  {
    schema = "evidence-v2";
    plan_digest;
    bindings =
      {
        scenario_digest = plan_digest;
        source_digest = plan_digest;
        lock_digest = plan_digest;
        runtime_digest = plan_digest;
        controls_digest = plan_digest;
      };
    requested_limits = Sandbox_protocol.portable_limits;
    effective_limits = Sandbox_protocol.portable_limits;
    observed_resources = empty_observation;
    redacted_log_digest = "sha256:" ^ Sha256.digest_string "";
    final_filesystem_digest = plan_digest;
    artifacts = [];
    forensic_sidecars = [];
    events = [];
  }

let body_json = function
  | Backend_attested { id; version; platform; controls_digest } ->
      Json.Object
        [
          ("controls_digest", Json.String controls_digest);
          ("id", Json.String id);
          ("kind", Json.String "backend_attested");
          ("platform", Json.String platform);
          ("version", Json.String version);
        ]
  | Control_attested control ->
      Json.Object
        [
          ("control", Json.String control);
          ("kind", Json.String "control_attested");
        ]
  | Process_started { executable; argv } ->
      Json.Object
        [
          ("argv", Json.Array (List.map (fun value -> Json.String value) argv));
          ("executable", Json.String executable);
          ("kind", Json.String "process_started");
        ]
  | Process_exited { code } ->
      Json.Object
        [ ("code", Json.Int code); ("kind", Json.String "process_exited") ]
  | Filesystem_access { path; operation; allowed } ->
      Json.Object
        [
          ("allowed", Json.Bool allowed);
          ("kind", Json.String "filesystem_access");
          ("operation", Json.String operation);
          ("path", Json.String (Util.normalize_slashes path));
        ]
  | Network_attempt { host; port; allowed } ->
      Json.Object
        [
          ("allowed", Json.Bool allowed);
          ("host", Json.String host);
          ("kind", Json.String "network_attempt");
          ("port", Json.Int port);
        ]
  | Artifact_recorded { path; digest } ->
      Json.Object
        [
          ("digest", Json.String digest);
          ("kind", Json.String "artifact_recorded");
          ("path", Json.String (Util.normalize_slashes path));
        ]
  | Secret_redacted { name } ->
      Json.Object
        [ ("kind", Json.String "secret_redacted"); ("name", Json.String name) ]
  | Resource_observed observation ->
      Json.Object
        [
          ("cpu_time_ms", Json.Int observation.cpu_time_ms);
          ("kind", Json.String "resource_observed");
          ("output_bytes", Json.Int observation.output_bytes);
          ("peak_memory_bytes", Json.Int64 observation.peak_memory_bytes);
          ("processes", Json.Int observation.processes);
          ("scratch_bytes", Json.Int64 observation.scratch_bytes);
          ("scratch_entries", Json.Int observation.scratch_entries);
          ("wall_time_ms", Json.Int observation.wall_time_ms);
        ]
  | Log_recorded { digest } ->
      Json.Object
        [ ("digest", Json.String digest); ("kind", Json.String "log_recorded") ]
  | Filesystem_final { digest } ->
      Json.Object
        [
          ("digest", Json.String digest);
          ("kind", Json.String "filesystem_final");
        ]
  | Backend_error message ->
      Json.Object
        [
          ("kind", Json.String "backend_error"); ("message", Json.String message);
        ]

let unsigned_event_fields sequence previous_digest body =
  [
    ("body", body_json body);
    ("previous_digest", Json.String previous_digest);
    ("sequence", Json.Int sequence);
  ]

let unsigned_event sequence previous_digest body =
  Json.Object (unsigned_event_fields sequence previous_digest body)

let append body evidence =
  let sequence = List.length evidence.events in
  let previous_digest =
    match List.rev evidence.events with
    | [] -> evidence.plan_digest
    | (event : event) :: _ -> event.digest
  in
  let digest = digest_json (unsigned_event sequence previous_digest body) in
  let ( observed_resources,
        redacted_log_digest,
        final_filesystem_digest,
        artifacts ) =
    match body with
    | Resource_observed
        {
          wall_time_ms;
          cpu_time_ms;
          peak_memory_bytes;
          processes;
          output_bytes;
          scratch_bytes;
          scratch_entries;
        } ->
        ( {
            wall_time_ms;
            cpu_time_ms;
            peak_memory_bytes;
            processes;
            output_bytes;
            scratch_bytes;
            scratch_entries;
          },
          evidence.redacted_log_digest,
          evidence.final_filesystem_digest,
          evidence.artifacts )
    | Log_recorded { digest } ->
        ( evidence.observed_resources,
          digest,
          evidence.final_filesystem_digest,
          evidence.artifacts )
    | Filesystem_final { digest } ->
        ( evidence.observed_resources,
          evidence.redacted_log_digest,
          digest,
          evidence.artifacts )
    | Artifact_recorded { path; digest } ->
        ( evidence.observed_resources,
          evidence.redacted_log_digest,
          evidence.final_filesystem_digest,
          { path = Util.normalize_slashes path; digest } :: evidence.artifacts
        )
    | _ ->
        ( evidence.observed_resources,
          evidence.redacted_log_digest,
          evidence.final_filesystem_digest,
          evidence.artifacts )
  in
  {
    evidence with
    observed_resources;
    redacted_log_digest;
    final_filesystem_digest;
    artifacts =
      List.sort
        (fun (left : artifact) (right : artifact) ->
          String.compare left.path right.path)
        artifacts;
    events = evidence.events @ [ { sequence; previous_digest; digest; body } ];
  }

let valid_digest = Dependency_identity.valid_content_digest

let aggregate evidence =
  List.fold_left
    (fun (observation, log_digest, filesystem_digest, artifacts) event ->
      match event.body with
      | Resource_observed
          {
            wall_time_ms;
            cpu_time_ms;
            peak_memory_bytes;
            processes;
            output_bytes;
            scratch_bytes;
            scratch_entries;
          } ->
          ( {
              wall_time_ms;
              cpu_time_ms;
              peak_memory_bytes;
              processes;
              output_bytes;
              scratch_bytes;
              scratch_entries;
            },
            log_digest,
            filesystem_digest,
            artifacts )
      | Log_recorded { digest } ->
          (observation, digest, filesystem_digest, artifacts)
      | Filesystem_final { digest } ->
          (observation, log_digest, digest, artifacts)
      | Artifact_recorded { path; digest } ->
          ( observation,
            log_digest,
            filesystem_digest,
            { path = Util.normalize_slashes path; digest } :: artifacts )
      | _ -> (observation, log_digest, filesystem_digest, artifacts))
    ( empty_observation,
      "sha256:" ^ Sha256.digest_string "",
      evidence.bindings.source_digest,
      [] )
    evidence.events

let validate evidence =
  let digests =
    [
      evidence.plan_digest;
      evidence.bindings.scenario_digest;
      evidence.bindings.source_digest;
      evidence.bindings.lock_digest;
      evidence.bindings.runtime_digest;
      evidence.bindings.controls_digest;
      evidence.redacted_log_digest;
      evidence.final_filesystem_digest;
    ]
    @ List.map (fun (artifact : artifact) -> artifact.digest) evidence.artifacts
    @ List.map
        (fun (sidecar : sidecar) -> sidecar.digest)
        evidence.forensic_sidecars
  in
  if evidence.schema <> "evidence-v2" then
    Error "evidence schema must be evidence-v2"
  else if not (List.for_all valid_digest digests) then
    Error "evidence-v2 contains an invalid SHA-256 digest"
  else if
    evidence.requested_limits <> Sandbox_protocol.portable_limits
    || evidence.effective_limits <> Sandbox_protocol.portable_limits
  then Error "evidence-v2 portable limits do not match runner-v2"
  else if
    List.exists
      (fun (artifact : artifact) ->
        artifact.path = ""
        || (not (Filename.is_relative artifact.path))
        || Util.starts_with ~prefix:"/" artifact.path)
      evidence.artifacts
  then Error "evidence artifact paths must be root-relative"
  else if
    evidence.observed_resources.wall_time_ms < 0
    || evidence.observed_resources.cpu_time_ms < 0
    || evidence.observed_resources.peak_memory_bytes < 0L
    || evidence.observed_resources.processes < 0
    || evidence.observed_resources.output_bytes < 0
    || evidence.observed_resources.scratch_bytes < 0L
    || evidence.observed_resources.scratch_entries < 0
  then Error "evidence resource observations cannot be negative"
  else if
    List.exists
      (fun (sidecar : sidecar) -> String.trim sidecar.kind = "")
      evidence.forensic_sidecars
  then Error "forensic sidecar kind must not be empty"
  else
    let rec loop expected_sequence previous = function
      | [] -> Ok ()
      | (event : event) :: rest ->
          if event.sequence <> expected_sequence then
            Error "evidence sequence is not contiguous"
          else if event.previous_digest <> previous then
            Error "evidence previous digest mismatch"
          else
            let expected =
              digest_json
                (unsigned_event event.sequence event.previous_digest event.body)
            in
            if expected <> event.digest then
              Error "evidence event digest mismatch"
            else loop (expected_sequence + 1) event.digest rest
    in
    let open Util in
    let* () = loop 0 evidence.plan_digest evidence.events in
    let ( observed_resources,
          redacted_log_digest,
          final_filesystem_digest,
          artifacts ) =
      aggregate evidence
    in
    let artifacts =
      List.sort
        (fun (left : artifact) (right : artifact) ->
          String.compare left.path right.path)
        artifacts
    in
    if observed_resources <> evidence.observed_resources then
      Error "evidence observed resource summary does not match its event chain"
    else if redacted_log_digest <> evidence.redacted_log_digest then
      Error "evidence log digest does not match its event chain"
    else if final_filesystem_digest <> evidence.final_filesystem_digest then
      Error "evidence final filesystem digest does not match its event chain"
    else if artifacts <> evidence.artifacts then
      Error "evidence artifact summary does not match its event chain"
    else Ok ()

let validate_for_plan (plan : Sandbox_protocol.plan) evidence =
  let open Util in
  let* () = validate evidence in
  let expected = for_plan plan in
  let bodies = List.map (fun (event : event) -> event.body) evidence.events in
  let count predicate =
    List.fold_left
      (fun total body -> if predicate body then total + 1 else total)
      0 bodies
  in
  let backend_attestations =
    bodies
    |> List.filter_map (function
      | Backend_attested { controls_digest; _ } -> Some controls_digest
      | _ -> None)
  and controls =
    bodies
    |> List.filter_map (function
      | Control_attested value -> Some value
      | _ -> None)
  and starts =
    bodies
    |> List.filter_map (function
      | Process_started { executable; argv } -> Some (executable, argv)
      | _ -> None)
  in
  let exits =
    count (function
      | Process_exited _ -> true
      | _ -> false)
  in
  let expected_controls =
    List.map Sandbox_protocol.control_name plan.controls
  in
  let rec lifecycle_matches starts steps =
    match (starts, steps) with
    | [], _ -> true
    | _, [] -> false
    | (executable, argv) :: starts, (step : Sandbox_protocol.step) :: steps -> (
        match step.argv with
        | expected_executable :: expected_argv ->
            executable = expected_executable
            && argv = expected_argv
            && lifecycle_matches starts steps
        | [] -> false)
  in
  if evidence.plan_digest <> plan.digest then
    Error "evidence plan digest mismatch"
  else if evidence.bindings <> expected.bindings then
    Error "evidence provenance bindings do not match runner-v2"
  else if evidence.requested_limits <> plan.limits then
    Error "evidence requested limits do not match runner-v2"
  else if evidence.effective_limits <> plan.limits then
    Error "evidence effective limits do not match runner-v2"
  else if List.length backend_attestations <> 1 then
    Error "evidence-v2 requires exactly one backend attestation"
  else if
    not
      (List.for_all
         (fun controls_digest ->
           controls_digest = expected.bindings.controls_digest)
         backend_attestations)
  then Error "backend attestation controls do not match runner-v2"
  else if controls <> expected_controls then
    Error "control attestations do not exactly match runner-v2"
  else if
    count (function
      | Resource_observed _ -> true
      | _ -> false)
    <> 1
  then Error "evidence-v2 requires exactly one resource observation"
  else if
    count (function
      | Log_recorded _ -> true
      | _ -> false)
    <> 1
  then Error "evidence-v2 requires exactly one redacted log record"
  else if
    count (function
      | Filesystem_final _ -> true
      | _ -> false)
    <> 1
  then Error "evidence-v2 requires exactly one final filesystem record"
  else if List.length starts <> exits then
    Error "process lifecycle start/exit events are unbalanced"
  else if plan.steps <> [] && starts = [] then
    Error "evidence-v2 is missing the planned process lifecycle"
  else if not (lifecycle_matches starts plan.steps) then
    Error "process lifecycle does not match the ordered runner-v2 steps"
  else Ok ()

let effects_of_body = function
  | Process_started _ -> [ Ir.Command_execution ]
  | Filesystem_access { operation; _ } ->
      if Util.contains ~needle:"write" (String.lowercase_ascii operation) then
        [ Ir.File_write ]
      else [ Ir.File_read ]
  | Network_attempt _ -> [ Ir.Network_request ]
  | Artifact_recorded _
  | Backend_attested _
  | Control_attested _
  | Process_exited _
  | Secret_redacted _
  | Resource_observed _
  | Log_recorded _
  | Filesystem_final _
  | Backend_error _ -> []

let observed_effects evidence =
  evidence.events
  |> List.concat_map (fun (event : event) -> effects_of_body event.body)
  |> Util.deduplicate_compare Stdlib.compare

let observes_effect observable evidence =
  List.mem observable (observed_effects evidence)

let event_json (event : event) =
  Json.Object
    (("digest", Json.String event.digest)
    :: unsigned_event_fields event.sequence event.previous_digest event.body)

let limits_json limits =
  Json.Object
    [
      ("cpu_cores", Json.Int 1);
      ( "memory_bytes",
        Json.Int (limits.Sandbox_protocol.memory_mb * 1024 * 1024) );
      ("output_bytes", Json.Int limits.output_bytes);
      ("processes", Json.Int limits.processes);
      ("scratch_bytes", Json.Int64 4_294_967_296L);
      ("scratch_entries", Json.Int 100_000);
      ("wall_time_seconds", Json.Int limits.cpu_seconds);
    ]

let observation_json value =
  Json.Object
    [
      ("cpu_time_ms", Json.Int value.cpu_time_ms);
      ("output_bytes", Json.Int value.output_bytes);
      ("peak_memory_bytes", Json.Int64 value.peak_memory_bytes);
      ("processes", Json.Int value.processes);
      ("scratch_bytes", Json.Int64 value.scratch_bytes);
      ("scratch_entries", Json.Int value.scratch_entries);
      ("wall_time_ms", Json.Int value.wall_time_ms);
    ]

let to_json evidence =
  Json.Object
    [
      ( "artifacts",
        Json.Array
          (List.map
             (fun (artifact : artifact) ->
               Json.Object
                 [
                   ("digest", Json.String artifact.digest);
                   ("path", Json.String artifact.path);
                 ])
             evidence.artifacts) );
      ( "bindings",
        Json.Object
          [
            ("controls_digest", Json.String evidence.bindings.controls_digest);
            ("lock_digest", Json.String evidence.bindings.lock_digest);
            ("runtime_digest", Json.String evidence.bindings.runtime_digest);
            ("scenario_digest", Json.String evidence.bindings.scenario_digest);
            ("source_digest", Json.String evidence.bindings.source_digest);
          ] );
      ("effective_limits", limits_json evidence.effective_limits);
      ("events", Json.Array (List.map event_json evidence.events));
      ("final_filesystem_digest", Json.String evidence.final_filesystem_digest);
      ( "forensic_sidecars",
        Json.Array
          (List.map
             (fun (sidecar : sidecar) ->
               Json.Object
                 [
                   ("digest", Json.String sidecar.digest);
                   ("kind", Json.String sidecar.kind);
                 ])
             evidence.forensic_sidecars) );
      ("observed_resources", observation_json evidence.observed_resources);
      ("plan_digest", Json.String evidence.plan_digest);
      ("redacted_log_digest", Json.String evidence.redacted_log_digest);
      ("requested_limits", limits_json evidence.requested_limits);
      ("schema", Json.String evidence.schema);
    ]

let to_canonical_json evidence = Json.to_string (to_json evidence) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("evidence-v2 needs field " ^ name)

let string_array name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error (name ^ " must contain only strings")
  in
  loop [] values

let int64_field name json =
  match Json.member name json with
  | Some (Json.Int value) -> Ok (Int64.of_int value)
  | Some (Json.Int64 value) -> Ok value
  | _ -> Error (name ^ " must be an integer")

let exact context fields json =
  Json.exact_object ~context ~allowed:fields json |> Result.map (fun _ -> ())

let parse_body json =
  let open Util in
  let* kind = required "kind" Json.as_string json in
  match kind with
  | "backend_attested" ->
      let* () =
        exact "backend_attested"
          [ "controls_digest"; "id"; "kind"; "platform"; "version" ]
          json
      in
      let* id = required "id" Json.as_string json in
      let* version = required "version" Json.as_string json in
      let* platform = required "platform" Json.as_string json in
      let* controls_digest = required "controls_digest" Json.as_string json in
      Ok (Backend_attested { id; version; platform; controls_digest })
  | "control_attested" ->
      let* () = exact "control_attested" [ "control"; "kind" ] json in
      let* control = required "control" Json.as_string json in
      Ok (Control_attested control)
  | "process_started" ->
      let* () = exact "process_started" [ "argv"; "executable"; "kind" ] json in
      let* executable = required "executable" Json.as_string json in
      let* argv = string_array "argv" json in
      Ok (Process_started { executable; argv })
  | "process_exited" ->
      let* () = exact "process_exited" [ "code"; "kind" ] json in
      let* code = required "code" Json.as_int json in
      Ok (Process_exited { code })
  | "filesystem_access" ->
      let* () =
        exact "filesystem_access"
          [ "allowed"; "kind"; "operation"; "path" ]
          json
      in
      let* path = required "path" Json.as_string json in
      let* operation = required "operation" Json.as_string json in
      let* allowed = required "allowed" Json.as_bool json in
      Ok (Filesystem_access { path; operation; allowed })
  | "network_attempt" ->
      let* () =
        exact "network_attempt" [ "allowed"; "host"; "kind"; "port" ] json
      in
      let* host = required "host" Json.as_string json in
      let* port = required "port" Json.as_int json in
      let* allowed = required "allowed" Json.as_bool json in
      if port < 0 || port > 65_535 then Error "network port is out of range"
      else Ok (Network_attempt { host; port; allowed })
  | "artifact_recorded" ->
      let* () = exact "artifact_recorded" [ "digest"; "kind"; "path" ] json in
      let* path = required "path" Json.as_string json in
      let* digest = required "digest" Json.as_string json in
      Ok (Artifact_recorded { path; digest })
  | "secret_redacted" ->
      let* () = exact "secret_redacted" [ "kind"; "name" ] json in
      let* name = required "name" Json.as_string json in
      Ok (Secret_redacted { name })
  | "resource_observed" ->
      let fields =
        [
          "cpu_time_ms";
          "kind";
          "output_bytes";
          "peak_memory_bytes";
          "processes";
          "scratch_bytes";
          "scratch_entries";
          "wall_time_ms";
        ]
      in
      let* () = exact "resource_observed" fields json in
      let* wall_time_ms = required "wall_time_ms" Json.as_int json in
      let* cpu_time_ms = required "cpu_time_ms" Json.as_int json in
      let* peak_memory_bytes = int64_field "peak_memory_bytes" json in
      let* processes = required "processes" Json.as_int json in
      let* output_bytes = required "output_bytes" Json.as_int json in
      let* scratch_bytes = int64_field "scratch_bytes" json in
      let* scratch_entries = required "scratch_entries" Json.as_int json in
      Ok
        (Resource_observed
           {
             wall_time_ms;
             cpu_time_ms;
             peak_memory_bytes;
             processes;
             output_bytes;
             scratch_bytes;
             scratch_entries;
           })
  | "log_recorded" ->
      let* () = exact "log_recorded" [ "digest"; "kind" ] json in
      let* digest = required "digest" Json.as_string json in
      Ok (Log_recorded { digest })
  | "filesystem_final" ->
      let* () = exact "filesystem_final" [ "digest"; "kind" ] json in
      let* digest = required "digest" Json.as_string json in
      Ok (Filesystem_final { digest })
  | "backend_error" ->
      let* () = exact "backend_error" [ "kind"; "message" ] json in
      let* message = required "message" Json.as_string json in
      Ok (Backend_error message)
  | other -> Error ("unknown evidence event kind " ^ other)

let parse_event json =
  let open Util in
  let* () =
    exact "evidence event"
      [ "body"; "digest"; "previous_digest"; "sequence" ]
      json
  in
  let* sequence = required "sequence" Json.as_int json in
  let* previous_digest = required "previous_digest" Json.as_string json in
  let* digest = required "digest" Json.as_string json in
  let* body_json =
    match Json.member "body" json with
    | Some value -> Ok value
    | None -> Error "evidence event needs body"
  in
  let* body = parse_body body_json in
  Ok { sequence; previous_digest; digest; body }

let parse_limits context json =
  let open Util in
  let fields =
    [
      "cpu_cores";
      "memory_bytes";
      "output_bytes";
      "processes";
      "scratch_bytes";
      "scratch_entries";
      "wall_time_seconds";
    ]
  in
  let* () = exact context fields json in
  let* cpu = required "cpu_cores" Json.as_int json in
  let* memory = required "memory_bytes" Json.as_int json in
  let* processes = required "processes" Json.as_int json in
  let* output_bytes = required "output_bytes" Json.as_int json in
  let* scratch = int64_field "scratch_bytes" json in
  let* scratch_entries = required "scratch_entries" Json.as_int json in
  let* cpu_seconds = required "wall_time_seconds" Json.as_int json in
  if
    cpu <> 1 || memory <> 2_147_483_648 || scratch <> 4_294_967_296L
    || scratch_entries <> 100_000
  then Error (context ^ " portable constants do not match runner-v2")
  else
    Ok
      {
        Sandbox_protocol.cpu_seconds;
        memory_mb = memory / 1024 / 1024;
        processes;
        output_bytes;
      }

let parse_observation json =
  let open Util in
  let fields =
    [
      "cpu_time_ms";
      "output_bytes";
      "peak_memory_bytes";
      "processes";
      "scratch_bytes";
      "scratch_entries";
      "wall_time_ms";
    ]
  in
  let* () = exact "observed_resources" fields json in
  let* wall_time_ms = required "wall_time_ms" Json.as_int json in
  let* cpu_time_ms = required "cpu_time_ms" Json.as_int json in
  let* peak_memory_bytes = int64_field "peak_memory_bytes" json in
  let* processes = required "processes" Json.as_int json in
  let* output_bytes = required "output_bytes" Json.as_int json in
  let* scratch_bytes = int64_field "scratch_bytes" json in
  let* scratch_entries = required "scratch_entries" Json.as_int json in
  Ok
    {
      wall_time_ms;
      cpu_time_ms;
      peak_memory_bytes;
      processes;
      output_bytes;
      scratch_bytes;
      scratch_entries;
    }

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* () =
    exact "evidence-v2"
      [
        "artifacts";
        "bindings";
        "effective_limits";
        "events";
        "final_filesystem_digest";
        "forensic_sidecars";
        "observed_resources";
        "plan_digest";
        "redacted_log_digest";
        "requested_limits";
        "schema";
      ]
      json
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "evidence-v2" then Error ("unsupported evidence schema " ^ schema)
  else
    let* plan_digest = required "plan_digest" Json.as_string json in
    let* bindings_json =
      match Json.member "bindings" json with
      | Some value -> Ok value
      | None -> Error "evidence-v2 needs bindings"
    in
    let* () =
      exact "evidence bindings"
        [
          "controls_digest";
          "lock_digest";
          "runtime_digest";
          "scenario_digest";
          "source_digest";
        ]
        bindings_json
    in
    let* scenario_digest =
      required "scenario_digest" Json.as_string bindings_json
    in
    let* source_digest =
      required "source_digest" Json.as_string bindings_json
    in
    let* lock_digest = required "lock_digest" Json.as_string bindings_json in
    let* runtime_digest =
      required "runtime_digest" Json.as_string bindings_json
    in
    let* controls_digest =
      required "controls_digest" Json.as_string bindings_json
    in
    let bindings =
      {
        scenario_digest;
        source_digest;
        lock_digest;
        runtime_digest;
        controls_digest;
      }
    in
    let* requested_json =
      match Json.member "requested_limits" json with
      | Some value -> Ok value
      | None -> Error "missing requested_limits"
    in
    let* requested_limits = parse_limits "requested_limits" requested_json in
    let* effective_json =
      match Json.member "effective_limits" json with
      | Some value -> Ok value
      | None -> Error "missing effective_limits"
    in
    let* effective_limits = parse_limits "effective_limits" effective_json in
    let* observed_json =
      match Json.member "observed_resources" json with
      | Some value -> Ok value
      | None -> Error "missing observed_resources"
    in
    let* observed_resources = parse_observation observed_json in
    let* redacted_log_digest =
      required "redacted_log_digest" Json.as_string json
    in
    let* final_filesystem_digest =
      required "final_filesystem_digest" Json.as_string json
    in
    let* artifact_jsons = required "artifacts" Json.as_array json in
    let rec parse_artifacts accumulator = function
      | [] -> Ok (List.rev accumulator)
      | value :: rest ->
          let* () = exact "artifact" [ "digest"; "path" ] value in
          let* path = required "path" Json.as_string value in
          let* digest = required "digest" Json.as_string value in
          parse_artifacts ({ path; digest } :: accumulator) rest
    in
    let* artifacts = parse_artifacts [] artifact_jsons in
    let* sidecar_jsons = required "forensic_sidecars" Json.as_array json in
    let rec parse_sidecars accumulator = function
      | [] -> Ok (List.rev accumulator)
      | value :: rest ->
          let* () = exact "forensic sidecar" [ "digest"; "kind" ] value in
          let* kind = required "kind" Json.as_string value in
          let* digest = required "digest" Json.as_string value in
          parse_sidecars ({ kind; digest } :: accumulator) rest
    in
    let* forensic_sidecars = parse_sidecars [] sidecar_jsons in
    let* event_jsons = required "events" Json.as_array json in
    let rec parse_events accumulator = function
      | [] -> Ok (List.rev accumulator)
      | value :: rest ->
          let* event = parse_event value in
          parse_events (event :: accumulator) rest
    in
    let* events = parse_events [] event_jsons in
    let evidence =
      {
        schema;
        plan_digest;
        bindings;
        requested_limits;
        effective_limits;
        observed_resources;
        redacted_log_digest;
        final_filesystem_digest;
        artifacts;
        forensic_sidecars;
        events;
      }
    in
    let* () = validate evidence in
    Ok evidence
