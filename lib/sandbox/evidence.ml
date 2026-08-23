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
  | Backend_error of string

type event = {
  sequence : int;
  previous_digest : string;
  digest : string;
  body : body;
}

type t = { schema : string; plan_digest : string; events : event list }

let empty ~plan_digest = { schema = "evidence-v1"; plan_digest; events = [] }

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
  | Backend_error message ->
      Json.Object
        [
          ("kind", Json.String "backend_error"); ("message", Json.String message);
        ]

let unsigned_event sequence previous_digest body =
  Json.Object
    [
      ("body", body_json body);
      ("previous_digest", Json.String previous_digest);
      ("sequence", Json.Int sequence);
    ]

let append body evidence =
  let sequence = List.length evidence.events in
  let previous_digest =
    match List.rev evidence.events with
    | [] -> evidence.plan_digest
    | event :: _ -> event.digest
  in
  let digest =
    "sha256:"
    ^ Sha256.digest_string
        (Json.to_string (unsigned_event sequence previous_digest body))
  in
  {
    evidence with
    events = evidence.events @ [ { sequence; previous_digest; digest; body } ];
  }

let validate evidence =
  let rec loop expected_sequence previous = function
    | [] -> Ok ()
    | event :: rest ->
        if event.sequence <> expected_sequence then
          Error "evidence sequence is not contiguous"
        else if event.previous_digest <> previous then
          Error "evidence previous digest mismatch"
        else
          let expected =
            "sha256:"
            ^ Sha256.digest_string
                (Json.to_string
                   (unsigned_event event.sequence event.previous_digest
                      event.body))
          in
          if expected <> event.digest then
            Error "evidence event digest mismatch"
          else loop (expected_sequence + 1) event.digest rest
  in
  loop 0 evidence.plan_digest evidence.events

let effects_of_body = function
  | Process_started _ -> [ Ir.Command_execution ]
  | Filesystem_access { operation; _ } ->
      if Util.contains ~needle:"write" (String.lowercase_ascii operation) then
        [ Ir.File_write ]
      else [ Ir.File_read ]
  | Network_attempt _ -> [ Ir.Network_request ]
  | Artifact_recorded _ -> [ Ir.Artifact_publish ]
  | Backend_attested _
  | Control_attested _
  | Process_exited _
  | Secret_redacted _
  | Backend_error _ -> []

let observed_effects evidence =
  evidence.events
  |> List.concat_map (fun event -> effects_of_body event.body)
  |> Util.deduplicate_compare Stdlib.compare

let observes_effect observable evidence =
  List.mem observable (observed_effects evidence)

let event_json event =
  match unsigned_event event.sequence event.previous_digest event.body with
  | Json.Object fields ->
      Json.Object (("digest", Json.String event.digest) :: fields)
  | _ -> assert false

let to_json evidence =
  Json.Object
    [
      ("events", Json.Array (List.map event_json evidence.events));
      ("plan_digest", Json.String evidence.plan_digest);
      ("schema", Json.String evidence.schema);
    ]

let to_canonical_json evidence = Json.to_string (to_json evidence) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("evidence needs field " ^ name)

let string_array name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error (name ^ " must contain only strings")
  in
  loop [] values

let parse_body json =
  let open Util in
  let* kind = required "kind" Json.as_string json in
  match kind with
  | "backend_attested" ->
      let* id = required "id" Json.as_string json in
      let* version = required "version" Json.as_string json in
      let* platform = required "platform" Json.as_string json in
      let* controls_digest = required "controls_digest" Json.as_string json in
      Ok (Backend_attested { id; version; platform; controls_digest })
  | "control_attested" ->
      let* control = required "control" Json.as_string json in
      Ok (Control_attested control)
  | "process_started" ->
      let* executable = required "executable" Json.as_string json in
      let* argv = string_array "argv" json in
      Ok (Process_started { executable; argv })
  | "process_exited" ->
      let* code = required "code" Json.as_int json in
      Ok (Process_exited { code })
  | "filesystem_access" ->
      let* path = required "path" Json.as_string json in
      let* operation = required "operation" Json.as_string json in
      let* allowed = required "allowed" Json.as_bool json in
      Ok (Filesystem_access { path; operation; allowed })
  | "network_attempt" ->
      let* host = required "host" Json.as_string json in
      let* port = required "port" Json.as_int json in
      let* allowed = required "allowed" Json.as_bool json in
      if port < 0 || port > 65_535 then Error "network port is out of range"
      else Ok (Network_attempt { host; port; allowed })
  | "artifact_recorded" ->
      let* path = required "path" Json.as_string json in
      let* digest = required "digest" Json.as_string json in
      Ok (Artifact_recorded { path; digest })
  | "secret_redacted" ->
      let* name = required "name" Json.as_string json in
      Ok (Secret_redacted { name })
  | "backend_error" ->
      let* message = required "message" Json.as_string json in
      Ok (Backend_error message)
  | other -> Error ("unknown evidence event kind " ^ other)

let parse_event json =
  let open Util in
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

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "evidence-v1" then Error ("unsupported evidence schema " ^ schema)
  else
    let* plan_digest = required "plan_digest" Json.as_string json in
    let* event_jsons = required "events" Json.as_array json in
    let rec parse_events accumulator = function
      | [] -> Ok (List.rev accumulator)
      | item :: rest ->
          let* event = parse_event item in
          parse_events (event :: accumulator) rest
    in
    let* events = parse_events [] event_jsons in
    let evidence = { schema; plan_digest; events } in
    let* () = validate evidence in
    Ok evidence
