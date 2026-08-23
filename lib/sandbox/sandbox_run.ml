type outcome =
  | Completed
  | Step_failed of { step : string; code : int option }
  | Timed_out of { step : string }
  | Output_limit_exceeded of { step : string }

type t = { evidence : Evidence.t; outcome : outcome }

let outcome_json = function
  | Completed -> Json.Object [ ("state", Json.String "completed") ]
  | Step_failed { step; code } ->
      Json.Object
        [
          ( "code",
            Option.fold ~none:Json.Null ~some:(fun value -> Json.Int value) code
          );
          ("state", Json.String "step_failed");
          ("step", Json.String step);
        ]
  | Timed_out { step } ->
      Json.Object
        [ ("state", Json.String "timed_out"); ("step", Json.String step) ]
  | Output_limit_exceeded { step } ->
      Json.Object
        [
          ("state", Json.String "output_limit_exceeded");
          ("step", Json.String step);
        ]

let to_json run =
  Json.Object
    [
      ("evidence", Evidence.to_json run.evidence);
      ("outcome", outcome_json run.outcome);
      ("schema", Json.String "sandbox-run-v1");
    ]

let to_canonical_json run = Json.to_string (to_json run) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("sandbox run needs field " ^ name)

let parse_outcome json =
  let open Util in
  let* state = required "state" Json.as_string json in
  match state with
  | "completed" -> Ok Completed
  | "step_failed" ->
      let* step = required "step" Json.as_string json in
      let code = Option.bind (Json.member "code" json) Json.as_int in
      Ok (Step_failed { step; code })
  | "timed_out" ->
      let* step = required "step" Json.as_string json in
      Ok (Timed_out { step })
  | "output_limit_exceeded" ->
      let* step = required "step" Json.as_string json in
      Ok (Output_limit_exceeded { step })
  | other -> Error ("unknown sandbox outcome " ^ other)

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "sandbox-run-v1" then
    Error ("unsupported sandbox run schema " ^ schema)
  else
    let* evidence_json =
      match Json.member "evidence" json with
      | Some value -> Ok value
      | None -> Error "sandbox run needs evidence"
    in
    let* outcome_json =
      match Json.member "outcome" json with
      | Some value -> Ok value
      | None -> Error "sandbox run needs outcome"
    in
    let* evidence = Evidence.parse (Json.to_string evidence_json) in
    let* outcome = parse_outcome outcome_json in
    Ok { evidence; outcome }
