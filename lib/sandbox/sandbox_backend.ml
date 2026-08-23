type request = {
  backend : Sandbox_protocol.backend;
  required_controls : Sandbox_protocol.control list;
}

type attestation = {
  id : string;
  version : string;
  platform : string;
  controls : Sandbox_protocol.control list;
}

type probe = {
  available : bool;
  attestation : attestation;
  reasons : string list;
}

let ( let* ) result continuation =
  match result with
  | Ok value -> continuation value
  | Error _ as error -> error

let required name projection json =
  match Option.bind (Json.member name json) projection with
  | Some value -> Ok value
  | None -> Error ("missing or invalid " ^ name)

let select request available =
  let requested_id = Sandbox_protocol.backend_name request.backend in
  match
    List.find_opt (fun candidate -> candidate.id = requested_id) available
  with
  | None -> Error request.required_controls
  | Some candidate ->
      let missing =
        List.filter
          (fun control -> not (List.mem control candidate.controls))
          request.required_controls
      in
      if missing = [] then Ok candidate else Error missing

let attestation_fields attestation =
  [
    ( "controls",
      Json.Array
        (List.map
           (fun value -> Json.String (Sandbox_protocol.control_name value))
           attestation.controls) );
    ("id", Json.String attestation.id);
    ("platform", Json.String attestation.platform);
    ("version", Json.String attestation.version);
  ]

let attestation_to_json attestation =
  Json.Object (attestation_fields attestation)

let probe_to_json probe =
  Json.Object
    (("available", Json.Bool probe.available)
    :: ( "reasons",
         Json.Array (List.map (fun reason -> Json.String reason) probe.reasons)
       )
    :: ("schema", Json.String "backend-attestation-v1")
    :: attestation_fields probe.attestation)

let parse_probe source =
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "backend-attestation-v1" then
    Error ("unsupported backend attestation schema " ^ schema)
  else
    let* available = required "available" Json.as_bool json in
    let* id = required "id" Json.as_string json in
    let* version = required "version" Json.as_string json in
    let* platform = required "platform" Json.as_string json in
    let* control_values = required "controls" Json.as_array json in
    let* reason_values = required "reasons" Json.as_array json in
    let rec strings accumulator = function
      | [] -> Ok (List.rev accumulator)
      | Json.String value :: rest -> strings (value :: accumulator) rest
      | _ -> Error "backend probe reasons must be strings"
    in
    let* reasons = strings [] reason_values in
    let rec controls seen accumulator = function
      | [] -> Ok (List.rev accumulator)
      | Json.String name :: rest -> (
          match Sandbox_protocol.control_of_name name with
          | None -> Error ("unknown sandbox control " ^ name)
          | Some value when List.mem value seen ->
              Error ("duplicate sandbox control " ^ name)
          | Some value -> controls (value :: seen) (value :: accumulator) rest)
      | _ -> Error "backend controls must be strings"
    in
    if id = "" || version = "" || platform = "" then
      Error "backend attestation identity fields cannot be empty"
    else
      let* controls = controls [] [] control_values in
      if available && reasons <> [] then
        Error "an available backend probe cannot report failure reasons"
      else
        Ok
          {
            available;
            attestation = { id; version; platform; controls };
            reasons = Util.deduplicate_strings reasons;
          }
