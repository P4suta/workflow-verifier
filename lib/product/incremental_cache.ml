type t = {
  schema : string;
  key : string;
  exit_code : int;
  report : string;
  integrity : string;
}

let key ~tool_version ~config_digest ~lock_digest inputs =
  let inputs =
    inputs
    |> List.map (fun (path, digest) -> (Util.normalize_slashes path, digest))
    |> List.sort (fun (left, _) (right, _) -> String.compare left right)
  in
  let material =
    Json.Object
      [
        ("config_digest", Json.String config_digest);
        ( "inputs",
          Json.Array
            (List.map
               (fun (path, digest) ->
                 Json.Object
                   [
                     ("digest", Json.String digest); ("path", Json.String path);
                   ])
               inputs) );
        ("lock_digest", Json.String lock_digest);
        ("schema", Json.String "analysis-cache-key-v1");
        ("tool_version", Json.String tool_version);
      ]
  in
  "sha256:" ^ Sha256.digest_string (Json.to_string material)

let unsigned_fields entry =
  [
    ("exit_code", Json.Int entry.exit_code);
    ("key", Json.String entry.key);
    ("report", Json.String entry.report);
    ("schema", Json.String entry.schema);
  ]

let unsigned_json entry = Json.Object (unsigned_fields entry)

let create ~key ~exit_code ~report =
  if exit_code < 0 || exit_code > 5 then
    Error "cache exit code must be 0..5"
  else
    let provisional =
      { schema = "analysis-cache-v1"; key; exit_code; report; integrity = "" }
    in
    let integrity =
      "sha256:"
      ^ Sha256.digest_string (Json.to_string (unsigned_json provisional))
    in
    Ok { provisional with integrity }

let to_json entry =
  Json.Object
    (("integrity", Json.String entry.integrity) :: unsigned_fields entry)

let to_canonical_json entry = Json.to_string (to_json entry) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("analysis cache needs field " ^ name)

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "analysis-cache-v1" then
    Error ("unsupported analysis cache schema " ^ schema)
  else
    let* key = required "key" Json.as_string json in
    let* exit_code = required "exit_code" Json.as_int json in
    let* report = required "report" Json.as_string json in
    let* integrity = required "integrity" Json.as_string json in
    if exit_code < 0 || exit_code > 5 then Error "cache exit code must be 0..5"
    else
      let* rebuilt = create ~key ~exit_code ~report in
      if rebuilt.integrity <> integrity then
        Error "analysis cache integrity mismatch"
      else Ok rebuilt
