type entry = {
  provider : Ir.provider;
  reference : string;
  revision : string;
  digest : string;
  source : string;
  summary : Dependency_summary.t option;
}

type t = { schema : string; entries : entry list; integrity : string }

let compare_entry left right =
  match
    String.compare
      (Ir.provider_name left.provider)
      (Ir.provider_name right.provider)
  with
  | 0 -> String.compare left.reference right.reference
  | comparison -> comparison

let entry_json entry =
  let fields =
    [
      ("digest", Json.String entry.digest);
      ("provider", Json.String (Ir.provider_name entry.provider));
      ("reference", Json.String entry.reference);
      ("revision", Json.String entry.revision);
      ("source", Json.String entry.source);
    ]
  in
  Json.Object
    (match entry.summary with
    | None -> fields
    | Some summary -> ("summary", Dependency_summary.to_json summary) :: fields)

let unsigned_json schema entries =
  Json.Object
    [
      ("entries", Json.Array (List.map entry_json entries));
      ("schema", Json.String schema);
    ]

let assemble schema entries =
  let integrity =
    "sha256:"
    ^ Sha256.digest_string (Json.to_string (unsigned_json schema entries))
  in
  { schema; entries; integrity }

let valid_hex value =
  String.length value > 0
  && String.for_all
       (function
         | '0' .. '9' | 'a' .. 'f' -> true
         | _ -> false)
       (String.lowercase_ascii value)

let valid_sha256 value =
  Util.starts_with ~prefix:"sha256:" value
  && String.length value = 71
  && valid_hex (String.sub value 7 64)

let validate_entry entry =
  if String.trim entry.reference = "" then
    Error "lock reference must not be empty"
  else if String.trim entry.revision = "" then
    Error "lock revision must not be empty"
  else if not (valid_sha256 entry.digest) then
    Error ("invalid SHA-256 digest for " ^ entry.reference)
  else if String.trim entry.source = "" then
    Error "lock source must not be empty"
  else Ok ()

let same_payload left right =
  left.revision = right.revision
  && left.digest = right.digest && left.source = right.source
  && left.summary = right.summary

let create_with_schema schema entries =
  if schema <> "lock-v1" && schema <> "lock-v2" then
    Error ("unsupported lock schema " ^ schema)
  else if
    schema = "lock-v1"
    && List.exists (fun entry -> Option.is_some entry.summary) entries
  then Error "lock-v1 entries cannot contain semantic summaries"
  else
    let entries = List.sort compare_entry entries in
    let rec validate previous accumulator = function
      | [] -> Ok (List.rev accumulator)
      | entry :: rest -> (
          match validate_entry entry with
          | Error _ as error -> error
          | Ok () -> (
              match previous with
              | Some prior when compare_entry prior entry = 0 ->
                  if same_payload prior entry then
                    validate previous accumulator rest
                  else
                    Error
                      (Printf.sprintf "conflicting lock entries for %s:%s"
                         (Ir.provider_name entry.provider)
                         entry.reference)
              | _ -> validate (Some entry) (entry :: accumulator) rest))
    in
    match validate None [] entries with
    | Error _ as error -> error
    | Ok entries -> Ok (assemble schema entries)

let create entries = create_with_schema "lock-v2" entries
let empty = assemble "lock-v2" []

let find lock provider reference =
  List.find_opt
    (fun entry -> entry.provider = provider && entry.reference = reference)
    lock.entries

let to_json lock =
  Json.Object
    [
      ("entries", Json.Array (List.map entry_json lock.entries));
      ("integrity", Json.String lock.integrity);
      ("schema", Json.String lock.schema);
    ]

let to_canonical_json lock = Json.to_string (to_json lock) ^ "\n"

let provider_of_string = function
  | "github" -> Some Ir.Github
  | "gitlab" -> Some Gitlab
  | "azure" -> Some Azure
  | "circleci" -> Some Circleci
  | _ -> None

let required_string name json =
  match Option.bind (Json.member name json) Json.as_string with
  | Some value -> Ok value
  | None -> Error ("lock entry needs string field " ^ name)

let validate_fields ~context ~allowed json =
  match Json.as_object json with
  | None -> Error (context ^ " must be an object")
  | Some fields -> (
      let names = List.map fst fields in
      let unique = Util.deduplicate_strings names in
      if List.length unique <> List.length names then
        Error (context ^ " contains a duplicate field")
      else
        match List.find_opt (fun name -> not (List.mem name allowed)) names with
        | Some name -> Error (context ^ " contains unknown field " ^ name)
        | None -> Ok ())

let parse_entry schema json =
  let open Util in
  let* () =
    validate_fields ~context:"lock entry"
      ~allowed:
        (if schema = "lock-v1" then
           [ "provider"; "reference"; "revision"; "digest"; "source" ]
         else
           [
             "provider"; "reference"; "revision"; "digest"; "source"; "summary";
           ])
      json
  in
  let* provider_name = required_string "provider" json in
  let* provider =
    match provider_of_string provider_name with
    | Some value -> Ok value
    | None -> Error ("unknown lock provider " ^ provider_name)
  in
  let* reference = required_string "reference" json in
  let* revision = required_string "revision" json in
  let* digest = required_string "digest" json in
  let* source = required_string "source" json in
  let* summary =
    match Json.member "summary" json with
    | None -> Ok None
    | Some value ->
        let* summary = Dependency_summary.of_json value in
        Ok (Some summary)
  in
  Ok { provider; reference; revision; digest; source; summary }

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* () =
    validate_fields ~context:"lockfile"
      ~allowed:[ "schema"; "integrity"; "entries" ]
      json
  in
  let* schema = required_string "schema" json in
  if schema <> "lock-v1" && schema <> "lock-v2" then
    Error ("unsupported lock schema " ^ schema)
  else
    let* integrity = required_string "integrity" json in
    let* entries_json =
      match Option.bind (Json.member "entries" json) Json.as_array with
      | Some values -> Ok values
      | None -> Error "lockfile entries must be an array"
    in
    let rec parse_entries accumulator = function
      | [] -> Ok (List.rev accumulator)
      | item :: rest ->
          let* entry = parse_entry schema item in
          parse_entries (entry :: accumulator) rest
    in
    let* entries = parse_entries [] entries_json in
    let* rebuilt = create_with_schema schema entries in
    if rebuilt.integrity <> integrity then
      Error "lockfile integrity digest mismatch"
    else Ok rebuilt
