type runner_platform =
  | Linux_x86_64
  | Linux_arm64
  | Windows_x86_64
  | Windows_arm64
  | Macos_x86_64
  | Macos_arm64

type t = {
  schema : string;
  digest : string;
  provider : Ir.provider;
  workflow_entrypoint : string;
  job : string;
  event : string;
  inputs : (string * string) list;
  matrix : (string * Json.t) list;
  variables : (string * string) list;
  runner_platform : runner_platform;
  secret_names : string list;
}

let runner_name = function
  | Linux_x86_64 -> "linux-x86_64"
  | Linux_arm64 -> "linux-arm64"
  | Windows_x86_64 -> "windows-x86_64"
  | Windows_arm64 -> "windows-arm64"
  | Macos_x86_64 -> "macos-x86_64"
  | Macos_arm64 -> "macos-arm64"

let runner_os = function
  | Linux_x86_64 | Linux_arm64 -> "linux"
  | Windows_x86_64 | Windows_arm64 -> "windows"
  | Macos_x86_64 | Macos_arm64 -> "macos"

let runner_of_string = function
  | "linux-x86_64" -> Some Linux_x86_64
  | "linux-arm64" -> Some Linux_arm64
  | "windows-x86_64" -> Some Windows_x86_64
  | "windows-arm64" -> Some Windows_arm64
  | "macos-x86_64" -> Some Macos_x86_64
  | "macos-arm64" -> Some Macos_arm64
  | _ -> None

let provider_of_string = function
  | "github" -> Some Ir.Github
  | "gitlab" -> Some Ir.Gitlab
  | "azure" -> Some Ir.Azure
  | "circleci" -> Some Ir.Circleci
  | _ -> None

let portable_name value =
  let first = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' | '-' | '.' -> true
    | _ -> false
  in
  String.length value > 0
  && first value.[0]
  && String.sub value 1 (String.length value - 1) |> String.for_all rest

let secret_name value =
  let first = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' -> true
    | _ -> false
  in
  String.length value > 0
  && first value.[0]
  && String.sub value 1 (String.length value - 1) |> String.for_all rest

let safe_entrypoint path =
  let path = Util.normalize_slashes path in
  path <> "" && Filename.is_relative path
  && (not (Util.starts_with ~prefix:"/" path))
  && (not (String.length path >= 2 && path.[1] = ':'))
  && Util.valid_utf8 path
  && path |> String.split_on_char '/'
     |> List.for_all (fun segment ->
         segment <> "" && segment <> "." && segment <> "..")

let canonical_pairs pairs =
  pairs
  |> List.map (fun (name, value) -> (name, value))
  |> List.sort (fun (left, _) (right, _) -> String.compare left right)

let string_object pairs =
  Json.Object (List.map (fun (name, value) -> (name, Json.String value)) pairs)

let unsigned_fields scenario =
  [
    ("event", Json.String scenario.event);
    ("inputs", string_object scenario.inputs);
    ("job", Json.String scenario.job);
    ("matrix", Json.Object scenario.matrix);
    ("provider", Json.String (Ir.provider_name scenario.provider));
    ("runner_platform", Json.String (runner_name scenario.runner_platform));
    ("schema", Json.String scenario.schema);
    ( "secret_names",
      Json.Array
        (List.map (fun value -> Json.String value) scenario.secret_names) );
    ("variables", string_object scenario.variables);
    ("workflow_entrypoint", Json.String scenario.workflow_entrypoint);
  ]

let unsigned_json scenario = Json.Object (unsigned_fields scenario)

let to_json scenario =
  Json.Object
    (("digest", Json.String scenario.digest) :: unsigned_fields scenario)

let to_canonical_json scenario = Json.to_string (to_json scenario) ^ "\n"

let unique_names context pairs =
  let names = List.map fst pairs in
  if List.length names = List.length (Util.deduplicate_strings names) then Ok ()
  else Error (context ^ " names must be unique")

let make ~provider ~workflow_entrypoint ~job ~event ~inputs ~matrix ~variables
    ~runner_platform ~secret_names =
  let workflow_entrypoint = Util.normalize_slashes workflow_entrypoint
  and inputs = canonical_pairs inputs
  and matrix = canonical_pairs matrix
  and variables = canonical_pairs variables
  and secret_names = List.sort String.compare secret_names in
  let open Util in
  let* () =
    if safe_entrypoint workflow_entrypoint then Ok ()
    else Error "scenario workflow_entrypoint must be a root-relative UTF-8 path"
  in
  let* () =
    if String.trim job <> "" then Ok ()
    else Error "scenario job must not be empty"
  in
  let* () =
    if String.trim event <> "" then Ok ()
    else Error "scenario event must not be empty"
  in
  let* () = unique_names "scenario input" inputs in
  let* () = unique_names "scenario matrix" matrix in
  let* () = unique_names "scenario variable" variables in
  let* () =
    if
      List.for_all (fun (name, _) -> portable_name name) (inputs @ variables)
      && List.for_all (fun (name, _) -> portable_name name) matrix
    then Ok ()
    else Error "scenario input, matrix, and variable names must be portable"
  in
  let* () =
    if
      List.for_all secret_name secret_names
      && List.length secret_names
         = List.length (Util.deduplicate_strings secret_names)
    then Ok ()
    else
      Error
        "scenario secret_names must be unique identifiers matching \
         [A-Za-z_][A-Za-z0-9_]*"
  in
  let provisional =
    {
      schema = "scenario-v1";
      digest = "";
      provider;
      workflow_entrypoint;
      job;
      event;
      inputs;
      matrix;
      variables;
      runner_platform;
      secret_names;
    }
  in
  let digest =
    "sha256:"
    ^ Sha256.digest_string (Json.to_string (unsigned_json provisional))
  in
  Ok { provisional with digest }

let parse_assignment value =
  match String.index_opt value '=' with
  | None -> Error ("expected NAME=VALUE: " ^ value)
  | Some index ->
      let name = String.sub value 0 index
      and contents =
        String.sub value (index + 1) (String.length value - index - 1)
      in
      if portable_name name then Ok (name, contents)
      else Error ("invalid portable assignment name: " ^ name)

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("scenario-v1 needs field " ^ name)

let string_pairs name json =
  let open Util in
  let* fields = required name Json.as_object json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | (key, Json.String value) :: rest ->
        loop ((key, value) :: accumulator) rest
    | (key, _) :: _ -> Error (name ^ "." ^ key ^ " must be a string")
  in
  loop [] fields

let matrix_pairs json =
  let open Util in
  let* fields = required "matrix" Json.as_object json in
  if
    List.for_all
      (fun (_, value) ->
        match value with
        | Json.String _ | Json.Bool _ | Json.Int _ | Json.Int64 _ -> true
        | _ -> false)
      fields
  then Ok fields
  else
    Error "scenario matrix values must be scalar strings, booleans, or integers"

let string_list name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error (name ^ " must contain only strings")
  in
  loop [] values

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error
          (Printf.sprintf "scenario JSON byte %d: %s" error.offset error.message)
  in
  let* _ =
    Json.exact_object ~context:"scenario-v1"
      ~allowed:
        [
          "digest";
          "event";
          "inputs";
          "job";
          "matrix";
          "provider";
          "runner_platform";
          "schema";
          "secret_names";
          "variables";
          "workflow_entrypoint";
        ]
      json
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "scenario-v1" then Error ("unsupported scenario schema " ^ schema)
  else
    let* supplied_digest = required "digest" Json.as_string json in
    let* provider_name = required "provider" Json.as_string json in
    let* provider =
      match provider_of_string provider_name with
      | Some value -> Ok value
      | None -> Error ("unknown scenario provider " ^ provider_name)
    in
    let* workflow_entrypoint =
      required "workflow_entrypoint" Json.as_string json
    in
    let* job = required "job" Json.as_string json in
    let* event = required "event" Json.as_string json in
    let* inputs = string_pairs "inputs" json in
    let* matrix = matrix_pairs json in
    let* variables = string_pairs "variables" json in
    let* runner_name = required "runner_platform" Json.as_string json in
    let* runner_platform =
      match runner_of_string runner_name with
      | Some value -> Ok value
      | None -> Error ("unknown runner platform " ^ runner_name)
    in
    let* secret_names = string_list "secret_names" json in
    let* scenario =
      make ~provider ~workflow_entrypoint ~job ~event ~inputs ~matrix ~variables
        ~runner_platform ~secret_names
    in
    if scenario.digest = supplied_digest then Ok scenario
    else Error "scenario digest mismatch"
