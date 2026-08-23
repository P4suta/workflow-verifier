type control =
  | Source_read_only
  | Scratch_overlay
  | Network_deny
  | Process_isolation
  | Resource_limits
  | Secret_redaction
  | Namespace
  | Seccomp
  | Landlock
  | Cgroup_v2
  | App_container
  | Restricted_token
  | Job_object
  | App_sandbox
  | Virtual_machine

type backend = Oci of string | Linux_native | Windows_native | Macos_vm

type limits = {
  cpu_seconds : int;
  memory_mb : int;
  processes : int;
  output_bytes : int;
}

type dependency = {
  reference : string;
  digest : string option;
  available : bool;
}

type step = {
  id : string;
  image : string;
  argv : string list;
  environment : (string * string) list;
  working_directory : string;
  supported : bool;
}

type status = Complete | Incomplete of string list

type plan = {
  schema : string;
  digest : string;
  backend : backend;
  source_digest : string;
  lock_digest : string;
  controls : control list;
  limits : limits;
  secret_names : string list;
  dependencies : dependency list;
  steps : step list;
  status : status;
}

let control_name = function
  | Source_read_only -> "source_read_only"
  | Scratch_overlay -> "scratch_overlay"
  | Network_deny -> "network_deny"
  | Process_isolation -> "process_isolation"
  | Resource_limits -> "resource_limits"
  | Secret_redaction -> "secret_redaction"
  | Namespace -> "namespace"
  | Seccomp -> "seccomp"
  | Landlock -> "landlock"
  | Cgroup_v2 -> "cgroup_v2"
  | App_container -> "app_container"
  | Restricted_token -> "restricted_token"
  | Job_object -> "job_object"
  | App_sandbox -> "app_sandbox"
  | Virtual_machine -> "virtual_machine"

let control_of_name = function
  | "source_read_only" -> Some Source_read_only
  | "scratch_overlay" -> Some Scratch_overlay
  | "network_deny" -> Some Network_deny
  | "process_isolation" -> Some Process_isolation
  | "resource_limits" -> Some Resource_limits
  | "secret_redaction" -> Some Secret_redaction
  | "namespace" -> Some Namespace
  | "seccomp" -> Some Seccomp
  | "landlock" -> Some Landlock
  | "cgroup_v2" -> Some Cgroup_v2
  | "app_container" -> Some App_container
  | "restricted_token" -> Some Restricted_token
  | "job_object" -> Some Job_object
  | "app_sandbox" -> Some App_sandbox
  | "virtual_machine" -> Some Virtual_machine
  | _ -> None

let controls_digest controls =
  "sha256:"
  ^ Sha256.digest_string
      (Json.to_string
         (Json.Array
            (List.map
               (fun control -> Json.String (control_name control))
               controls)))

let backend_name = function
  | Oci engine -> "oci:" ^ engine
  | Linux_native -> "linux-native"
  | Windows_native -> "windows-native"
  | Macos_vm -> "macos-vm"

let backend_of_name value =
  if Util.starts_with ~prefix:"oci:" value then
    Some (Oci (String.sub value 4 (String.length value - 4)))
  else
    match value with
    | "linux-native" -> Some Linux_native
    | "windows-native" -> Some Windows_native
    | "macos-vm" -> Some Macos_vm
    | _ -> None

let dependency_json dependency =
  Json.Object
    [
      ("available", Json.Bool dependency.available);
      ( "digest",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          dependency.digest );
      ("reference", Json.String dependency.reference);
    ]

let step_json step =
  Json.Object
    [
      ("argv", Json.Array (List.map (fun value -> Json.String value) step.argv));
      ( "environment",
        Json.Object
          (List.map
             (fun (key, value) -> (key, Json.String value))
             step.environment) );
      ("id", Json.String step.id);
      ("image", Json.String step.image);
      ("supported", Json.Bool step.supported);
      ("working_directory", Json.String step.working_directory);
    ]

let status_json = function
  | Complete -> Json.Object [ ("state", Json.String "complete") ]
  | Incomplete reasons ->
      Json.Object
        [
          ( "reasons",
            Json.Array (List.map (fun value -> Json.String value) reasons) );
          ("state", Json.String "incomplete");
        ]

let unsigned_fields plan =
  [
    ("backend", Json.String (backend_name plan.backend));
    ( "controls",
      Json.Array
        (List.map (fun value -> Json.String (control_name value)) plan.controls)
    );
    ("dependencies", Json.Array (List.map dependency_json plan.dependencies));
    ( "limits",
      Json.Object
        [
          ("cpu_seconds", Json.Int plan.limits.cpu_seconds);
          ("memory_mb", Json.Int plan.limits.memory_mb);
          ("output_bytes", Json.Int plan.limits.output_bytes);
          ("processes", Json.Int plan.limits.processes);
        ] );
    ("lock_digest", Json.String plan.lock_digest);
    ("schema", Json.String plan.schema);
    ( "secret_names",
      Json.Array (List.map (fun value -> Json.String value) plan.secret_names)
    );
    ("source_digest", Json.String plan.source_digest);
    ("status", status_json plan.status);
    ("steps", Json.Array (List.map step_json plan.steps));
  ]

let unsigned_json plan = Json.Object (unsigned_fields plan)

let redact_environment secret_names environment =
  List.map
    (fun (name, value) ->
      if List.mem name secret_names then (name, "${SECRET:" ^ name ^ "}")
      else (name, value))
    environment

let valid_identifier value =
  let valid_start = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and valid_rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' -> true
    | _ -> false
  in
  String.length value > 0
  && valid_start value.[0]
  && String.sub value 1 (String.length value - 1) |> String.for_all valid_rest

let valid_engine value =
  String.length value > 0
  && String.for_all
       (function
         | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' | '.' | '-' -> true
         | _ -> false)
       value

let valid_content_digest value =
  String.length value = 71
  && Util.starts_with ~prefix:"sha256:" value
  && String.sub value 7 64
     |> String.for_all (function
       | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
       | _ -> false)

let validate_plan_arguments ~backend ~limits ~secret_names ~dependencies ~steps
    =
  if
    match backend with
    | Oci engine -> not (valid_engine engine)
    | _ -> false
  then Error "OCI backend name is invalid"
  else if
    List.exists
      (fun value -> value <= 0)
      [
        limits.cpu_seconds;
        limits.memory_mb;
        limits.processes;
        limits.output_bytes;
      ]
  then Error "runner limits must be positive"
  else if List.exists (fun name -> not (valid_identifier name)) secret_names
  then Error "secret names must be portable identifiers"
  else if
    List.exists
      (fun step ->
        step.id = "" || step.argv = [] || step.working_directory = "")
      steps
  then Error "steps need a non-empty id, argv, and working directory"
  else if
    List.length (List.map (fun step -> step.id) steps)
    <> List.length
         (List.map (fun step -> step.id) steps |> Util.deduplicate_strings)
  then Error "step IDs must be unique"
  else if
    List.exists (fun dependency -> dependency.reference = "") dependencies
    || List.length
         (List.map (fun dependency -> dependency.reference) dependencies)
       <> List.length
            (List.map (fun dependency -> dependency.reference) dependencies
            |> Util.deduplicate_strings)
  then Error "dependency references must be non-empty and unique"
  else Ok ()

let make_plan ~backend ~source_digest ~lock_digest ~controls ~limits
    ~secret_names ~dependencies ~steps =
  let open Util in
  let* () =
    validate_plan_arguments ~backend ~limits ~secret_names ~dependencies ~steps
  in
  let secret_names = Util.deduplicate_strings secret_names in
  let steps =
    List.map
      (fun step ->
        {
          step with
          environment =
            redact_environment secret_names step.environment
            |> List.sort (fun (a, _) (b, _) -> String.compare a b);
        })
      steps
    |> List.sort (fun left right -> String.compare left.id right.id)
  and dependencies =
    List.sort
      (fun left right -> String.compare left.reference right.reference)
      dependencies
  and controls = Util.deduplicate_compare Stdlib.compare controls in
  let dependency_reasons =
    dependencies
    |> List.filter_map (fun dependency ->
        if (not dependency.available) || dependency.digest = None then
          Some ("unresolved dependency: " ^ dependency.reference)
        else None)
  and step_reasons =
    steps
    |> List.concat_map (fun step ->
        (if step.supported then [] else [ "unsupported step: " ^ step.id ])
        @
        if valid_content_digest step.image then []
        else [ "unresolved image: " ^ step.id ])
  in
  let reasons = dependency_reasons @ step_reasons |> Util.deduplicate_strings in
  let status = if reasons = [] then Complete else Incomplete reasons in
  let provisional =
    {
      schema = "runner-v1";
      digest = "";
      backend;
      source_digest;
      lock_digest;
      controls;
      limits;
      secret_names;
      dependencies;
      steps;
      status;
    }
  in
  let digest =
    "sha256:"
    ^ Sha256.digest_string (Json.to_string (unsigned_json provisional))
  in
  Ok { provisional with digest }

let to_json plan =
  Json.Object (("digest", Json.String plan.digest) :: unsigned_fields plan)

let to_canonical_json plan = Json.to_string (to_json plan) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("runner plan needs field " ^ name)

let string_list name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error (name ^ " must contain strings")
  in
  loop [] values

let parse_dependency json =
  let open Util in
  let* reference = required "reference" Json.as_string json in
  let* available = required "available" Json.as_bool json in
  let digest =
    match Json.member "digest" json with
    | Some (Json.String value) -> Some value
    | _ -> None
  in
  Ok { reference; digest; available }

let parse_step json =
  let open Util in
  let* id = required "id" Json.as_string json in
  let* image = required "image" Json.as_string json in
  let* argv = string_list "argv" json in
  let* working_directory = required "working_directory" Json.as_string json in
  let* supported = required "supported" Json.as_bool json in
  let environment =
    match Option.bind (Json.member "environment" json) Json.as_object with
    | None -> []
    | Some values ->
        List.filter_map
          (fun (key, value) ->
            Option.map (fun value -> (key, value)) (Json.as_string value))
          values
  in
  Ok { id; image; argv; environment; working_directory; supported }

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "runner-v1" then Error ("unsupported runner schema " ^ schema)
  else
    let* supplied_digest = required "digest" Json.as_string json in
    let* backend_name = required "backend" Json.as_string json in
    let* backend =
      match backend_of_name backend_name with
      | Some value -> Ok value
      | None -> Error ("unknown backend " ^ backend_name)
    in
    let* source_digest = required "source_digest" Json.as_string json in
    let* lock_digest = required "lock_digest" Json.as_string json in
    let* control_names = string_list "controls" json in
    let rec parse_controls accumulator = function
      | [] -> Ok (List.rev accumulator)
      | name :: rest -> (
          match control_of_name name with
          | Some value -> parse_controls (value :: accumulator) rest
          | None -> Error ("unknown control " ^ name))
    in
    let* controls = parse_controls [] control_names in
    let* secret_names = string_list "secret_names" json in
    let* limits_json =
      match Json.member "limits" json with
      | Some value -> Ok value
      | None -> Error "missing limits"
    in
    let* cpu_seconds = required "cpu_seconds" Json.as_int limits_json in
    let* memory_mb = required "memory_mb" Json.as_int limits_json in
    let* processes = required "processes" Json.as_int limits_json in
    let* output_bytes = required "output_bytes" Json.as_int limits_json in
    let limits = { cpu_seconds; memory_mb; processes; output_bytes } in
    let* dependency_jsons = required "dependencies" Json.as_array json in
    let rec parse_many parser accumulator = function
      | [] -> Ok (List.rev accumulator)
      | item :: rest ->
          let* value = parser item in
          parse_many parser (value :: accumulator) rest
    in
    let* dependencies = parse_many parse_dependency [] dependency_jsons in
    let* step_jsons = required "steps" Json.as_array json in
    let* steps = parse_many parse_step [] step_jsons in
    let* plan =
      make_plan ~backend ~source_digest ~lock_digest ~controls ~limits
        ~secret_names ~dependencies ~steps
    in
    if plan.digest <> supplied_digest then Error "runner plan digest mismatch"
    else Ok plan
