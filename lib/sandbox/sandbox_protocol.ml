type control =
  | Source_read_only
  | Scratch_overlay
  | Network_deny
  | Egress_broker
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

type runtime = {
  kind : string;
  runner_platform : string;
  workload_digest : string;
  rootfs_digest : string option;
  helper_digest : string option;
  boot_digest : string option;
  capability_fingerprint : string option;
}

type status = Complete | Incomplete of string list

type plan = {
  schema : string;
  digest : string;
  backend : backend;
  scenario_digest : string;
  provider_profile : string;
  selected_jobs : string list;
  source_digest : string;
  lock_digest : string;
  runtime : runtime;
  controls : control list;
  limits : limits;
  network_destinations : string list;
  secret_names : string list;
  dependencies : dependency list;
  steps : step list;
  status : status;
}

let portable_limits =
  {
    cpu_seconds = 900;
    memory_mb = 2048;
    processes = 128;
    output_bytes = 16 * 1024 * 1024;
  }

let control_name = function
  | Source_read_only -> "source_read_only"
  | Scratch_overlay -> "scratch_overlay"
  | Network_deny -> "network_deny"
  | Egress_broker -> "egress_broker"
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
  | "egress_broker" -> Some Egress_broker
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
  if Util.starts_with ~prefix:"oci:" value && String.length value > 4 then
    Some (Oci (String.sub value 4 (String.length value - 4)))
  else
    match value with
    | "linux-native" -> Some Linux_native
    | "windows-native" -> Some Windows_native
    | "macos-vm" -> Some Macos_vm
    | _ -> None

let unresolved_digest = "sha256:" ^ String.make 64 '0'

let resolved_digest value =
  Dependency_identity.valid_content_digest value && value <> unresolved_digest

let runtime_for ~backend ~runner_platform ~steps =
  let images =
    steps |> List.map (fun step -> step.image) |> Util.deduplicate_strings
  in
  let workload_digest =
    match images with
    | [ value ] -> value
    | _ -> unresolved_digest
  in
  match backend with
  | Oci _ ->
      {
        kind = "oci-capsule";
        runner_platform;
        workload_digest;
        rootfs_digest = Some workload_digest;
        helper_digest = None;
        boot_digest = None;
        capability_fingerprint = None;
      }
  | Linux_native ->
      {
        kind = "linux-capsule";
        runner_platform;
        workload_digest;
        rootfs_digest = Some workload_digest;
        helper_digest = None;
        boot_digest = None;
        capability_fingerprint = None;
      }
  | Windows_native ->
      {
        kind = "windows-runtime-profile";
        runner_platform;
        workload_digest;
        rootfs_digest = None;
        helper_digest = None;
        boot_digest = None;
        capability_fingerprint = None;
      }
  | Macos_vm ->
      {
        kind = "macos-vm";
        runner_platform;
        workload_digest;
        rootfs_digest = Some workload_digest;
        helper_digest = None;
        boot_digest = None;
        capability_fingerprint = None;
      }

let option_string = function
  | None -> Json.Null
  | Some value -> Json.String value

let dependency_json dependency =
  Json.Object
    [
      ("available", Json.Bool dependency.available);
      ("digest", option_string dependency.digest);
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

let runtime_json runtime =
  Json.Object
    [
      ("boot_digest", option_string runtime.boot_digest);
      ("capability_fingerprint", option_string runtime.capability_fingerprint);
      ("helper_digest", option_string runtime.helper_digest);
      ("kind", Json.String runtime.kind);
      ("rootfs_digest", option_string runtime.rootfs_digest);
      ("runner_platform", Json.String runtime.runner_platform);
      ("workload_digest", Json.String runtime.workload_digest);
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
          ("cpu_cores", Json.Int 1);
          ("memory_bytes", Json.Int (plan.limits.memory_mb * 1024 * 1024));
          ("output_bytes", Json.Int plan.limits.output_bytes);
          ("processes", Json.Int plan.limits.processes);
          ("scratch_bytes", Json.Int64 4_294_967_296L);
          ("scratch_entries", Json.Int 100_000);
          ("wall_time_seconds", Json.Int plan.limits.cpu_seconds);
        ] );
    ("lock_digest", Json.String plan.lock_digest);
    ( "network",
      Json.Object
        [
          ( "destinations",
            Json.Array
              (List.map
                 (fun value -> Json.String value)
                 plan.network_destinations) );
          ( "mode",
            Json.String
              (if List.mem Network_deny plan.controls then "deny"
               else "allowlist") );
        ] );
    ("provider_profile", Json.String plan.provider_profile);
    ("runtime", runtime_json plan.runtime);
    ("scenario_digest", Json.String plan.scenario_digest);
    ("schema", Json.String plan.schema);
    ( "secret_names",
      Json.Array (List.map (fun value -> Json.String value) plan.secret_names)
    );
    ( "selected_jobs",
      Json.Array (List.map (fun value -> Json.String value) plan.selected_jobs)
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

let valid_https_destination value =
  Util.starts_with ~prefix:"https://" value
  && (not
        (String.exists
           (function
             | '@' | '\\' | '?' | '#' | '\000' | '\r' | '\n' -> true
             | _ -> false)
           value))
  && not (Util.contains ~needle:".." value)

let runtime_compatible backend runner =
  match backend with
  | Oci _ | Linux_native -> Util.starts_with ~prefix:"linux-" runner
  | Windows_native -> Util.starts_with ~prefix:"windows-" runner
  | Macos_vm -> Util.starts_with ~prefix:"macos-" runner

let expected_runtime_kind = function
  | Oci _ -> "oci-capsule"
  | Linux_native -> "linux-capsule"
  | Windows_native -> "windows-runtime-profile"
  | Macos_vm -> "macos-vm"

let optional_digest_valid = function
  | None -> true
  | Some value -> Dependency_identity.valid_content_digest value

let validate_runtime ~backend ~steps runtime =
  let expected_workload =
    match
      steps |> List.map (fun step -> step.image) |> Util.deduplicate_strings
    with
    | [ value ] -> value
    | _ -> unresolved_digest
  in
  if runtime.kind <> expected_runtime_kind backend then
    Error "runtime kind contradicts the selected backend"
  else if not (runtime_compatible backend runtime.runner_platform) then
    Error "runtime platform contradicts the selected backend"
  else if runtime.workload_digest <> expected_workload then
    Error "runtime workload digest contradicts the selected steps"
  else if
    not
      (Dependency_identity.valid_content_digest runtime.workload_digest
      && optional_digest_valid runtime.rootfs_digest
      && optional_digest_valid runtime.helper_digest
      && optional_digest_valid runtime.boot_digest
      && optional_digest_valid runtime.capability_fingerprint)
  then Error "runtime identities must be SHA-256 content digests"
  else
    match backend with
    | Oci _ | Linux_native ->
        if runtime.rootfs_digest <> Some runtime.workload_digest then
          Error "capsule runtime rootfs must equal the workload digest"
        else Ok ()
    | Windows_native ->
        if runtime.rootfs_digest <> None || runtime.boot_digest <> None then
          Error "Windows runtime profiles cannot bind rootfs or boot assets"
        else Ok ()
    | Macos_vm ->
        if runtime.rootfs_digest <> Some runtime.workload_digest then
          Error "macOS VM rootfs must equal the workload digest"
        else Ok ()

let validate_plan_arguments ~backend ~scenario_digest ~provider_profile
    ~selected_jobs ~runner_platform ~source_digest ~lock_digest ~controls
    ~limits ~network_destinations ~secret_names ~dependencies ~steps =
  if
    match backend with
    | Oci engine -> not (valid_engine engine)
    | _ -> false
  then Error "OCI backend name is invalid"
  else if limits <> portable_limits then
    Error
      "runner-v2 portable limits must be exactly 900s/1 core/2 GiB/128/16 MiB"
  else if not (runtime_compatible backend runner_platform) then
    Error "runner platform contradicts the selected backend"
  else if
    not
      (List.for_all Dependency_identity.valid_content_digest
         [ scenario_digest; source_digest; lock_digest ])
  then Error "runner-v2 scenario/source/lock digests must be SHA-256"
  else if String.trim provider_profile = "" then
    Error "provider profile is required"
  else if
    selected_jobs = []
    || List.exists (fun value -> String.trim value = "") selected_jobs
  then Error "runner-v2 requires at least one selected job"
  else if
    List.length selected_jobs
    <> List.length (Util.deduplicate_strings selected_jobs)
  then Error "selected jobs must be unique"
  else if List.exists (fun name -> not (valid_identifier name)) secret_names
  then Error "secret names must be portable identifiers"
  else if
    List.exists
      (fun value -> not (valid_https_destination value))
      network_destinations
  then
    Error "network destinations must be normalized HTTPS origin/path policies"
  else if List.mem Network_deny controls && network_destinations <> [] then
    Error "network-deny plans cannot contain destination grants"
  else if (not (List.mem Network_deny controls)) && network_destinations = []
  then Error "network-enabled plans require at least one destination policy"
  else if
    List.length controls
    <> List.length (Util.deduplicate_compare Stdlib.compare controls)
  then Error "controls must be unique"
  else if
    List.length secret_names
    <> List.length (Util.deduplicate_strings secret_names)
  then Error "secret names must be unique"
  else if
    List.length network_destinations
    <> List.length (Util.deduplicate_strings network_destinations)
  then Error "network destinations must be unique"
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

let core_make ~backend ~scenario_digest ~provider_profile ~selected_jobs
    ~runner_platform ~source_digest ~lock_digest ~controls ~limits
    ~network_destinations ~secret_names ~dependencies ~steps ~incomplete_reasons
    =
  let open Util in
  let* () =
    validate_plan_arguments ~backend ~scenario_digest ~provider_profile
      ~selected_jobs ~runner_platform ~source_digest ~lock_digest ~controls
      ~limits ~network_destinations ~secret_names ~dependencies ~steps
  in
  let secret_names = Util.deduplicate_strings secret_names
  and selected_jobs = Util.deduplicate_strings selected_jobs
  and network_destinations = Util.deduplicate_strings network_destinations
  and dependencies =
    List.sort
      (fun left right -> String.compare left.reference right.reference)
      dependencies
  and controls = Util.deduplicate_compare Stdlib.compare controls in
  let steps =
    List.map
      (fun step ->
        {
          step with
          image =
            (if Dependency_identity.valid_content_digest step.image then
               step.image
             else unresolved_digest);
          environment =
            redact_environment secret_names step.environment
            |> List.sort (fun (left, _) (right, _) -> String.compare left right);
        })
      steps
  in
  let dependency_reasons =
    dependencies
    |> List.filter_map (fun dependency ->
        if (not dependency.available) || dependency.digest = None then
          Some ("Incomplete.Unresolved_dependency: " ^ dependency.reference)
        else None)
  and step_reasons =
    steps
    |> List.concat_map (fun step ->
        (if step.supported then []
         else [ "Incomplete.Unsupported_step: " ^ step.id ])
        @
        if resolved_digest step.image then []
        else [ "Incomplete.Unresolved_capsule: " ^ step.id ])
  in
  let runtime = runtime_for ~backend ~runner_platform ~steps in
  let runtime_reasons =
    (if resolved_digest runtime.workload_digest then []
     else [ "Incomplete.Unresolved_runtime_workload" ])
    @
    match backend with
    | Oci _ -> []
    | Linux_native | Windows_native ->
        if Option.fold ~none:false ~some:resolved_digest runtime.helper_digest
        then []
        else [ "Incomplete.Unresolved_runtime_helper" ]
    | Macos_vm ->
        (if Option.fold ~none:false ~some:resolved_digest runtime.helper_digest
         then []
         else [ "Incomplete.Unresolved_runtime_helper" ])
        @
        if Option.fold ~none:false ~some:resolved_digest runtime.boot_digest
        then []
        else [ "Incomplete.Unresolved_macos_boot_bundle" ]
  in
  let reasons =
    incomplete_reasons @ dependency_reasons @ step_reasons @ runtime_reasons
    |> Util.deduplicate_strings
  in
  let status = if reasons = [] then Complete else Incomplete reasons in
  let provisional =
    {
      schema = "runner-v2";
      digest = "";
      backend;
      scenario_digest;
      provider_profile;
      selected_jobs;
      source_digest;
      lock_digest;
      runtime;
      controls;
      limits;
      network_destinations;
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

let make_scenario_plan = core_make

let make_plan ~backend ~source_digest ~lock_digest ~controls ~limits
    ~secret_names ~dependencies ~steps =
  let runner_platform =
    match backend with
    | Oci _ | Linux_native -> "linux-x86_64"
    | Windows_native -> "windows-x86_64"
    | Macos_vm -> "macos-arm64"
  in
  core_make ~backend
    ~scenario_digest:("sha256:" ^ Sha256.digest_string "scenario-v1:missing")
    ~provider_profile:"unspecified-semantic-v1" ~selected_jobs:[ "unspecified" ]
    ~runner_platform ~source_digest ~lock_digest ~controls ~limits
    ~network_destinations:[] ~secret_names ~dependencies ~steps
    ~incomplete_reasons:[ "Incomplete.Missing_scenario" ]

let to_json plan =
  Json.Object (("digest", Json.String plan.digest) :: unsigned_fields plan)

let to_canonical_json plan = Json.to_string (to_json plan) ^ "\n"

let required name converter json =
  match Option.bind (Json.member name json) converter with
  | Some value -> Ok value
  | None -> Error ("runner-v2 needs field " ^ name)

let string_list name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error (name ^ " must contain strings")
  in
  loop [] values

let optional_string name json =
  match Json.member name json with
  | Some Json.Null -> Ok None
  | Some (Json.String value) -> Ok (Some value)
  | Some _ -> Error (name ^ " must be a string or null")
  | None -> Error ("runner-v2 needs field " ^ name)

let parse_dependency json =
  let open Util in
  let* _ =
    Json.exact_object ~context:"runner-v2 dependency"
      ~allowed:[ "available"; "digest"; "reference" ]
      json
  in
  let* reference = required "reference" Json.as_string json in
  let* available = required "available" Json.as_bool json in
  let* digest = optional_string "digest" json in
  Ok { reference; digest; available }

let parse_step json =
  let open Util in
  let* _ =
    Json.exact_object ~context:"runner-v2 step"
      ~allowed:
        [
          "argv"; "environment"; "id"; "image"; "supported"; "working_directory";
        ]
      json
  in
  let* id = required "id" Json.as_string json in
  let* image = required "image" Json.as_string json in
  let* argv = string_list "argv" json in
  let* working_directory = required "working_directory" Json.as_string json in
  let* supported = required "supported" Json.as_bool json in
  let* environment_fields = required "environment" Json.as_object json in
  let rec parse_environment accumulator = function
    | [] -> Ok (List.rev accumulator)
    | (key, Json.String value) :: rest ->
        parse_environment ((key, value) :: accumulator) rest
    | (key, _) :: _ -> Error ("environment." ^ key ^ " must be a string")
  in
  let* environment = parse_environment [] environment_fields in
  Ok { id; image; argv; environment; working_directory; supported }

let parse_many parser values =
  let open Util in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | value :: rest ->
        let* value = parser value in
        loop (value :: accumulator) rest
  in
  loop [] values

let parse_status json =
  let open Util in
  let* state = required "state" Json.as_string json in
  match state with
  | "complete" ->
      let* _ =
        Json.exact_object ~context:"runner-v2 status" ~allowed:[ "state" ] json
      in
      Ok Complete
  | "incomplete" ->
      let* _ =
        Json.exact_object ~context:"runner-v2 status"
          ~allowed:[ "reasons"; "state" ] json
      in
      let* reasons = string_list "reasons" json in
      if reasons = [] then Error "incomplete status needs reasons"
      else Ok (Incomplete reasons)
  | value -> Error ("unknown runner-v2 status " ^ value)

let parse_runtime json =
  let open Util in
  let* _ =
    Json.exact_object ~context:"runner-v2 runtime"
      ~allowed:
        [
          "boot_digest";
          "capability_fingerprint";
          "helper_digest";
          "kind";
          "rootfs_digest";
          "runner_platform";
          "workload_digest";
        ]
      json
  in
  let* kind = required "kind" Json.as_string json in
  let* runner_platform = required "runner_platform" Json.as_string json in
  let* workload_digest = required "workload_digest" Json.as_string json in
  let* rootfs_digest = optional_string "rootfs_digest" json in
  let* helper_digest = optional_string "helper_digest" json in
  let* boot_digest = optional_string "boot_digest" json in
  let* capability_fingerprint = optional_string "capability_fingerprint" json in
  Ok
    {
      kind;
      runner_platform;
      workload_digest;
      rootfs_digest;
      helper_digest;
      boot_digest;
      capability_fingerprint;
    }

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* _ =
    Json.exact_object ~context:"runner-v2"
      ~allowed:
        [
          "backend";
          "controls";
          "dependencies";
          "digest";
          "limits";
          "lock_digest";
          "network";
          "provider_profile";
          "runtime";
          "scenario_digest";
          "schema";
          "secret_names";
          "selected_jobs";
          "source_digest";
          "status";
          "steps";
        ]
      json
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "runner-v2" then Error ("unsupported runner schema " ^ schema)
  else
    let* supplied_digest = required "digest" Json.as_string json in
    let* backend_value = required "backend" Json.as_string json in
    let* backend =
      match backend_of_name backend_value with
      | Some value -> Ok value
      | None -> Error ("unknown backend " ^ backend_value)
    in
    let* scenario_digest = required "scenario_digest" Json.as_string json in
    let* provider_profile = required "provider_profile" Json.as_string json in
    let* selected_jobs = string_list "selected_jobs" json in
    let* source_digest = required "source_digest" Json.as_string json in
    let* lock_digest = required "lock_digest" Json.as_string json in
    let* control_names = string_list "controls" json in
    let* controls =
      parse_many
        (function
          | Json.String name -> (
              match control_of_name name with
              | Some value -> Ok value
              | None -> Error ("unknown control " ^ name))
          | _ -> Error "control must be a string")
        (List.map (fun name -> Json.String name) control_names)
    in
    let* secret_names = string_list "secret_names" json in
    let* limits_json =
      match Json.member "limits" json with
      | Some value -> Ok value
      | None -> Error "runner-v2 needs limits"
    in
    let* _ =
      Json.exact_object ~context:"runner-v2 limits"
        ~allowed:
          [
            "cpu_cores";
            "memory_bytes";
            "output_bytes";
            "processes";
            "scratch_bytes";
            "scratch_entries";
            "wall_time_seconds";
          ]
        limits_json
    in
    let* cpu_seconds = required "wall_time_seconds" Json.as_int limits_json in
    let* cpu_cores = required "cpu_cores" Json.as_int limits_json in
    let* memory_bytes = required "memory_bytes" Json.as_int limits_json in
    let* processes = required "processes" Json.as_int limits_json in
    let* output_bytes = required "output_bytes" Json.as_int limits_json in
    let* scratch_bytes =
      match Json.member "scratch_bytes" limits_json with
      | Some (Json.Int value) -> Ok (Int64.of_int value)
      | Some (Json.Int64 value) -> Ok value
      | _ -> Error "scratch_bytes must be an integer"
    in
    let* scratch_entries = required "scratch_entries" Json.as_int limits_json in
    if
      cpu_cores <> 1
      || memory_bytes <> 2_147_483_648
      || scratch_bytes <> 4_294_967_296L
      || scratch_entries <> 100_000
    then Error "runner-v2 portable limit constants do not match"
    else
      let limits =
        {
          cpu_seconds;
          memory_mb = memory_bytes / 1024 / 1024;
          processes;
          output_bytes;
        }
      in
      let* network_json =
        match Json.member "network" json with
        | Some value -> Ok value
        | None -> Error "runner-v2 needs network"
      in
      let* _ =
        Json.exact_object ~context:"runner-v2 network"
          ~allowed:[ "destinations"; "mode" ] network_json
      in
      let* mode = required "mode" Json.as_string network_json in
      let* network_destinations = string_list "destinations" network_json in
      let expected_mode =
        if List.mem Network_deny controls then "deny" else "allowlist"
      in
      if mode <> expected_mode then
        Error "runner-v2 network mode contradicts controls"
      else
        let* runtime_json =
          match Json.member "runtime" json with
          | Some value -> Ok value
          | None -> Error "runner-v2 needs runtime"
        in
        let* runtime = parse_runtime runtime_json in
        let* dependency_jsons = required "dependencies" Json.as_array json in
        let* dependencies = parse_many parse_dependency dependency_jsons in
        let* step_jsons = required "steps" Json.as_array json in
        let* steps = parse_many parse_step step_jsons in
        let* status_json =
          match Json.member "status" json with
          | Some value -> Ok value
          | None -> Error "runner-v2 needs status"
        in
        let* status = parse_status status_json in
        let provisional =
          {
            schema;
            digest = "";
            backend;
            scenario_digest;
            provider_profile;
            selected_jobs;
            source_digest;
            lock_digest;
            runtime;
            controls;
            limits;
            network_destinations;
            secret_names;
            dependencies;
            steps;
            status;
          }
        in
        let expected =
          "sha256:"
          ^ Sha256.digest_string (Json.to_string (unsigned_json provisional))
        in
        if supplied_digest <> expected then Error "runner plan digest mismatch"
        else
          let* () =
            validate_plan_arguments ~backend ~scenario_digest ~provider_profile
              ~selected_jobs ~runner_platform:runtime.runner_platform
              ~source_digest ~lock_digest ~controls ~limits
              ~network_destinations ~secret_names ~dependencies ~steps
          in
          let* () = validate_runtime ~backend ~steps runtime in
          let required_reasons =
            (dependencies
            |> List.filter_map (fun dependency ->
                if (not dependency.available) || dependency.digest = None then
                  Some
                    ("Incomplete.Unresolved_dependency: " ^ dependency.reference)
                else None))
            @ (steps
              |> List.concat_map (fun step ->
                  (if step.supported then []
                   else [ "Incomplete.Unsupported_step: " ^ step.id ])
                  @
                  if resolved_digest step.image then []
                  else [ "Incomplete.Unresolved_capsule: " ^ step.id ]))
            @
            if resolved_digest runtime.workload_digest then []
            else [ "Incomplete.Unresolved_runtime_workload" ]
          in
          let* () =
            match status with
            | Complete when required_reasons <> [] ->
                Error "complete plan contains unresolved or unsupported work"
            | Incomplete declared
              when not
                     (List.for_all
                        (fun reason -> List.mem reason declared)
                        required_reasons) ->
                Error "incomplete status omits a required reason"
            | Complete | Incomplete _ -> Ok ()
          in
          Ok { provisional with digest = supplied_digest }
