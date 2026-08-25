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

val portable_limits : limits
val control_name : control -> string
val control_of_name : string -> control option
val controls_digest : control list -> string
val backend_name : backend -> string

val runtime_for :
  backend:backend -> runner_platform:string -> steps:step list -> runtime

val make_plan :
  backend:backend ->
  source_digest:string ->
  lock_digest:string ->
  controls:control list ->
  limits:limits ->
  secret_names:string list ->
  dependencies:dependency list ->
  steps:step list ->
  (plan, string) result

val make_scenario_plan :
  backend:backend ->
  scenario_digest:string ->
  provider_profile:string ->
  selected_jobs:string list ->
  runner_platform:string ->
  source_digest:string ->
  lock_digest:string ->
  controls:control list ->
  limits:limits ->
  network_destinations:string list ->
  secret_names:string list ->
  dependencies:dependency list ->
  steps:step list ->
  incomplete_reasons:string list ->
  (plan, string) result

val to_json : plan -> Json.t
val to_canonical_json : plan -> string
val parse : string -> (plan, string) result
