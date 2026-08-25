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

val runner_name : runner_platform -> string
val runner_os : runner_platform -> string
val runner_of_string : string -> runner_platform option

val make :
  provider:Ir.provider ->
  workflow_entrypoint:string ->
  job:string ->
  event:string ->
  inputs:(string * string) list ->
  matrix:(string * Json.t) list ->
  variables:(string * string) list ->
  runner_platform:runner_platform ->
  secret_names:string list ->
  (t, string) result

val parse_assignment : string -> (string * string, string) result
val parse : string -> (t, string) result
val to_json : t -> Json.t
val to_canonical_json : t -> string
