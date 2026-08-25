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
  | Resource_observed of {
      wall_time_ms : int;
      cpu_time_ms : int;
      peak_memory_bytes : int64;
      processes : int;
      output_bytes : int;
      scratch_bytes : int64;
      scratch_entries : int;
    }
  | Log_recorded of { digest : string }
  | Filesystem_final of { digest : string }
  | Backend_error of string

type event = {
  sequence : int;
  previous_digest : string;
  digest : string;
  body : body;
}

type bindings = {
  scenario_digest : string;
  source_digest : string;
  lock_digest : string;
  runtime_digest : string;
  controls_digest : string;
}

type observed_resources = {
  wall_time_ms : int;
  cpu_time_ms : int;
  peak_memory_bytes : int64;
  processes : int;
  output_bytes : int;
  scratch_bytes : int64;
  scratch_entries : int;
}

type artifact = { path : string; digest : string }
type sidecar = { kind : string; digest : string }

type t = {
  schema : string;
  plan_digest : string;
  bindings : bindings;
  requested_limits : Sandbox_protocol.limits;
  effective_limits : Sandbox_protocol.limits;
  observed_resources : observed_resources;
  redacted_log_digest : string;
  final_filesystem_digest : string;
  artifacts : artifact list;
  forensic_sidecars : sidecar list;
  events : event list;
}

val empty : plan_digest:string -> t
val for_plan : Sandbox_protocol.plan -> t
val append : body -> t -> t
val validate : t -> (unit, string) result
val validate_for_plan : Sandbox_protocol.plan -> t -> (unit, string) result
val observes_effect : Ir.observable_effect -> t -> bool
val observed_effects : t -> Ir.observable_effect list
val to_json : t -> Json.t
val to_canonical_json : t -> string
val parse : string -> (t, string) result
