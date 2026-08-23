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
  | Backend_error of string

type event = {
  sequence : int;
  previous_digest : string;
  digest : string;
  body : body;
}

type t = { schema : string; plan_digest : string; events : event list }

val empty : plan_digest:string -> t
val append : body -> t -> t
val validate : t -> (unit, string) result
val observes_effect : Ir.observable_effect -> t -> bool
val observed_effects : t -> Ir.observable_effect list
val to_json : t -> Json.t
val to_canonical_json : t -> string
val parse : string -> (t, string) result
