type suppression = { rule : string; path : string option; reason : string }
type resolver = { require_immutable : bool; allowed_sources : string list }

type sandbox = {
  backend : string;
  image : string;
  network : string;
  cpu_seconds : int;
  memory_mb : int;
  processes : int;
  output_bytes : int;
}

type allowlist_entry = { kind : string; value : string; reason : string }

type t = {
  version : int;
  persona : Verifier.persona;
  frontends : Ir.provider list;
  offline : bool;
  resolver : resolver;
  sandbox : sandbox;
  allowlist : allowlist_entry list;
  rules : Policy.rule list;
  suppressions : suppression list;
}

val default : t
val parse : string -> (t, string list) result
val suppressed : t -> Diagnostic.t -> bool
val to_json : t -> Json.t
