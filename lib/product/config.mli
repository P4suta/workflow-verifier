type trust = Built_in | Trusted_policy | Repository
type provenance = { origin : string; trust : trust; digest : string }

type suppression = {
  rule : string;
  path : string;
  reason : string;
  owner : string;
  expiry : string;
}

type resolver_origin = { origin : string; path_prefixes : string list }

type resolver = {
  require_immutable : bool;
  allowed_origins : resolver_origin list;
  allowed_sources : string list;
}

type analysis_budget = {
  max_file_bytes : int;
  max_entries : int;
  max_snapshot_bytes : int64;
  max_yaml_depth : int;
  max_yaml_aliases : int;
  max_expansion_depth : int;
  max_graph_nodes : int;
  max_bdd_nodes : int;
  max_resolver_bytes : int;
  max_report_bytes : int;
}

type sandbox = {
  backend : string;
  image : string;
  network : string;
  cpu_seconds : int;
  cpu_cores : int;
  memory_mb : int;
  processes : int;
  output_bytes : int;
  scratch_bytes : int64;
  scratch_entries : int;
}

type allowlist_entry = { kind : string; value : string; reason : string }

type t = {
  version : int;
  persona : Verifier.persona;
  frontends : Ir.provider list;
  offline : bool;
  source_exclusions : string list;
  resolver : resolver;
  analysis : analysis_budget;
  sandbox : sandbox;
  allowlist : allowlist_entry list;
  rules : Policy.rule list;
  suppressions : suppression list;
  provenance : provenance;
}

val default : t

val parse :
  ?origin:string ->
  ?trust:trust ->
  ?today:string ->
  string ->
  (t, string list) result

val trust_name : trust -> string
val suppressed : t -> Diagnostic.t -> bool
val to_json : t -> Json.t
