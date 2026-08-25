type kind = Regular | Symlink

type entry = {
  path : string;
  kind : kind;
  executable : bool;
  size : int64;
  digest : string;
  target : string option;
  identity : string option;
}

type source =
  | Regular_source of {
      contents : string;
      executable : bool;
      identity : string option;
    }
  | Symlink_source of { target : string; identity : string option }

type exclusion = { path : string; reason : string }

type budget = {
  max_file_bytes : int;
  max_entries : int;
  max_snapshot_bytes : int64;
}

type t = {
  schema : string;
  entries : entry list;
  exclusions : exclusion list;
  exclusion_policy_digest : string;
  total_size : int64;
  canonical_json : string;
  digest : string;
}

val generated_directories : string list
val default_budget : budget
val is_generated : root:string -> string -> bool

val is_excluded :
  root:string -> trusted_exclusions:string list -> string -> bool

val create_from_sources :
  budget:budget ->
  trusted_exclusions:string list ->
  root:string ->
  files:(string * source) list ->
  (t, string) result

val create : root:string -> files:(string * string) list -> (t, string) result
val to_json : t -> Json.t
val to_canonical_json : t -> string
