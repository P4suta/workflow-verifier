type path_change = {
  source : string;
  sink : string;
  path : string list;
  effect_name : string;
}

type change =
  | New_reachable_path of path_change
  | Capability_added of Ir.capability
  | Capability_removed of Ir.capability
  | Dependency_became_mutable of string
  | Property_changed of { property : string; before : string; after : string }

type t = {
  schema : string;
  base_digest : string;
  head_digest : string;
  changes : change list;
}

val compare : Ir.t -> Ir.t -> t
val compare_program : Ir.t list -> Ir.t list -> t
val to_json : t -> Json.t
val to_canonical_json : t -> string
