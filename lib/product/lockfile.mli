type entry = {
  provider : Ir.provider;
  reference : string;
  revision : string;
  digest : string;
  source : string;
  summary : Dependency_summary.t option;
}

type t = { schema : string; entries : entry list; integrity : string }

val make : entry list -> t
val create : entry list -> (t, string) result
val validate_entry : entry -> (unit, string) result
val find : t -> Ir.provider -> string -> entry option
val to_json : t -> Json.t
val to_canonical_json : t -> string
val parse : string -> (t, string) result
