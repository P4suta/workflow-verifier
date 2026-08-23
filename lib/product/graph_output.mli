type kind = All | Control | Dataflow | Call | Capability

val to_json : kind:kind -> Ir.t -> Json.t
val to_canonical_json : kind:kind -> Ir.t -> string
val to_dot : kind:kind -> Ir.t -> string
