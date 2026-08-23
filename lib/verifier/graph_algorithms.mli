val shortest_path :
  ?edge_kinds:Ir.edge_kind list ->
  ?avoid:string list ->
  Ir.t ->
  string ->
  string ->
  Ir.node list option

val dominates : Ir.t -> dominator:string -> node:string -> bool
val control_cycles : Ir.t -> string list list
val cycles : ?edge_kinds:Ir.edge_kind list -> Ir.t -> string list list
