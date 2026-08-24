type indexed

val index : Ir.t -> indexed
val graph : indexed -> Ir.t
val nodes : indexed -> Ir.node list
val feasible_edges : indexed -> Ir.edge list
val find_node : indexed -> string -> Ir.node option

val edges_from :
  ?edge_kinds:Ir.edge_kind list -> indexed -> string -> Ir.edge list

val edges_to :
  ?edge_kinds:Ir.edge_kind list -> indexed -> string -> Ir.edge list

val has_incident_edge :
  ?edge_kinds:Ir.edge_kind list -> indexed -> string -> bool

val shortest_path_indexed :
  ?edge_kinds:Ir.edge_kind list ->
  ?avoid:string list ->
  indexed ->
  string ->
  string ->
  Ir.node list option

val shortest_path :
  ?edge_kinds:Ir.edge_kind list ->
  ?avoid:string list ->
  Ir.t ->
  string ->
  string ->
  Ir.node list option

val reachable_from_indexed :
  ?edge_kinds:Ir.edge_kind list ->
  ?avoid:string list ->
  indexed ->
  string ->
  Ir.node list

val reachable_from :
  ?edge_kinds:Ir.edge_kind list ->
  ?avoid:string list ->
  Ir.t ->
  string ->
  Ir.node list

val dominates_indexed : indexed -> dominator:string -> node:string -> bool
val dominates : Ir.t -> dominator:string -> node:string -> bool

val cycles_indexed :
  ?edge_kinds:Ir.edge_kind list -> indexed -> string list list

val cycles : ?edge_kinds:Ir.edge_kind list -> Ir.t -> string list list
val control_cycles_indexed : indexed -> string list list
val control_cycles : Ir.t -> string list list
