val effects_of_node : Ir.node -> Ir.observable_effect list
val minimal_for_path : Ir.node list -> Ir.capability list

val declared_grants_indexed :
  Graph_algorithms.indexed -> (Ir.node * Ir.capability) list

val declared_grants : Ir.t -> (Ir.node * Ir.capability) list

type demand = Required | Excessive | Unknown of Unknown.reason list

val grant_demands_indexed :
  Graph_algorithms.indexed -> ((Ir.node * Ir.capability) * demand) list

val grant_demands : Ir.t -> ((Ir.node * Ir.capability) * demand) list

val excessive_grants_indexed :
  Graph_algorithms.indexed -> (Ir.node * Ir.capability) list

val excessive_grants : Ir.t -> (Ir.node * Ir.capability) list
