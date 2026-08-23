val effects_of_node : Ir.node -> Ir.observable_effect list
val minimal_for_path : Ir.node list -> Ir.capability list
val declared_grants : Ir.t -> (Ir.node * Ir.capability) list
val excessive_grants : Ir.t -> (Ir.node * Ir.capability) list
