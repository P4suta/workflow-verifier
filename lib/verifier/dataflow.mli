type solution = { values : (string * Abstract_value.t) list; complete : bool }

val solve_indexed : Graph_algorithms.indexed -> solution
val solve : Ir.t -> solution
val value_at : solution -> string -> Abstract_value.t
