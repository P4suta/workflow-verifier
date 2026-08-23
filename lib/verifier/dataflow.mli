type solution = { values : (string * Abstract_value.t) list; complete : bool }

val solve : Ir.t -> solution
val value_at : solution -> string -> Abstract_value.t
