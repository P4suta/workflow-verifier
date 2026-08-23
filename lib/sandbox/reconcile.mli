val property :
  static:Property.state ->
  possible_effect:Ir.observable_effect ->
  evidence:Evidence.t ->
  Property.state

val envelope : graphs:Ir.t list -> evidence:Evidence.t -> Property.t
