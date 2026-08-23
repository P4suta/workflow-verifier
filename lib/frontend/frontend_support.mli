val scalar_strings : Yaml_cst.node -> string list
val field_strings : string -> Yaml_cst.node -> string list
val mapping_keys : Yaml_cst.node -> string list
val condition : Ir.provider -> string -> Condition.t

val add_gate :
  provider:Ir.provider ->
  owner:Ir.node ->
  name:string ->
  phase:Ir.phase ->
  expression_node:Yaml_cst.node ->
  Ir.t ->
  Ir.t * Ir.node

val add_resource :
  provider:Ir.provider ->
  owner:Ir.node ->
  name:string ->
  phase:Ir.phase ->
  span:Span.t ->
  ?attributes:(string * Abstract_value.t) list ->
  ?capabilities:Ir.capability list ->
  ?effects:Ir.observable_effect list ->
  ?edge_kind:Ir.edge_kind ->
  ?resource_to_owner:bool ->
  Ir.t ->
  Ir.t * Ir.node

val link_dependencies :
  unknown_code:string ->
  cycle_code:string ->
  label:string ->
  nodes:Ir.node list ->
  dependencies:(string * string list * Span.t) list ->
  Ir.t ->
  Ir.t * Frontend_intf.problem list

val link_sequence : Ir.node list -> Ir.t -> Ir.t
