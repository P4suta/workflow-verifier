val parse :
  Frontend_intf.source_unit ->
  (Frontend_intf.parsed, Frontend_intf.problem list) result

val expand : Frontend_intf.parsed -> Frontend_intf.expanded

val dependency :
  ?kind:Frontend_intf.dependency_kind ->
  ?locator:Frontend_intf.dependency_locator ->
  Ir.provider ->
  string ->
  Span.t ->
  Frontend_intf.dependency

val scalar : Yaml_cst.node -> string option
val mapping : Yaml_cst.node -> Yaml_cst.mapping_entry list
val sequence_nodes : Yaml_cst.node -> Yaml_cst.node list
val field : string -> Yaml_cst.node -> Yaml_cst.node option
val field_scalar : string -> Yaml_cst.node -> string option
val root : Frontend_intf.resolved -> Yaml_cst.node option
val yaml_problems : Yaml_cst.t -> Frontend_intf.problem list

val command_value :
  Ir.provider ->
  Yaml_cst.node ->
  string ->
  Abstract_value.t * Expression.reference list

val add_control : Ir.node -> Ir.node -> Ir.t -> Ir.t
val add_call : Ir.node -> Ir.node -> Ir.t -> Ir.t

val add_references :
  Ir.provider -> Ir.node -> Expression.reference list -> Ir.t -> Ir.t

val workflow_node : Ir.provider -> string -> Yaml_cst.node -> Ir.node
