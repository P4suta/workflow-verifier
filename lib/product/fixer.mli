type proposal = {
  id : string;
  description : string;
  edits : Yaml_cst.edit list;
  safe : bool;
}

val pin_dependency :
  cst:Yaml_cst.t -> reference:string -> revision:string -> proposal option

val reduce_write_all :
  cst:Yaml_cst.t -> unused_capabilities:Ir.capability list -> proposal option

val bind_expression_to_environment :
  cst:Yaml_cst.t ->
  shell:Script_adapter.shell ->
  expression:string ->
  name:string ->
  proposal option

val replace_scalar :
  cst:Yaml_cst.t ->
  scalar:Yaml_cst.scalar ->
  replacement:string ->
  description:string ->
  proposal

val apply : cst:Yaml_cst.t -> proposal -> (string, string) result
val combine : proposal list -> (proposal, string) result
val unified_diff : path:string -> before:string -> after:string -> string
val to_json : proposal -> Json.t
