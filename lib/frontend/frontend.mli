type semantic_shape = {
  workflows : int;
  stages : int;
  jobs : int;
  steps : int;
  calls : int;
  commands : int;
  parameters : int;
  control_edges : int;
  data_edges : int;
  call_edges : int;
}

val detect : path:string -> source:string -> Ir.provider option
val entrypoint : provider:Ir.provider -> path:string -> source:string -> bool

val compile_string :
  provider:Ir.provider ->
  path:string ->
  source:string ->
  unit ->
  (Frontend_intf.compilation, Frontend_intf.problem list) result

val compile_auto :
  path:string ->
  source:string ->
  unit ->
  (Frontend_intf.compilation, Frontend_intf.problem list) result

val semantic_shape : Ir.t -> semantic_shape
