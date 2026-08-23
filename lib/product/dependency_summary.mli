type t = {
  complete : bool;
  reasons : string list;
  capabilities : Ir.capability list;
  effects : Ir.observable_effect list;
}

val make :
  complete:bool ->
  reasons:string list ->
  capabilities:Ir.capability list ->
  effects:Ir.observable_effect list ->
  t

val unknown : string -> t
val infer : Frontend_intf.dependency -> path:string -> source:string -> t
val to_json : t -> Json.t
val of_json : Json.t -> (t, string) result
