type persona = Gate | Audit | Paranoid

type result = {
  properties : Property.t list;
  diagnostics : Diagnostic.t list;
  complete : bool;
  analyzed_nodes : int;
  analyzed_edges : int;
}

val persona_name : persona -> string
val verify : persona:persona -> Ir.t -> result
val verify_program : persona:persona -> Ir.t list -> result
val should_fail : persona -> result -> bool
val to_json : result -> Json.t
