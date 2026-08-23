type trust = Trusted | Untrusted | Mixed | Unknown

type predicate =
  | Provider of Ir.provider
  | Node_kind of Ir.node_kind
  | Path_prefix of string
  | Trust of trust
  | Effect of Ir.observable_effect
  | Capability of Ir.capability
  | Dependency_mutability of Frontend_intf.mutability
  | Dominated_by_gate of bool

type selector =
  | All of predicate list
  | Any of predicate list
  | None_of of predicate list

type rule_kind = Forbid | Require | Limit of int | Forbid_path

type rule = {
  id : string;
  kind : rule_kind;
  selector : selector;
  message : string;
  severity : Diagnostic.severity;
}

val evaluate : rule list -> Ir.t -> Diagnostic.t list
val predicate_of_assignment : string -> string -> (predicate, string) result
val rule_to_json : rule -> Json.t
