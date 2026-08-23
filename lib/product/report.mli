type input = { path : string; digest : string }

type t = {
  schema : string;
  tool_version : string;
  persona : Verifier.persona;
  inputs : input list;
  graphs : Ir.t list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  digest : string;
}

val make :
  persona:Verifier.persona ->
  inputs:(string * string) list ->
  graphs:Ir.t list ->
  verifications:Verifier.result list ->
  policy_diagnostics:Diagnostic.t list ->
  t

val diagnostics : t -> Diagnostic.t list
val to_json : t -> Json.t
val to_canonical_json : t -> string
