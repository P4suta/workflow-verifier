type input = { path : string; digest : string }
type gate_result = Pass | Finding | Incomplete

type provenance = {
  binary_digest : string;
  source_commit : string option;
  config_origin : string;
  config_trust : string;
  config_digest : string;
  lock_digest : string;
  source_manifest_digest : string;
  provider_profiles : string list;
  completeness_reasons : string list;
  gate_result : gate_result;
  exit_code : int;
}

type t = {
  schema : string;
  tool_version : string;
  persona : Verifier.persona;
  inputs : input list;
  graphs : Ir.t list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  provenance : provenance;
  digest : string;
}

val make :
  persona:Verifier.persona ->
  inputs:(string * string) list ->
  graphs:Ir.t list ->
  verifications:Verifier.result list ->
  policy_diagnostics:Diagnostic.t list ->
  t

val make_v2 :
  persona:Verifier.persona ->
  inputs:(string * string) list ->
  graphs:Ir.t list ->
  verifications:Verifier.result list ->
  policy_diagnostics:Diagnostic.t list ->
  binary_digest:string ->
  source_commit:string option ->
  config:Config.t ->
  lock_digest:string ->
  source_manifest_digest:string ->
  provider_profiles:string list ->
  completeness_reasons:string list ->
  gate_result:gate_result ->
  exit_code:int ->
  t

val gate_result_name : gate_result -> string
val diagnostics : t -> Diagnostic.t list
val to_json : t -> Json.t
val to_canonical_json : t -> string
