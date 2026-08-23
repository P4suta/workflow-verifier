type status = Verified | Incomplete of string list

type t = {
  schema : string;
  plan_digest : string;
  source_digest : string;
  backend : string;
  controls_digest : string;
  status : status;
  observed_effects : Ir.observable_effect list;
  reconciliation : Property.t option;
  event_count : int;
  evidence_tail : string;
}

val evaluate :
  plan:Sandbox_protocol.plan -> evidence:Evidence.t -> (t, string) result

val evaluate_with_graphs :
  graphs:Ir.t list ->
  plan:Sandbox_protocol.plan ->
  evidence:Evidence.t ->
  (t, string) result

val to_json : t -> Json.t
val to_canonical_json : t -> string
