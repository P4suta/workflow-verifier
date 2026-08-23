type severity = Critical | Error | Warning | Note
type confidence = High | Medium | Low
type trace_hop = { node_id : string; label : string; span : Span.t }

type fix = {
  kind : string;
  description : string;
  replacement : string option;
  span : Span.t option;
}

type t = {
  id : string;
  rule_id : string;
  severity : severity;
  confidence : confidence;
  message : string;
  span : Span.t;
  trace : trace_hop list;
  capabilities : Ir.capability list;
  evidence : string list;
  fix : fix option;
}

val make :
  rule_id:string ->
  severity:severity ->
  confidence:confidence ->
  message:string ->
  span:Span.t ->
  ?trace:trace_hop list ->
  ?capabilities:Ir.capability list ->
  ?evidence:string list ->
  ?fix:fix ->
  unit ->
  t

val severity_name : severity -> string
val confidence_name : confidence -> string
val compare : t -> t -> int
val to_json : t -> Json.t
