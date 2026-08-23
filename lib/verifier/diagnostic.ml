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

let severity_name = function
  | Critical -> "critical"
  | Error -> "error"
  | Warning -> "warning"
  | Note -> "note"

let confidence_name = function
  | High -> "high"
  | Medium -> "medium"
  | Low -> "low"

let make ~rule_id ~severity ~confidence ~message ~span ?(trace = [])
    ?(capabilities = []) ?(evidence = []) ?fix () =
  let id =
    "diag_"
    ^ String.sub
        (Sha256.digest_string
           (String.concat "\000"
              [
                rule_id;
                Util.normalize_slashes span.Span.file;
                string_of_int span.start.byte;
                message;
              ]))
        0 20
  in
  {
    id;
    rule_id;
    severity;
    confidence;
    message;
    span;
    trace;
    capabilities = Util.deduplicate_compare Stdlib.compare capabilities;
    evidence = Util.deduplicate_strings evidence;
    fix;
  }

let compare left right =
  match Span.compare left.span right.span with
  | 0 -> (
      match String.compare left.rule_id right.rule_id with
      | 0 -> String.compare left.id right.id
      | comparison -> comparison)
  | comparison -> comparison

let trace_json hop =
  Json.Object
    [
      ("label", Json.String hop.label);
      ("node_id", Json.String hop.node_id);
      ("span", Span.to_json hop.span);
    ]

let fix_json fix =
  Json.Object
    [
      ("description", Json.String fix.description);
      ("kind", Json.String fix.kind);
      ( "replacement",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          fix.replacement );
      ("span", Option.fold ~none:Json.Null ~some:Span.to_json fix.span);
    ]

let to_json diagnostic =
  Json.Object
    [
      ( "capabilities",
        Json.Array
          (List.map
             (fun capability -> Json.String (Ir.capability_name capability))
             diagnostic.capabilities) );
      ("confidence", Json.String (confidence_name diagnostic.confidence));
      ( "evidence",
        Json.Array
          (List.map (fun value -> Json.String value) diagnostic.evidence) );
      ("fix", Option.fold ~none:Json.Null ~some:fix_json diagnostic.fix);
      ("id", Json.String diagnostic.id);
      ("message", Json.String diagnostic.message);
      ("rule_id", Json.String diagnostic.rule_id);
      ("severity", Json.String (severity_name diagnostic.severity));
      ("span", Span.to_json diagnostic.span);
      ("trace", Json.Array (List.map trace_json diagnostic.trace));
    ]
