type expectation = { schema : string; expected_rules : string list }

type result = {
  fixture : string;
  expected_rules : string list;
  actual_rules : string list;
  missing_rules : string list;
  unexpected_rules : string list;
  passed : bool;
}

val parse : string -> (expectation, string) Stdlib.result
val evaluate : fixture:string -> expectation -> Diagnostic.t list -> result
val to_json : result -> Json.t
