type expectation = { schema : string; expected_rules : string list }

type result = {
  fixture : string;
  expected_rules : string list;
  actual_rules : string list;
  missing_rules : string list;
  unexpected_rules : string list;
  passed : bool;
}

let parse source =
  let open Util in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error (Printf.sprintf "JSON byte %d: %s" error.offset error.message)
  in
  let* schema =
    match Option.bind (Json.member "schema" json) Json.as_string with
    | Some value -> Ok value
    | None -> Error "policy fixture needs schema"
  in
  if schema <> "policy-fixture-v1" then
    Error ("unsupported policy fixture schema " ^ schema)
  else
    let* values =
      match Option.bind (Json.member "expected_rules" json) Json.as_array with
      | Some values -> Ok values
      | None -> Error "policy fixture expected_rules must be an array"
    in
    let rec strings accumulator = function
      | [] -> Ok (List.rev accumulator)
      | Json.String value :: rest when String.trim value <> "" ->
          strings (value :: accumulator) rest
      | _ -> Error "policy fixture rule IDs must be non-empty strings"
    in
    let* expected_rules = strings [] values in
    if
      List.length expected_rules
      <> List.length (Util.deduplicate_strings expected_rules)
    then Error "policy fixture rule IDs must be unique"
    else Ok { schema; expected_rules = List.sort String.compare expected_rules }

let evaluate ~fixture (expectation : expectation) diagnostics =
  let actual_rules =
    diagnostics
    |> List.map (fun diagnostic -> diagnostic.Diagnostic.rule_id)
    |> Util.deduplicate_strings
  in
  let missing_rules =
    List.filter
      (fun expected -> not (List.mem expected actual_rules))
      expectation.expected_rules
  and unexpected_rules =
    List.filter
      (fun actual -> not (List.mem actual expectation.expected_rules))
      actual_rules
  in
  {
    fixture = Util.normalize_slashes fixture;
    expected_rules = expectation.expected_rules;
    actual_rules;
    missing_rules;
    unexpected_rules;
    passed = missing_rules = [] && unexpected_rules = [];
  }

let strings values =
  Json.Array (List.map (fun value -> Json.String value) values)

let to_json result =
  Json.Object
    [
      ("actual_rules", strings result.actual_rules);
      ("expected_rules", strings result.expected_rules);
      ("fixture", Json.String result.fixture);
      ("missing_rules", strings result.missing_rules);
      ("passed", Json.Bool result.passed);
      ("unexpected_rules", strings result.unexpected_rules);
    ]
