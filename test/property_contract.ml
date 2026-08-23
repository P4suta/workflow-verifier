exception Property_failed of string

let fail format =
  Printf.ksprintf (fun message -> raise (Property_failed message)) format

type rng = { mutable state : int64 }

let next random bound =
  if bound <= 0 then invalid_arg "next bound";
  random.state <-
    Int64.add (Int64.mul random.state 6364136223846793005L) 1442695040888963407L;
  Int64.(
    to_int
      (rem
         (logand (shift_right_logical random.state 1) 0x3fffffffL)
         (of_int bound)))

let choose random values = List.nth values (next random (List.length values))

let alpha random length =
  String.init length (fun _ ->
      "abcdefghijklmnopqrstuvwxyz0123456789".[next random 36])

let json_equal left right = Json.to_string left = Json.to_string right

let check name iterations property =
  let random = { state = 0x5eed5eed1234567L } in
  for index = 0 to iterations - 1 do
    try property random index with
    | Property_failed _ as error -> raise error
    | exception_ ->
        fail "%s failed at case %d: %s" name index
          (Printexc.to_string exception_)
  done;
  Printf.printf "ok - %s (%d cases)\n%!" name iterations

let newline random = if next random 2 = 0 then "\n" else "\r\n"

let replace_newline source separator =
  source
  |> Util.replace_all ~needle:"\r\n" ~replacement:"\n"
  |> Util.replace_all ~needle:"\n" ~replacement:separator

let valid_yaml random index =
  let a = alpha random (1 + next random 16)
  and b = alpha random (1 + next random 16)
  and c = alpha random (1 + next random 16) in
  let source =
    match index mod 8 with
    | 0 ->
        Printf.sprintf "# %s\nkey_%s: %s\nnumber: %d\n" c a b
          (next random 10000)
    | 1 -> Printf.sprintf "items:\n  - '%s''quoted'\n  - \"%s\\nline\"\n" a b
    | 2 ->
        Printf.sprintf "defaults: &shared\n  shell: %s\njob:\n  <<: *shared\n" a
    | 3 -> Printf.sprintf "flow: {%s: [%s, %s], nested: {ok: true}}\n" a b c
    | 4 ->
        Printf.sprintf "literal: |\n  %s\n  %s\nfolded: >\n  %s\n  %s\n" a b b c
    | 5 -> Printf.sprintf "---\nname: %s\n...\n---\n- %s\n- %s\n" a b c
    | 6 -> Printf.sprintf "? [%s, %s]\n: {%s: %s}\n" a b c a
    | _ ->
        Printf.sprintf
          "root:\n  nested:\n    enabled: %s\n    values: [%s, '%s']\n"
          (if next random 2 = 0 then "true" else "false")
          a b
  in
  replace_newline source (newline random)

let check_span source (span : Span.t) =
  let length = String.length source in
  if
    span.start.byte < 0
    || span.stop.byte < span.start.byte
    || span.stop.byte > length
  then fail "span outside source: %s (length %d)" (Span.to_string span) length;
  if
    span.start.line < 1 || span.stop.line < 1 || span.start.column < 1
    || span.stop.column < 1
  then
    fail "span has a non-positive source coordinate: %s" (Span.to_string span)

let rec check_node_spans source = function
  | Yaml_cst.Scalar scalar -> check_span source scalar.span
  | Alias alias -> check_span source alias.span
  | Invalid invalid -> check_span source invalid.span
  | Sequence (items, span) ->
      check_span source span;
      List.iter
        (fun (item : Yaml_cst.sequence_item) ->
          check_span source item.dash_span;
          check_span source item.span;
          check_node_spans source item.value)
        items
  | Flow_sequence (items, span) ->
      check_span source span;
      List.iter (check_node_spans source) items
  | Mapping (entries, span) | Flow_mapping (entries, span) ->
      check_span source span;
      List.iter
        (fun (entry : Yaml_cst.mapping_entry) ->
          check_span source entry.key.span;
          check_span source entry.colon_span;
          check_span source entry.span;
          check_node_spans source entry.key_node;
          check_node_spans source entry.value)
        entries
  | Decorated decorated ->
      check_span source decorated.span;
      check_node_spans source decorated.value

let yaml_round_trip_property random index =
  let source = valid_yaml random index in
  let first = Yaml_cst.parse ~file:"fuzz.yml" source in
  if Yaml_cst.print first <> source then
    fail "lossless print changed valid input";
  let second = Yaml_cst.parse ~file:"fuzz.yml" (Yaml_cst.print first) in
  if not (Yaml_cst.structural_equal first second) then
    fail "parse-print-parse changed valid structure\n%s" source;
  if
    Yaml_event.to_string (Yaml_event.of_cst first)
    <> Yaml_event.to_string (Yaml_event.of_cst second)
  then fail "parse-print-parse changed valid event projection\n%s" source;
  List.iter
    (fun (document : Yaml_cst.document) ->
      check_span source document.span;
      Option.iter (check_node_spans source) document.root)
    first.documents;
  List.iter
    (fun (trivia : Yaml_cst.trivia) -> check_span source trivia.span)
    first.trivia;
  List.iter
    (fun (problem : Yaml_cst.problem) -> check_span source problem.span)
    first.problems;
  match Yaml_cst.apply_edits first [] with
  | Ok unchanged when unchanged = source -> ()
  | Ok _ -> fail "empty edit list changed source"
  | Error message -> fail "empty edit list failed: %s" message

let malformed_yaml_property random index =
  let alphabet =
    "\000\001\t\n\r !#%&*,-:?[]{}'\"\\abcdefghijklmnopqrstuvwxyz\255"
  in
  let length = next random 256 in
  let source =
    String.init length (fun _ ->
        alphabet.[next random (String.length alphabet)])
  in
  let first =
    Yaml_cst.parse ~file:(Printf.sprintf "malformed-%d.yml" index) source
  in
  if Yaml_cst.print first <> source then
    fail "lossless print changed arbitrary bytes";
  let second = Yaml_cst.parse ~file:first.file (Yaml_cst.print first) in
  if not (Yaml_cst.structural_equal first second) then
    fail "parse-print-parse changed arbitrary structure"

let provenance index =
  {
    Abstract_value.origin = "property-" ^ string_of_int (index mod 7);
    operation = "generated";
    span =
      Span.make ~file:"property"
        (Span.position ~byte:(index mod 20) ())
        (Span.position ~byte:((index mod 20) + 1) ());
  }

let trust random =
  match next random 3 with
  | 0 -> Abstract_value.Trusted
  | 1 -> Mixed
  | _ -> Untrusted

let secrecy random =
  match next random 3 with
  | 0 -> Abstract_value.Public
  | 1 -> Sensitive
  | _ -> Secret

let abstract_value random index =
  let open Abstract_value in
  let base_trust = trust random and base_secrecy = secrecy random in
  match next random 7 with
  | 0 -> bottom
  | 1 ->
      string_constant
        (alpha random (1 + next random 10))
        ~trust:base_trust ~secrecy:base_secrecy
        ~provenance:[ provenance index ]
  | 2 ->
      {
        value_type = Bool_type;
        value = Boolean (choose random [ False; True; Maybe ]);
        trust = base_trust;
        secrecy = base_secrecy;
        provenance = [ provenance index ];
      }
  | 3 ->
      let lower = Int64.of_int (next random 100) in
      {
        value_type = Number_type;
        value =
          Number
            {
              minimum = Some lower;
              maximum = Some (Int64.add lower (Int64.of_int (next random 100)));
            };
        trust = base_trust;
        secrecy = base_secrecy;
        provenance = [ provenance index ];
      }
  | 4 -> unknown (Unknown.Dynamic_string (alpha random 5))
  | 5 ->
      {
        value_type = List_type;
        value =
          List
            (Some
               [
                 string_constant (alpha random 4) ~trust:base_trust
                   ~secrecy:base_secrecy ~provenance:[];
               ]);
        trust = base_trust;
        secrecy = base_secrecy;
        provenance = [ provenance index ];
      }
  | _ ->
      {
        value_type = Object_type;
        value =
          Object
            (Some
               [
                 ( "key",
                   string_constant (alpha random 4) ~trust:base_trust
                     ~secrecy:base_secrecy ~provenance:[] );
               ]);
        trust = base_trust;
        secrecy = base_secrecy;
        provenance = [ provenance index ];
      }

let value_equal left right =
  json_equal (Abstract_value.to_json left) (Abstract_value.to_json right)

let abstract_join_property random index =
  let a = abstract_value random (index * 3)
  and b = abstract_value random ((index * 3) + 1)
  and c = abstract_value random ((index * 3) + 2) in
  if not (value_equal (Abstract_value.join a a) a) then
    fail "join is not idempotent";
  if not (value_equal (Abstract_value.join a Abstract_value.bottom) a) then
    fail "bottom is not a right identity";
  if not (value_equal (Abstract_value.join Abstract_value.bottom a) a) then
    fail "bottom is not a left identity";
  if not (value_equal (Abstract_value.join a b) (Abstract_value.join b a)) then
    fail "join is not commutative";
  if
    not
      (value_equal
         (Abstract_value.join (Abstract_value.join a b) c)
         (Abstract_value.join a (Abstract_value.join b c)))
  then
    fail "join is not associative at case %d\na=%s\nb=%s\nc=%s\nlhs=%s\nrhs=%s"
      index
      (Json.to_string (Abstract_value.to_json a))
      (Json.to_string (Abstract_value.to_json b))
      (Json.to_string (Abstract_value.to_json c))
      (Json.to_string
         (Abstract_value.to_json
            (Abstract_value.join (Abstract_value.join a b) c)))
      (Json.to_string
         (Abstract_value.to_json
            (Abstract_value.join a (Abstract_value.join b c))))

let rec formula random depth =
  if depth = 0 then Condition.atom (choose random [ "a"; "b"; "c"; "d" ])
  else
    match next random 5 with
    | 0 -> Condition.not_ (formula random (depth - 1))
    | 1 ->
        Condition.and_ (formula random (depth - 1)) (formula random (depth - 1))
    | 2 ->
        Condition.or_ (formula random (depth - 1)) (formula random (depth - 1))
    | 3 -> Condition.true_
    | _ -> Condition.false_

let condition_property random _index =
  let a = formula random 4 and b = formula random 4 and c = formula random 3 in
  let equal = Condition.equal in
  if not (equal (Condition.not_ (Condition.not_ a)) a) then
    fail "double negation failed";
  if not (equal (Condition.and_ a b) (Condition.and_ b a)) then
    fail "and is not commutative";
  if not (equal (Condition.or_ a b) (Condition.or_ b a)) then
    fail "or is not commutative";
  if
    not
      (equal
         (Condition.and_ (Condition.and_ a b) c)
         (Condition.and_ a (Condition.and_ b c)))
  then fail "and is not associative";
  if
    not
      (equal
         (Condition.or_ (Condition.or_ a b) c)
         (Condition.or_ a (Condition.or_ b c)))
  then fail "or is not associative";
  if not (equal (Condition.or_ a (Condition.and_ a b)) a) then
    fail "or absorption failed";
  if not (equal (Condition.and_ a (Condition.or_ a b)) a) then
    fail "and absorption failed";
  if not (Condition.implies (Condition.and_ a b) a) then
    fail "conjunction implication failed"

let rec json_value random depth =
  if depth = 0 then
    choose random
      [
        Json.Null;
        Bool true;
        Bool false;
        Int (next random 1000);
        String (alpha random (next random 20));
      ]
  else
    match next random 4 with
    | 0 ->
        Json.Array
          (List.init (next random 5) (fun _ -> json_value random (depth - 1)))
    | 1 ->
        Json.Object
          (List.init (next random 5) (fun index ->
               (Printf.sprintf "k%02d" index, json_value random (depth - 1))))
    | _ -> json_value random 0

let canonical_json_property random _index =
  let value = json_value random 4 in
  let serialized = Json.to_string value in
  match Json.parse serialized with
  | Error error ->
      fail "canonical JSON did not parse at byte %d: %s" error.offset
        error.message
  | Ok parsed ->
      if Json.to_string parsed <> serialized then
        fail "canonical JSON was not idempotent"

let diagnostic_ids diagnostics =
  diagnostics |> List.map (fun (diagnostic : Diagnostic.t) -> diagnostic.id)

let policy_property random index =
  let nodes =
    List.init 24 (fun node_index ->
        let network = next random 2 = 0 and write = next random 3 = 0 in
        Ir.make_node ~provider:Github
          ~kind:(if node_index mod 2 = 0 then Ir.Command else Call)
          ~name:("echo node-" ^ string_of_int node_index)
          ~phase:Run
          ~span:
            (Span.make ~file:"policy.yml"
               (Span.position ~byte:(node_index * 2) ())
               (Span.position ~byte:((node_index * 2) + 1) ()))
          ~capabilities:(if network then [ Ir.Network ] else [])
          ~effects:(if write then [ Ir.File_write ] else [])
          ())
  in
  let graph_of sequence =
    List.fold_left
      (fun graph node -> Ir.add_node node graph)
      (Ir.empty Github "policy.yml")
      sequence
    |> Ir.finalize
  in
  let rules =
    [
      {
        Policy.id = "ORG-NETWORK-001";
        kind = Forbid;
        selector = Any [ Capability Ir.Network; Effect Ir.File_write ];
        message = "network or write forbidden";
        severity = Diagnostic.Warning;
      };
      {
        Policy.id = "ORG-COMMAND-001";
        kind = Limit 12;
        selector = All [ Node_kind Ir.Command ];
        message = "command count limited";
        severity = Diagnostic.Note;
      };
      {
        Policy.id = "ORG-PROVIDER-001";
        kind = Require;
        selector = All [ Provider Github ];
        message = "github required";
        severity = Diagnostic.Error;
      };
    ]
  in
  let first = Policy.evaluate rules (graph_of nodes)
  and second = Policy.evaluate (List.rev rules) (graph_of (List.rev nodes)) in
  if diagnostic_ids first <> diagnostic_ids second then
    fail "policy output changed under input permutation at case %d" index

let () =
  Printexc.record_backtrace true;
  try
    check "lossless YAML valid round trips and spans" 2000
      yaml_round_trip_property;
    check "lossless YAML arbitrary-byte round trips" 2000
      malformed_yaml_property;
    check "abstract value join semilattice laws" 4000 abstract_join_property;
    check "ROBDD Boolean algebra laws" 4000 condition_property;
    check "canonical JSON parse/print idempotence" 2000 canonical_json_property;
    check "policy result permutation invariance" 1000 policy_property;
    Printf.printf "property contracts passed\n%!"
  with
  | Property_failed message ->
      Printf.eprintf "not ok - %s\n%!" message;
      exit 1
  | exception_ ->
      Printf.eprintf "not ok - unexpected %s\n%s%!"
        (Printexc.to_string exception_)
        (Printexc.get_backtrace ());
      exit 1
