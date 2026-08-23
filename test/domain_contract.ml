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

let robdd_test () =
  let open Condition in
  let a = atom "authorized" and b = atom "fork" in
  let absorbed = and_ a (or_ a b) in
  expect "ROBDD reduction must prove absorption" (equal absorbed a);
  expect "a implies a or b" (implies a (or_ a b));
  expect "a and not a must be unsatisfiable"
    (not (satisfiable (and_ a (not_ a))));
  expect "unknown input evaluates to Unknown"
    (evaluate (fun _ -> None) a = Condition.Unknown)

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
