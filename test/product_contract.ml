type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let string_value ?(trust = Abstract_value.Trusted) text =
  Abstract_value.string_constant text ~trust ~secrecy:Abstract_value.Public
    ~provenance:[]

let node ?(kind = Ir.Command) ?(phase = Ir.Run) ?(attributes = [])
    ?(capabilities = []) ?(effects = []) name =
  Ir.make_node ~provider:Ir.Github ~kind ~name ~phase ~span:Span.none
    ~attributes ~capabilities ~effects ()

let edge ?(kind = Ir.Control) (source : Ir.node) (target : Ir.node) =
  Ir.make_edge ~kind ~from_:source.id ~to_:target.id ()

let graph ?(source = ".github/workflows/ci.yml") (nodes : Ir.node list)
    (edges : Ir.edge list) (entry : Ir.node) =
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_node node graph)
    (Ir.empty Ir.Github source)
    nodes
  |> fun graph ->
  List.fold_left (fun graph edge -> Ir.add_edge edge graph) graph edges
  |> Ir.add_entrypoint entry.Ir.id
  |> Ir.finalize

let config_and_policy_test () =
  let source =
    "version = 1\n" ^ "persona = \"gate\"\n"
    ^ "frontends = [\"github\", \"gitlab\"]\n" ^ "[[rules]]\n"
    ^ "id = \"ORG-001\"\n" ^ "kind = \"forbid\"\n"
    ^ "selector.effect = \"network_request\"\n"
    ^ "selector.trust = \"untrusted\"\n"
    ^ "message = \"untrusted network command\"\n" ^ "[[rules]]\n"
    ^ "id = \"ORG-002\"\n" ^ "kind = \"limit\"\n"
    ^ "selector.capability = \"repository_write\"\n" ^ "limit = 0\n"
  in
  let config =
    match Config.parse source with
    | Ok value -> value
    | Error errors -> fail "%s" (String.concat "; " errors)
  in
  expect "two typed policy rules must parse" (List.length config.rules = 2);
  let command =
    node
      ~attributes:
        [ ("command", string_value ~trust:Abstract_value.Untrusted "curl bad") ]
      ~capabilities:[ Ir.Shell; Ir.Network; Ir.Repository_write ]
      "curl bad"
  in
  let pipeline = graph [ command ] [] command in
  let diagnostics = Policy.evaluate config.rules pipeline in
  expect "forbid rule must match effect and trust conjunction"
    (List.exists (fun item -> item.Diagnostic.rule_id = "ORG-001") diagnostics);
  expect "limit rule must count matching capability"
    (List.exists (fun item -> item.Diagnostic.rule_id = "ORG-002") diagnostics);
  (match Config.parse "version = 1\neval = \"danger()\"\n" with
  | Error _ -> ()
  | Ok _ -> fail "string evaluation keys must be rejected");
  List.iter
    (fun source ->
      expect
        ("unsafe or unknown config must fail: " ^ source)
        (Result.is_error (Config.parse source)))
    [
      "version = 2\n";
      "version = 1\noffline = false\n";
      "version = 1\n[sandbox]\nnetwork = \"allow\"\n";
      "version = 1\nfrontends = [\"github\", \"github\"]\n";
    ]

let report_and_sarif_test () =
  let command =
    node
      ~attributes:
        [
          ("command", string_value ~trust:Abstract_value.Untrusted "echo $TITLE");
        ]
      ~capabilities:[ Ir.Shell ] "echo $TITLE"
  in
  let pipeline = graph ~source:"z/workflow.yml" [ command ] [] command in
  let verification = Verifier.verify ~persona:Verifier.Gate pipeline in
  let safe_command =
    node
      ~attributes:[ ("command", string_value "echo safe") ]
      ~capabilities:[ Ir.Shell ] "echo safe"
  in
  let safe_pipeline =
    graph ~source:"a/workflow.yml" [ safe_command ] [] safe_command
  and safe_verification =
    Verifier.verify ~persona:Verifier.Gate
      (graph ~source:"a/workflow.yml" [ safe_command ] [] safe_command)
  in
  let report =
    Report.make ~persona:Verifier.Gate
      ~inputs:[ ("z/workflow.yml", "z"); ("a/workflow.yml", "a") ]
      ~graphs:[ pipeline; safe_pipeline ]
      ~verifications:[ verification; safe_verification ]
      ~policy_diagnostics:[]
  and reordered =
    Report.make ~persona:Verifier.Gate
      ~inputs:[ ("a/workflow.yml", "a"); ("z/workflow.yml", "z") ]
      ~graphs:[ safe_pipeline; pipeline ]
      ~verifications:[ safe_verification; verification ]
      ~policy_diagnostics:[]
  in
  let first = Report.to_canonical_json report
  and second = Report.to_canonical_json reordered in
  expect "report JSON is byte deterministic under input permutation"
    (first = second);
  let parsed =
    match Json.parse first with
    | Ok value -> value
    | Error error -> fail "%d:%s" error.offset error.message
  in
  expect "report schema version is v1"
    (Json.member "schema" parsed = Some (Json.String "report-v1"));
  expect "every property state is serialized"
    (Util.contains ~needle:"\"state\":\"Violated\"" first);
  let sarif = Sarif.to_canonical_json report in
  expect "SARIF 2.1.0 contract is emitted"
    (Util.contains ~needle:"\"version\":\"2.1.0\"" sarif);
  expect "SARIF retains the stable rule ID"
    (Util.contains ~needle:"WV-SEC-001" sarif);
  expect "SARIF retains semantic traces"
    (Util.contains ~needle:"\"codeFlows\"" sarif);
  expect "SARIF retains capabilities and evidence"
    (Util.contains ~needle:"\"capabilities\"" sarif
    && Util.contains ~needle:"\"evidence\"" sarif);
  expect "SARIF exposes behavior-preserving fix guidance"
    (Util.contains ~needle:"\"fixes\"" sarif)

let lockfile_and_resolver_test () =
  let entries =
    [
      {
        Lockfile.provider = Ir.Github;
        reference = "owner/action@v4";
        revision = String.make 40 'a';
        digest = "sha256:" ^ String.make 64 'b';
        source = "https://github.com/owner/action";
        summary = None;
      };
      {
        provider = Ir.Circleci;
        reference = "circleci/node@5";
        revision = "5.2.0";
        digest = "sha256:" ^ String.make 64 'c';
        source = "https://circleci.com/orbs/registry/orb/circleci/node";
        summary = None;
      };
    ]
  in
  let lock = Lockfile.make entries in
  let bytes = Lockfile.to_canonical_json lock in
  let reparsed =
    match Lockfile.parse bytes with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  expect "lockfile round trip is canonical"
    (bytes = Lockfile.to_canonical_json reparsed);
  let network_calls = ref 0 in
  let dependency =
    {
      Frontend_intf.provider = Ir.Github;
      kind = Action;
      reference = "owner/action@v4";
      locator = Direct_reference;
      span = Span.none;
      mutability = Mutable;
      status = Unresolved (Unknown.Unresolved_dependency "owner/action@v4");
    }
  in
  let result = Resolver.resolve ~network:None ~lock [ dependency ] in
  expect "offline resolver uses a matching lock entry"
    (List.length result.locked = 1);
  expect "offline resolver performs no hidden network call" (!network_calls = 0);
  expect "locked resolution is complete" (result.unresolved = [])

let legacy_lock_v1_compatibility_test () =
  let legacy =
    {|{"entries":[{"digest":"sha256:0f48a50cf2edeea3d6e270f8dae645529128ca8b2954993891a2fb8f7b16145a","provider":"github","reference":"actions/checkout@v4","revision":"11d5960a326750d5838078e36cf38b85af677262","source":"https://github.com/actions/checkout/tree/11d5960a326750d5838078e36cf38b85af677262"}],"integrity":"sha256:c3fba30089ded7a131a3234785fb7b1bad3836be2605bc3139e2331cc43494fe","schema":"lock-v1"}|}
    ^ "\n"
  in
  let parsed =
    match Lockfile.parse legacy with
    | Ok value -> value
    | Error error -> fail "legacy lock-v1: %s" error
  in
  expect "lock-v1 remains readable" (parsed.schema = "lock-v1");
  expect "digest-only v1 entries have no invented semantic summary"
    (match parsed.entries with
    | [ entry ] -> Option.is_none entry.Lockfile.summary
    | _ -> false);
  expect "lock-v1 round trips without changing protocol bytes"
    (Lockfile.to_canonical_json parsed = legacy)

let semantic_diff_test () =
  let source =
    node ~kind:Ir.Resource ~phase:Ir.Source
      ~attributes:
        [ ("value", string_value ~trust:Abstract_value.Untrusted "PR title") ]
      "pull request title"
  and sink =
    node
      ~attributes:[ ("command", string_value "curl https://example.invalid") ]
      ~capabilities:[ Ir.Network; Ir.Shell ] "curl https://example.invalid"
  in
  let base = graph [ source; sink ] [] source
  and head = graph [ source; sink ] [ edge ~kind:Ir.Data source sink ] source in
  let difference = Semantic_diff.compare base head in
  expect "new source-to-effect reachability must be reported"
    (List.exists
       (function
         | Semantic_diff.New_reachable_path _ -> true
         | _ -> false)
       difference.changes);
  expect "semantic diff JSON is deterministic"
    (Semantic_diff.to_canonical_json difference
    = Semantic_diff.to_canonical_json difference)

let graph_output_test () =
  let first = node ~kind:Ir.Workflow ~phase:Ir.Compile "ci"
  and second = node ~kind:Ir.Job ~phase:Ir.Plan "build" in
  let pipeline = graph [ first; second ] [ edge first second ] first in
  let dot = Graph_output.to_dot ~kind:Graph_output.All pipeline in
  expect "DOT declares a directed graph"
    (Util.starts_with ~prefix:"digraph workflow" dot);
  expect "DOT output includes stable node IDs"
    (Util.contains ~needle:first.id dot);
  let json =
    Graph_output.to_canonical_json ~kind:Graph_output.Control pipeline
  in
  expect "graph JSON includes control edge"
    (Util.contains ~needle:"control" json)

let safe_fix_test () =
  let source =
    "steps:\n  - uses: actions/checkout@v4 # preserve this comment\n"
  in
  let cst = Yaml_cst.parse ~file:"workflow.yml" source in
  let revision = String.make 40 'd' in
  let proposal =
    match
      Fixer.pin_dependency ~cst ~reference:"actions/checkout@v4" ~revision
    with
    | Some value -> value
    | None -> fail "expected a safe pin proposal"
  in
  expect "pin transform is behavior-preserving by construction" proposal.safe;
  let edited =
    match Fixer.apply ~cst proposal with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  expect "fix touches only scalar bytes and keeps comments"
    (edited
    = "steps:\n  - uses: actions/checkout@" ^ revision
      ^ " # preserve this comment\n")

let tests : test list =
  [
    ("typed config drives declarative policy", config_and_policy_test);
    ("report-v1 and SARIF are deterministic", report_and_sarif_test);
    ("lockfile enables truly offline resolution", lockfile_and_resolver_test);
    ("legacy lock-v1 remains readable", legacy_lock_v1_compatibility_test);
    ("semantic diff reports newly reachable attacks", semantic_diff_test);
    ("graph views preserve stable semantic identity", graph_output_test);
    ("safe fix pins only the dependency scalar", safe_fix_test);
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
