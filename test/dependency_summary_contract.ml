type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let lockfile entries =
  match Lockfile.create entries with
  | Ok lock -> lock
  | Error message -> fail "%s" message

let dependency_for provider kind reference =
  {
    Frontend_intf.provider;
    kind;
    reference;
    locator = Direct_reference;
    span = Span.none;
    mutability = Mutable;
    status = Unresolved (Unknown.Unresolved_dependency reference);
  }

let dependency reference =
  dependency_for Ir.Github Frontend_intf.Action reference

let compile source =
  match
    Frontend.compile_string ~provider:Ir.Github ~path:".github/workflows/ci.yml"
      ~source ()
  with
  | Ok compilation -> compilation
  | Error problems ->
      fail "compile: %s"
        (String.concat "; "
           (List.map (fun problem -> problem.Frontend_intf.message) problems))

let composite_summary_test () =
  let source =
    "name: exact composite\n" ^ "runs:\n  using: composite\n  steps:\n"
    ^ "    - shell: bash\n      run: curl https://example.invalid\n"
  in
  let summary =
    Dependency_summary.infer
      (dependency "owner/action@v1")
      ~path:"action.yml" ~source
  in
  expect "complete composite source discharges uncertainty" summary.complete;
  expect "script effects are inferred from exact locked source"
    (List.mem Ir.Network_request summary.effects);
  expect "required capabilities are retained"
    (List.mem Ir.Network summary.capabilities
    && List.mem Ir.Shell summary.capabilities)

let binary_metadata_summary_test () =
  let source =
    "name: javascript action\n"
    ^ "runs:\n  using: node20\n  main: dist/index.js\n"
  in
  let summary =
    Dependency_summary.infer
      (dependency "owner/action@v1")
      ~path:"action.yml" ~source
  in
  expect "metadata cannot prove an unavailable binary implementation"
    ((not summary.complete) && summary.reasons <> []);
  expect "metadata-declared execution is retained"
    (List.mem Ir.Command_execution summary.effects)

let production_metadata_summary_test () =
  let source =
    "name: checkout\n"
    ^ "inputs:\n  repository:\n    default: ${{ github.repository }}\n"
    ^ "  token:\n    description: >\n"
    ^ "      [Learn more](https://example.invalid/docs)\n"
    ^ "    default: ${{ github.token }}\n"
    ^ "runs:\n  using: node20\n  main: dist/index.js\n"
  in
  let summary =
    Dependency_summary.infer
      (dependency "actions/checkout@v4")
      ~path:"action.yml" ~source
  in
  expect "only the unavailable JavaScript implementation remains unknown"
    (summary.reasons
    = [ "node20 action implementation is unavailable beyond locked metadata" ]);
  expect "production metadata retains its declared execution effect"
    (List.mem Ir.Command_execution summary.effects)

let task_and_orb_summary_test () =
  let task =
    Dependency_summary.infer
      (dependency_for Ir.Azure Frontend_intf.Task "UsePythonVersion@0")
      ~path:"Tasks/UsePythonVersionV0/task.json"
      ~source:"{\"execution\":{\"Node20_1\":{\"target\":\"main.js\"}}}"
  in
  expect
    "Azure task metadata declares execution but not implementation semantics"
    ((not task.complete) && List.mem Ir.Command_execution task.effects);
  expect "Azure task metadata does not invent network access"
    (not (List.mem Ir.Network task.capabilities));
  let orb =
    Dependency_summary.infer
      (dependency_for Ir.Circleci Frontend_intf.Orb "circleci/example@1.2.3")
      ~path:".circleci/config.yml"
      ~source:
        ("version: 2.1\ncommands:\n  ping:\n    steps:\n"
       ^ "      - run: curl https://example.invalid\n")
  in
  expect "complete orb source is summarized through the CircleCI frontend"
    orb.complete;
  expect "orb command effects are inferred from exact source"
    (List.mem Ir.Network_request orb.effects
    && List.mem Ir.Network orb.capabilities)

let resolver_and_lock_summary_test () =
  let dependency = dependency "owner/action@v1" in
  let semantic_source =
    {
      Resolver.path = "action.yml";
      content =
        "name: composite\nruns:\n  using: composite\n  steps:\n"
        ^ "    - shell: bash\n      run: echo exact\n";
    }
  in
  let network =
    {
      Resolver.fetch =
        (fun _ ->
          Ok
            {
              Resolver.revision = String.make 40 'a';
              content = "immutable archive";
              source = "https://github.com/owner/action/tree/exact";
              semantic_source = Some semantic_source;
            });
    }
  in
  let resolved =
    Resolver.resolve ~network:(Some network) ~lock:Lockfile.empty [ dependency ]
  in
  let entry =
    match resolved.locked with
    | [ (_, entry) ] -> entry
    | _ -> fail "expected one locked dependency"
  in
  expect "resolver stores an inferred semantic summary"
    (Option.is_some entry.Lockfile.summary);
  expect "semantic summaries advance the lock protocol"
    (resolved.lockfile.schema = "lock-v2");
  let bytes = Lockfile.to_canonical_json resolved.lockfile in
  let reparsed =
    match Lockfile.parse bytes with
    | Ok lock -> lock
    | Error message -> fail "%s" message
  in
  expect "summary-bearing lockfiles round trip canonically"
    (Lockfile.to_canonical_json reparsed = bytes)

let locked_program_uncertainty_test () =
  let workflow =
    "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    ^ "    steps:\n      - uses: owner/action@v1\n"
  in
  let compilation = compile workflow in
  let summary =
    Dependency_summary.make ~complete:false
      ~reasons:[ "JavaScript implementation is unavailable" ]
      ~capabilities:[ Ir.Network ] ~effects:[ Ir.Network_request ]
  in
  let entry =
    {
      Lockfile.provider = Ir.Github;
      reference = "owner/action@v1";
      revision = String.make 40 'a';
      digest = "sha256:" ^ String.make 64 'b';
      source = "https://github.com/owner/action/tree/exact";
      summary = Some summary;
    }
  in
  let locked = Locked_program.apply (lockfile [ entry ]) compilation in
  let call =
    locked.graph.nodes
    |> List.find (fun (node : Ir.node) ->
        node.kind = Ir.Call && node.name = entry.reference)
  in
  expect "incomplete locked source remains explicitly Unknown"
    (Option.is_some call.unknown);
  expect "locked summary augments the call effect and capability"
    (List.mem Ir.Network_request call.effects
    && List.mem Ir.Network call.capabilities);
  let complete =
    { entry with summary = Some { summary with complete = true; reasons = [] } }
  in
  let locked = Locked_program.apply (lockfile [ complete ]) compilation in
  let call =
    locked.graph.nodes
    |> List.find (fun (node : Ir.node) ->
        node.kind = Ir.Call && node.name = entry.reference)
  in
  expect "only a complete exact-source summary discharges call uncertainty"
    (Option.is_none call.unknown);
  let legacy = { entry with summary = None } in
  let locked = Locked_program.apply (lockfile [ legacy ]) compilation in
  let call =
    locked.graph.nodes
    |> List.find (fun (node : Ir.node) ->
        node.kind = Ir.Call && node.name = entry.reference)
  in
  expect "legacy digest-only locks expose missing semantic evidence"
    (match call.unknown with
    | Some reason ->
        Util.contains ~needle:"no semantic summary" (Unknown.to_string reason)
    | None -> false)

let orb_alias_lock_link_test () =
  let source =
    "version: 2.1\norbs:\n  node: circleci/node@5.0.3\n"
    ^ "jobs:\n  build:\n    docker:\n      - image: cimg/base:current\n"
    ^ "    steps:\n      - node/test\n"
    ^ "workflows:\n  ci:\n    jobs: [build]\n"
  in
  let compilation =
    match
      Frontend.compile_string ~provider:Ir.Circleci ~path:".circleci/config.yml"
        ~source ()
    with
    | Ok value -> value
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  let summary =
    Dependency_summary.make ~complete:true ~reasons:[]
      ~capabilities:[ Ir.Network ] ~effects:[ Ir.Network_request ]
  in
  let entry =
    {
      Lockfile.provider = Ir.Circleci;
      reference = "circleci/node@5.0.3";
      revision = "5.0.3";
      digest = "sha256:" ^ String.make 64 'c';
      source = "https://circleci.com/developer/orbs/orb/circleci/node/5.0.3";
      summary = Some summary;
    }
  in
  let locked = Locked_program.apply (lockfile [ entry ]) compilation in
  let call =
    locked.graph.nodes
    |> List.find (fun (node : Ir.node) -> node.name = "orb:node/test")
  in
  expect "orb alias calls receive their immutable dependency summary"
    (Option.is_none call.unknown && List.mem Ir.Network_request call.effects)

let tests =
  [
    ( "composite actions are summarized from exact source",
      composite_summary_test );
    ("binary action metadata remains incomplete", binary_metadata_summary_test);
    ( "production action metadata has no YAML false positive",
      production_metadata_summary_test );
    ( "Azure task and CircleCI orb summaries stay sound",
      task_and_orb_summary_test );
    ( "resolver persists summaries in canonical locks",
      resolver_and_lock_summary_test );
    ( "locked summaries refine calls without hiding Unknown",
      locked_program_uncertainty_test );
    ( "orb aliases link runtime calls to immutable summaries",
      orb_alias_lock_link_test );
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
