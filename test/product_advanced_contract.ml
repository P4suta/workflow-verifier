type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let lockfile entries =
  match Lockfile.create entries with
  | Ok lock -> lock
  | Error message -> fail "%s" message

let string_value ?(trust = Abstract_value.Trusted) value =
  Abstract_value.string_constant value ~trust ~secrecy:Abstract_value.Public
    ~provenance:[ { origin = "fixture"; span = Span.none; operation = "test" } ]

let node ?(kind = Ir.Command) ?(effects = []) ?(capabilities = [])
    ?(attributes = []) name =
  Ir.make_node ~provider:Ir.Github ~kind ~name ~phase:Ir.Run ~span:Span.none
    ~effects ~capabilities ~attributes ()

let edge ?(kind = Ir.Control) (left : Ir.node) (right : Ir.node) =
  Ir.make_edge ~kind ~from_:left.Ir.id ~to_:right.Ir.id ()

let graph source (nodes : Ir.node list) (edges : Ir.edge list)
    (entrypoint : Ir.node) =
  List.fold_left
    (fun graph node -> Ir.add_node node graph)
    (Ir.empty Ir.Github source)
    nodes
  |> fun graph ->
  List.fold_left (fun graph edge -> Ir.add_edge edge graph) graph edges
  |> Ir.add_entrypoint entrypoint.Ir.id
  |> Ir.finalize

let config_surface_test () =
  let source =
    {|version = 2
persona = "gate"
frontends = ["github"]
offline = true

[resolver]
require_immutable = true

[[resolver.allowed_origins]]
origin = "https://github.com"
path_prefixes = ["/"]

[sandbox]
backend = "linux-native"
network = "deny"

[[allowlist]]
kind = "network_host"
value = "example.invalid"
reason = "fixture service"

[[rules]]
id = "ORG-ANY"
kind = "forbid"
selector.mode = "any"
selector.effect = "network"
selector.capability = "oidc"
message = "sensitive surface"

[[suppressions]]
rule = "ORG-ANY"
path = ".github/workflows/generated.yml"
reason = "generated and reviewed"
owner = "platform-team"
expiry = "2027-01-31"
|}
  in
  let config =
    match Config.parse source with
    | Ok value -> value
    | Error errors -> fail "%s" (String.concat "; " errors)
  in
  expect "resolver immutable policy is typed" config.resolver.require_immutable;
  expect "resolver source allowlist is retained"
    (config.resolver.allowed_sources = [ "https://github.com/" ]);
  expect "sandbox limits are typed"
    (config.sandbox.backend = "linux-native"
    && config.sandbox.cpu_seconds = 900
    && config.sandbox.memory_mb = 2048);
  expect "allowlist entries require a reason" (List.length config.allowlist = 1);
  (match config.rules with
  | [ { Policy.selector = Any [ Effect _; Capability _ ]; _ } ] -> ()
  | _ -> fail "selector.mode=any was not retained");
  let diagnostic =
    Diagnostic.make ~rule_id:"ORG-ANY" ~severity:Error ~confidence:High
      ~message:"fixture"
      ~span:{ Span.none with file = ".github/workflows/generated.yml" }
      ()
  in
  expect "reasoned path suppression applies exactly"
    (Config.suppressed config diagnostic)

let forbid_path_test () =
  let source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", string_value ~trust:Abstract_value.Untrusted "PR") ]
      "pull request"
  and reachable =
    node ~effects:[ Ir.Network_request ] ~capabilities:[ Ir.Network ] "publish"
  and isolated =
    node ~effects:[ Ir.Network_request ] ~capabilities:[ Ir.Network ] "isolated"
  in
  let pipeline =
    graph "workflow.yml"
      [ source; reachable; isolated ]
      [ edge ~kind:Ir.Data source reachable ]
      source
  in
  let rule =
    {
      Policy.id = "ORG-PATH";
      kind = Forbid_path;
      selector = All [ Effect Ir.Network_request ];
      message = "untrusted data must not reach network";
      severity = Diagnostic.Error;
    }
  in
  match Policy.evaluate [ rule ] pipeline with
  | [ diagnostic ] ->
      expect "path policy reports a complete source-to-sink trace"
        (List.length diagnostic.Diagnostic.trace >= 2
        && (List.hd (List.rev diagnostic.trace)).Diagnostic.node_id
           = reachable.id)
  | diagnostics ->
      fail "expected one reachable-path diagnostic, got %d"
        (List.length diagnostics)

let lock_and_resolver_integrity_test () =
  let first =
    {
      Lockfile.provider = Ir.Github;
      reference = "owner/action@v1";
      revision = String.make 40 'a';
      digest = "sha256:" ^ String.make 64 'b';
      source = "https://github.com/owner/action";
      summary = None;
    }
  and conflicting =
    {
      Lockfile.provider = Ir.Github;
      reference = "owner/action@v1";
      revision = String.make 40 'c';
      digest = "sha256:" ^ String.make 64 'd';
      source = "https://github.com/owner/action";
      summary = None;
    }
  in
  expect "conflicting lock identities are rejected"
    (Result.is_error (Lockfile.create [ first; conflicting ]));
  let dependency =
    {
      Frontend_intf.provider = Ir.Github;
      kind = Action;
      reference = "owner/action@v1";
      locator = Direct_reference;
      span = Span.none;
      mutability = Mutable;
      status = Unresolved (Unknown.Unresolved_dependency "owner/action@v1");
    }
  in
  let network =
    {
      Resolver.fetch =
        (fun _ ->
          Ok
            {
              Resolver.revision = "v1";
              content = "payload";
              source = "https://github.com/owner/action";
              semantic_source = None;
            });
    }
  in
  let result =
    Resolver.resolve ~network:(Some network) ~lock:Lockfile.empty [ dependency ]
  in
  expect "mutable fetched revisions never enter the lock" (result.locked = []);
  expect "resolver exposes the integrity failure" (result.errors <> [])

let resolver_rejects_invalid_lock_entry_test () =
  let dependency =
    {
      Frontend_intf.provider = Ir.Github;
      kind = Action;
      reference = "owner/action@v1";
      locator = Direct_reference;
      span = Span.none;
      mutability = Mutable;
      status = Unresolved (Unknown.Unresolved_dependency "owner/action@v1");
    }
  in
  let network =
    {
      Resolver.fetch =
        (fun _ ->
          Ok
            {
              Resolver.revision = String.make 40 'a';
              content = "payload";
              source = "";
              semantic_source = None;
            });
    }
  in
  let result =
    Resolver.resolve ~network:(Some network) ~lock:Lockfile.empty [ dependency ]
  in
  expect
    "invalid fetched entries remain unresolved without escaping an exception"
    (result.locked = []
    && result.unresolved = [ dependency ]
    && result.errors <> []
    && result.lockfile.entries = [])

let semantic_program_diff_test () =
  let safe = node "echo safe" in
  let source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", string_value ~trust:Abstract_value.Untrusted "PR") ]
      "PR"
  and sink =
    node
      ~attributes:[ ("command", string_value "echo $TITLE") ]
      ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment; Ir.Shell ]
      "echo $TITLE"
  in
  let base =
    [
      graph "one.yml" [ safe ] [] safe;
      graph "two.yml" [ source; sink ] [] source;
    ]
  and head =
    [
      graph "one.yml" [ safe ] [] safe;
      graph "two.yml" [ source; sink ] [ edge ~kind:Ir.Data source sink ] source;
    ]
  in
  let difference = Semantic_diff.compare_program base head in
  expect "program diff compares every file and privileged effect"
    (List.exists
       (function
         | Semantic_diff.New_reachable_path path ->
             path.effect_name = "deployment_change"
         | _ -> false)
       difference.changes);
  expect "program diff includes proof-state transitions"
    (List.exists
       (function
         | Semantic_diff.Property_changed _ -> true
         | _ -> false)
       difference.changes)

let composite_fix_test () =
  let source = "a: old # a\nb: old # b\n" in
  let cst = Yaml_cst.parse ~file:"fixture.yml" source in
  let scalars =
    let rec collect accumulator = function
      | Yaml_cst.Scalar scalar when scalar.value = "old" ->
          scalar :: accumulator
      | Scalar _ | Alias _ | Invalid _ -> accumulator
      | Sequence (items, _) ->
          List.fold_left
            (fun acc (item : Yaml_cst.sequence_item) -> collect acc item.value)
            accumulator items
      | Flow_sequence (items, _) -> List.fold_left collect accumulator items
      | Mapping (entries, _) | Flow_mapping (entries, _) ->
          List.fold_left
            (fun acc (entry : Yaml_cst.mapping_entry) ->
              collect (collect acc entry.key_node) entry.value)
            accumulator entries
      | Decorated decorated -> collect accumulator decorated.value
    in
    Option.fold ~none:[] ~some:(collect []) (Yaml_cst.root cst)
  in
  match scalars with
  | first :: second :: _ ->
      let one =
        Fixer.replace_scalar ~cst ~scalar:first ~replacement:"one"
          ~description:"one"
      and two =
        Fixer.replace_scalar ~cst ~scalar:second ~replacement:"two"
          ~description:"two"
      in
      let combined =
        match Fixer.combine [ one; two ] with
        | Ok value -> value
        | Error error -> fail "%s" error
      in
      let edited =
        match Fixer.apply ~cst combined with
        | Ok value -> value
        | Error e -> fail "%s" e
      in
      expect "multiple safe edits apply atomically and retain comments"
        (Util.contains ~needle:"# a" edited
        && Util.contains ~needle:"# b" edited
        && not (Util.contains ~needle:"old" edited))
  | _ -> fail "fixture scalars missing"

let locked_program_test () =
  let source =
    "name: ci\n\
     on: push\n\
     jobs:\n\
    \  build:\n\
    \    runs-on: ubuntu-latest\n\
    \    steps:\n\
    \      - uses: owner/action@v1\n"
  in
  let compilation =
    match
      Frontend.compile_string ~provider:Ir.Github
        ~path:".github/workflows/ci.yml" ~source ()
    with
    | Ok value -> value
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  let entry =
    {
      Lockfile.provider = Ir.Github;
      reference = "owner/action@v1";
      revision = String.make 40 'a';
      digest = "sha256:" ^ String.make 64 'b';
      source = "https://github.com/owner/action";
      summary = None;
    }
  in
  let locked = Locked_program.apply (lockfile [ entry ]) compilation in
  expect "dependency status is upgraded from lock evidence"
    (List.for_all
       (fun dependency ->
         match dependency.Frontend_intf.status with
         | Locked _ -> true
         | Unresolved _ -> false)
       locked.dependencies);
  let verification = Verifier.verify ~persona:Verifier.Audit locked.graph in
  expect "supply-chain verifier accepts a content-addressed lock overlay"
    (not
       (List.exists
          (fun diagnostic -> diagnostic.Diagnostic.rule_id = "WV-SUPPLY-001")
          verification.diagnostics))

let compile provider path source =
  match Frontend.compile_string ~provider ~path ~source () with
  | Ok compilation -> compilation
  | Error problems ->
      fail "%s"
        (String.concat "; "
           (List.map (fun problem -> problem.Frontend_intf.message) problems))

let local_dependency_linker_test () =
  let workflow_source =
    "name: ci\n\
     on: push\n\
     jobs:\n\
    \  build:\n\
    \    runs-on: ubuntu-latest\n\
    \    steps:\n\
    \      - uses: ./actions/build\n"
  and action_source =
    "name: build\nruns:\n  using: composite\n  steps:\n    - run: echo linked\n"
  in
  let workflow_path = "repo/.github/workflows/ci.yml"
  and action_path = "repo/actions/build/action.yml" in
  let root = compile Ir.Github workflow_path workflow_source in
  let linked =
    match
      Local_linker.link ~root:"repo"
        ~sources:
          [
            { Frontend_intf.path = workflow_path; source = workflow_source };
            { Frontend_intf.path = action_path; source = action_source };
          ]
        [ root ]
    with
    | Ok compilations -> compilations
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  expect "a referenced action is compiled even when it was not a root"
    (List.length linked = 2);
  let root =
    List.find
      (fun compilation ->
        compilation.Frontend_intf.graph.source = workflow_path)
      linked
  in
  let expected_digest = "sha256:" ^ Sha256.digest_string action_source in
  expect "local dependencies carry content-addressed workspace evidence"
    (match root.dependencies with
    | [ dependency ] -> (
        match dependency.Frontend_intf.status with
        | Locked { revision; digest } ->
            dependency.mutability = Local
            && revision = "local:actions/build/action.yml"
            && digest = expected_digest
        | Unresolved _ -> false)
    | _ -> false);
  let call =
    List.find
      (fun (node : Ir.node) ->
        node.kind = Ir.Call && node.name = "./actions/build")
      root.graph.nodes
  in
  expect "local call uncertainty is discharged only by exact source bytes"
    (call.unknown = None
    && Option.is_some (List.assoc_opt "dependency.digest" call.attributes));
  let program =
    Program_graph.compose
      (List.map
         (fun (compilation : Frontend_intf.compilation) -> compilation.graph)
         linked)
  in
  expect "the local call is connected to the referenced unit entrypoint"
    (List.exists
       (fun (edge : Ir.edge) ->
         edge.kind = Ir.Call_edge && edge.from_ = call.id
         && edge.label = Some "local-unit")
       program.edges)

let resolver_local_dependency_test () =
  let calls = ref 0 in
  let dependency =
    {
      Frontend_intf.provider = Ir.Github;
      kind = Action;
      reference = "./actions/build";
      locator = Direct_reference;
      span = Span.none;
      mutability = Local;
      status =
        Locked
          {
            revision = "local:actions/build/action.yml";
            digest = "sha256:" ^ String.make 64 'a';
          };
    }
  in
  let network =
    {
      Resolver.fetch =
        (fun _ ->
          incr calls;
          Error "local dependencies must never reach the network");
    }
  in
  let result =
    Resolver.resolve ~network:(Some network) ~lock:Lockfile.empty [ dependency ]
  in
  expect "local dependency evidence is complete without a lockfile entry"
    (result.unresolved = [] && result.errors = []
    && result.lockfile.entries = []);
  expect "resolve never sends workspace paths to a network adapter" (!calls = 0)

let missing_local_dependency_test () =
  let source =
    "job:\n\
    \  script: echo root\n\
     child:\n\
    \  trigger:\n\
    \    include:\n\
    \      - local: /missing-child.yml\n"
  in
  let path = "repo/.gitlab-ci.yml" in
  let compilations =
    match
      Local_linker.link ~root:"repo"
        ~sources:[ { Frontend_intf.path; source } ]
        [ compile Ir.Gitlab path source ]
    with
    | Ok value -> value
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  let dependency =
    compilations
    |> List.concat_map (fun compilation ->
        compilation.Frontend_intf.dependencies)
    |> List.find (fun dependency ->
        dependency.Frontend_intf.reference = "/missing-child.yml")
  in
  expect "a missing local target remains Unknown but is never remote"
    (dependency.mutability = Local
    &&
    match dependency.status with
    | Unresolved _ -> true
    | Locked _ -> false);
  let calls = ref 0 in
  let result =
    Resolver.resolve
      ~network:
        (Some
           {
             Resolver.fetch =
               (fun _ ->
                 incr calls;
                 Error "must stay offline");
           })
      ~lock:Lockfile.empty [ dependency ]
  in
  expect "missing workspace units are incomplete without network access"
    (!calls = 0 && result.errors = [] && result.unresolved = [ dependency ])

let azure_local_template_linker_test () =
  let pipeline_source =
    "trigger: none\n\
     jobs:\n\
    \  - job: build\n\
    \    steps:\n\
    \      - template: templates/build.yml\n"
  and template_source = "steps:\n  - script: echo linked template\n" in
  let pipeline_path = "repo/azure-pipelines.yml"
  and template_path = "repo/templates/build.yml" in
  let linked =
    match
      Local_linker.link ~root:"repo"
        ~sources:
          [
            { Frontend_intf.path = pipeline_path; source = pipeline_source };
            { Frontend_intf.path = template_path; source = template_source };
          ]
        [ compile Ir.Azure pipeline_path pipeline_source ]
    with
    | Ok compilations -> compilations
    | Error problems ->
        fail "%s"
          (String.concat "; "
             (List.map (fun problem -> problem.Frontend_intf.message) problems))
  in
  expect "provider-inherited compilation expands an Azure template"
    (List.exists
       (fun compilation ->
         compilation.Frontend_intf.graph.source = template_path
         && List.exists
              (fun (node : Ir.node) ->
                node.kind = Ir.Command && node.name = "echo linked template")
              compilation.graph.nodes)
       linked);
  let pipeline =
    List.find
      (fun compilation ->
        compilation.Frontend_intf.graph.source = pipeline_path)
      linked
  in
  expect "an unqualified Azure template is a local immutable unit"
    (List.for_all
       (fun dependency ->
         match dependency.Frontend_intf.status with
         | Locked _ -> true
         | Unresolved _ -> false)
       pipeline.dependencies)

let proved_fix_test () =
  let permissions_source =
    "permissions: write-all # retain permission rationale\njobs: {}\n"
  in
  let permissions_cst =
    Yaml_cst.parse ~file:".github/workflows/ci.yml" permissions_source
  in
  expect "permission reduction needs proof for every removed grant"
    (Fixer.reduce_write_all ~cst:permissions_cst
       ~unused_capabilities:[ Ir.Repository_write ]
    = None);
  let proposal =
    match
      Fixer.reduce_write_all ~cst:permissions_cst
        ~unused_capabilities:[ Ir.Repository_write; Ir.Token_write ]
    with
    | Some value -> value
    | None -> fail "proved write-all reduction was not proposed"
  in
  let reduced =
    match Fixer.apply ~cst:permissions_cst proposal with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "proved permission reduction preserves comments"
    (reduced = "permissions: read-all # retain permission rationale\njobs: {}\n");
  let command_source =
    "jobs:\n\
    \  build:\n\
    \    steps:\n\
    \      - run: echo ${{ github.event.issue.title }} # retain command note\n"
  in
  let command_cst =
    Yaml_cst.parse ~file:".github/workflows/ci.yml" command_source
  in
  let boundary =
    match
      Fixer.bind_expression_to_environment ~cst:command_cst
        ~shell:Script_adapter.Bash ~expression:"${{ github.event.issue.title }}"
        ~name:"WV_UNTRUSTED_INPUT"
    with
    | Some value -> value
    | None -> fail "simple provider expression should have a safe env fix"
  in
  let rebound =
    match Fixer.apply ~cst:command_cst boundary with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  if
    not
      (Util.contains
         ~needle:"echo \"${WV_UNTRUSTED_INPUT}\" # retain command note" rebound
      && Util.contains
           ~needle:
             "env:\n\
             \          WV_UNTRUSTED_INPUT: ${{ github.event.issue.title }}"
           rebound)
  then fail "unexpected env-boundary edit: %S" rebound

let tests : test list =
  [
    ("typed resolver sandbox policy and suppressions", config_surface_test);
    ("forbid_path means reachable source-to-effect path", forbid_path_test);
    ( "lock and resolver reject mutable identities",
      lock_and_resolver_integrity_test );
    ( "resolver rejects invalid lock entries without exceptions",
      resolver_rejects_invalid_lock_entry_test );
    ("semantic diff composes the full program", semantic_program_diff_test);
    ("safe fixes compose atomically", composite_fix_test);
    ("offline lock evidence overlays the semantic program", locked_program_test);
    ( "local dependencies compile and link content-addressed units",
      local_dependency_linker_test );
    ("resolver keeps local dependencies offline", resolver_local_dependency_test);
    ( "missing local dependencies remain offline Unknowns",
      missing_local_dependency_test );
    ( "Azure local templates inherit their frontend",
      azure_local_template_linker_test );
    ("automatic fixes require explicit semantic proof", proved_fix_test);
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
