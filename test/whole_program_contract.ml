exception Failed of string

let fail format = Printf.ksprintf (fun message -> raise (Failed message)) format
let expect message condition = if not condition then fail "%s" message

let value ?(trust = Abstract_value.Trusted) ?(secrecy = Abstract_value.Public)
    source =
  Abstract_value.string_constant source ~trust ~secrecy
    ~provenance:[ { origin = "fixture"; span = Span.none; operation = "test" } ]

let node ?(kind = Ir.Command) ?(phase = Ir.Run) ?(attributes = [])
    ?(capabilities = []) ?(effects = []) ?unknown name =
  Ir.make_node ~provider:Ir.Github ~kind ~name ~phase ~span:Span.none
    ~attributes ~capabilities ~effects ?unknown ()

let edge ?(kind = Ir.Control) ?(condition = Condition.true_) (source : Ir.node)
    (target : Ir.node) =
  Ir.make_edge ~kind ~from_:source.id ~to_:target.id ~condition ()

let graph nodes edges entrypoints =
  List.fold_left
    (fun graph node -> Ir.add_node node graph)
    (Ir.empty Ir.Github "security-fixture.yml")
    nodes
  |> fun graph ->
  List.fold_left (fun graph edge -> Ir.add_edge edge graph) graph edges
  |> fun graph ->
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_entrypoint node.id graph)
    graph entrypoints
  |> Ir.finalize

let property id result =
  match
    List.find_opt
      (fun property -> property.Property.id = id)
      result.Verifier.properties
  with
  | Some property -> property
  | None -> fail "missing property %s" id

let diagnostic id result =
  match
    List.find_opt
      (fun diagnostic -> diagnostic.Diagnostic.rule_id = id)
      result.Verifier.diagnostics
  with
  | Some diagnostic -> diagnostic
  | None -> fail "missing diagnostic %s" id

let condition_aware_taint () =
  let source =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "title") ]
      "event.title"
  and sink =
    node
      ~attributes:[ ("command", value "echo $TITLE") ]
      ~capabilities:[ Ir.Shell ] "sink"
  in
  let safe =
    graph [ source; sink ]
      [ edge ~kind:Ir.Data ~condition:Condition.false_ source sink ]
      [ sink ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an unsatisfiable edge cannot propagate taint"
    ((property "WV-SEC-001" safe).state = Property.Proved);
  let unsafe =
    graph [ source; sink ] [ edge ~kind:Ir.Data source sink ] [ sink ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "the same feasible edge propagates taint"
    ((property "WV-SEC-001" unsafe).state = Property.Violated)

let quote_boundary () =
  let source =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "title") ]
      "env.TITLE"
  and safe =
    node
      ~attributes:
        [ ("command", value "printf '%s' \"$TITLE\""); ("shell", value "bash") ]
      ~capabilities:[ Ir.Shell ] "quoted"
  and unsafe =
    node
      ~attributes:
        [ ("command", value "printf %s $TITLE"); ("shell", value "bash") ]
      ~capabilities:[ Ir.Shell ] "unquoted"
  in
  let safe_result =
    graph [ source; safe ] [ edge ~kind:Ir.Data source safe ] [ safe ]
    |> Verifier.verify ~persona:Verifier.Gate
  and unsafe_result =
    graph [ source; unsafe ] [ edge ~kind:Ir.Data source unsafe ] [ unsafe ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "quoted env expansion is a safe shell boundary"
    ((property "WV-SEC-001" safe_result).state = Property.Proved);
  expect "unquoted env expansion remains injectable"
    ((property "WV-SEC-001" unsafe_result).state = Property.Violated)

let poisoning kind resource_name capability rule =
  let source =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "payload") ]
      "pull-request"
  and producer =
    node
      ~attributes:[ ("command", value "build") ]
      ~capabilities:[ Ir.Shell; capability ] "producer"
  and resource =
    node ~kind:Ir.Resource ~capabilities:[ capability ] resource_name
  and consumer =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Deployment ]
      ~effects:[ Ir.Deployment_change ] "deploy"
  in
  let result =
    graph
      [ source; producer; resource; consumer ]
      [
        edge ~kind:Ir.Data source producer;
        edge ~kind:Ir.Write producer resource;
        edge ~kind:Ir.Read resource consumer;
        edge producer consumer;
      ]
      [ producer ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect
    (kind ^ " poisoning is violated")
    ((property rule result).state = Property.Violated);
  let finding = diagnostic rule result in
  expect "poisoning trace crosses the persisted resource"
    (List.exists
       (fun hop -> hop.Diagnostic.node_id = resource.id)
       finding.trace);
  expect "minimal exploit set includes persistence and privileged effect"
    (List.mem capability finding.capabilities
    && List.mem Ir.Deployment finding.capabilities)

let artifact_poisoning () =
  poisoning "artifact" "artifact:bundle" Ir.Artifact_write "WV-ARTIFACT-001"

let cache_poisoning () =
  poisoning "cache" "cache:dependencies" Ir.Cache_write "WV-CACHE-001"

let toctou () =
  let ref_source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", value ~trust:Abstract_value.Untrusted "head.sha") ]
      "pull_request.head"
  and checkout =
    node ~kind:Ir.Call
      ~capabilities:[ Ir.Repository_read; Ir.Filesystem_write ]
      "actions/checkout@v4"
  and workspace = node ~kind:Ir.Resource "workspace:source"
  and publish =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Repository_write ]
      ~effects:[ Ir.Repository_change ] "publish"
  in
  let result =
    graph
      [ ref_source; checkout; workspace; publish ]
      [
        edge ~kind:Ir.Data ref_source checkout;
        edge ~kind:Ir.Write checkout workspace;
        edge ~kind:Ir.Read workspace publish;
        edge checkout publish;
      ]
      [ checkout ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "untrusted mutable checkout before publish is TOCTOU"
    ((property "WV-TOCTOU-001" result).state = Property.Violated)

let credential_persistence () =
  let secret =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~secrecy:Abstract_value.Secret "token") ]
      "github.token"
  and checkout =
    node ~kind:Ir.Call
      ~attributes:[ ("persist-credentials", value "true") ]
      ~capabilities:
        [ Ir.Token_read; Ir.Self_hosted_persistence; Ir.Filesystem_write ]
      "actions/checkout@0123456789012345678901234567890123456789"
  and workspace = node ~kind:Ir.Resource "workspace:self-hosted" in
  let result =
    graph
      [ secret; checkout; workspace ]
      [
        edge ~kind:Ir.Data secret checkout;
        edge ~kind:Ir.Persist checkout workspace;
      ]
      [ checkout ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "credentials persisted on a self-hosted workspace are diagnosed"
    ((property "WV-CRED-001" result).state = Property.Violated)

let call_recursion () =
  let first = node ~kind:Ir.Call ~phase:Ir.Compile "workflow:a"
  and second = node ~kind:Ir.Call ~phase:Ir.Compile "workflow:b" in
  let result =
    graph [ first; second ]
      [
        edge ~kind:Ir.Call_edge first second;
        edge ~kind:Ir.Call_edge second first;
      ]
      [ first ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "recursive reusable units violate correctness"
    ((property "WV-CORRECT-001" result).state = Property.Violated)

let authorization_semantics () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and ordinary = node ~kind:Ir.Gate ~phase:Ir.Plan "success condition"
  and misleading = node ~kind:Ir.Gate ~phase:Ir.Plan "branch naming check"
  and approval = node ~kind:Ir.Gate ~phase:Ir.Plan "environment approval"
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  in
  let ordinary_result =
    graph
      [ workflow; ordinary; deploy ]
      [ edge workflow ordinary; edge ordinary deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an ordinary success condition is not authorization"
    ((property "WV-AUTH-001" ordinary_result).state = Property.Violated);
  let misleading_result =
    graph
      [ workflow; misleading; deploy ]
      [ edge workflow misleading; edge misleading deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an authorization keyword in a gate label is not evidence"
    ((property "WV-AUTH-001" misleading_result).state = Property.Violated);
  let approved_result =
    graph
      [ workflow; approval; deploy ]
      [
        edge workflow approval;
        edge approval deploy;
        edge ~condition:Condition.false_ workflow deploy;
      ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an infeasible bypass does not defeat a real approval"
    ((property "WV-AUTH-001" approved_result).state = Property.Proved)

let secret_to_remote_call () =
  let secret =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~secrecy:Abstract_value.Secret "token") ]
      "secret"
  and remote =
    node ~kind:Ir.Call
      ~capabilities:[ Ir.Network; Ir.Secret_access ]
      ~effects:[ Ir.Network_request ] "vendor/action@v1"
  in
  let result =
    graph [ secret; remote ] [ edge ~kind:Ir.Data secret remote ] [ remote ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "secret exfiltration through a remote call is detected"
    ((property "WV-SEC-002" result).state = Property.Violated)

let ai_effect_semantics () =
  let prompt =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "prompt") ]
      "issue.body"
  and agent =
    node ~kind:Ir.Call ~capabilities:[ Ir.Ai_tool; Ir.Network ]
      ~effects:[ Ir.Ai_agent_execution; Ir.Network_request ]
      "vendor/tool@0123456789012345678901234567890123456789"
  in
  let result =
    graph [ prompt; agent ] [ edge ~kind:Ir.Data prompt agent ] [ agent ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "AI effects are semantic and do not depend on product naming"
    ((property "WV-AI-001" result).state = Property.Violated);
  let command_agent =
    node ~kind:Ir.Command ~capabilities:[ Ir.Ai_tool; Ir.Network ]
      ~effects:[ Ir.Ai_agent_execution; Ir.Network_request ]
      "ai-agent command"
  in
  let command_result =
    graph [ prompt; command_agent ]
      [ edge ~kind:Ir.Data prompt command_agent ]
      [ command_agent ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "local AI agent commands share the call security boundary"
    ((property "WV-AI-001" command_result).state = Property.Violated)

let integrity_state_triple () =
  let deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  and trusted =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value "trusted") ]
      "artifact:trusted"
  and uncertain =
    node ~kind:Ir.Resource
      ~attributes:
        [
          ( "value",
            Abstract_value.unknown (Unknown.External_state "artifact producer")
          );
        ]
      "artifact:uncertain"
  in
  let safe =
    graph [ trusted; deploy ] [ edge ~kind:Ir.Read trusted deploy ] [ deploy ]
    |> Verifier.verify ~persona:Verifier.Gate
  and unknown =
    graph [ uncertain; deploy ]
      [ edge ~kind:Ir.Read uncertain deploy ]
      [ deploy ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "trusted artifact proves integrity"
    ((property "WV-ARTIFACT-001" safe).state = Property.Proved);
  match (property "WV-ARTIFACT-001" unknown).state with
  | Property.Unknown (_ :: _) -> ()
  | _ -> fail "uncertain artifact producer must remain Unknown"

let cross_file_program () =
  let source =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "payload") ]
      "event"
  and producer = node ~capabilities:[ Ir.Artifact_write ] "producer"
  and artifact_writer = node ~kind:Ir.Resource "artifact:release"
  and artifact_reader =
    Ir.make_node ~provider:Ir.Github ~kind:Ir.Resource ~name:"artifact:release"
      ~phase:Ir.Run
      ~span:
        (Span.make ~file:"consumer.yml" (Span.position ~byte:1 ())
           (Span.position ~byte:2 ()))
      ()
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "cross-file deploy"
  in
  let producer_graph =
    graph
      [ source; producer; artifact_writer ]
      [
        edge ~kind:Ir.Data source producer;
        edge ~kind:Ir.Write producer artifact_writer;
      ]
      [ producer ]
  and consumer_graph =
    graph
      [ artifact_reader; deploy ]
      [ edge ~kind:Ir.Read artifact_reader deploy ]
      [ deploy ]
  in
  let result =
    Verifier.verify_program ~persona:Verifier.Gate
      [ producer_graph; consumer_graph ]
  in
  expect "same-named persisted resources link across source files"
    ((property "WV-ARTIFACT-001" result).state = Property.Violated)

let tests =
  [
    ("conditions constrain taint propagation", condition_aware_taint);
    ("shell quote boundary is semantic", quote_boundary);
    ("artifact poisoning", artifact_poisoning);
    ("cache poisoning", cache_poisoning);
    ("untrusted checkout TOCTOU", toctou);
    ("credential persistence", credential_persistence);
    ("reusable call recursion", call_recursion);
    ("authorization gate semantics", authorization_semantics);
    ("secret exfiltration through remote call", secret_to_remote_call);
    ("AI effect semantics", ai_effect_semantics);
    ("integrity proved/unknown states", integrity_state_triple);
    ("cross-file program composition", cross_file_program);
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
