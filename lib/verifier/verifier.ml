type persona = Gate | Audit | Paranoid

type result = {
  properties : Property.t list;
  diagnostics : Diagnostic.t list;
  complete : bool;
  analyzed_nodes : int;
  analyzed_edges : int;
}

type rule_result = { property : Property.t; diagnostics : Diagnostic.t list }

let persona_name = function
  | Gate -> "gate"
  | Audit -> "audit"
  | Paranoid -> "paranoid"

let attribute name (node : Ir.node) = List.assoc_opt name node.attributes

let reasons_of_value value =
  let value_reasons =
    match value.Abstract_value.value with
    | Unknown_value reasons -> reasons
    | _ -> []
  and trust_reasons =
    match value.trust with
    | Unknown_trust reasons -> reasons
    | _ -> []
  and secrecy_reasons =
    match value.secrecy with
    | Unknown_secrecy reasons -> reasons
    | _ -> []
  in
  Util.deduplicate_compare Unknown.compare
    (value_reasons @ trust_reasons @ secrecy_reasons)

let trace_hop label (node : Ir.node) =
  { Diagnostic.node_id = node.id; label; span = node.span }

type origin_path = From_origin of Ir.node list | Target_only of Ir.node

let shortest_origin_path ~is_origin ~edge_kinds graph (target : Ir.node) =
  match
    graph.Ir.nodes
    |> List.filter is_origin
    |> List.find_map (fun (source : Ir.node) ->
        Graph_algorithms.shortest_path ~edge_kinds graph source.id target.id)
  with
  | Some nodes -> From_origin nodes
  | None -> Target_only target

let origin_nodes = function
  | From_origin nodes -> nodes
  | Target_only target -> [ target ]

let data_trace graph solution (target : Ir.node) =
  let path =
    shortest_origin_path
      ~is_origin:(fun (node : Ir.node) ->
        node.kind = Ir.Resource
        && Abstract_value.is_untrusted (Dataflow.value_at solution node.id))
      ~edge_kinds:[ Ir.Data; Ir.Read; Ir.Write; Ir.Persist ]
      graph target
  and trace_target node =
    trace_hop "command sink contains untrusted data" node
  in
  match path with
  | Target_only _ -> List.map trace_target (origin_nodes path)
  | From_origin nodes ->
      List.mapi
        (fun index node ->
          trace_hop
            (if index = 0 then "untrusted source"
             else if index + 1 = List.length nodes then "command sink"
             else "data flow")
            node)
        nodes

let make_property id state explanation =
  { Property.id; state; subject = None; explanation }

let script_summary (node : Ir.node) = Script_adapter.analyze_node node

let environment_name (node : Ir.node) =
  if node.kind = Ir.Resource && Util.starts_with ~prefix:"env:" node.name then
    Some (String.sub node.name 4 (String.length node.name - 4))
  else None

let shell_identifier_character = function
  | 'a' .. 'z' | '0' .. '9' | '_' -> true
  | _ -> false

let contains_bounded_variable needle value =
  let needle_length = String.length needle
  and value_length = String.length value in
  let rec search offset =
    if offset + needle_length > value_length then false
    else if
      String.sub value offset needle_length = needle
      &&
      let after = offset + needle_length in
      after = value_length || not (shell_identifier_character value.[after])
    then true
    else search (offset + 1)
  in
  search 0

let expansion_mentions environment expansion =
  let environment = String.lowercase_ascii environment
  and expansion = String.lowercase_ascii expansion in
  contains_bounded_variable ("$" ^ environment) expansion
  || contains_bounded_variable ("$env:" ^ environment) expansion
  || List.exists
       (fun form -> Util.contains ~needle:form expansion)
       [
         "${" ^ environment ^ "}";
         "${env:" ^ environment ^ "}";
         "%" ^ environment ^ "%";
         "!" ^ environment ^ "!";
       ]

let environment_flow_is_unsafe summary path =
  match List.find_map environment_name path with
  | None -> summary.Script_adapter.unsafe_interpolation
  | Some environment ->
      summary.expansions
      |> List.exists (fun (expansion : Script_adapter.expansion) ->
          expansion_mentions environment expansion.expansion_text
          && not expansion.expansion_quoted)

let unsafe_untrusted_flow graph solution (command : Ir.node) summary =
  let paths =
    graph.Ir.nodes
    |> List.filter (fun (source : Ir.node) ->
        List.mem source.kind [ Ir.Resource; Ir.Parameter ]
        && Abstract_value.is_untrusted (Dataflow.value_at solution source.id))
    |> List.filter_map (fun (source : Ir.node) ->
        Graph_algorithms.shortest_path
          ~edge_kinds:[ Ir.Data; Ir.Read; Ir.Write; Ir.Persist ]
          graph source.id command.id)
  in
  if paths = [] then summary.Script_adapter.unsafe_interpolation
  else List.exists (environment_flow_is_unsafe summary) paths

let observable_effects graphs =
  graphs
  |> List.concat_map (fun graph ->
      graph.Ir.nodes
      |> List.concat_map (fun (node : Ir.node) ->
          node.effects
          @ if node.kind = Ir.Command then (script_summary node).effects else []))
  |> Util.deduplicate_compare Stdlib.compare

let injection_rule graph solution =
  let commands =
    List.filter (fun (node : Ir.node) -> node.kind = Ir.Command) graph.Ir.nodes
  in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (command : Ir.node) ->
        let value = Dataflow.value_at solution command.Ir.id in
        let summary = script_summary command in
        if
          Abstract_value.is_untrusted value
          && unsafe_untrusted_flow graph solution command summary
        then
          let diagnostic =
            Diagnostic.make ~rule_id:"WV-SEC-001" ~severity:Error
              ~confidence:High
              ~message:
                "untrusted workflow data reaches a shell command boundary"
              ~span:command.span
              ~trace:(data_trace graph solution command)
              ~capabilities:[ Ir.Shell ]
              ~evidence:
                [
                  "abstract trust = untrusted";
                  "script boundary = unquoted or provider-substituted";
                ]
              ~fix:
                {
                  kind = "environment-boundary";
                  description =
                    "pass the value through an environment variable and quote \
                     it in the target shell";
                  replacement = None;
                  span = Some command.span;
                }
              ()
          in
          (Property.Violated :: states, diagnostic :: diagnostics)
        else
          let reasons = reasons_of_value value in
          if reasons <> [] then (Property.Unknown reasons :: states, diagnostics)
          else (Property.Proved :: states, diagnostics))
      ([], []) commands
  in
  {
    property =
      make_property "WV-SEC-001" (Property.combine states)
        "untrusted values do not cross an unquoted command boundary";
    diagnostics;
  }

let secret_rule graph solution =
  let sinks =
    List.filter
      (fun (node : Ir.node) ->
        node.kind = Ir.Command
        || List.mem Ir.Network_request node.effects
        || (node.kind = Ir.Call && List.mem Ir.Network node.capabilities))
      graph.Ir.nodes
  in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (sink : Ir.node) ->
        let value = Dataflow.value_at solution sink.Ir.id in
        let summary =
          if sink.kind = Ir.Command then Some (script_summary sink) else None
        in
        let network, output =
          match summary with
          | Some summary -> (summary.secret_to_network, summary.secret_to_output)
          | None -> (List.mem Ir.Network_request sink.effects, false)
        and uncertainty =
          ((match sink.unknown with
             | Some reason -> [ reason ]
             | None -> [])
          @
          match summary with
          | Some summary -> summary.unknowns
          | None -> [])
          |> Util.deduplicate_compare Unknown.compare
        in
        let observable = network || output in
        if Abstract_value.is_secret value && observable then
          let capabilities =
            [ Ir.Secret_access ]
            @ (if sink.kind = Ir.Command then [ Ir.Shell ] else [])
            @ if network then [ Ir.Network ] else []
          in
          let diagnostic =
            Diagnostic.make ~rule_id:"WV-SEC-002" ~severity:Critical
              ~confidence:High
              ~message:
                (if network then "a secret reaches a network-capable command"
                 else "a secret reaches workflow output or logs")
              ~span:sink.span
              ~trace:(data_trace graph solution sink)
              ~capabilities
              ~evidence:
                [
                  "abstract secrecy = secret";
                  (if network then "script effect = network_request"
                   else "script effect = process output");
                ]
              ()
          in
          (Property.Violated :: states, diagnostic :: diagnostics)
        else if Abstract_value.is_secret value && uncertainty <> [] then
          (Property.Unknown uncertainty :: states, diagnostics)
        else
          match (value.secrecy, uncertainty) with
          | Abstract_value.Unknown_secrecy reasons, _ when observable ->
              (Property.Unknown reasons :: states, diagnostics)
          | _, reasons
            when reasons <> [] && List.mem Ir.Network sink.capabilities ->
              (Property.Unknown reasons :: states, diagnostics)
          | _ -> (Property.Proved :: states, diagnostics))
      ([], []) sinks
  in
  {
    property =
      make_property "WV-SEC-002" (Property.combine states)
        "secret values do not reach network, output, or logging effects";
    diagnostics;
  }

let immutable_reference reference =
  match Dependency_identity.classify_reference reference with
  | Dependency_identity.Local | Dependency_identity.Immutable -> Some true
  | Dependency_identity.Mutable -> Some false
  | Dependency_identity.Unknown -> None

let locked_dependency (node : Ir.node) =
  match
    Option.bind (attribute "dependency.digest" node) Abstract_value.constants
  with
  | Some (_ :: _ as digests) ->
      List.for_all Dependency_identity.valid_content_digest digests
  | _ -> false

let supply_chain_rule graph =
  let calls =
    List.filter (fun (node : Ir.node) -> node.kind = Ir.Call) graph.Ir.nodes
  in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (call : Ir.node) ->
        match
          if locked_dependency call then Some true
          else immutable_reference call.Ir.name
        with
        | Some true -> (Property.Proved :: states, diagnostics)
        | Some false ->
            let diagnostic =
              Diagnostic.make ~rule_id:"WV-SUPPLY-001" ~severity:Warning
                ~confidence:High
                ~message:
                  ("dependency is not pinned to immutable content: " ^ call.name)
                ~span:call.span
                ~trace:[ trace_hop "mutable dependency" call ]
                ~evidence:[ "reference = " ^ call.name ]
                ~fix:
                  {
                    kind = "pin-dependency";
                    description =
                      "resolve and replace the reference with an immutable \
                       revision";
                    replacement = None;
                    span = Some call.span;
                  }
                ()
            in
            (Property.Violated :: states, diagnostic :: diagnostics)
        | None ->
            ( Property.Unknown [ Unknown.Unresolved_dependency call.name ]
              :: states,
              diagnostics ))
      ([], []) calls
  in
  {
    property =
      make_property "WV-SUPPLY-001" (Property.combine states)
        "remote executable dependencies are content-addressed";
    diagnostics;
  }

let permission_rule graph =
  let grants = Capability_analysis.declared_grants graph in
  let demands = Capability_analysis.grant_demands graph in
  let unused =
    demands
    |> List.filter_map (function
      | grant, Capability_analysis.Excessive -> Some grant
      | _, (Capability_analysis.Required | Capability_analysis.Unknown _) ->
          None)
  in
  let diagnostics =
    List.map
      (fun ((node : Ir.node), capability) ->
        Diagnostic.make ~rule_id:"WV-PERM-001" ~severity:Warning
          ~confidence:High
          ~message:
            ("granted capability is not required: "
            ^ Ir.capability_name capability)
          ~span:node.span
          ~trace:[ trace_hop "capability grant" node ]
          ~capabilities:[ capability ]
          ~evidence:[ "no reachable effect requires this capability" ]
          ~fix:
            {
              kind = "reduce-permissions";
              description = "remove the unused grant";
              replacement = None;
              span = Some node.span;
            }
          ())
      unused
  in
  let state =
    if grants = [] then Property.Not_applicable
    else
      demands
      |> List.map (function
        | _, Capability_analysis.Required -> Property.Proved
        | _, Capability_analysis.Excessive -> Violated
        | _, Capability_analysis.Unknown reasons -> Property.Unknown reasons)
      |> Property.combine
  in
  {
    property =
      make_property "WV-PERM-001" state
        "granted capabilities are required by a reachable effect";
    diagnostics;
  }

let privileged_effect (node : Ir.node) =
  List.exists
    (fun observed ->
      List.mem observed
        [ Ir.Repository_change; Ir.Deployment_change; Ir.Workflow_change ])
    node.Ir.effects
  || node.kind = Ir.Command
     && List.exists
          (fun observed ->
            List.mem observed
              [ Ir.Repository_change; Ir.Deployment_change; Ir.Workflow_change ])
          (script_summary node).effects

let flow_edge_kinds =
  [ Ir.Data; Ir.Read; Ir.Write; Ir.Persist; Ir.Control; Ir.Call_edge ]

let path_trace first_label middle_label last_label path =
  List.mapi
    (fun index node ->
      trace_hop
        (if index = 0 then first_label
         else if index + 1 = List.length path then last_label
         else middle_label)
        node)
    path

let initial_untrusted (node : Ir.node) =
  List.exists
    (fun (_, value) -> Abstract_value.is_untrusted value)
    node.attributes

let integrity_rule ~rule_id ~label ~resource_matches ~write_capability
    ~read_capability graph solution =
  let resources =
    List.filter
      (fun (node : Ir.node) -> node.kind = Ir.Resource && resource_matches node)
      graph.Ir.nodes
  and sinks = List.filter privileged_effect graph.nodes in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (resource : Ir.node) ->
        let value = Dataflow.value_at solution resource.id in
        let attack =
          if Abstract_value.is_untrusted value then
            sinks
            |> List.find_map (fun (sink : Ir.node) ->
                Graph_algorithms.shortest_path ~edge_kinds:flow_edge_kinds graph
                  resource.id sink.Ir.id
                |> Option.map (fun suffix -> (sink, suffix)))
          else None
        in
        match attack with
        | Some (sink, suffix) ->
            let prefix =
              shortest_origin_path ~is_origin:initial_untrusted
                ~edge_kinds:[ Ir.Data; Ir.Write; Ir.Persist ]
                graph resource
              |> origin_nodes
            in
            let path =
              prefix
              @
              match suffix with
              | _resource :: rest -> rest
              | [] -> []
            in
            let capabilities =
              write_capability :: read_capability
              :: Capability_analysis.minimal_for_path path
              |> Util.deduplicate_compare Stdlib.compare
            in
            let diagnostic =
              Diagnostic.make ~rule_id ~severity:Critical ~confidence:High
                ~message:
                  ("untrusted data can poison " ^ label
                 ^ " consumed by a privileged effect")
                ~span:sink.span
                ~trace:
                  (path_trace "untrusted producer" (label ^ " propagation")
                     "privileged consumer" path)
                ~capabilities
                ~evidence:
                  [
                    "resource = " ^ resource.name; "abstract trust = untrusted";
                  ]
                ()
            in
            (Property.Violated :: states, diagnostic :: diagnostics)
        | None ->
            let reasons = reasons_of_value value in
            if reasons <> [] then
              (Property.Unknown reasons :: states, diagnostics)
            else (Property.Proved :: states, diagnostics))
      ([], []) resources
  in
  {
    property =
      make_property rule_id
        (if resources = [] then Property.Not_applicable
         else Property.combine states)
        (label ^ " integrity is preserved across producers and consumers");
    diagnostics;
  }

let artifact_rule graph solution =
  integrity_rule ~rule_id:"WV-ARTIFACT-001" ~label:"artifact"
    ~resource_matches:(fun node ->
      Util.starts_with ~prefix:"artifact:" (String.lowercase_ascii node.Ir.name)
      || List.exists
           (fun capability ->
             List.mem capability [ Ir.Artifact_read; Ir.Artifact_write ])
           node.capabilities)
    ~write_capability:Ir.Artifact_write ~read_capability:Ir.Artifact_read graph
    solution

let cache_rule graph solution =
  integrity_rule ~rule_id:"WV-CACHE-001" ~label:"cache"
    ~resource_matches:(fun node ->
      Util.starts_with ~prefix:"cache:" (String.lowercase_ascii node.Ir.name)
      || List.exists
           (fun capability ->
             List.mem capability [ Ir.Cache_read; Ir.Cache_write ])
           node.capabilities)
    ~write_capability:Ir.Cache_write ~read_capability:Ir.Cache_read graph
    solution

let toctou_rule graph solution =
  let checkouts =
    graph.Ir.nodes
    |> List.filter (fun (node : Ir.node) ->
        node.kind = Ir.Call
        &&
        let name = String.lowercase_ascii node.name in
        Util.contains ~needle:"checkout" name
        || Util.contains ~needle:"clone" name)
  and sinks = List.filter privileged_effect graph.nodes in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (checkout : Ir.node) ->
        let mutable_reference =
          immutable_reference checkout.name <> Some true
        in
        let untrusted =
          Abstract_value.is_untrusted (Dataflow.value_at solution checkout.id)
        in
        let attack =
          if mutable_reference && untrusted then
            sinks
            |> List.find_map (fun (sink : Ir.node) ->
                Graph_algorithms.shortest_path ~edge_kinds:flow_edge_kinds graph
                  checkout.id sink.Ir.id)
          else None
        in
        match attack with
        | None -> (Property.Proved :: states, diagnostics)
        | Some path ->
            let capabilities = Capability_analysis.minimal_for_path path in
            let diagnostic =
              Diagnostic.make ~rule_id:"WV-TOCTOU-001" ~severity:Critical
                ~confidence:High
                ~message:
                  "an untrusted mutable checkout reaches a privileged effect"
                ~span:checkout.span
                ~trace:
                  (path_trace "untrusted checkout" "mutable workspace"
                     "privileged effect" path)
                ~capabilities
                ~evidence:
                  [
                    "checkout reference is mutable";
                    "checkout selector is untrusted";
                  ]
                ()
            in
            (Property.Violated :: states, diagnostic :: diagnostics))
      ([], []) checkouts
  in
  {
    property =
      make_property "WV-TOCTOU-001"
        (if checkouts = [] then Property.Not_applicable
         else Property.combine states)
        "untrusted checkout selection cannot race a privileged consumer";
    diagnostics;
  }

let credential_persistence_rule (graph : Ir.t) solution =
  let candidates =
    graph.Ir.nodes
    |> List.filter (fun (node : Ir.node) ->
        node.kind = Ir.Call
        && (List.mem Ir.Self_hosted_persistence node.capabilities
           || List.exists
                (fun (edge : Ir.edge) ->
                  edge.from_ = node.id && edge.kind = Ir.Persist)
                graph.edges)
        &&
        match attribute "persist-credentials" node with
        | None -> true
        | Some value -> Abstract_value.constants value <> Some [ "false" ])
  in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (candidate : Ir.node) ->
        let value = Dataflow.value_at solution candidate.id in
        if Abstract_value.is_secret value then
          let path =
            shortest_origin_path
              ~is_origin:(fun node ->
                List.exists
                  (fun (_, value) -> Abstract_value.is_secret value)
                  node.Ir.attributes)
              ~edge_kinds:[ Ir.Data; Ir.Persist; Ir.Write ]
              graph candidate
            |> origin_nodes
          in
          let capabilities =
            Ir.Secret_access :: Ir.Self_hosted_persistence
            :: Capability_analysis.minimal_for_path path
            |> Util.deduplicate_compare Stdlib.compare
          in
          let diagnostic =
            Diagnostic.make ~rule_id:"WV-CRED-001" ~severity:Critical
              ~confidence:High
              ~message:
                "a credential can persist beyond its intended step or job"
              ~span:candidate.span
              ~trace:
                (path_trace "credential source" "credential propagation"
                   "persistent consumer" path)
              ~capabilities
              ~evidence:[ "abstract secrecy = secret"; "persist edge present" ]
              ()
          in
          (Property.Violated :: states, diagnostic :: diagnostics)
        else
          match value.secrecy with
          | Abstract_value.Unknown_secrecy reasons ->
              (Property.Unknown reasons :: states, diagnostics)
          | _ -> (Property.Proved :: states, diagnostics))
      ([], []) candidates
  in
  {
    property =
      make_property "WV-CRED-001"
        (if candidates = [] then Property.Not_applicable
         else Property.combine states)
        "credentials do not persist into reusable runner state";
    diagnostics;
  }

type gate_assurance =
  | Trusted_gate
  | Unknown_gate of Unknown.reason list
  | Not_authorization_gate

let gate_mechanism (node : Ir.node) =
  match attribute "mechanism" node with
  | None -> false
  | Some value -> (
      match Abstract_value.constants value with
      | None -> false
      | Some mechanisms ->
          List.exists
            (fun mechanism ->
              List.mem
                (String.lowercase_ascii mechanism)
                [ "approval"; "manual" ])
            mechanisms)

let protected_reference_atom atom =
  List.mem
    (String.lowercase_ascii atom)
    [
      "(github.ref_protected==true)";
      "(true==github.ref_protected)";
      "(ci_commit_ref_protected==\"true\")";
      "(\"true\"==ci_commit_ref_protected)";
      "github.ref_protected";
    ]

let protected_reference_gate (node : Ir.node) =
  Condition.atoms node.condition
  |> List.exists (fun atom ->
      protected_reference_atom atom
      && Condition.implies node.condition (Condition.atom atom))

let explicit_approval_gate (node : Ir.node) =
  let name = String.lowercase_ascii node.name in
  name = "environment approval"
  || (node.provider = Ir.Circleci && Util.starts_with ~prefix:"approval:" name)

let authorization_gate solution (node : Ir.node) =
  let authorization_evidence =
    gate_mechanism node
    || protected_reference_gate node
    || explicit_approval_gate node
  in
  let value = Dataflow.value_at solution node.id in
  if (not authorization_evidence) || Abstract_value.is_untrusted value then
    Not_authorization_gate
  else
    let reasons = reasons_of_value value in
    if reasons = [] then Trusted_gate else Unknown_gate reasons

let environment_authorization_reasons graph (sink : Ir.node) =
  graph.Ir.nodes
  |> List.filter_map (fun (resource : Ir.node) ->
      if
        resource.kind = Ir.Resource
        && Util.starts_with ~prefix:"environment:"
             (String.lowercase_ascii resource.name)
        && Option.is_some
             (Graph_algorithms.shortest_path
                ~edge_kinds:[ Ir.Grant; Ir.Control; Ir.Call_edge ]
                graph resource.id sink.id)
      then
        Some
          (match resource.unknown with
          | Some reason -> reason
          | None ->
              Unknown.External_state ("protection rules for " ^ resource.name))
      else None)
  |> Util.deduplicate_compare Unknown.compare

let authorization_rule graph solution =
  let sinks = List.filter privileged_effect graph.Ir.nodes
  and trusted_gates =
    List.filter
      (fun (node : Ir.node) ->
        node.kind = Ir.Gate && authorization_gate solution node = Trusted_gate)
      graph.nodes
  and unknown_gates =
    List.filter_map
      (fun (node : Ir.node) ->
        if node.kind <> Ir.Gate then None
        else
          match authorization_gate solution node with
          | Unknown_gate reasons -> Some (node, reasons)
          | Trusted_gate | Not_authorization_gate -> None)
      graph.nodes
  in
  let states, diagnostics =
    List.fold_left
      (fun (states, diagnostics) (sink : Ir.node) ->
        let trusted_dominators =
          List.filter
            (fun (gate : Ir.node) ->
              Graph_algorithms.dominates graph ~dominator:gate.id
                ~node:sink.Ir.id)
            trusted_gates
        in
        let unknown_dominator_reasons =
          unknown_gates
          |> List.filter_map (fun ((gate : Ir.node), reasons) ->
              if
                Graph_algorithms.dominates graph ~dominator:gate.id
                  ~node:sink.Ir.id
              then Some reasons
              else None)
          |> List.concat
          |> Util.deduplicate_compare Unknown.compare
        in
        if trusted_dominators <> [] then (Property.Proved :: states, diagnostics)
        else if unknown_dominator_reasons <> [] then
          (Property.Unknown unknown_dominator_reasons :: states, diagnostics)
        else
          let environment_reasons =
            environment_authorization_reasons graph sink
          in
          if environment_reasons <> [] then
            (Property.Unknown environment_reasons :: states, diagnostics)
          else
            let path =
              List.find_map
                (fun entry ->
                  Graph_algorithms.shortest_path ~edge_kinds:[ Ir.Control ]
                    ~avoid:
                      (List.map (fun (gate : Ir.node) -> gate.id) trusted_gates)
                    graph entry sink.id)
                graph.entrypoints
            in
            let trace =
              match path with
              | Some nodes -> List.map (trace_hop "authorization bypass") nodes
              | None ->
                  [ trace_hop "privileged sink without dominating gate" sink ]
            in
            let diagnostic =
              Diagnostic.make ~rule_id:"WV-AUTH-001" ~severity:Error
                ~confidence:High
                ~message:
                  "a privileged effect is reachable without a dominating \
                   authorization gate"
                ~span:sink.span ~trace ~capabilities:sink.capabilities
                ~evidence:[ "dominator set contains no Gate node" ]
                ()
            in
            (Property.Violated :: states, diagnostic :: diagnostics))
      ([], []) sinks
  in
  {
    property =
      make_property "WV-AUTH-001" (Property.combine states)
        "every privileged effect is dominated by an authorization gate";
    diagnostics;
  }

let correctness_rule graph =
  let issues = Ir.validate graph in
  let cycles = Graph_algorithms.control_cycles graph in
  let call_cycles =
    Graph_algorithms.cycles ~edge_kinds:[ Ir.Call_edge ] graph
  in
  let diagnostics =
    List.map
      (fun issue ->
        let span =
          List.find_map (Ir.find_node graph) issue.Ir.node_ids
          |> Option.map (fun node -> node.Ir.span)
          |> Option.value ~default:Span.none
        in
        Diagnostic.make ~rule_id:"WV-CORRECT-001" ~severity:Error
          ~confidence:High ~message:issue.message ~span ~evidence:[ issue.code ]
          ())
      issues
    @ List.map
        (fun cycle ->
          let span =
            List.find_map (Ir.find_node graph) cycle
            |> Option.map (fun node -> node.Ir.span)
            |> Option.value ~default:Span.none
          in
          Diagnostic.make ~rule_id:"WV-CORRECT-001" ~severity:Error
            ~confidence:High ~message:"control dependency cycle" ~span
            ~evidence:[ String.concat " -> " cycle ]
            ())
        cycles
    @ List.map
        (fun cycle ->
          let span =
            List.find_map (Ir.find_node graph) cycle
            |> Option.map (fun node -> node.Ir.span)
            |> Option.value ~default:Span.none
          in
          Diagnostic.make ~rule_id:"WV-CORRECT-001" ~severity:Error
            ~confidence:High ~message:"recursive call graph" ~span
            ~evidence:[ String.concat " -> " cycle ]
            ())
        call_cycles
  in
  let applicable = graph.nodes <> [] in
  {
    property =
      make_property "WV-CORRECT-001"
        (if diagnostics <> [] then Property.Violated
         else if applicable then Proved
         else Not_applicable)
        "the lowered graph is well-formed, phase-valid, and acyclic";
    diagnostics;
  }

let ai_rule graph solution =
  let agents =
    graph.Ir.nodes
    |> List.filter (fun (node : Ir.node) ->
        let name = String.lowercase_ascii node.name in
        (node.kind = Ir.Call || node.kind = Ir.Command)
        && (List.mem Ir.Ai_agent_execution node.effects
           || List.mem Ir.Ai_tool node.capabilities
           || List.exists
                (fun marker -> Util.contains ~needle:marker name)
                [
                  "copilot";
                  "openai";
                  "claude";
                  "gemini";
                  "ai-agent";
                  "agent-action";
                ]))
  in
  let vulnerable =
    List.filter
      (fun (node : Ir.node) ->
        Abstract_value.is_untrusted (Dataflow.value_at solution node.id)
        && (List.mem Ir.Network node.capabilities
           || List.mem Ir.Ai_tool node.capabilities))
      agents
  in
  let diagnostics =
    List.map
      (fun (node : Ir.node) ->
        Diagnostic.make ~rule_id:"WV-AI-001" ~severity:Critical ~confidence:High
          ~message:
            "untrusted prompt data reaches an AI agent with tool or network \
             authority"
          ~span:node.Ir.span
          ~trace:(data_trace graph solution node)
          ~capabilities:[ Ir.Ai_tool; Ir.Network ] ())
      vulnerable
  in
  {
    property =
      make_property "WV-AI-001"
        (if agents = [] then Property.Not_applicable
         else if vulnerable = [] then Proved
         else Violated)
        "AI agent input is trusted or isolated from tools and network";
    diagnostics;
  }

let self_modification_rule graph =
  let write_granted =
    List.exists
      (fun (node : Ir.node) -> List.mem Ir.Repository_write node.capabilities)
      graph.Ir.nodes
  in
  let offenders =
    if not write_granted then []
    else
      List.filter
        (fun (node : Ir.node) ->
          node.kind = Ir.Command
          && List.mem Ir.Workflow_change (script_summary node).effects)
        graph.nodes
  in
  let diagnostics =
    List.map
      (fun (node : Ir.node) ->
        Diagnostic.make ~rule_id:"WV-SELF-001" ~severity:Critical
          ~confidence:High
          ~message:
            "workflow code can modify CI configuration with repository write \
             authority"
          ~span:node.Ir.span
          ~trace:[ trace_hop "self-modifying command" node ]
          ~capabilities:[ Ir.Repository_write; Ir.Filesystem_write; Ir.Shell ]
          ())
      offenders
  in
  {
    property =
      make_property "WV-SELF-001"
        (if not write_granted then Not_applicable
         else if offenders = [] then Proved
         else Violated)
        "workflow execution cannot rewrite trusted CI definitions";
    diagnostics;
  }

let verify ~persona:_ graph =
  let solution = Dataflow.solve graph in
  let results =
    [
      correctness_rule graph;
      injection_rule graph solution;
      secret_rule graph solution;
      supply_chain_rule graph;
      permission_rule graph;
      authorization_rule graph solution;
      artifact_rule graph solution;
      cache_rule graph solution;
      toctou_rule graph solution;
      credential_persistence_rule graph solution;
      ai_rule graph solution;
      self_modification_rule graph;
    ]
  in
  {
    properties =
      List.map (fun result -> result.property) results
      |> List.sort Property.compare;
    diagnostics =
      List.concat_map (fun result -> result.diagnostics) results
      |> List.sort Diagnostic.compare;
    complete =
      solution.complete
      && not
           (List.exists
              (fun (node : Ir.node) -> Option.is_some node.unknown)
              graph.nodes);
    analyzed_nodes = List.length graph.nodes;
    analyzed_edges = List.length graph.edges;
  }

let verify_program ~persona graphs =
  Program_graph.compose graphs |> verify ~persona

let should_fail persona (result : result) =
  match persona with
  | Audit -> false
  | Gate ->
      List.exists
        (fun diagnostic ->
          diagnostic.Diagnostic.confidence = High
          && List.mem diagnostic.severity [ Diagnostic.Critical; Error ])
        result.diagnostics
  | Paranoid ->
      result.diagnostics <> []
      || List.exists
           (fun property ->
             match property.Property.state with
             | Unknown _ -> true
             | _ -> false)
           result.properties

let to_json (result : result) =
  Json.Object
    [
      ("analyzed_edges", Json.Int result.analyzed_edges);
      ("analyzed_nodes", Json.Int result.analyzed_nodes);
      ("complete", Json.Bool result.complete);
      ( "diagnostics",
        Json.Array (List.map Diagnostic.to_json result.diagnostics) );
      ("properties", Json.Array (List.map Property.to_json result.properties));
    ]
