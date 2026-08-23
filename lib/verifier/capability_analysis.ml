let effects_of_node (node : Ir.node) =
  let inferred =
    if node.kind = Ir.Command then
      Script_adapter.analyze Script_adapter.Bash node.name |> fun summary ->
      summary.Script_adapter.effects
    else []
  in
  Util.deduplicate_compare Stdlib.compare (node.effects @ inferred)

let required_by_effect observed_effect =
  match observed_effect with
  | Ir.Repository_change -> [ Ir.Repository_write; Ir.Token_write ]
  | Network_request -> [ Ir.Network ]
  | File_read -> [ Ir.Filesystem_read ]
  | File_write -> [ Ir.Filesystem_write ]
  | Command_execution -> [ Ir.Shell ]
  | Artifact_publish -> [ Ir.Artifact_write ]
  | Cache_publish -> [ Ir.Cache_write ]
  | Deployment_change -> [ Ir.Deployment ]
  | Credential_use -> [ Ir.Secret_access ]
  | Workflow_change -> [ Ir.Repository_write; Ir.Filesystem_write ]
  | Ai_agent_execution -> [ Ir.Ai_tool ]

let privileged =
  [
    Ir.Repository_write;
    Ir.Token_write;
    Ir.Oidc;
    Ir.Cloud_credential;
    Ir.Secret_access;
    Ir.Network;
    Ir.Filesystem_write;
    Ir.Artifact_read;
    Ir.Artifact_write;
    Ir.Cache_read;
    Ir.Cache_write;
    Ir.Deployment;
    Ir.Self_hosted_persistence;
    Ir.Ai_tool;
  ]

let minimal_for_path nodes =
  let granted =
    nodes |> List.concat_map (fun (node : Ir.node) -> node.capabilities)
  and required =
    nodes
    |> List.concat_map effects_of_node
    |> List.concat_map required_by_effect
  in
  Util.deduplicate_compare Stdlib.compare
    (List.filter
       (fun capability -> List.mem capability privileged)
       (granted @ required))

let reaches graph source target =
  Option.is_some
    (Graph_algorithms.shortest_path
       ~edge_kinds:[ Ir.Control; Call_edge; Grant; Data; Persist; Read; Write ]
       graph source target)

let capability_matches capability effects =
  let required = List.concat_map required_by_effect effects in
  match capability with
  | Ir.Repository_read | Token_read | Filesystem_read | Shell -> true
  | Oidc | Cloud_credential ->
      List.mem Ir.Deployment_change effects
      || List.mem Ir.Credential_use effects
  | Self_hosted_persistence ->
      List.mem Ir.File_write effects || List.mem Ir.Workflow_change effects
  | Artifact_read -> List.mem Ir.Artifact_publish effects
  | Cache_read -> List.mem Ir.Cache_publish effects
  | capability -> List.mem capability required

let declared_grants graph =
  let has_grant_edge (node : Ir.node) =
    List.exists
      (fun (edge : Ir.edge) ->
        edge.kind = Ir.Grant && (edge.from_ = node.id || edge.to_ = node.id))
      graph.Ir.edges
  in
  graph.Ir.nodes
  |> List.filter (fun (node : Ir.node) ->
      List.mem node.kind [ Ir.Workflow; Ir.Job ] || has_grant_edge node)
  |> List.concat_map (fun (node : Ir.node) ->
      List.map (fun capability -> (node, capability)) node.capabilities)

let excessive_grants graph =
  let sinks =
    graph.Ir.nodes |> List.filter (fun node -> effects_of_node node <> [])
  in
  declared_grants graph
  |> List.filter_map (fun ((grant : Ir.node), capability) ->
      let effects =
        sinks
        |> List.filter (fun (sink : Ir.node) ->
            reaches graph grant.id sink.Ir.id)
        |> List.concat_map effects_of_node
        |> Util.deduplicate_compare Stdlib.compare
      in
      if
        List.mem capability privileged
        && not (capability_matches capability effects)
      then Some (grant, capability)
      else None)
