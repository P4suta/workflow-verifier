let effects_of_node (node : Ir.node) =
  let inferred =
    if node.kind = Ir.Command then
      (Script_adapter.analyze_node node).Script_adapter.effects
    else []
  in
  Util.deduplicate_compare Stdlib.compare (node.effects @ inferred)

let required_by_effect observed_effect =
  match observed_effect with
  | Ir.Repository_change -> [ Ir.Repository_write; Ir.Token_write ]
  | Network_request -> [ Ir.Network ]
  | File_read -> []
  | File_write -> [ Ir.Filesystem_write ]
  | Command_execution -> []
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

let capability_matches capability effects =
  let required = List.concat_map required_by_effect effects in
  match capability with
  | Ir.Oidc | Cloud_credential ->
      List.mem Ir.Deployment_change effects
      || List.mem Ir.Credential_use effects
  | Self_hosted_persistence ->
      List.mem Ir.File_write effects || List.mem Ir.Workflow_change effects
  | Artifact_read -> List.mem Ir.Artifact_publish effects
  | Cache_read -> List.mem Ir.Cache_publish effects
  | capability -> List.mem capability required

let declared_grants_indexed indexed =
  let has_grant_edge (node : Ir.node) =
    Graph_algorithms.has_incident_edge ~edge_kinds:[ Ir.Grant ] indexed node.id
  in
  Graph_algorithms.nodes indexed
  |> List.filter (fun (node : Ir.node) ->
      List.mem node.kind [ Ir.Workflow; Ir.Job ] || has_grant_edge node)
  |> List.concat_map (fun (node : Ir.node) ->
      List.map (fun capability -> (node, capability)) node.capabilities)

let declared_grants graph =
  declared_grants_indexed (Graph_algorithms.index graph)

type demand = Required | Excessive | Unknown of Unknown.reason list

let value_unknowns value =
  let values =
    match value.Abstract_value.value with
    | Unknown_value reasons -> reasons
    | _ -> []
  and trust =
    match value.trust with
    | Unknown_trust reasons -> reasons
    | _ -> []
  and secrecy =
    match value.secrecy with
    | Unknown_secrecy reasons -> reasons
    | _ -> []
  in
  values @ trust @ secrecy

let node_unknowns (node : Ir.node) =
  (match node.unknown with
    | Some reason -> [ reason ]
    | None -> [])
  @ List.concat_map (fun (_, value) -> value_unknowns value) node.attributes
  |> Util.deduplicate_compare Unknown.compare

let grant_demands_indexed indexed =
  let reachable_by_owner =
    Hashtbl.create (max 1 (List.length (Graph_algorithms.nodes indexed)))
  in
  let reachable (grant : Ir.node) =
    match Hashtbl.find_opt reachable_by_owner grant.id with
    | Some nodes -> nodes
    | None ->
        let nodes = Graph_algorithms.reachable_from_indexed indexed grant.id in
        Hashtbl.replace reachable_by_owner grant.id nodes;
        nodes
  in
  declared_grants_indexed indexed
  |> List.map (fun ((grant : Ir.node), capability) ->
      let reachable = reachable grant in
      let effects =
        reachable
        |> List.concat_map effects_of_node
        |> Util.deduplicate_compare Stdlib.compare
      and unknowns =
        reachable
        |> List.concat_map node_unknowns
        |> Util.deduplicate_compare Unknown.compare
      in
      let demand =
        if not (List.mem capability privileged) then Required
        else if capability_matches capability effects then Required
        else if unknowns <> [] then Unknown unknowns
        else Excessive
      in
      ((grant, capability), demand))

let grant_demands graph = grant_demands_indexed (Graph_algorithms.index graph)

let excessive_grants_indexed indexed =
  grant_demands_indexed indexed
  |> List.filter_map (function
    | grant, Excessive -> Some grant
    | _, (Required | Unknown _) -> None)

let excessive_grants graph =
  excessive_grants_indexed (Graph_algorithms.index graph)
