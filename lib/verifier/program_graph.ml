let unique_nodes nodes =
  nodes
  |> List.sort_uniq (fun (left : Ir.node) right ->
      String.compare left.id right.id)

let unique_edges edges =
  edges
  |> List.sort_uniq (fun (left : Ir.edge) right ->
      String.compare left.id right.id)

let strip_reference_suffix reference =
  match String.index_opt reference '@' with
  | Some index when not (Util.starts_with ~prefix:"@" reference) ->
      String.sub reference 0 index
  | _ -> reference

let local_target reference =
  let reference =
    if Util.starts_with ~prefix:"child:" reference then
      String.sub reference 6 (String.length reference - 6)
    else reference
  in
  let reference = strip_reference_suffix reference |> Util.normalize_slashes in
  if
    Util.starts_with ~prefix:"./" reference
    || Util.starts_with ~prefix:"../" reference
    || Util.starts_with ~prefix:".github/" reference
    || Util.ends_with ~suffix:".yml" reference
    || Util.ends_with ~suffix:".yaml" reference
  then Some reference
  else None

let basename path =
  let path = Util.normalize_slashes path in
  match String.rindex_opt path '/' with
  | None -> path
  | Some index -> String.sub path (index + 1) (String.length path - index - 1)

let dirname path =
  let path = Util.normalize_slashes path in
  match String.rindex_opt path '/' with
  | None -> ""
  | Some index -> String.sub path 0 index

let is_action_manifest path =
  match basename path |> String.lowercase_ascii with
  | "action.yml" | "action.yaml" -> true
  | _ -> false

let target_graph graphs reference =
  let normalized =
    reference
    |> Util.replace_all ~needle:"./" ~replacement:""
    |> Util.normalize_slashes
  in
  graphs
  |> List.find_opt (fun (graph : Ir.t) ->
      let source = Util.normalize_slashes graph.Ir.source in
      Util.ends_with ~suffix:normalized source
      || basename source = basename normalized
      || is_action_manifest source
         && Util.ends_with ~suffix:normalized (dirname source))

let link_calls graphs graph =
  let ownership =
    graphs
    |> List.concat_map (fun (source_graph : Ir.t) ->
        List.map
          (fun (node : Ir.node) -> (node.id, source_graph))
          source_graph.nodes)
  in
  graph.Ir.nodes
  |> List.filter (fun (node : Ir.node) -> node.kind = Ir.Call)
  |> List.fold_left
       (fun graph call ->
         match local_target call.Ir.name with
         | None -> graph
         | Some reference -> (
             match target_graph graphs reference with
             | None -> graph
             | Some target ->
                 let caller_graph = List.assoc_opt call.id ownership in
                 if
                   Option.fold ~none:false
                     ~some:(fun caller -> caller.Ir.source = target.source)
                     caller_graph
                 then graph
                 else
                   target.entrypoints
                   |> List.fold_left
                        (fun graph entrypoint ->
                          graph
                          |> Ir.add_edge
                               (Ir.make_edge ~kind:Ir.Call_edge ~from_:call.id
                                  ~to_:entrypoint ~label:"local-unit" ())
                          |> Ir.add_edge
                               (Ir.make_edge ~kind:Ir.Control ~from_:call.id
                                  ~to_:entrypoint ~label:"local-unit" ()))
                        graph))
       graph

let resource_written graph (resource : Ir.node) =
  List.exists
    (fun (edge : Ir.edge) ->
      edge.to_ = resource.id && List.mem edge.kind [ Ir.Write; Ir.Persist ])
    graph.Ir.edges

let resource_read graph (resource : Ir.node) =
  List.exists
    (fun (edge : Ir.edge) ->
      edge.from_ = resource.id && List.mem edge.kind [ Ir.Read; Ir.Data ])
    graph.Ir.edges

let link_resources graph =
  let resources =
    List.filter (fun (node : Ir.node) -> node.kind = Ir.Resource) graph.Ir.nodes
  in
  resources
  |> List.fold_left
       (fun graph (writer : Ir.node) ->
         if not (resource_written graph writer) then graph
         else
           resources
           |> List.filter (fun (reader : Ir.node) ->
               reader.Ir.id <> writer.id && reader.name = writer.name
               && resource_read graph reader)
           |> List.fold_left
                (fun graph (reader : Ir.node) ->
                  Ir.add_edge
                    (Ir.make_edge ~kind:Ir.Persist ~from_:writer.id
                       ~to_:reader.id ~label:"cross-file resource" ())
                    graph)
                graph)
       graph

let compose graphs =
  match graphs with
  | [] -> Ir.empty Ir.Github "<program>"
  | (first : Ir.t) :: _ ->
      let graph =
        {
          Ir.provider = first.provider;
          source = "<program>";
          nodes =
            unique_nodes
              (List.concat_map (fun (graph : Ir.t) -> graph.Ir.nodes) graphs);
          edges =
            unique_edges
              (List.concat_map (fun (graph : Ir.t) -> graph.Ir.edges) graphs);
          entrypoints =
            graphs
            |> List.concat_map (fun (graph : Ir.t) -> graph.Ir.entrypoints)
            |> Util.deduplicate_strings;
        }
      in
      graph |> link_calls graphs |> link_resources |> Ir.finalize
