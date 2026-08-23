let matching_edge kinds (edge : Ir.edge) =
  match kinds with
  | None -> true
  | Some values -> List.mem edge.kind values

let feasible_edge graph (edge : Ir.edge) =
  let node_condition id =
    Ir.find_node graph id
    |> Option.fold ~none:Condition.false_ ~some:(fun (node : Ir.node) ->
        node.condition)
  in
  Condition.and_ edge.condition
    (Condition.and_ (node_condition edge.from_) (node_condition edge.to_))
  |> Condition.satisfiable

let shortest_path ?edge_kinds ?(avoid = []) graph source target =
  let rec bfs visited = function
    | [] -> None
    | (current, path) :: rest ->
        if current = target then
          Some
            (List.rev (current :: path)
            |> List.filter_map (fun id -> Ir.find_node graph id))
        else
          let next =
            graph.Ir.edges
            |> List.filter (fun (edge : Ir.edge) ->
                edge.from_ = current
                && matching_edge edge_kinds edge
                && feasible_edge graph edge)
            |> List.map (fun edge -> edge.Ir.to_)
            |> List.filter (fun id ->
                (not (List.mem id visited)) && not (List.mem id avoid))
            |> Util.deduplicate_strings
          in
          bfs (next @ visited)
            (rest @ List.map (fun id -> (id, current :: path)) next)
  in
  if List.mem source avoid || List.mem target avoid then None
  else bfs [ source ] [ (source, []) ]

let intersections sets =
  match sets with
  | [] -> []
  | first :: rest ->
      List.fold_left
        (fun accumulator values ->
          List.filter (fun item -> List.mem item values) accumulator)
        first rest

let dominates graph ~dominator ~node =
  let ids = List.map (fun (item : Ir.node) -> item.id) graph.Ir.nodes in
  let entries =
    if graph.entrypoints <> [] then graph.entrypoints
    else
      ids
      |> List.filter (fun id ->
          not
            (List.exists
               (fun (edge : Ir.edge) ->
                 edge.kind = Ir.Control && edge.to_ = id
                 && feasible_edge graph edge)
               graph.edges))
  in
  let table = Hashtbl.create (List.length ids) in
  List.iter
    (fun id ->
      Hashtbl.replace table id (if List.mem id entries then [ id ] else ids))
    ids;
  let changed = ref true in
  while !changed do
    changed := false;
    List.iter
      (fun id ->
        if not (List.mem id entries) then
          let predecessors =
            graph.edges
            |> List.filter (fun (edge : Ir.edge) ->
                edge.kind = Ir.Control && edge.to_ = id
                && feasible_edge graph edge)
            |> List.map (fun edge -> edge.Ir.from_)
          in
          let updated =
            if predecessors = [] then [ id ]
            else
              id
              :: intersections
                   (List.map
                      (fun predecessor ->
                        Option.value ~default:ids
                          (Hashtbl.find_opt table predecessor))
                      predecessors)
              |> Util.deduplicate_strings
          in
          if Option.value ~default:[] (Hashtbl.find_opt table id) <> updated
          then (
            Hashtbl.replace table id updated;
            changed := true))
      ids
  done;
  match Hashtbl.find_opt table node with
  | Some values -> List.mem dominator values
  | None -> false

let cycles ?edge_kinds graph =
  let rec visit path visiting visited id cycles =
    if List.mem id visiting then
      let cycle =
        id :: Util.take_while (fun value -> value <> id) path |> List.rev
      in
      (visited, cycle :: cycles)
    else if List.mem id visited then (visited, cycles)
    else
      let successors =
        graph.Ir.edges
        |> List.filter (fun (edge : Ir.edge) ->
            edge.from_ = id
            && matching_edge edge_kinds edge
            && feasible_edge graph edge)
        |> List.map (fun edge -> edge.Ir.to_)
        |> Util.deduplicate_strings
      in
      let visited, cycles =
        List.fold_left
          (fun (visited, cycles) child ->
            visit (id :: path) (id :: visiting) visited child cycles)
          (visited, cycles) successors
      in
      (id :: visited, cycles)
  in
  let _, cycles =
    List.fold_left
      (fun (visited, cycles) (node : Ir.node) ->
        let visited, found = visit [] [] visited node.id [] in
        (visited, found @ cycles))
      ([], []) graph.nodes
  in
  cycles
  |> List.map Util.deduplicate_strings
  |> Util.deduplicate_compare Stdlib.compare

let control_cycles graph = cycles ~edge_kinds:[ Ir.Control ] graph
