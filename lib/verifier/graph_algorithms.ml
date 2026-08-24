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
  let visited = Hashtbl.create (List.length graph.Ir.nodes) in
  let rec bfs remaining = function
    | [] -> None
    | _ when remaining = 0 -> None
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
                (not (Hashtbl.mem visited id)) && not (List.mem id avoid))
            |> Util.deduplicate_strings
          in
          List.iter (fun id -> Hashtbl.replace visited id ()) next;
          bfs (pred remaining)
            (rest @ List.map (fun id -> (id, current :: path)) next)
  in
  if List.mem source avoid || List.mem target avoid then None
  else (
    Hashtbl.replace visited source ();
    bfs (List.length graph.Ir.nodes) [ (source, []) ])

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
  let entries = graph.entrypoints in
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
  let visited = Hashtbl.create (List.length graph.Ir.nodes) in
  let rec visit path visiting id cycles =
    if List.mem id visiting then
      let cycle =
        id :: Util.take_while (fun value -> value <> id) path |> List.rev
      in
      cycle :: cycles
    else if Hashtbl.mem visited id then cycles
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
      let cycles =
        List.fold_left
          (fun cycles child ->
            visit (id :: path) (id :: visiting) child cycles)
          cycles successors
      in
      Hashtbl.replace visited id ();
      cycles
  in
  let cycles =
    List.fold_left
      (fun cycles (node : Ir.node) -> visit [] [] node.id cycles)
      [] graph.nodes
  in
  cycles
  |> List.map Util.deduplicate_strings
  |> Util.deduplicate_compare Stdlib.compare

let control_cycles graph = cycles ~edge_kinds:[ Ir.Control ] graph
