type solution = { values : (string * Abstract_value.t) list; complete : bool }

let initial (node : Ir.node) =
  if not (Condition.satisfiable node.Ir.condition) then Abstract_value.bottom
  else
    let value =
      List.fold_left
        (fun value (_, attribute) -> Abstract_value.join value attribute)
        Abstract_value.bottom node.Ir.attributes
    in
    match node.unknown with
    | None -> value
    | Some reason -> Abstract_value.join value (Abstract_value.unknown reason)

let value table id =
  Option.value ~default:Abstract_value.bottom (List.assoc_opt id table)

let flows = function
  | Ir.Data | Read | Write | Persist -> true
  | Control | Call_edge | Grant -> false

let solve_indexed indexed =
  let graph = Graph_algorithms.graph indexed in
  let table = Hashtbl.create (List.length graph.Ir.nodes)
  and outgoing = Hashtbl.create (List.length graph.nodes)
  and queued = Hashtbl.create (List.length graph.nodes)
  and queue = Queue.create () in
  let nodes = List.sort Ir.compare_node graph.nodes in
  List.iter
    (fun (node : Ir.node) ->
      Hashtbl.replace table node.id (initial node);
      Queue.add node.id queue;
      Hashtbl.replace queued node.id ())
    nodes;
  Graph_algorithms.feasible_edges indexed
  |> List.filter (fun edge -> flows edge.Ir.kind)
  |> List.sort Ir.compare_edge
  |> List.iter (fun edge ->
      let edges =
        Option.value ~default:[] (Hashtbl.find_opt outgoing edge.Ir.from_)
      in
      Hashtbl.replace outgoing edge.from_ (edge :: edges));
  while not (Queue.is_empty queue) do
    let source = Queue.take queue in
    Hashtbl.remove queued source;
    let source_value =
      Option.value ~default:Abstract_value.bottom
        (Hashtbl.find_opt table source)
    in
    Option.value ~default:[] (Hashtbl.find_opt outgoing source)
    |> List.iter (fun (edge : Ir.edge) ->
        let before =
          Option.value ~default:Abstract_value.bottom
            (Hashtbl.find_opt table edge.to_)
        in
        let after = Abstract_value.join before source_value in
        if before <> after then (
          Hashtbl.replace table edge.to_ after;
          if not (Hashtbl.mem queued edge.to_) then (
            Queue.add edge.to_ queue;
            Hashtbl.replace queued edge.to_ ())))
  done;
  let values =
    List.map
      (fun (node : Ir.node) ->
        ( node.id,
          Option.value ~default:Abstract_value.bottom
            (Hashtbl.find_opt table node.id) ))
      nodes
  in
  { values; complete = true }

let solve graph = solve_indexed (Graph_algorithms.index graph)

let value_at solution id = value solution.values id
