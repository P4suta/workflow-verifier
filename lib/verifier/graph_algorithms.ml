module String_set = Set.Make (String)

type indexed = {
  graph : Ir.t;
  nodes_by_id : (string, Ir.node) Hashtbl.t;
  feasible_edges : Ir.edge list;
  outgoing : (string, Ir.edge list) Hashtbl.t;
  incoming : (string, Ir.edge list) Hashtbl.t;
  entrypoints : (string, unit) Hashtbl.t;
  dominators : (string, String_set.t) Hashtbl.t Lazy.t;
}

let matching_edge kinds (edge : Ir.edge) =
  match kinds with
  | None -> true
  | Some values -> List.mem edge.kind values

let index graph =
  let size = max 1 (List.length graph.Ir.nodes) in
  let nodes_by_id = Hashtbl.create size
  and outgoing = Hashtbl.create size
  and incoming = Hashtbl.create size
  and entrypoints = Hashtbl.create (max 1 (List.length graph.entrypoints)) in
  List.iter
    (fun (node : Ir.node) ->
      if not (Hashtbl.mem nodes_by_id node.id) then
        Hashtbl.add nodes_by_id node.id node)
    graph.nodes;
  List.iter (fun id -> Hashtbl.replace entrypoints id ()) graph.entrypoints;
  let node_condition id =
    Hashtbl.find_opt nodes_by_id id
    |> Option.fold ~none:Condition.false_ ~some:(fun (node : Ir.node) ->
        node.condition)
  in
  let feasible (edge : Ir.edge) =
    Condition.and_ edge.condition
      (Condition.and_ (node_condition edge.from_) (node_condition edge.to_))
    |> Condition.satisfiable
  in
  let feasible_edges = List.filter feasible graph.edges in
  let add table key edge =
    let previous = Option.value ~default:[] (Hashtbl.find_opt table key) in
    Hashtbl.replace table key (edge :: previous)
  in
  (* Reverse once before consing so each adjacency list retains graph edge order. *)
  List.iter
    (fun (edge : Ir.edge) ->
      add outgoing edge.from_ edge;
      add incoming edge.to_ edge)
    (List.rev feasible_edges);
  let dominators =
    lazy
      (let ids = List.map (fun (node : Ir.node) -> node.id) graph.nodes in
       let all =
         List.fold_left
           (fun set id -> String_set.add id set)
           String_set.empty ids
       in
       let table = Hashtbl.create (max 1 (List.length ids)) in
       List.iter
         (fun id ->
           Hashtbl.replace table id
             (if Hashtbl.mem entrypoints id then String_set.singleton id
              else all))
         ids;
       let intersections = function
         | [] -> String_set.empty
         | first :: rest -> List.fold_left String_set.inter first rest
       in
       let changed = ref true in
       while !changed do
         changed := false;
         List.iter
           (fun id ->
             if not (Hashtbl.mem entrypoints id) then
               let predecessors =
                 Option.value ~default:[] (Hashtbl.find_opt incoming id)
                 |> List.filter (fun (edge : Ir.edge) -> edge.kind = Ir.Control)
                 |> List.map (fun (edge : Ir.edge) -> edge.from_)
               in
               let updated =
                 match predecessors with
                 | [] -> String_set.singleton id
                 | _ ->
                     predecessors
                     |> List.map (fun predecessor ->
                         Option.value ~default:all
                           (Hashtbl.find_opt table predecessor))
                     |> intersections |> String_set.add id
               in
               let before =
                 Option.value ~default:String_set.empty
                   (Hashtbl.find_opt table id)
               in
               if not (String_set.equal before updated) then (
                 Hashtbl.replace table id updated;
                 changed := true))
           ids
       done;
       table)
  in
  {
    graph;
    nodes_by_id;
    feasible_edges;
    outgoing;
    incoming;
    entrypoints;
    dominators;
  }

let graph indexed = indexed.graph
let nodes indexed = indexed.graph.Ir.nodes
let feasible_edges indexed = indexed.feasible_edges
let find_node indexed id = Hashtbl.find_opt indexed.nodes_by_id id

let edges_from ?edge_kinds indexed id =
  Option.value ~default:[] (Hashtbl.find_opt indexed.outgoing id)
  |> List.filter (matching_edge edge_kinds)

let edges_to ?edge_kinds indexed id =
  Option.value ~default:[] (Hashtbl.find_opt indexed.incoming id)
  |> List.filter (matching_edge edge_kinds)

let has_incident_edge ?edge_kinds indexed id =
  List.exists (matching_edge edge_kinds)
    (Option.value ~default:[] (Hashtbl.find_opt indexed.outgoing id))
  || List.exists (matching_edge edge_kinds)
       (Option.value ~default:[] (Hashtbl.find_opt indexed.incoming id))

let avoid_table avoid =
  let table = Hashtbl.create (max 1 (List.length avoid)) in
  List.iter (fun id -> Hashtbl.replace table id ()) avoid;
  table

let shortest_path_indexed ?edge_kinds ?(avoid = []) indexed source target =
  let avoided = avoid_table avoid in
  if Hashtbl.mem avoided source || Hashtbl.mem avoided target then None
  else
    let visited = Hashtbl.create (max 1 (List.length indexed.graph.nodes))
    and parent = Hashtbl.create (max 1 (List.length indexed.graph.nodes))
    and queue = Queue.create () in
    Hashtbl.replace visited source ();
    Queue.add source queue;
    let found = ref false in
    while (not !found) && not (Queue.is_empty queue) do
      let current = Queue.take queue in
      if current = target then found := true
      else
        edges_from ?edge_kinds indexed current
        |> List.map (fun (edge : Ir.edge) -> edge.to_)
        |> Util.deduplicate_strings
        |> List.iter (fun child ->
            if
              (not (Hashtbl.mem visited child))
              && not (Hashtbl.mem avoided child)
            then (
              Hashtbl.replace visited child ();
              Hashtbl.replace parent child current;
              Queue.add child queue))
    done;
    if not !found then None
    else
      let rec reconstruct id path =
        if id = source then Some (source :: path)
        else
          Option.bind (Hashtbl.find_opt parent id) (fun previous ->
              reconstruct previous (id :: path))
      in
      reconstruct target [] |> Option.map (List.filter_map (find_node indexed))

let shortest_path ?edge_kinds ?(avoid = []) graph source target =
  shortest_path_indexed ?edge_kinds ~avoid (index graph) source target

let reachable_from_indexed ?edge_kinds ?(avoid = []) indexed source =
  let avoided = avoid_table avoid in
  if Hashtbl.mem avoided source then []
  else
    let visited = Hashtbl.create (max 1 (List.length indexed.graph.nodes))
    and queue = Queue.create () in
    Hashtbl.replace visited source ();
    Queue.add source queue;
    while not (Queue.is_empty queue) do
      let current = Queue.take queue in
      edges_from ?edge_kinds indexed current
      |> List.iter (fun (edge : Ir.edge) ->
          let child = edge.to_ in
          if
            (not (Hashtbl.mem visited child)) && not (Hashtbl.mem avoided child)
          then (
            Hashtbl.replace visited child ();
            Queue.add child queue))
    done;
    List.filter
      (fun (node : Ir.node) -> Hashtbl.mem visited node.id)
      indexed.graph.nodes

let reachable_from ?edge_kinds ?(avoid = []) graph source =
  reachable_from_indexed ?edge_kinds ~avoid (index graph) source

let dominator_table indexed = Lazy.force indexed.dominators

let dominates_indexed indexed ~dominator ~node =
  Hashtbl.find_opt (dominator_table indexed) node
  |> Option.fold ~none:false ~some:(String_set.mem dominator)

let dominates graph ~dominator ~node =
  dominates_indexed (index graph) ~dominator ~node

let cycles_indexed ?edge_kinds indexed =
  let visited = Hashtbl.create (max 1 (List.length indexed.graph.nodes)) in
  let rec visit path visiting id cycles =
    if List.mem id visiting then
      let cycle =
        id :: Util.take_while (fun value -> value <> id) path |> List.rev
      in
      cycle :: cycles
    else if Hashtbl.mem visited id then cycles
    else
      let successors =
        edges_from ?edge_kinds indexed id
        |> List.map (fun (edge : Ir.edge) -> edge.to_)
        |> Util.deduplicate_strings
      in
      let cycles =
        List.fold_left
          (fun cycles child -> visit (id :: path) (id :: visiting) child cycles)
          cycles successors
      in
      Hashtbl.replace visited id ();
      cycles
  in
  List.fold_left
    (fun cycles (node : Ir.node) -> visit [] [] node.id cycles)
    [] indexed.graph.nodes
  |> List.map Util.deduplicate_strings
  |> Util.deduplicate_compare Stdlib.compare

let cycles ?edge_kinds graph = cycles_indexed ?edge_kinds (index graph)

let control_cycles_indexed indexed =
  cycles_indexed ~edge_kinds:[ Ir.Control ] indexed

let control_cycles graph = control_cycles_indexed (index graph)
