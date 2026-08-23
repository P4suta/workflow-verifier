type kind = All | Control | Dataflow | Call | Capability

let keep kind (edge : Ir.edge) =
  match kind with
  | All -> true
  | Control -> edge.kind = Ir.Control
  | Dataflow -> List.mem edge.kind [ Ir.Data; Ir.Read; Ir.Write; Ir.Persist ]
  | Call -> edge.kind = Ir.Call_edge
  | Capability -> edge.kind = Ir.Grant

let filtered kind graph =
  let edges = List.filter (keep kind) graph.Ir.edges in
  let used =
    edges
    |> List.concat_map (fun (edge : Ir.edge) -> [ edge.from_; edge.to_ ])
    |> Util.deduplicate_strings
  in
  let nodes =
    if kind = All then graph.nodes
    else List.filter (fun (node : Ir.node) -> List.mem node.id used) graph.nodes
  in
  Ir.finalize
    {
      graph with
      nodes;
      edges;
      entrypoints = List.filter (fun id -> List.mem id used) graph.entrypoints;
    }

let to_json ~kind graph = Ir.to_json (filtered kind graph)
let to_canonical_json ~kind graph = Json.to_string (to_json ~kind graph) ^ "\n"

let dot_escape value =
  value
  |> Util.replace_all ~needle:"\\" ~replacement:"\\\\"
  |> Util.replace_all ~needle:"\"" ~replacement:"\\\""
  |> Util.replace_all ~needle:"\n" ~replacement:"\\n"

let to_dot ~kind graph =
  let graph = filtered kind graph in
  let buffer = Buffer.create 512 in
  Buffer.add_string buffer "digraph workflow {\n  rankdir=LR;\n";
  List.iter
    (fun (node : Ir.node) ->
      Printf.bprintf buffer "  \"%s\" [label=\"%s\\n%s\"];\n" node.id
        (dot_escape node.name) (Ir.kind_name node.kind))
    graph.nodes;
  List.iter
    (fun (edge : Ir.edge) ->
      Printf.bprintf buffer "  \"%s\" -> \"%s\" [label=\"%s\"];\n" edge.from_
        edge.to_
        (Ir.edge_kind_name edge.kind))
    graph.edges;
  Buffer.add_string buffer "}\n";
  Buffer.contents buffer
