let scalar_strings node =
  match Yaml_cst.scalar_value node with
  | Some value -> [ value ]
  | None ->
      Frontend_common.sequence_nodes node
      |> List.filter_map Yaml_cst.scalar_value

let field_strings name node =
  match Frontend_common.field name node with
  | None -> []
  | Some value -> scalar_strings value

let mapping_keys node =
  Frontend_common.mapping node
  |> List.map (fun (entry : Yaml_cst.mapping_entry) -> entry.key.value)

let condition provider source =
  match Expression.parse provider ~phase:Ir.Plan ~span:Span.none source with
  | Ok expression -> Expression.to_condition expression
  | Error _ ->
      Condition.atom
        (Ir.provider_name provider ^ ":"
        ^ (source |> String.trim |> String.lowercase_ascii))

let insert_gate ~(owner : Ir.node) (gate : Ir.node) graph =
  let incoming, retained =
    List.partition
      (fun (edge : Ir.edge) -> edge.kind = Ir.Control && edge.to_ = owner.id)
      graph.Ir.edges
  in
  let graph = { graph with Ir.edges = retained } in
  let graph =
    {
      graph with
      Ir.entrypoints =
        List.map
          (fun entrypoint ->
            if entrypoint = owner.id then gate.id else entrypoint)
          graph.entrypoints;
    }
  in
  let graph = Ir.add_node gate graph in
  let graph =
    List.fold_left
      (fun graph (edge : Ir.edge) ->
        Ir.add_edge
          (Ir.make_edge ~kind:Ir.Control ~from_:edge.from_ ~to_:gate.id
             ~condition:edge.condition ?label:edge.label ())
          graph)
      graph incoming
  in
  Ir.add_edge
    (Ir.make_edge ~kind:Ir.Control ~from_:gate.id ~to_:owner.id
       ~condition:gate.condition ~label:"gate" ())
    graph

let add_gate ~provider ~(owner : Ir.node) ~name ~phase ~expression_node graph =
  let expression =
    Option.value ~default:"<opaque condition>"
      (Yaml_cst.scalar_value expression_node)
  in
  let parsed =
    Expression.parse provider ~phase
      ~span:(Yaml_cst.node_span expression_node)
      expression
  in
  let predicate, references, phase_unknown =
    match parsed with
    | Ok parsed ->
        ( Expression.to_condition parsed,
          Expression.references parsed,
          match Expression.validate_phase parsed with
          | reason :: _ -> Some reason
          | [] -> None )
    | Error _ ->
        ( condition provider expression,
          Expression.scan provider ~default_phase:phase
            ~span:(Yaml_cst.node_span expression_node)
            expression,
          Some (Unknown.Unsupported_syntax "condition expression") )
  in
  let gate =
    Ir.make_node ~provider ~kind:Ir.Gate ~name ~phase
      ~span:(Yaml_cst.node_span expression_node)
      ~condition:predicate
      ~attributes:
        (( "expression",
           Abstract_value.string_constant expression
             ~trust:Abstract_value.Trusted ~secrecy:Abstract_value.Public
             ~provenance:
               [
                 {
                   origin = "workflow condition";
                   span = Yaml_cst.node_span expression_node;
                   operation = "gate";
                 };
               ] )
        :: Expression.references_to_attributes references)
      ?unknown:phase_unknown ()
  in
  let graph = insert_gate ~owner gate graph in
  let graph = Frontend_common.add_references provider gate references graph in
  (graph, gate)

let add_static_gate ~provider ~(owner : Ir.node) ~name ~phase ~span ~mechanism
    graph =
  let gate =
    Ir.make_node ~provider ~kind:Ir.Gate ~name ~phase ~span
      ~attributes:
        [
          ( "mechanism",
            Abstract_value.string_constant mechanism
              ~trust:Abstract_value.Trusted ~secrecy:Abstract_value.Public
              ~provenance:
                [ { origin = mechanism; span; operation = "static gate" } ] );
        ]
      ()
  in
  (insert_gate ~owner gate graph, gate)

let add_resource ~provider ~(owner : Ir.node) ~name ~phase ~span
    ?(attributes = []) ?(capabilities = []) ?(effects = [])
    ?(edge_kind = Ir.Control) ?(resource_to_owner = false) graph =
  let resource =
    Ir.make_node ~provider ~kind:Ir.Resource ~name ~phase ~span ~attributes
      ~capabilities ~effects ()
  in
  let graph =
    graph |> Ir.add_node resource
    |> Ir.add_edge
         (Ir.make_edge ~kind:edge_kind
            ~from_:(if resource_to_owner then resource.id else owner.id)
            ~to_:(if resource_to_owner then owner.id else resource.id)
            ())
  in
  (graph, resource)

let link_dependencies ~unknown_code ~cycle_code ~label ~nodes ~dependencies
    graph =
  let problems = ref [] and graph = ref graph in
  let find name =
    List.find_opt (fun (node : Ir.node) -> node.name = name) nodes
  in
  List.iter
    (fun (owner_name, targets, span) ->
      match find owner_name with
      | None -> ()
      | Some owner ->
          List.iter
            (fun target_name ->
              match find target_name with
              | Some target ->
                  graph :=
                    Ir.add_edge
                      (Ir.make_edge ~kind:Ir.Control ~from_:target.id
                         ~to_:owner.id ~label ())
                      !graph
              | None ->
                  problems :=
                    {
                      Frontend_intf.code = unknown_code;
                      message =
                        Printf.sprintf "%s references unknown %s" owner_name
                          target_name;
                      span;
                    }
                    :: !problems)
            targets)
    dependencies;
  let adjacency name =
    dependencies
    |> List.find_map (fun (owner, targets, _) ->
        if owner = name then Some targets else None)
    |> Option.value ~default:[]
  in
  let visiting = ref [] and visited = ref [] and cycle = ref None in
  let rec visit path name =
    if !cycle <> None || List.mem name !visited then ()
    else if List.mem name !visiting then cycle := Some (List.rev (name :: path))
    else (
      visiting := name :: !visiting;
      adjacency name
      |> List.filter (fun target -> Option.is_some (find target))
      |> List.iter (visit (name :: path));
      visiting := List.filter (( <> ) name) !visiting;
      visited := name :: !visited)
  in
  List.iter (fun (node : Ir.node) -> visit [] node.name) nodes;
  Option.iter
    (fun path ->
      let span =
        match path |> List.find_map find with
        | Some node -> node.Ir.span
        | None -> Span.none
      in
      problems :=
        {
          Frontend_intf.code = cycle_code;
          message = "dependency cycle: " ^ String.concat " -> " path;
          span;
        }
        :: !problems)
    !cycle;
  (!graph, List.rev !problems)

let link_sequence (nodes : Ir.node list) graph =
  let rec loop graph = function
    | (left : Ir.node) :: ((right : Ir.node) :: _ as rest) ->
        loop
          (Ir.add_edge
             (Ir.make_edge ~kind:Ir.Control ~from_:left.Ir.id ~to_:right.Ir.id
                ~label:"sequence" ())
             graph)
          rest
    | _ -> graph
  in
  loop graph nodes
