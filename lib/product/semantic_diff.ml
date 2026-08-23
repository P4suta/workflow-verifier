type path_change = {
  source : string;
  sink : string;
  path : string list;
  effect_name : string;
}

type change =
  | New_reachable_path of path_change
  | Capability_added of Ir.capability
  | Capability_removed of Ir.capability
  | Dependency_became_mutable of string
  | Property_changed of { property : string; before : string; after : string }

type t = {
  schema : string;
  base_digest : string;
  head_digest : string;
  changes : change list;
}

let node_value node =
  List.fold_left
    (fun accumulator (_, value) -> Abstract_value.join accumulator value)
    Abstract_value.bottom node.Ir.attributes

let effects (node : Ir.node) =
  let inferred =
    if node.Ir.kind = Ir.Command then
      (Script_adapter.analyze Bash node.name).effects
    else []
  in
  Util.deduplicate_compare Stdlib.compare (node.effects @ inferred)

let attack_paths graph =
  let sources =
    List.filter
      (fun (node : Ir.node) -> Abstract_value.is_untrusted (node_value node))
      graph.Ir.nodes
  and sinks =
    graph.nodes
    |> List.concat_map (fun node ->
        effects node |> List.map (fun observable -> (node, observable)))
  in
  List.concat_map
    (fun (source : Ir.node) ->
      sinks
      |> List.filter_map (fun ((sink : Ir.node), observable) ->
          Graph_algorithms.shortest_path
            ~edge_kinds:
              [
                Ir.Data; Ir.Read; Ir.Write; Ir.Persist; Ir.Call_edge; Ir.Control;
              ]
            graph source.id sink.id
          |> Option.map (fun path ->
              {
                source = source.id;
                sink = sink.id;
                path = List.map (fun (node : Ir.node) -> node.id) path;
                effect_name = Ir.effect_name observable;
              })))
    sources

let path_key path =
  String.concat "\000"
    (path.source :: path.sink :: path.effect_name :: path.path)

let capabilities graph =
  graph.Ir.nodes
  |> List.concat_map (fun (node : Ir.node) -> node.capabilities)
  |> Util.deduplicate_compare Stdlib.compare

let mutable_reference reference =
  match String.rindex_opt reference '@' with
  | None -> false
  | Some index ->
      let revision =
        String.sub reference (index + 1) (String.length reference - index - 1)
      in
      String.length revision < 40
      && not (Util.starts_with ~prefix:"sha256:" revision)

let mutable_calls graph =
  graph.Ir.nodes
  |> List.filter_map (fun (node : Ir.node) ->
      if node.kind = Ir.Call && mutable_reference node.name then Some node.name
      else None)
  |> Util.deduplicate_strings

let compare_with_properties base head base_properties head_properties =
  let base_paths = attack_paths base and head_paths = attack_paths head in
  let new_paths =
    List.filter
      (fun path ->
        not (List.exists (fun old -> path_key old = path_key path) base_paths))
      head_paths
    |> List.map (fun value -> New_reachable_path value)
  in
  let base_caps = capabilities base and head_caps = capabilities head in
  let added =
    List.filter (fun value -> not (List.mem value base_caps)) head_caps
    |> List.map (fun value -> Capability_added value)
  and removed =
    List.filter (fun value -> not (List.mem value head_caps)) base_caps
    |> List.map (fun value -> Capability_removed value)
  and mutable_added =
    let old = mutable_calls base in
    mutable_calls head
    |> List.filter (fun value -> not (List.mem value old))
    |> List.map (fun value -> Dependency_became_mutable value)
  and property_changes =
    head_properties
    |> List.filter_map (fun (property : Property.t) ->
        match
          List.find_opt
            (fun (candidate : Property.t) -> candidate.id = property.id)
            base_properties
        with
        | None ->
            Some
              (Property_changed
                 {
                   property = property.id;
                   before = "NotApplicable";
                   after = Property.state_name property.state;
                 })
        | Some before ->
            let before_name = Property.state_name before.state
            and after_name = Property.state_name property.state in
            if before_name = after_name then None
            else
              Some
                (Property_changed
                   {
                     property = property.id;
                     before = before_name;
                     after = after_name;
                   }))
    |> List.sort (fun left right ->
        match (left, right) with
        | Property_changed left, Property_changed right ->
            String.compare left.property right.property
        | _ -> 0)
  in
  {
    schema = "semantic-diff-v1";
    base_digest =
      "sha256:" ^ Sha256.digest_string (Json.to_string (Ir.to_json base));
    head_digest =
      "sha256:" ^ Sha256.digest_string (Json.to_string (Ir.to_json head));
    changes = new_paths @ added @ removed @ mutable_added @ property_changes;
  }

let compare base head = compare_with_properties base head [] []

let compare_program base head =
  let base_program = Program_graph.compose base
  and head_program = Program_graph.compose head
  and base_verification = Verifier.verify_program ~persona:Verifier.Audit base
  and head_verification =
    Verifier.verify_program ~persona:Verifier.Audit head
  in
  compare_with_properties base_program head_program base_verification.properties
    head_verification.properties

let change_json = function
  | New_reachable_path path ->
      Json.Object
        [
          ("effect", Json.String path.effect_name);
          ("kind", Json.String "new_reachable_path");
          ( "path",
            Json.Array (List.map (fun value -> Json.String value) path.path) );
          ("sink", Json.String path.sink);
          ("source", Json.String path.source);
        ]
  | Capability_added value ->
      Json.Object
        [
          ("capability", Json.String (Ir.capability_name value));
          ("kind", Json.String "capability_added");
        ]
  | Capability_removed value ->
      Json.Object
        [
          ("capability", Json.String (Ir.capability_name value));
          ("kind", Json.String "capability_removed");
        ]
  | Dependency_became_mutable value ->
      Json.Object
        [
          ("kind", Json.String "dependency_became_mutable");
          ("reference", Json.String value);
        ]
  | Property_changed { property; before; after } ->
      Json.Object
        [
          ("after", Json.String after);
          ("before", Json.String before);
          ("kind", Json.String "property_changed");
          ("property", Json.String property);
        ]

let to_json difference =
  Json.Object
    [
      ("base_digest", Json.String difference.base_digest);
      ("changes", Json.Array (List.map change_json difference.changes));
      ("head_digest", Json.String difference.head_digest);
      ("schema", Json.String difference.schema);
    ]

let to_canonical_json difference = Json.to_string (to_json difference) ^ "\n"
