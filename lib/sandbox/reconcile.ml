let property ~static ~possible_effect ~evidence =
  match static with
  | Property.Violated -> Property.Violated
  | Proved ->
      if Evidence.observes_effect possible_effect evidence then
        Property.Violated
      else Property.Proved
  | Unknown reasons ->
      if Evidence.observes_effect possible_effect evidence then
        Property.Violated
      else Property.Unknown reasons
  | Not_applicable ->
      if Evidence.observes_effect possible_effect evidence then
        Property.Violated
      else Property.Not_applicable

let envelope ~graphs ~evidence =
  let static_effects =
    graphs
    |> List.concat_map (fun graph ->
        graph.Ir.nodes
        |> List.concat_map (fun (node : Ir.node) ->
            node.effects
            @ if node.kind = Ir.Command then [ Ir.Command_execution ] else []))
    |> Util.deduplicate_compare Stdlib.compare
  and unknowns =
    graphs
    |> List.concat_map (fun graph ->
        graph.Ir.nodes |> List.filter_map (fun (node : Ir.node) -> node.unknown))
    |> Util.deduplicate_compare Unknown.compare
  in
  let unexpected =
    Evidence.observed_effects evidence
    |> List.filter (fun observed -> not (List.mem observed static_effects))
  in
  let state =
    match (unexpected, unknowns, graphs) with
    | [], _, _ -> Property.Proved
    | _ :: _, [], _ :: _ -> Property.Violated
    | _ :: _, reasons, _ :: _ -> Property.Unknown reasons
    | _ :: _, _, [] ->
        Property.Unknown
          [ Unknown.External_state "static graphs were not supplied" ]
  in
  let explanation =
    match unexpected with
    | [] ->
        "observed runtime effects are contained in the static effect envelope"
    | values ->
        "runtime observed effects outside the static envelope: "
        ^ String.concat ", " (List.map Ir.effect_name values)
  in
  { Property.id = "WV-RUNTIME-001"; state; subject = None; explanation }
