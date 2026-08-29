type source = { id : int; path : string; provider : Ir.provider }
type dense_node = { id : int; source : int; node : Ir.node }
type dense_edge = { from_ : int; to_ : int; edge : Ir.edge }

let normalized_path path = Util.normalize_slashes path

let sources (report : Report.t) =
  report.graphs
  |> List.map (fun (graph : Ir.t) ->
      (normalized_path graph.source, graph.provider))
  |> List.sort_uniq
       (fun (left_path, left_provider) (right_path, right_provider) ->
         match String.compare left_path right_path with
         | 0 -> Stdlib.compare left_provider right_provider
         | comparison -> comparison)
  |> List.mapi (fun id (path, provider) -> { id; path; provider })

let source_id ?provider sources path =
  let path = normalized_path path in
  sources
  |> List.find_opt (fun (source : source) ->
      source.path = path
      && Option.fold ~none:true
           ~some:(fun provider -> source.provider = provider)
           provider)
  |> Option.map (fun (source : source) -> source.id)
  |> Option.value ~default:0

let position_json (position : Span.position) =
  Json.Object
    [
      ("byte", Json.Int position.byte);
      ("column", Json.Int position.column);
      ("line", Json.Int position.line);
    ]

let span_json sources (span : Span.t) =
  Json.Object
    [
      ("source", Json.Int (source_id sources span.file));
      ("start", position_json span.start);
      ("stop", position_json span.stop);
    ]

let rec normalize_spans sources = function
  | Json.Object fields -> (
      match
        ( List.assoc_opt "file" fields,
          List.assoc_opt "start" fields,
          List.assoc_opt "stop" fields )
      with
      | Some (Json.String file), Some start, Some stop ->
          Json.Object
            [
              ("source", Json.Int (source_id sources file));
              ("start", normalize_spans sources start);
              ("stop", normalize_spans sources stop);
            ]
      | _ ->
          Json.Object
            (List.map
               (fun (name, child) -> (name, normalize_spans sources child))
               fields))
  | Json.Array values -> Json.Array (List.map (normalize_spans sources) values)
  | (Json.Null | Json.Bool _ | Json.Int _ | Json.Int64 _ | Json.String _) as
    value -> value

let compare_node (left : Ir.node) (right : Ir.node) =
  match
    String.compare
      (normalized_path left.span.file)
      (normalized_path right.span.file)
  with
  | 0 -> (
      match Span.compare left.span right.span with
      | 0 -> (
          match Stdlib.compare left.provider right.provider with
          | 0 -> (
              match Stdlib.compare left.kind right.kind with
              | 0 -> (
                  match String.compare left.name right.name with
                  | 0 -> Stdlib.compare left.phase right.phase
                  | comparison -> comparison)
              | comparison -> comparison)
          | comparison -> comparison)
      | comparison -> comparison)
  | comparison -> comparison

let dense_program report sources =
  let program = Program_graph.compose report.Report.graphs in
  let nodes = List.sort compare_node program.nodes in
  let ids = Hashtbl.create (max 1 (List.length nodes)) in
  let nodes =
    List.mapi
      (fun id (node : Ir.node) ->
        Hashtbl.replace ids node.id id;
        {
          id;
          source = source_id ~provider:node.provider sources node.span.file;
          node;
        })
      nodes
  in
  let dense_id id = Hashtbl.find_opt ids id |> Option.value ~default:(-1) in
  let edges =
    program.edges
    |> List.filter_map (fun (edge : Ir.edge) ->
        let from_ = dense_id edge.from_ and to_ = dense_id edge.to_ in
        if from_ < 0 || to_ < 0 || from_ = to_ then None
        else Some { from_; to_; edge })
    |> List.sort_uniq (fun left right ->
        match Int.compare left.from_ right.from_ with
        | 0 -> (
            match Int.compare left.to_ right.to_ with
            | 0 -> (
                match Stdlib.compare left.edge.kind right.edge.kind with
                | 0 -> (
                    match
                      String.compare
                        (Condition.to_string left.edge.condition)
                        (Condition.to_string right.edge.condition)
                    with
                    | 0 ->
                        Option.compare String.compare left.edge.label
                          right.edge.label
                    | comparison -> comparison)
                | comparison -> comparison)
            | comparison -> comparison)
        | comparison -> comparison)
  in
  let entrypoints =
    program.entrypoints |> List.map dense_id
    |> List.filter (( <= ) 0)
    |> List.sort_uniq Int.compare
  in
  (nodes, edges, entrypoints, dense_id)

let source_json (source : source) =
  Json.Object
    [
      ("id", Json.Int source.id);
      ("path", Json.String source.path);
      ("provider", Json.String (Ir.provider_name source.provider));
    ]

let node_json sources (value : dense_node) =
  let node = value.node in
  let fields =
    [
      ("id", Json.Int value.id);
      ("kind", Json.String (Ir.kind_name node.kind));
      ("name", Json.String node.name);
      ("phase", Json.String (Ir.phase_name node.phase));
      ("source", Json.Int value.source);
      ("span", span_json sources node.span);
    ]
  in
  let fields =
    if node.attributes = [] then fields
    else
      ( "attributes",
        Json.Object
          (List.map
             (fun (name, value) ->
               (name, Abstract_value.to_json value |> normalize_spans sources))
             node.attributes) )
      :: fields
  in
  let fields =
    if node.capabilities = [] then fields
    else
      ( "capabilities",
        Json.Array
          (List.map
             (fun value -> Json.String (Ir.capability_name value))
             node.capabilities) )
      :: fields
  in
  let fields =
    if Condition.equal node.condition Condition.true_ then fields
    else ("condition", Condition.to_json node.condition) :: fields
  in
  let fields =
    if node.effects = [] then fields
    else
      ( "effects",
        Json.Array
          (List.map
             (fun value -> Json.String (Ir.effect_name value))
             node.effects) )
      :: fields
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun unknown -> ("unknown", Unknown.to_json unknown) :: fields)
      node.unknown
  in
  Json.Object fields

let edge_json value =
  let edge = value.edge in
  let fields =
    [
      ("from", Json.Int value.from_);
      ("kind", Json.String (Ir.edge_kind_name edge.kind));
      ("to", Json.Int value.to_);
    ]
  in
  let fields =
    if Condition.equal edge.condition Condition.true_ then fields
    else ("condition", Condition.to_json edge.condition) :: fields
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun label -> ("label", Json.String label) :: fields)
      edge.label
  in
  Json.Object fields

let fix_json sources (fix : Diagnostic.fix) =
  let fields =
    [
      ("description", Json.String fix.description);
      ("kind", Json.String fix.kind);
    ]
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun replacement ->
        ("replacement", Json.String replacement) :: fields)
      fix.replacement
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun span -> ("span", span_json sources span) :: fields)
      fix.span
  in
  Json.Object fields

let diagnostic_json sources dense_id (diagnostic : Diagnostic.t) =
  let fields =
    [
      ( "confidence",
        Json.String (Diagnostic.confidence_name diagnostic.confidence) );
      ("message", Json.String diagnostic.message);
      ("rule_id", Json.String diagnostic.rule_id);
      ("severity", Json.String (Diagnostic.severity_name diagnostic.severity));
      ("span", span_json sources diagnostic.span);
    ]
  in
  let fields =
    if diagnostic.capabilities = [] then fields
    else
      ( "capabilities",
        Json.Array
          (List.map
             (fun value -> Json.String (Ir.capability_name value))
             diagnostic.capabilities) )
      :: fields
  in
  let fields =
    if diagnostic.evidence = [] then fields
    else
      ( "evidence",
        Json.Array
          (List.map (fun value -> Json.String value) diagnostic.evidence) )
      :: fields
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun fix -> ("fix", fix_json sources fix) :: fields)
      diagnostic.fix
  in
  let fields =
    if diagnostic.trace = [] then fields
    else
      ( "trace",
        Json.Array
          (List.map
             (fun (hop : Diagnostic.trace_hop) ->
               Json.Object
                 [
                   ("label", Json.String hop.label);
                   ("node", Json.Int (dense_id hop.node_id));
                   ("span", span_json sources hop.span);
                 ])
             diagnostic.trace) )
      :: fields
  in
  Json.Object fields

let property_json (property : Property.t) =
  let fields =
    [
      ("explanation", Json.String property.explanation);
      ("id", Json.String property.id);
      ("state", Json.String (Property.state_name property.state));
    ]
  in
  let fields =
    match property.state with
    | Property.Unknown reasons ->
        ("reasons", Json.Array (List.map Unknown.to_json reasons)) :: fields
    | Proved | Violated | Not_applicable -> fields
  in
  let fields =
    Option.fold ~none:fields
      ~some:(fun subject -> ("subject", Json.String subject) :: fields)
      property.subject
  in
  Json.Object fields

let to_canonical_json (report : Report.t) =
  let sources = sources report in
  let nodes, edges, entrypoints, dense_id = dense_program report sources in
  let diagnostics = Report.diagnostics report in
  let properties =
    report.verifications
    |> List.concat_map (fun result -> result.Verifier.properties)
    |> List.sort Property.compare
  in
  let completeness_reasons =
    Util.deduplicate_strings report.provenance.completeness_reasons
  in
  let fields digest =
    [
      ( "completeness",
        Json.Object
          [
            ( "reasons",
              Json.Array
                (List.map (fun value -> Json.String value) completeness_reasons)
            );
            ( "state",
              Json.String
                (if completeness_reasons = [] then "complete" else "incomplete")
            );
          ] );
      ( "diagnostics",
        Json.Array (List.map (diagnostic_json sources dense_id) diagnostics) );
      ("digest", digest);
      ("edges", Json.Array (List.map edge_json edges));
      ( "entrypoints",
        Json.Array (List.map (fun value -> Json.Int value) entrypoints) );
      ( "gate",
        Json.Object
          [
            ("exit_code", Json.Int report.provenance.exit_code);
            ( "result",
              Json.String
                (Report.gate_result_name report.provenance.gate_result) );
          ] );
      ("nodes", Json.Array (List.map (node_json sources) nodes));
      ("properties", Json.Array (List.map property_json properties));
      ("schema", Json.String "semantic-conformance/1");
      ("sources", Json.Array (List.map source_json sources));
    ]
  in
  let digest =
    "sha256:"
    ^ Sha256.digest_string (Json.to_string (Json.Object (fields Json.Null)))
  in
  Json.to_string (Json.Object (fields (Json.String digest))) ^ "\n"
