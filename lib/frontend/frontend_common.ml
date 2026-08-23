let yaml_problems tree =
  List.map
    (fun problem ->
      {
        Frontend_intf.code = problem.Yaml_cst.code;
        message = problem.message;
        span = problem.span;
      })
    tree.Yaml_cst.problems

let parse unit_ =
  let cst = Yaml_cst.parse ~file:unit_.Frontend_intf.path unit_.source in
  match Yaml_cst.root cst with
  | None ->
      Error
        [
          {
            Frontend_intf.code = "FRONTEND-EMPTY";
            message = "workflow document has no root node";
            span = Span.none;
          };
        ]
  | Some _ -> Ok { Frontend_intf.unit_; cst }

let expand parsed = { Frontend_intf.parsed; expansion_unknowns = [] }

let is_hex character =
  match character with
  | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
  | _ -> false

let immutable_revision reference =
  match String.rindex_opt reference '@' with
  | Some index ->
      let revision =
        String.sub reference (index + 1) (String.length reference - index - 1)
      in
      (String.length revision = 40 || String.length revision = 64)
      && String.for_all is_hex revision
      || Util.starts_with ~prefix:"sha256:" revision
         && String.length revision = 71
         && String.sub revision 7 64 |> String.for_all is_hex
  | None -> false

let dependency ?(kind = Frontend_intf.Unknown_dependency_kind)
    ?(locator = Frontend_intf.Direct_reference) provider reference span =
  let local =
    Util.starts_with ~prefix:"./" reference
    || Util.starts_with ~prefix:"../" reference
  in
  let mutability =
    if local then Frontend_intf.Local
    else if immutable_revision reference then Immutable
    else if
      String.contains reference '@' || Util.contains ~needle:"://" reference
    then Mutable
    else Unknown_mutability
  in
  let reason = Unknown.Unresolved_dependency reference in
  {
    Frontend_intf.provider;
    kind;
    reference;
    locator;
    span;
    mutability;
    status = Unresolved reason;
  }

let scalar = Yaml_cst.scalar_value
let mapping node = Option.value ~default:[] (Yaml_cst.as_mapping node)

let sequence_nodes node =
  match Yaml_cst.as_sequence node with
  | Some items ->
      List.map (fun (item : Yaml_cst.sequence_item) -> item.value) items
  | None -> (
      match node with
      | Yaml_cst.Flow_sequence (nodes, _) -> nodes
      | _ -> [ node ])

let field name node = Yaml_cst.mapping_find name (mapping node)
let field_scalar name node = Option.bind (field name node) scalar
let root resolved = Yaml_cst.root resolved.Frontend_intf.expanded.parsed.cst

let command_value provider node source =
  let span = Yaml_cst.node_span node in
  let references =
    Expression.scan provider ~default_phase:Ir.Run ~span source
  in
  let base =
    Abstract_value.string_constant source ~trust:Abstract_value.Trusted
      ~secrecy:Abstract_value.Public
      ~provenance:
        [ { origin = "workflow source"; span; operation = "command" } ]
  in
  let value =
    List.fold_left
      (fun accumulator reference ->
        Abstract_value.join accumulator reference.Expression.value)
      base references
  in
  (value, references)

let add_control (source : Ir.node) (target : Ir.node) graph =
  Ir.add_edge
    (Ir.make_edge ~kind:Ir.Control ~from_:source.Ir.id ~to_:target.id ())
    graph

let add_call (source : Ir.node) (target : Ir.node) graph =
  graph |> add_control source target
  |> Ir.add_edge
       (Ir.make_edge ~kind:Ir.Call_edge ~from_:source.id ~to_:target.id ())

let add_references provider (target : Ir.node) references graph =
  List.fold_left
    (fun graph reference ->
      let source =
        Ir.make_node ~provider ~kind:Ir.Resource ~name:reference.Expression.name
          ~phase:reference.phase ~span:reference.span
          ~attributes:[ ("value", reference.value) ]
          ()
      in
      graph |> Ir.add_node source
      |> Ir.add_edge
           (Ir.make_edge ~kind:Ir.Data ~from_:source.id ~to_:target.Ir.id
              ~label:reference.name ()))
    graph references

let workflow_node provider fallback root =
  let name = Option.value ~default:fallback (field_scalar "name" root) in
  Ir.make_node ~provider ~kind:Ir.Workflow ~name ~phase:Ir.Compile
    ~span:(Yaml_cst.node_span root) ()
