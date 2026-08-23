type t =
  | Stream_start
  | Stream_end
  | Document_start of { explicit : bool }
  | Document_end of { explicit : bool }
  | Sequence_start of {
      flow : bool;
      anchor : string option;
      tag : string option;
    }
  | Sequence_end
  | Mapping_start of {
      flow : bool;
      anchor : string option;
      tag : string option;
    }
  | Mapping_end
  | Scalar of {
      value : string;
      style : Yaml_cst.scalar_style;
      anchor : string option;
      tag : string option;
    }
  | Alias of string

let append_property marker = function
  | None -> ""
  | Some value -> " " ^ marker ^ value

let tag_property = function
  | None -> ""
  | Some "!" -> " <!>"
  | Some tag -> " <" ^ tag ^ ">"

let escape_scalar value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (function
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\000' -> Buffer.add_string buffer "\\0"
      | '\007' -> Buffer.add_string buffer "\\a"
      | '\008' -> Buffer.add_string buffer "\\b"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | '\011' -> Buffer.add_string buffer "\\v"
      | '\012' -> Buffer.add_string buffer "\\f"
      | '\027' -> Buffer.add_string buffer "\\e"
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let style_marker = function
  | Yaml_cst.Plain -> ":"
  | Single_quoted -> "'"
  | Double_quoted -> "\""
  | Literal -> "|"
  | Folded -> ">"

let container_start kind flow anchor tag =
  let flow_marker =
    match (kind, flow) with
    | "SEQ", true -> " []"
    | "MAP", true -> " {}"
    | _ -> ""
  in
  "+" ^ kind ^ flow_marker ^ append_property "&" anchor ^ tag_property tag

let to_line = function
  | Stream_start -> "+STR"
  | Stream_end -> "-STR"
  | Document_start { explicit } -> if explicit then "+DOC ---" else "+DOC"
  | Document_end { explicit } -> if explicit then "-DOC ..." else "-DOC"
  | Sequence_start { flow; anchor; tag } ->
      container_start "SEQ" flow anchor tag
  | Sequence_end -> "-SEQ"
  | Mapping_start { flow; anchor; tag } -> container_start "MAP" flow anchor tag
  | Mapping_end -> "-MAP"
  | Scalar { value; style; anchor; tag } ->
      "=VAL" ^ append_property "&" anchor ^ tag_property tag ^ " "
      ^ style_marker style ^ escape_scalar value
  | Alias name -> "=ALI *" ^ name

let to_string events =
  String.concat "\n" (List.map to_line events)
  ^ if events = [] then "" else "\n"

let trivia_in_document kind (tree : Yaml_cst.t) (document : Yaml_cst.document) =
  List.exists
    (fun (trivia : Yaml_cst.trivia) ->
      trivia.kind = kind && Span.contains document.span trivia.span.start.byte)
    tree.trivia

let hex_value = function
  | '0' .. '9' as character -> Some (Char.code character - Char.code '0')
  | 'a' .. 'f' as character -> Some (10 + Char.code character - Char.code 'a')
  | 'A' .. 'F' as character -> Some (10 + Char.code character - Char.code 'A')
  | _ -> None

let percent_decode value =
  let buffer = Buffer.create (String.length value) in
  let rec loop index =
    if index >= String.length value then ()
    else if index + 2 < String.length value && value.[index] = '%' then (
      match (hex_value value.[index + 1], hex_value value.[index + 2]) with
      | Some high, Some low ->
          Buffer.add_char buffer (Char.chr ((high * 16) + low));
          loop (index + 3)
      | _ ->
          Buffer.add_char buffer value.[index];
          loop (index + 1))
    else (
      Buffer.add_char buffer value.[index];
      loop (index + 1))
  in
  loop 0;
  Buffer.contents buffer

let directive_handles (document : Yaml_cst.document) =
  let declared =
    document.directives
    |> List.filter_map (fun (directive : Yaml_cst.trivia) ->
        let words =
          directive.raw
          |> Util.replace_all ~needle:"\t" ~replacement:" "
          |> String.split_on_char ' '
          |> List.filter (( <> ) "")
        in
        match words with
        | [ "%TAG"; handle; prefix ] -> Some (handle, prefix)
        | _ -> None)
  in
  declared @ [ ("!!", "tag:yaml.org,2002:") ]

let expand_tag handles tag =
  let length = String.length tag in
  if length >= 3 && Util.starts_with ~prefix:"!<" tag && tag.[length - 1] = '>'
  then String.sub tag 2 (length - 3) |> percent_decode
  else if Util.starts_with ~prefix:"tag:" tag then percent_decode tag
  else
    handles
    |> List.filter (fun (handle, _) -> Util.starts_with ~prefix:handle tag)
    |> List.stable_sort (fun (left, _) (right, _) ->
        Int.compare (String.length right) (String.length left))
    |> function
    | (handle, prefix) :: _ ->
        prefix
        ^ String.sub tag (String.length handle)
            (String.length tag - String.length handle)
        |> percent_decode
    | [] -> percent_decode tag

let of_cst tree =
  let rec node expand accumulator = function
    | Yaml_cst.Scalar scalar ->
        Scalar
          {
            value = scalar.value;
            style = scalar.style;
            anchor = scalar.anchor;
            tag = Option.map expand scalar.tag;
          }
        :: accumulator
    | Alias alias -> Alias alias.name :: accumulator
    | Decorated
        {
          value =
            Decorated
              {
                value;
                anchor = inner_anchor;
                tag = inner_tag;
                span = inner_span;
              };
          anchor;
          tag;
          _;
        } ->
        node expand accumulator
          (Yaml_cst.Decorated
             {
               value;
               anchor =
                 (match anchor with
                 | Some _ -> anchor
                 | None -> inner_anchor);
               tag =
                 (match tag with
                 | Some _ -> tag
                 | None -> inner_tag);
               span = inner_span;
             })
    | Decorated { value = Scalar scalar; anchor; tag; _ } ->
        Scalar
          {
            value = scalar.value;
            style = scalar.style;
            anchor =
              (match anchor with
              | Some _ -> anchor
              | None -> scalar.anchor);
            tag =
              Option.map expand
                (match tag with
                | Some _ -> tag
                | None -> scalar.tag);
          }
        :: accumulator
    | Decorated { value = Sequence (items, _); anchor; tag; _ } ->
        let accumulator =
          Sequence_start { flow = false; anchor; tag = Option.map expand tag }
          :: accumulator
        in
        let accumulator =
          List.fold_left
            (fun state (item : Yaml_cst.sequence_item) ->
              node expand state item.value)
            accumulator items
        in
        Sequence_end :: accumulator
    | Decorated { value = Flow_sequence (items, _); anchor; tag; _ } ->
        let accumulator =
          Sequence_start { flow = true; anchor; tag = Option.map expand tag }
          :: accumulator
        in
        Sequence_end :: List.fold_left (node expand) accumulator items
    | Decorated { value = Mapping (entries, _); anchor; tag; _ } ->
        mapping expand ~anchor ~tag false accumulator entries
    | Decorated { value = Flow_mapping (entries, _); anchor; tag; _ } ->
        mapping expand ~anchor ~tag true accumulator entries
    | Decorated { value; _ } -> node expand accumulator value
    | Sequence (items, _) ->
        let accumulator =
          Sequence_start { flow = false; anchor = None; tag = None }
          :: accumulator
        in
        let accumulator =
          List.fold_left
            (fun state (item : Yaml_cst.sequence_item) ->
              node expand state item.value)
            accumulator items
        in
        Sequence_end :: accumulator
    | Flow_sequence (items, _) ->
        let accumulator =
          Sequence_start { flow = true; anchor = None; tag = None }
          :: accumulator
        in
        Sequence_end :: List.fold_left (node expand) accumulator items
    | Mapping (entries, _) ->
        mapping expand ~anchor:None ~tag:None false accumulator entries
    | Flow_mapping (entries, _) ->
        mapping expand ~anchor:None ~tag:None true accumulator entries
    | Invalid invalid ->
        Scalar
          {
            value = invalid.raw;
            style = Yaml_cst.Plain;
            anchor = None;
            tag = None;
          }
        :: accumulator
  and mapping expand ~anchor ~tag flow accumulator entries =
    let accumulator =
      Mapping_start { flow; anchor; tag = Option.map expand tag } :: accumulator
    in
    let accumulator =
      List.fold_left
        (fun state (entry : Yaml_cst.mapping_entry) ->
          node expand (node expand state entry.key_node) entry.value)
        accumulator entries
    in
    Mapping_end :: accumulator
  in
  let events = ref [ Stream_start ] in
  List.iter
    (fun (document : Yaml_cst.document) ->
      let handles = directive_handles document in
      let expand = expand_tag handles in
      events :=
        Document_start
          {
            explicit = trivia_in_document Yaml_cst.Document_start tree document;
          }
        :: !events;
      Option.iter (fun root -> events := node expand !events root) document.root;
      events :=
        Document_end
          { explicit = trivia_in_document Yaml_cst.Document_end tree document }
        :: !events)
    tree.documents;
  List.rev (Stream_end :: !events)
