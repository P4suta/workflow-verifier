type proposal = {
  id : string;
  description : string;
  edits : Yaml_cst.edit list;
  safe : bool;
}

let make description edits safe =
  let material =
    description
    ^ String.concat ""
        (List.map
           (fun (edit : Yaml_cst.edit) ->
             Printf.sprintf "%d:%d:%s" edit.start_byte edit.stop_byte
               edit.replacement)
           edits)
  in
  {
    id = "fix_" ^ String.sub (Sha256.digest_string material) 0 20;
    description;
    edits;
    safe;
  }

let replace_scalar ~cst:_ ~(scalar : Yaml_cst.scalar) ~replacement ~description
    =
  make description
    [
      {
        Yaml_cst.start_byte = scalar.Yaml_cst.span.start.byte;
        stop_byte = scalar.span.stop.byte;
        replacement;
      };
    ]
    true

let rec find_scalar reference = function
  | Yaml_cst.Scalar scalar when scalar.value = reference -> Some scalar
  | Scalar _ | Alias _ | Invalid _ -> None
  | Sequence (items, _) ->
      List.find_map
        (fun (item : Yaml_cst.sequence_item) ->
          find_scalar reference item.value)
        items
  | Flow_sequence (nodes, _) -> List.find_map (find_scalar reference) nodes
  | Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.find_map
        (fun (entry : Yaml_cst.mapping_entry) ->
          match find_scalar reference entry.key_node with
          | Some _ as found -> found
          | None -> find_scalar reference entry.value)
        entries
  | Decorated decorated -> find_scalar reference decorated.value

let pin_dependency ~cst ~reference ~revision =
  let prefix =
    match String.rindex_opt reference '@' with
    | Some index -> String.sub reference 0 (index + 1)
    | None -> reference ^ "@"
  in
  match Option.bind (Yaml_cst.root cst) (find_scalar reference) with
  | None -> None
  | Some scalar ->
      Some
        (replace_scalar ~cst ~scalar ~replacement:(prefix ^ revision)
           ~description:("pin " ^ reference ^ " to " ^ revision))

let reduce_write_all ~cst ~unused_capabilities =
  if
    not
      (List.for_all
         (fun capability -> List.mem capability unused_capabilities)
         [ Ir.Repository_write; Ir.Token_write ])
  then None
  else
    match Option.bind (Yaml_cst.root cst) (find_scalar "write-all") with
    | None -> None
    | Some scalar ->
        Some
          (replace_scalar ~cst ~scalar ~replacement:"read-all"
             ~description:
               "reduce write-all after proving repository and token write \
                grants unused")

let substring_index ~needle value =
  let needle_length = String.length needle
  and value_length = String.length value in
  let rec search index =
    if index + needle_length > value_length then None
    else if String.sub value index needle_length = needle then Some index
    else search (index + 1)
  in
  if needle_length = 0 then None else search 0

let exactly_once ~needle value =
  match substring_index ~needle value with
  | None -> None
  | Some first ->
      let after = first + String.length needle in
      let suffix = String.sub value after (String.length value - after) in
      if Option.is_some (substring_index ~needle suffix) then None
      else Some first

let valid_environment_name value =
  let valid_start = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and valid_rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' -> true
    | _ -> false
  in
  String.length value > 0
  && valid_start value.[0]
  && String.sub value 1 (String.length value - 1) |> String.for_all valid_rest

let rec find_run expression = function
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) -> (
      let direct =
        if Option.is_some (Yaml_cst.mapping_find "env" entries) then None
        else
          entries
          |> List.find_map (fun (entry : Yaml_cst.mapping_entry) ->
              if entry.key.value <> "run" then None
              else
                match entry.value with
                | Scalar scalar
                  when scalar.style = Yaml_cst.Plain
                       && scalar.raw = scalar.value
                       && Option.is_some
                            (substring_index ~needle:expression scalar.value) ->
                    Some (entry, scalar)
                | _ -> None)
      in
      match direct with
      | Some _ as value -> value
      | None ->
          entries
          |> List.find_map (fun (entry : Yaml_cst.mapping_entry) ->
              match find_run expression entry.value with
              | Some _ as value -> value
              | None -> find_run expression entry.key_node))
  | Sequence (items, _) ->
      items
      |> List.find_map (fun (item : Yaml_cst.sequence_item) ->
          find_run expression item.value)
  | Flow_sequence (items, _) -> List.find_map (find_run expression) items
  | Decorated decorated -> find_run expression decorated.value
  | Scalar _ | Alias _ | Invalid _ -> None

let line_insertion cst stop_byte =
  let source = cst.Yaml_cst.source in
  let rec find index =
    if index >= String.length source then (String.length source, false)
    else
      match source.[index] with
      | '\n' -> (index + 1, true)
      | '\r' ->
          if index + 1 < String.length source && source.[index + 1] = '\n' then
            (index + 2, true)
          else (index + 1, true)
      | _ -> find (index + 1)
  in
  find stop_byte

let bind_expression_to_environment ~cst ~shell ~expression ~name =
  if
    (not (valid_environment_name name))
    || not
         (Util.starts_with ~prefix:"${{" expression
         || Util.starts_with ~prefix:"$[[" expression)
  then None
  else
    match Option.bind (Yaml_cst.root cst) (find_run expression) with
    | None -> None
    | Some (entry, scalar) -> (
        match exactly_once ~needle:expression scalar.value with
        | None -> None
        | Some relative ->
            let variable =
              match shell with
              | Script_adapter.Posix | Bash -> Some ("\"${" ^ name ^ "}\"")
              | PowerShell -> Some ("\"$env:" ^ name ^ "\"")
              | Cmd -> Some ("\"%" ^ name ^ "%\"")
              | Python | Unknown_shell _ -> None
            in
            Option.map
              (fun variable ->
                let insertion, had_newline =
                  line_insertion cst scalar.span.stop.byte
                and newline =
                  match cst.newline with
                  | `CrLf -> "\r\n"
                  | `Cr -> "\r"
                  | `Lf | `None -> "\n"
                and indent =
                  String.make (max 0 (entry.key.span.start.column - 1)) ' '
                in
                let env_block =
                  (if had_newline then "" else newline)
                  ^ indent ^ "env:" ^ newline ^ indent ^ "  " ^ name ^ ": "
                  ^ expression ^ newline
                in
                make
                  ("bind " ^ expression ^ " through environment variable "
                 ^ name)
                  [
                    {
                      Yaml_cst.start_byte = scalar.span.start.byte + relative;
                      stop_byte =
                        scalar.span.start.byte + relative
                        + String.length expression;
                      replacement = variable;
                    };
                    {
                      Yaml_cst.start_byte = insertion;
                      stop_byte = insertion;
                      replacement = env_block;
                    };
                  ]
                  true)
              variable)

let apply ~cst proposal =
  if not proposal.safe then
    Error "unsafe proposals cannot be applied automatically"
  else Yaml_cst.apply_edits cst proposal.edits

let combine proposals =
  if proposals = [] then Error "at least one fix proposal is required"
  else if List.exists (fun proposal -> not proposal.safe) proposals then
    Error "unsafe proposals cannot be combined for automatic application"
  else
    let edits =
      proposals
      |> List.concat_map (fun proposal -> proposal.edits)
      |> List.sort (fun left right ->
          match Int.compare left.Yaml_cst.start_byte right.start_byte with
          | 0 -> Int.compare left.stop_byte right.stop_byte
          | comparison -> comparison)
    in
    let rec overlap = function
      | left :: (right :: _ as rest) ->
          if left.Yaml_cst.stop_byte > right.start_byte then true
          else overlap rest
      | _ -> false
    in
    if overlap edits then Error "fix proposals contain overlapping edits"
    else
      Ok
        (make
           (proposals
           |> List.map (fun proposal -> proposal.description)
           |> Util.deduplicate_strings |> String.concat "; ")
           edits true)

let diff_lines source =
  let lines = String.split_on_char '\n' source in
  match List.rev lines with
  | "" :: rest -> List.rev rest
  | _ -> lines

let unified_diff ~path ~before ~after =
  if before = after then ""
  else
    let before_lines = diff_lines before and after_lines = diff_lines after in
    let buffer =
      Buffer.create (String.length before + String.length after + 128)
    in
    Printf.bprintf buffer "--- %s\n+++ %s\n@@ -1,%d +1,%d @@\n"
      (Util.normalize_slashes path)
      (Util.normalize_slashes path)
      (List.length before_lines) (List.length after_lines);
    List.iter
      (fun line -> Buffer.add_string buffer ("-" ^ line ^ "\n"))
      before_lines;
    List.iter
      (fun line -> Buffer.add_string buffer ("+" ^ line ^ "\n"))
      after_lines;
    Buffer.contents buffer

let to_json proposal =
  Json.Object
    [
      ("description", Json.String proposal.description);
      ( "edits",
        Json.Array
          (List.map
             (fun (edit : Yaml_cst.edit) ->
               Json.Object
                 [
                   ("replacement", Json.String edit.replacement);
                   ("start_byte", Json.Int edit.start_byte);
                   ("stop_byte", Json.Int edit.stop_byte);
                 ])
             proposal.edits) );
      ("id", Json.String proposal.id);
      ("safe", Json.Bool proposal.safe);
    ]
