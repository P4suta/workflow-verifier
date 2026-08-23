type scalar_style = Plain | Single_quoted | Double_quoted | Literal | Folded
type trivia_kind = Comment | Blank | Directive | Document_start | Document_end
type quote = Single_quote | Double_quote
type trivia = { kind : trivia_kind; raw : string; span : Span.t }

type scalar = {
  value : string;
  raw : string;
  style : scalar_style;
  anchor : string option;
  tag : string option;
  span : Span.t;
}

type node =
  | Scalar of scalar
  | Alias of { name : string; raw : string; span : Span.t }
  | Sequence of sequence_item list * Span.t
  | Mapping of mapping_entry list * Span.t
  | Flow_sequence of node list * Span.t
  | Flow_mapping of mapping_entry list * Span.t
  | Decorated of {
      value : node;
      anchor : string option;
      tag : string option;
      span : Span.t;
    }
  | Invalid of { raw : string; reason : string; span : Span.t }

and sequence_item = { value : node; dash_span : Span.t; span : Span.t }

and mapping_entry = {
  key : scalar;
  key_node : node;
  value : node;
  colon_span : Span.t;
  span : Span.t;
  merge : bool;
  duplicate : bool;
}

type problem = { code : string; message : string; span : Span.t }
type document = { root : node option; directives : trivia list; span : Span.t }

type t = {
  file : string;
  source : string;
  bom : bool;
  newline : [ `Lf | `CrLf | `Cr | `None ];
  documents : document list;
  trivia : trivia list;
  anchors : (string * node) list;
  problems : problem list;
}

type edit = { start_byte : int; stop_byte : int; replacement : string }

type line = {
  number : int;
  start_byte : int;
  stop_byte : int;
  raw : string;
  indent : int;
  content : string;
  content_byte : int;
  comment_byte : int option;
}

let position_of_offset ~line ~column byte = { Span.byte; line; column }

let span_of_range file line start_column start_byte stop_column stop_byte =
  Span.make ~file
    (position_of_offset ~line ~column:start_column start_byte)
    (position_of_offset ~line ~column:stop_column stop_byte)

let node_span = function
  | Scalar scalar -> scalar.span
  | Alias alias -> alias.span
  | Sequence (_, span)
  | Mapping (_, span)
  | Flow_sequence (_, span)
  | Flow_mapping (_, span) -> span
  | Decorated decorated -> decorated.span
  | Invalid invalid -> invalid.span

let rec scalar_value = function
  | Scalar scalar -> Some scalar.value
  | Decorated decorated -> scalar_value decorated.value
  | _ -> None

let rec as_mapping = function
  | Mapping (entries, _) | Flow_mapping (entries, _) -> Some entries
  | Decorated decorated -> as_mapping decorated.value
  | _ -> None

let rec as_sequence = function
  | Sequence (items, _) -> Some items
  | Decorated decorated -> as_sequence decorated.value
  | _ -> None

let mapping_find name (entries : mapping_entry list) =
  entries
  |> List.find_opt (fun (entry : mapping_entry) ->
      String.equal entry.key.value name)
  |> Option.map (fun (entry : mapping_entry) -> entry.value)

let mapping_find_entry name (entries : mapping_entry list) =
  List.find_opt
    (fun (entry : mapping_entry) -> String.equal entry.key.value name)
    entries

let get_path root path =
  List.fold_left
    (fun current key ->
      match current with
      | None -> None
      | Some node -> Option.bind (as_mapping node) (mapping_find key))
    (Some root) path

let print tree = tree.source

let structural_equal left right =
  let rec scalar_equal (left : scalar) (right : scalar) =
    left.value = right.value && left.style = right.style
    && left.anchor = right.anchor && left.tag = right.tag
  and node_equal left right =
    match (left, right) with
    | Scalar left, Scalar right -> scalar_equal left right
    | Alias left, Alias right -> left.name = right.name
    | Sequence (left, _), Sequence (right, _) ->
        List.length left = List.length right
        && List.for_all2
             (fun (l : sequence_item) (r : sequence_item) ->
               node_equal l.value r.value)
             left right
    | Mapping (left, _), Mapping (right, _)
    | Flow_mapping (left, _), Flow_mapping (right, _) ->
        List.length left = List.length right
        && List.for_all2
             (fun (l : mapping_entry) (r : mapping_entry) ->
               node_equal l.key_node r.key_node
               && node_equal l.value r.value && l.merge = r.merge)
             left right
    | Flow_sequence (left, _), Flow_sequence (right, _) ->
        List.length left = List.length right
        && List.for_all2 node_equal left right
    | Decorated left, Decorated right ->
        left.anchor = right.anchor && left.tag = right.tag
        && node_equal left.value right.value
    | Invalid left, Invalid right ->
        left.raw = right.raw && left.reason = right.reason
    | _ -> false
  in
  List.length left.documents = List.length right.documents
  && List.for_all2
       (fun (left : document) (right : document) ->
         match (left.root, right.root) with
         | None, None -> true
         | Some left, Some right -> node_equal left right
         | _ -> false)
       left.documents right.documents

let newline_style source =
  let rec loop index =
    if index >= String.length source then `None
    else
      match source.[index] with
      | '\n' -> `Lf
      | '\r' when index + 1 < String.length source && source.[index + 1] = '\n'
        -> `CrLf
      | '\r' -> `Cr
      | _ -> loop (index + 1)
  in
  loop 0

let comment_index value =
  let quote = ref None and flow_depth = ref 0 and escaped = ref false in
  let result = ref None in
  let index = ref 0 in
  while !index < String.length value && !result = None do
    let character = value.[!index] in
    (match !quote with
    | Some Double_quote ->
        if !escaped then escaped := false
        else if character = '\\' then escaped := true
        else if character = '"' then quote := None
    | Some Single_quote -> if character = '\'' then quote := None
    | None -> (
        match character with
        | '"' -> quote := Some Double_quote
        | '\'' -> quote := Some Single_quote
        | '[' | '{' | '(' -> incr flow_depth
        | ']' | '}' | ')' -> flow_depth := max 0 (!flow_depth - 1)
        | '#'
          when !index = 0
               ||
               match value.[!index - 1] with
               | ' ' | '\t' -> true
               | _ -> false -> result := Some !index
        | _ -> ()));
    incr index
  done;
  !result

let split_lines source =
  let length = String.length source in
  let rec loop number start accumulator =
    if start >= length then
      if length = 0 then
        [
          {
            number = 1;
            start_byte = 0;
            stop_byte = 0;
            raw = "";
            indent = 0;
            content = "";
            content_byte = 0;
            comment_byte = None;
          };
        ]
      else List.rev accumulator
    else
      let cursor = ref start in
      while
        !cursor < length && source.[!cursor] <> '\n' && source.[!cursor] <> '\r'
      do
        incr cursor
      done;
      let line_stop = !cursor in
      if !cursor < length then
        if
          source.[!cursor] = '\r'
          && !cursor + 1 < length
          && source.[!cursor + 1] = '\n'
        then cursor := !cursor + 2
        else incr cursor;
      let raw = String.sub source start (line_stop - start) in
      let indent = ref 0 in
      while !indent < String.length raw && raw.[!indent] = ' ' do
        incr indent
      done;
      let unindented = String.sub raw !indent (String.length raw - !indent) in
      let relative_comment = comment_index unindented in
      let content =
        match relative_comment with
        | None -> unindented
        | Some offset -> String.sub unindented 0 offset
      in
      let line =
        {
          number;
          start_byte = start;
          stop_byte = line_stop;
          raw;
          indent = !indent;
          content;
          content_byte = start + !indent;
          comment_byte =
            Option.map (fun offset -> start + !indent + offset) relative_comment;
        }
      in
      loop (number + 1) !cursor (line :: accumulator)
  in
  loop 1 0 [] |> Array.of_list

let without_bom value =
  if
    String.length value >= 3
    && Char.code value.[0] = 0xef
    && Char.code value.[1] = 0xbb
    && Char.code value.[2] = 0xbf
  then String.sub value 3 (String.length value - 3)
  else value

let has_document_indicator indicator line =
  if line.indent <> 0 then false
  else
    let content = without_bom line.raw in
    let length = String.length indicator in
    String.length content >= length
    && String.sub content 0 length = indicator
    && (String.length content = length
       ||
       match content.[length] with
       | ' ' | '\t' -> true
       | _ -> false)

let document_start_line = has_document_indicator "---"
let document_end_line = has_document_indicator "..."

let semantic_line line =
  if not (document_start_line line) then line
  else
    let original_content = line.content in
    let content = without_bom original_content in
    let bom_width = String.length original_content - String.length content in
    let cursor = ref 3 in
    while
      !cursor < String.length content
      &&
      match content.[!cursor] with
      | ' ' | '\t' -> true
      | _ -> false
    do
      incr cursor
    done;
    if !cursor = String.length content then line
    else
      {
        line with
        content = String.sub content !cursor (String.length content - !cursor);
        content_byte = line.content_byte + bom_width + !cursor;
      }

let trim_right value =
  let index = ref (String.length value - 1) in
  while !index >= 0 && (value.[!index] = ' ' || value.[!index] = '\t') do
    decr index
  done;
  if !index < 0 then "" else String.sub value 0 (!index + 1)

let is_ignorable line =
  let content = String.trim line.content in
  content = ""
  || Util.starts_with ~prefix:"#" content
  || Util.starts_with ~prefix:"%" content
  || content = "---" || content = "..."

let indicator_with_separation indicator value =
  String.length value > 0
  && value.[0] = indicator
  && (String.length value = 1
     ||
     match value.[1] with
     | ' ' | '\t' -> true
     | _ -> false)

let next_significant lines limit index =
  let cursor = ref index in
  while !cursor < limit && is_ignorable lines.(!cursor) do
    incr cursor
  done;
  !cursor

let property_prefix_length value =
  let length = String.length value in
  let cursor = ref 0 and found = ref false and continue = ref true in
  let skip_space () =
    while
      !cursor < length
      &&
      match value.[!cursor] with
      | ' ' | '\t' -> true
      | _ -> false
    do
      incr cursor
    done
  in
  skip_space ();
  while !continue && !cursor < length do
    match value.[!cursor] with
    | '&' | '!' ->
        found := true;
        while
          !cursor < length
          &&
          match value.[!cursor] with
          | ' ' | '\t' -> false
          | _ -> true
        do
          incr cursor
        done;
        skip_space ()
    | _ -> continue := false
  done;
  if !found then !cursor else 0

let find_mapping_colon value =
  let quote = ref None
  and escaped = ref false
  and depth = ref 0
  and answer = ref None in
  let scalar_start = property_prefix_length value in
  let index = ref scalar_start in
  while !index < String.length value && !answer = None do
    let character = value.[!index] in
    (match !quote with
    | Some Double_quote ->
        if !escaped then escaped := false
        else if character = '\\' then escaped := true
        else if character = '"' then quote := None
    | Some Single_quote -> if character = '\'' then quote := None
    | None -> (
        match character with
        | '"' when !index = scalar_start -> quote := Some Double_quote
        | '\'' when !index = scalar_start -> quote := Some Single_quote
        | '[' | '{' | '(' -> incr depth
        | ']' | '}' | ')' -> depth := max 0 (!depth - 1)
        | ':'
          when !depth = 0
               && (!index + 1 = String.length value
                  ||
                  match value.[!index + 1] with
                  | ' ' | '\t' -> true
                  | _ -> false) -> answer := Some !index
        | _ -> ()));
    incr index
  done;
  !answer

let find_flow_mapping_colon value =
  let trimmed = String.trim value in
  let compact_key =
    String.length trimmed > 0
    &&
    match trimmed.[0] with
    | '"' | '\'' | '[' | '{' -> true
    | _ -> false
  in
  let quote = ref None
  and escaped = ref false
  and depth = ref 0
  and answer = ref None
  and index = ref 0 in
  while !index < String.length value && !answer = None do
    let character = value.[!index] in
    (match !quote with
    | Some Double_quote ->
        if !escaped then escaped := false
        else if character = '\\' then escaped := true
        else if character = '"' then quote := None
    | Some Single_quote -> if character = '\'' then quote := None
    | None -> (
        match character with
        | '"' -> quote := Some Double_quote
        | '\'' -> quote := Some Single_quote
        | '[' | '{' | '(' -> incr depth
        | ']' | '}' | ')' -> depth := max 0 (!depth - 1)
        | ':'
          when !depth = 0
               && (compact_key
                  || !index + 1 = String.length value
                  ||
                  match value.[!index + 1] with
                  | ' ' | '\t' | '\r' | '\n' -> true
                  | _ -> false) -> answer := Some !index
        | _ -> ()));
    incr index
  done;
  !answer

let split_flow separator value =
  let parts = ref []
  and start = ref 0
  and quote = ref None
  and escaped = ref false
  and depth = ref 0 in
  let push stop =
    parts := String.sub value !start (stop - !start) :: !parts;
    start := stop + 1
  in
  String.iteri
    (fun index character ->
      match !quote with
      | Some Double_quote ->
          if !escaped then escaped := false
          else if character = '\\' then escaped := true
          else if character = '"' then quote := None
      | Some Single_quote -> if character = '\'' then quote := None
      | None -> (
          match character with
          | '"' -> quote := Some Double_quote
          | '\'' -> quote := Some Single_quote
          | '[' | '{' | '(' -> incr depth
          | ']' | '}' | ')' -> depth := max 0 (!depth - 1)
          | character when character = separator && !depth = 0 -> push index
          | _ -> ()))
    value;
  parts := String.sub value !start (String.length value - !start) :: !parts;
  List.rev !parts

let decode_single value = Util.replace_all ~needle:"''" ~replacement:"'" value

let add_utf8 buffer codepoint =
  if codepoint <= 0x7f then Buffer.add_char buffer (Char.chr codepoint)
  else if codepoint <= 0x7ff then (
    Buffer.add_char buffer (Char.chr (0xc0 lor (codepoint lsr 6)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))))
  else if codepoint <= 0xffff then (
    Buffer.add_char buffer (Char.chr (0xe0 lor (codepoint lsr 12)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 6) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))))
  else (
    Buffer.add_char buffer (Char.chr (0xf0 lor (codepoint lsr 18)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 12) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 6) land 0x3f)));
    Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))))

let hex_value = function
  | '0' .. '9' as character -> Some (Char.code character - Char.code '0')
  | 'a' .. 'f' as character -> Some (10 + Char.code character - Char.code 'a')
  | 'A' .. 'F' as character -> Some (10 + Char.code character - Char.code 'A')
  | _ -> None

let decode_hex value start digits =
  if start + digits > String.length value then None
  else
    let answer = ref 0 and valid = ref true in
    for index = start to start + digits - 1 do
      match hex_value value.[index] with
      | Some digit -> answer := (!answer * 16) + digit
      | None -> valid := false
    done;
    if !valid then Some !answer else None

let decode_double value =
  let buffer = Buffer.create (String.length value) in
  let rec loop index =
    if index >= String.length value then ()
    else if value.[index] <> '\\' then (
      Buffer.add_char buffer value.[index];
      loop (index + 1))
    else if index + 1 >= String.length value then Buffer.add_char buffer '\\'
    else
      let escaped = value.[index + 1] in
      let simple =
        match escaped with
        | '0' -> Some '\000'
        | 'a' -> Some '\007'
        | 'b' -> Some '\008'
        | 't' | '\t' -> Some '\t'
        | 'n' -> Some '\n'
        | 'v' -> Some '\011'
        | 'f' -> Some '\012'
        | 'r' -> Some '\r'
        | 'e' -> Some '\027'
        | ' ' -> Some ' '
        | '"' -> Some '"'
        | '/' -> Some '/'
        | '\\' -> Some '\\'
        | _ -> None
      in
      match simple with
      | Some character ->
          Buffer.add_char buffer character;
          loop (index + 2)
      | None -> (
          let unicode, digits =
            match escaped with
            | 'N' -> (Some 0x85, 0)
            | '_' -> (Some 0xa0, 0)
            | 'L' -> (Some 0x2028, 0)
            | 'P' -> (Some 0x2029, 0)
            | 'x' -> (decode_hex value (index + 2) 2, 2)
            | 'u' -> (decode_hex value (index + 2) 4, 4)
            | 'U' -> (decode_hex value (index + 2) 8, 8)
            | _ -> (None, -1)
          in
          match unicode with
          | Some codepoint ->
              add_utf8 buffer codepoint;
              loop (index + 2 + digits)
          | None ->
              Buffer.add_char buffer escaped;
              loop (index + 2))
  in
  loop 0;
  Buffer.contents buffer

let trim_left value =
  let index = ref 0 in
  while
    !index < String.length value
    &&
    match value.[!index] with
    | ' ' | '\t' -> true
    | _ -> false
  do
    incr index
  done;
  String.sub value !index (String.length value - !index)

let trailing_unescaped_backslash value =
  let count = ref 0 and index = ref (String.length value - 1) in
  while !index >= 0 && value.[!index] = '\\' do
    incr count;
    decr index
  done;
  !count mod 2 = 1

let join_escaped_lines lines =
  let rec loop accumulator = function
    | current :: next :: rest when trailing_unescaped_backslash current ->
        let current = String.sub current 0 (String.length current - 1) in
        loop accumulator ((current ^ trim_left next) :: rest)
    | current :: rest -> loop (current :: accumulator) rest
    | [] -> List.rev accumulator
  in
  loop [] lines

let fold_quoted ~double value =
  let value =
    value
    |> Util.replace_all ~needle:"\r\n" ~replacement:"\n"
    |> Util.replace_all ~needle:"\r" ~replacement:"\n"
  in
  let lines = String.split_on_char '\n' value in
  let lines = if double then join_escaped_lines lines else lines in
  let last_content =
    List.fold_left
      (fun answer (index, line) ->
        if String.trim line = "" then answer else index)
      0
      (List.mapi (fun index line -> (index, line)) lines)
  in
  let lines =
    List.mapi
      (fun index line ->
        let line = if index = 0 then line else trim_left line in
        if index < last_content then (
          let stop = ref (String.length line) in
          while !stop > 0 && line.[!stop - 1] = ' ' do
            decr stop
          done;
          let tab_start = ref !stop in
          while !tab_start > 0 && line.[!tab_start - 1] = '\t' do
            decr tab_start
          done;
          if
            !tab_start < !stop
            && (!tab_start = 0 || line.[!tab_start - 1] <> '\\')
          then stop := !tab_start;
          String.sub line 0 !stop)
        else line)
      lines
  in
  match lines with
  | [] -> ""
  | first :: rest ->
      let buffer = Buffer.create (String.length value) in
      Buffer.add_string buffer first;
      let blank_lines = ref 0 in
      List.iter
        (fun line ->
          let line = trim_left line in
          if line = "" then incr blank_lines
          else (
            if !blank_lines = 0 then Buffer.add_char buffer ' '
            else (
              for _ = 1 to !blank_lines do
                Buffer.add_char buffer '\n'
              done;
              blank_lines := 0);
            Buffer.add_string buffer line))
        rest;
      if Buffer.length buffer > 0 && !blank_lines > 0 then
        if !blank_lines = 1 then Buffer.add_char buffer ' '
        else
          for _ = 1 to !blank_lines - 1 do
            Buffer.add_char buffer '\n'
          done;
      (if Buffer.length buffer = 0 && List.length lines > 1 then
         let breaks = List.length lines - 1 in
         if breaks = 1 then Buffer.add_char buffer ' '
         else
           for _ = 1 to breaks - 1 do
             Buffer.add_char buffer '\n'
           done);
      Buffer.contents buffer

let normalize_tag tag = tag

let parse_prefixes raw =
  let source = String.trim raw in
  let length = String.length source and cursor = ref 0 in
  let anchor = ref None and tag = ref None and parsing = ref true in
  let separation = function
    | ' ' | '\t' | '\r' | '\n' -> true
    | _ -> false
  in
  let skip_separation () =
    while !cursor < length && separation source.[!cursor] do
      incr cursor
    done
  in
  skip_separation ();
  while !cursor < length && !parsing do
    match source.[!cursor] with
    | ('&' | '!') as indicator ->
        let start = !cursor in
        while !cursor < length && not (separation source.[!cursor]) do
          incr cursor
        done;
        let token = String.sub source start (!cursor - start) in
        if indicator = '&' then
          anchor := Some (String.sub token 1 (String.length token - 1))
        else tag := Some (normalize_tag token);
        skip_separation ()
    | _ -> parsing := false
  done;
  (!anchor, !tag, !cursor)

let inline_needs_continuation raw =
  let trimmed = String.trim raw in
  let _, _, prefix_length = parse_prefixes trimmed in
  let body =
    if prefix_length = 0 then trimmed
    else
      String.sub trimmed prefix_length (String.length trimmed - prefix_length)
      |> String.trim
  in
  if body = "" then false
  else
    match body.[0] with
    | ('"' | '\'') as quote ->
        String.length body < 2 || body.[String.length body - 1] <> quote
    | '[' | '{' ->
        let depth = ref 0 and quote = ref None and escaped = ref false in
        String.iter
          (fun character ->
            match !quote with
            | Some Double_quote ->
                if !escaped then escaped := false
                else if character = '\\' then escaped := true
                else if character = '"' then quote := None
            | Some Single_quote -> if character = '\'' then quote := None
            | None -> (
                match character with
                | '"' -> quote := Some Double_quote
                | '\'' -> quote := Some Single_quote
                | '[' | '{' -> incr depth
                | ']' | '}' -> decr depth
                | _ -> ()))
          body;
        !depth > 0 || Option.is_some !quote
    | _ -> false

let rec parse_inline ?(implicit_flow_mapping = false) ~file ~line ~column ~byte
    raw =
  let raw = trim_right raw in
  let leading = String.length raw - String.length (String.trim raw) in
  let trimmed = String.trim raw in
  let start_byte = byte + leading and start_column = column + leading in
  let stop_byte = start_byte + String.length trimmed in
  let span =
    span_of_range file line start_column start_byte
      (start_column + String.length trimmed)
      stop_byte
  in
  let anchor, tag, prefix_length = parse_prefixes trimmed in
  let body =
    if prefix_length = 0 then trimmed
    else
      String.sub trimmed prefix_length (String.length trimmed - prefix_length)
      |> String.trim
  in
  let decorate value =
    match (anchor, tag) with
    | None, None -> value
    | _ -> Decorated { value; anchor; tag; span }
  in
  if trimmed = "" then
    Scalar
      { value = ""; raw = ""; style = Plain; anchor = None; tag = None; span }
  else if body <> "" && body.[0] = '*' then
    Alias
      { name = String.sub body 1 (String.length body - 1); raw = trimmed; span }
  else if
    String.length body >= 2
    && body.[0] = '['
    && body.[String.length body - 1] = ']'
  then
    let inner = String.sub body 1 (String.length body - 2) in
    let body_byte = start_byte + prefix_length in
    let body_column = start_column + prefix_length in
    let children =
      if String.trim inner = "" then []
      else
        split_flow ',' inner
        |> List.filter (fun part -> String.trim part <> "")
        |> List.map (fun part ->
            parse_inline ~implicit_flow_mapping:true ~file ~line
              ~column:(body_column + 1) ~byte:(body_byte + 1) part)
    in
    decorate (Flow_sequence (children, span))
  else if
    String.length body >= 2
    && body.[0] = '{'
    && body.[String.length body - 1] = '}'
  then
    let inner = String.sub body 1 (String.length body - 2) in
    let body_byte = start_byte + prefix_length in
    let body_column = start_column + prefix_length in
    let seen = ref [] in
    let entries =
      if String.trim inner = "" then []
      else
        split_flow ',' inner
        |> List.filter (fun part -> String.trim part <> "")
        |> List.map (fun part ->
            match find_flow_mapping_colon part with
            | colon ->
                let key_raw, value_raw, colon_offset =
                  match colon with
                  | None -> (String.trim part, "", String.length part)
                  | Some colon ->
                      ( String.sub part 0 colon |> String.trim,
                        String.sub part (colon + 1)
                          (String.length part - colon - 1),
                        colon )
                in
                let key_raw =
                  if indicator_with_separation '?' (String.trim key_raw) then
                    let key = String.trim key_raw in
                    if String.length key = 1 then ""
                    else String.sub key 1 (String.length key - 1) |> String.trim
                  else key_raw
                in
                let key_node =
                  parse_inline ~file ~line ~column:(body_column + 1)
                    ~byte:(body_byte + 1) key_raw
                in
                let key =
                  match key_node with
                  | Scalar scalar -> scalar
                  | _ ->
                      {
                        value = key_raw;
                        raw = key_raw;
                        style = Plain;
                        anchor = None;
                        tag = None;
                        span;
                      }
                in
                let duplicate = List.mem key.value !seen in
                seen := key.value :: !seen;
                let value =
                  parse_inline ~file ~line
                    ~column:(start_column + colon_offset + 2)
                    ~byte:(start_byte + colon_offset + 1)
                    value_raw
                in
                {
                  key;
                  key_node;
                  value;
                  colon_span = span;
                  span;
                  merge = key.value = "<<";
                  duplicate;
                })
    in
    decorate (Flow_mapping (entries, span))
  else if implicit_flow_mapping && Option.is_some (find_flow_mapping_colon body)
  then
    match
      parse_inline ~file ~line ~column:start_column ~byte:start_byte
        ("{" ^ trimmed ^ "}")
    with
    | Flow_mapping (entries, _) -> Flow_mapping (entries, span)
    | Decorated { value = Flow_mapping (entries, _); _ } ->
        Flow_mapping (entries, span)
    | value -> value
  else
    let style, value =
      if
        String.length body >= 2
        && body.[0] = '\''
        && body.[String.length body - 1] = '\''
      then
        ( Single_quoted,
          String.sub body 1 (String.length body - 2)
          |> fold_quoted ~double:false |> decode_single )
      else if
        String.length body >= 2
        && body.[0] = '"'
        && body.[String.length body - 1] = '"'
      then
        ( Double_quoted,
          String.sub body 1 (String.length body - 2)
          |> fold_quoted ~double:true |> decode_double )
      else
        ( Plain,
          if String.contains body '\n' then fold_quoted ~double:false body
          else body )
    in
    Scalar { value; raw = trimmed; style; anchor; tag; span }

let parse ?(file = "<memory>") source =
  let bom =
    String.length source >= 3
    && Char.code source.[0] = 0xef
    && Char.code source.[1] = 0xbb
    && Char.code source.[2] = 0xbf
  in
  let source_lines = split_lines source in
  let lines = Array.map semantic_line source_lines in
  let line_count = Array.length lines in
  let problems = ref [] and anchors = ref [] in
  let add_problem code message span =
    problems := { code; message; span } :: !problems
  in
  let rec register_anchors node =
    (match node with
    | Scalar ({ anchor = Some name; _ } as _scalar) ->
        anchors := (name, node) :: !anchors
    | Sequence (items, _) ->
        List.iter
          (fun (item : sequence_item) -> ignore (register_anchors item.value))
          items
    | Mapping (entries, _) | Flow_mapping (entries, _) ->
        List.iter
          (fun (entry : mapping_entry) ->
            ignore (register_anchors entry.key_node);
            ignore (register_anchors entry.value))
          entries
    | Flow_sequence (nodes, _) ->
        List.iter (fun child -> ignore (register_anchors child)) nodes
    | Decorated decorated ->
        Option.iter
          (fun name -> anchors := (name, decorated.value) :: !anchors)
          decorated.anchor;
        ignore (register_anchors decorated.value)
    | Alias _ | Invalid _ | Scalar _ -> ());
    node
  in
  let key_projection raw key_node =
    match key_node with
    | Scalar scalar -> scalar
    | _ ->
        let span = node_span key_node in
        { value = raw; raw; style = Plain; anchor = None; tag = None; span }
  in
  let collect_inline limit next_index initial =
    let cursor = ref next_index and source = ref initial in
    while !cursor < limit && inline_needs_continuation !source do
      let line = lines.(!cursor) in
      if document_start_line line || document_end_line line then cursor := limit
      else (
        source := !source ^ "\n" ^ line.content;
        (match comment_index !source with
        | Some offset -> source := String.sub !source 0 offset |> trim_right
        | None -> ());
        incr cursor)
    done;
    (!source, !cursor, not (inline_needs_continuation !source))
  in
  let extend_plain_scalar limit parent_indent next_index node =
    match node with
    | Scalar ({ style = Plain; _ } as scalar) ->
        let cursor = ref next_index
        and blank_lines = ref 0
        and value = Buffer.create (String.length scalar.value + 32)
        and last_span = ref scalar.span
        and consumed = ref false
        and finished = ref false in
        Buffer.add_string value scalar.value;
        while !cursor < limit && not !finished do
          let line = lines.(!cursor) in
          let content = String.trim line.content in
          if document_start_line line || document_end_line line then
            finished := true
          else if
            (Option.is_some line.comment_byte && content = "")
            || Option.is_some (find_mapping_colon content)
          then finished := true
          else if content = "" || Util.starts_with ~prefix:"#" content then (
            incr blank_lines;
            incr cursor)
          else if line.indent > parent_indent then (
            consumed := true;
            if !blank_lines = 0 then Buffer.add_char value ' '
            else (
              for _ = 1 to !blank_lines do
                Buffer.add_char value '\n'
              done;
              blank_lines := 0);
            Buffer.add_string value content;
            last_span :=
              span_of_range file line.number (line.indent + 1) line.content_byte
                (String.length line.raw + 1)
                line.stop_byte;
            incr cursor;
            if Option.is_some line.comment_byte then finished := true)
          else finished := true
        done;
        if !consumed then
          ( Scalar
              {
                scalar with
                value = Buffer.contents value;
                span = Span.merge scalar.span !last_span;
              },
            !cursor )
        else (node, next_index)
    | _ -> (node, next_index)
  in
  let parse_inline_value ?(implicit_flow_mapping = false) limit parent_indent
      next_index line column byte raw =
    let collected, next, complete = collect_inline limit next_index raw in
    let node =
      parse_inline ~implicit_flow_mapping ~file ~line:line.number ~column ~byte
        collected
    in
    if not complete then
      add_problem "YAML-SYNTAX" "unterminated quoted scalar or flow collection"
        (node_span node);
    if next <> next_index then (node, next)
    else if Option.is_some line.comment_byte then (node, next_index)
    else extend_plain_scalar limit parent_indent next_index node
  in
  let nested_mapping_value parent_indent child_index =
    child_index < line_count
    && (lines.(child_index).indent > parent_indent
       ||
       let content = String.trim lines.(child_index).content in
       lines.(child_index).indent = parent_indent
       && indicator_with_separation '-' content)
  in
  let block_header raw =
    let anchor, tag, prefix_length = parse_prefixes raw in
    let body =
      if prefix_length = 0 then String.trim raw
      else
        String.sub (String.trim raw) prefix_length
          (String.length (String.trim raw) - prefix_length)
        |> String.trim
    in
    if body = "" || (body.[0] <> '|' && body.[0] <> '>') then None
    else
      let style = if body.[0] = '|' then Literal else Folded in
      let chomping = ref `Clip
      and indentation = ref None
      and valid = ref true in
      String.iteri
        (fun index character ->
          if index > 0 then
            match character with
            | '+' when !chomping = `Clip -> chomping := `Keep
            | '-' when !chomping = `Clip -> chomping := `Strip
            | '1' .. '9' when !indentation = None ->
                indentation := Some (Char.code character - Char.code '0')
            | _ -> valid := false)
        body;
      if !valid then Some (style, !chomping, !indentation, anchor, tag)
      else None
  in
  let strip_trailing_newlines value =
    let stop = ref (String.length value) in
    while !stop > 0 && value.[!stop - 1] = '\n' do
      decr stop
    done;
    String.sub value 0 !stop
  in
  let parse_block_scalar limit base_indent next_index line column byte raw =
    match block_header raw with
    | None ->
        (parse_inline ~file ~line:line.number ~column ~byte raw, next_index)
    | Some (style, chomping, indentation, anchor, tag) ->
        let cursor = ref next_index
        and block_indent = ref (Option.map (( + ) base_indent) indentation)
        and chunks = ref []
        and finished = ref false
        and saw_non_blank = ref false
        and last_span =
          ref
            (span_of_range file line.number column byte
               (column + String.length raw)
               (byte + String.length raw))
        in
        while !cursor < limit && not !finished do
          let block_line = lines.(!cursor) in
          if document_start_line block_line || document_end_line block_line then
            finished := true
          else
            let blank = String.trim block_line.raw = "" in
            if blank then (
              let had_break = true in
              let text, more_indented =
                match !block_indent with
                | Some required when String.length block_line.raw > required ->
                    ( String.sub block_line.raw required
                        (String.length block_line.raw - required),
                      true )
                | None ->
                    let required = max 0 (base_indent + 1) in
                    let text =
                      if String.length block_line.raw <= required then ""
                      else
                        String.sub block_line.raw required
                          (String.length block_line.raw - required)
                    in
                    let text =
                      if String.contains text '\t' then
                        String.to_seq text
                        |> Seq.filter (fun character -> character <> ' ')
                        |> String.of_seq
                      else ""
                    in
                    (text, text <> "")
                | Some _ -> ("", false)
              in
              chunks := (text, more_indented, had_break) :: !chunks;
              last_span :=
                span_of_range file block_line.number 1 block_line.start_byte
                  (String.length block_line.raw + 1)
                  block_line.stop_byte;
              incr cursor)
            else (
              if !block_indent = None && block_line.indent > base_indent then
                block_indent := Some block_line.indent;
              (match (!block_indent, indentation) with
              | Some required, Some _
                when (not !saw_non_blank) && block_line.indent < required ->
                  block_indent := Some block_line.indent
              | _ -> ());
              match !block_indent with
              | None -> finished := true
              | Some required when block_line.indent < required ->
                  finished := true
              | Some required ->
                  saw_non_blank := true;
                  let text =
                    if String.length block_line.raw <= required then ""
                    else
                      String.sub block_line.raw required
                        (String.length block_line.raw - required)
                  in
                  let had_break = true in
                  let more_indented =
                    block_line.indent > required
                    || text <> ""
                       &&
                       match text.[0] with
                       | ' ' | '\t' -> true
                       | _ -> false
                  in
                  chunks := (text, more_indented, had_break) :: !chunks;
                  last_span :=
                    span_of_range file block_line.number (required + 1)
                      (block_line.start_byte + required)
                      (String.length block_line.raw + 1)
                      block_line.stop_byte;
                  incr cursor)
        done;
        let chunks = List.rev !chunks in
        let buffer = Buffer.create 64 in
        (if style = Literal then
           List.iter
             (fun (text, _, had_break) ->
               Buffer.add_string buffer text;
               if had_break then Buffer.add_char buffer '\n')
             chunks
         else
           let previous = ref None and pending_blank = ref 0 in
           List.iter
             (fun (text, more_indented, had_break) ->
               if text = "" then incr pending_blank
               else (
                 (match !previous with
                 | None ->
                     for _ = 1 to !pending_blank do
                       Buffer.add_char buffer '\n'
                     done
                 | Some (previous_more, previous_had_break) ->
                     if !pending_blank > 0 then
                       for
                         _ = 1
                         to !pending_blank
                            + if previous_more || more_indented then 1 else 0
                       do
                         Buffer.add_char buffer '\n'
                       done
                     else if previous_had_break then
                       Buffer.add_char buffer
                         (if previous_more || more_indented then '\n' else ' '));
                 pending_blank := 0;
                 Buffer.add_string buffer text;
                 previous := Some (more_indented, had_break)))
             chunks;
           match !previous with
           | None ->
               for _ = 1 to !pending_blank do
                 Buffer.add_char buffer '\n'
               done
           | Some (_, had_break) ->
               if !pending_blank = 0 then (
                 if had_break then Buffer.add_char buffer '\n')
               else
                 for _ = 0 to !pending_blank do
                   Buffer.add_char buffer '\n'
                 done);
        let value = Buffer.contents buffer in
        let value =
          match chomping with
          | `Keep -> value
          | `Strip -> strip_trailing_newlines value
          | `Clip ->
              let clipped = strip_trailing_newlines value in
              if not (List.exists (fun (text, _, _) -> text <> "") chunks) then
                ""
              else if value = clipped then clipped
              else clipped ^ "\n"
        in
        let header_span =
          span_of_range file line.number column byte
            (column + String.length raw)
            (byte + String.length raw)
        in
        ( Scalar
            {
              value;
              raw;
              style;
              anchor;
              tag;
              span = Span.merge header_span !last_span;
            },
          !cursor )
  in
  let rec parse_block limit index minimum_indent =
    let index = next_significant lines limit index in
    if index >= limit then (None, index)
    else
      let line = lines.(index) in
      if line.indent < minimum_indent then (None, index)
      else
        let content = String.trim line.content in
        let anchor, tag, prefix_length = parse_prefixes content in
        let prefix_body =
          if prefix_length = 0 then content
          else
            String.sub content prefix_length
              (String.length content - prefix_length)
            |> String.trim
        in
        if Option.is_some (block_header content) then
          let node, next =
            parse_block_scalar limit (line.indent - 1) (index + 1) line
              (line.indent + 1) line.content_byte content
          in
          (Some (register_anchors node), next)
        else if prefix_length > 0 && prefix_body = "" then
          let child_index = next_significant lines limit (index + 1) in
          if child_index < limit then
            match parse_block limit child_index lines.(child_index).indent with
            | Some child, next ->
                let prefix =
                  parse_inline ~file ~line:line.number ~column:(line.indent + 1)
                    ~byte:line.content_byte content
                in
                let decorated =
                  Decorated
                    {
                      value = child;
                      anchor;
                      tag;
                      span = Span.merge (node_span prefix) (node_span child);
                    }
                in
                (Some (register_anchors decorated), next)
            | None, next ->
                ( Some
                    (register_anchors
                       (parse_inline ~file ~line:line.number
                          ~column:(line.indent + 1) ~byte:line.content_byte
                          content)),
                  next )
          else
            ( Some
                (register_anchors
                   (parse_inline ~file ~line:line.number
                      ~column:(line.indent + 1) ~byte:line.content_byte content)),
              index + 1 )
        else if indicator_with_separation '-' content then
          let node, next = parse_sequence limit index line.indent None in
          (Some node, next)
        else if indicator_with_separation '?' content then
          let node, next = parse_explicit_mapping limit index line.indent in
          (Some node, next)
        else if
          String.length content > 1
          && content.[0] = '*'
          && content.[String.length content - 1] = ':'
        then
          let node =
            parse_inline ~file ~line:line.number ~column:(line.indent + 1)
              ~byte:line.content_byte content
          in
          (Some (register_anchors node), index + 1)
        else
          match find_mapping_colon content with
          | Some _ ->
              let node, next = parse_mapping limit index line.indent None in
              (Some node, next)
          | None ->
              let scalar_source =
                if inline_needs_continuation line.content then line.content
                else content
              in
              let node, next =
                parse_inline_value limit (line.indent - 1) (index + 1) line
                  (line.indent + 1) line.content_byte scalar_source
              in
              (Some (register_anchors node), next)
  and parse_sequence limit index indent first_item =
    let items = ref []
    and cursor = ref index
    and first_item = ref first_item
    and finished = ref false in
    while not !finished do
      let candidate =
        match !first_item with
        | Some (line, content, dash_byte) ->
            first_item := None;
            Some (!cursor, line, content, dash_byte, true)
        | None ->
            let significant = next_significant lines limit !cursor in
            if significant >= limit then (
              cursor := significant;
              None)
            else
              let line = lines.(significant) in
              let content = String.trim line.content in
              if
                line.indent <> indent
                || not (indicator_with_separation '-' content)
              then (
                cursor := significant;
                None)
              else
                let dash_in_line =
                  match String.index_opt line.content '-' with
                  | Some value -> value
                  | None -> 0
                in
                Some
                  ( significant,
                    line,
                    content,
                    line.content_byte + dash_in_line,
                    false )
      in
      match candidate with
      | None -> finished := true
      | Some (significant, line, content, dash_byte, synthetic) ->
          let dash_span =
            let column = dash_byte - line.start_byte + 1 in
            span_of_range file line.number column dash_byte (column + 1)
              (dash_byte + 1)
          in
          let rest_raw =
            if String.length content = 1 then ""
            else String.sub content 1 (String.length content - 1)
          in
          let rest_leading = ref 0 in
          while
            !rest_leading < String.length rest_raw
            &&
            match rest_raw.[!rest_leading] with
            | ' ' | '\t' -> true
            | _ -> false
          do
            incr rest_leading
          done;
          let rest =
            String.sub rest_raw !rest_leading
              (String.length rest_raw - !rest_leading)
            |> trim_right
          in
          let rest_byte = dash_byte + 1 + !rest_leading in
          let rest_column = rest_byte - line.start_byte + 1 in
          let value, next =
            if rest = "" then
              let child_index =
                next_significant lines limit
                  (if synthetic then !cursor else significant + 1)
              in
              if child_index < limit && lines.(child_index).indent > indent then
                match
                  parse_block limit child_index lines.(child_index).indent
                with
                | Some child, next -> (child, next)
                | None, next ->
                    ( parse_inline ~file ~line:line.number ~column:(indent + 2)
                        ~byte:(dash_byte + 1) "",
                      next )
              else
                ( parse_inline ~file ~line:line.number ~column:(indent + 2)
                    ~byte:(dash_byte + 1) "",
                  if synthetic then !cursor else significant + 1 )
            else
              let prefix_anchor, prefix_tag, prefix_length =
                parse_prefixes rest
              in
              let prefix_body =
                if prefix_length = 0 then rest
                else
                  String.sub rest prefix_length
                    (String.length rest - prefix_length)
                  |> String.trim
              in
              if Option.is_some (block_header rest) then
                parse_block_scalar limit indent
                  (if synthetic then !cursor else significant + 1)
                  line rest_column rest_byte rest
              else if prefix_length > 0 && prefix_body = "" then
                let child_index =
                  next_significant lines limit
                    (if synthetic then !cursor else significant + 1)
                in
                if child_index < limit && lines.(child_index).indent > indent
                then
                  match
                    parse_block limit child_index lines.(child_index).indent
                  with
                  | Some child, next ->
                      let prefix =
                        parse_inline ~file ~line:line.number ~column:rest_column
                          ~byte:rest_byte rest
                      in
                      ( Decorated
                          {
                            value = child;
                            anchor = prefix_anchor;
                            tag = prefix_tag;
                            span =
                              Span.merge (node_span prefix) (node_span child);
                          },
                        next )
                  | None, next ->
                      ( parse_inline ~file ~line:line.number ~column:rest_column
                          ~byte:rest_byte rest,
                        next )
                else
                  ( parse_inline ~file ~line:line.number ~column:rest_column
                      ~byte:rest_byte rest,
                    if synthetic then !cursor else significant + 1 )
              else if indicator_with_separation '?' rest then
                let body =
                  if String.length rest = 1 then ""
                  else String.sub rest 1 (String.length rest - 1) |> String.trim
                in
                let key_node =
                  parse_inline ~implicit_flow_mapping:true ~file
                    ~line:line.number ~column:rest_column ~byte:rest_byte body
                in
                let key_node =
                  match key_node with
                  | Flow_mapping (entries, span) -> Mapping (entries, span)
                  | node -> node
                in
                let next_index =
                  if synthetic then !cursor else significant + 1
                in
                let value, next =
                  let candidate_index =
                    next_significant lines limit next_index
                  in
                  let explicit_indent = rest_byte - line.start_byte in
                  if
                    candidate_index < limit
                    && lines.(candidate_index).indent = explicit_indent
                    && indicator_with_separation ':'
                         (String.trim lines.(candidate_index).content)
                  then
                    let candidate = lines.(candidate_index) in
                    let content = String.trim candidate.content in
                    let value_source =
                      if String.length content = 1 then ""
                      else
                        String.sub content 1 (String.length content - 1)
                        |> String.trim
                    in
                    if indicator_with_separation '-' value_source then
                      parse_sequence limit (candidate_index + 1)
                        (explicit_indent + 2)
                        (Some
                           (candidate, value_source, candidate.content_byte + 2))
                    else
                      let value =
                        parse_inline ~implicit_flow_mapping:true ~file
                          ~line:candidate.number ~column:(explicit_indent + 3)
                          ~byte:(candidate.content_byte + 2)
                          value_source
                      in
                      let value =
                        match value with
                        | Flow_mapping (entries, span) -> Mapping (entries, span)
                        | node -> node
                      in
                      (value, candidate_index + 1)
                  else
                    ( parse_inline ~file ~line:line.number
                        ~column:(rest_column + String.length rest)
                        ~byte:(rest_byte + String.length rest)
                        "",
                      next_index )
                in
                let key = key_projection body key_node in
                ( Mapping
                    ( [
                        {
                          key;
                          key_node;
                          value;
                          colon_span = node_span key_node;
                          span =
                            Span.merge (node_span key_node) (node_span value);
                          merge = false;
                          duplicate = false;
                        };
                      ],
                      Span.merge (node_span key_node) (node_span value) ),
                  next )
              else if indicator_with_separation '-' rest then
                parse_sequence limit
                  (if synthetic then !cursor else significant + 1)
                  (rest_byte - line.start_byte)
                  (Some (line, rest, rest_byte))
              else
                match find_mapping_colon rest with
                | Some _ ->
                    parse_mapping limit
                      (if synthetic then !cursor else significant + 1)
                      (rest_byte - line.start_byte)
                      (Some (line, rest, rest_byte))
                | None ->
                    let next_index =
                      if synthetic then !cursor else significant + 1
                    in
                    parse_inline_value limit indent next_index line rest_column
                      rest_byte rest
          in
          let value = register_anchors value in
          let span = Span.merge dash_span (node_span value) in
          items := { value; dash_span; span } :: !items;
          cursor := next
    done;
    let ordered = List.rev !items in
    let span =
      match ordered with
      | [] -> Span.none
      | first :: rest ->
          List.fold_left
            (fun span (item : sequence_item) -> Span.merge span item.span)
            first.span rest
    in
    (Sequence (ordered, span), !cursor)
  and parse_explicit_mapping limit index indent =
    let entries = ref [] and cursor = ref index and finished = ref false in
    while not !finished do
      let significant = next_significant lines limit !cursor in
      if significant >= limit then (
        cursor := significant;
        finished := true)
      else
        let line = lines.(significant) in
        let content = String.trim line.content in
        if
          line.indent <> indent
          || not
               (indicator_with_separation '?' content
               || indicator_with_separation ':' content)
        then (
          cursor := significant;
          finished := true)
        else if indicator_with_separation ':' content then (
          let colon_byte = line.content_byte in
          let colon_span =
            span_of_range file line.number (indent + 1) colon_byte (indent + 2)
              (colon_byte + 1)
          in
          let rest =
            if String.length content = 1 then ""
            else String.sub content 1 (String.length content - 1) |> String.trim
          in
          let value, next =
            if indicator_with_separation '-' rest then
              parse_sequence limit (significant + 1) (indent + 2)
                (Some (line, rest, colon_byte + 2))
            else if rest <> "" then
              parse_inline_value limit indent (significant + 1) line
                (indent + 3) (colon_byte + 2) rest
            else
              let child = next_significant lines limit (significant + 1) in
              if child < limit && nested_mapping_value indent child then
                match parse_block limit child lines.(child).indent with
                | Some value, next -> (value, next)
                | None, next ->
                    ( parse_inline ~file ~line:line.number ~column:(indent + 2)
                        ~byte:(colon_byte + 1) "",
                      next )
              else
                ( parse_inline ~file ~line:line.number ~column:(indent + 2)
                    ~byte:(colon_byte + 1) "",
                  significant + 1 )
          in
          let key_node =
            parse_inline ~file ~line:line.number ~column:(indent + 1)
              ~byte:colon_byte ""
          in
          let value = register_anchors value in
          let key = key_projection "" key_node in
          entries :=
            {
              key;
              key_node;
              value;
              colon_span;
              span = Span.merge (node_span key_node) (node_span value);
              merge = false;
              duplicate = false;
            }
            :: !entries;
          cursor := next)
        else
          let question_byte = line.content_byte in
          let question_span =
            span_of_range file line.number (line.indent + 1) question_byte
              (line.indent + 2) (question_byte + 1)
          in
          let key_raw =
            if String.length content = 1 then ""
            else String.sub content 1 (String.length content - 1) |> String.trim
          in
          let key_node, after_key =
            if Option.is_some (block_header key_raw) then
              parse_block_scalar limit indent (significant + 1) line
                (line.indent + 3) (question_byte + 2) key_raw
            else if indicator_with_separation '-' key_raw then
              parse_sequence limit (significant + 1) (indent + 2)
                (Some (line, key_raw, question_byte + 2))
            else if key_raw <> "" then
              parse_inline_value ~implicit_flow_mapping:true limit indent
                (significant + 1) line (line.indent + 3) (question_byte + 2)
                key_raw
            else
              let child = next_significant lines limit (significant + 1) in
              if child < limit && nested_mapping_value indent child then
                match parse_block limit child lines.(child).indent with
                | Some value, next -> (value, next)
                | None, next ->
                    ( parse_inline ~file ~line:line.number
                        ~column:(line.indent + 2) ~byte:(question_byte + 1) "",
                      next )
              else
                ( parse_inline ~file ~line:line.number ~column:(line.indent + 2)
                    ~byte:(question_byte + 1) "",
                  significant + 1 )
          in
          let value_line = next_significant lines limit after_key in
          let key_node =
            match key_node with
            | Flow_mapping (entries, span)
              when let key = String.trim key_raw in
                   key = "" || key.[0] <> '{' -> Mapping (entries, span)
            | node -> node
          in
          let value, next, colon_span =
            if value_line < limit && lines.(value_line).indent = indent then
              let candidate = lines.(value_line) in
              let value_content = String.trim candidate.content in
              if indicator_with_separation ':' value_content then
                let colon_byte = candidate.content_byte in
                let colon_span =
                  span_of_range file candidate.number (indent + 1) colon_byte
                    (indent + 2) (colon_byte + 1)
                in
                let rest =
                  if String.length value_content = 1 then ""
                  else
                    String.sub value_content 1 (String.length value_content - 1)
                    |> String.trim
                in
                if Option.is_some (block_header rest) then
                  let value, next =
                    parse_block_scalar limit indent (value_line + 1) candidate
                      (indent + 3) (colon_byte + 2) rest
                  in
                  (value, next, colon_span)
                else if indicator_with_separation '-' rest then
                  let value, next =
                    parse_sequence limit (value_line + 1) (indent + 2)
                      (Some (candidate, rest, colon_byte + 2))
                  in
                  (value, next, colon_span)
                else if rest <> "" then
                  let value, next =
                    parse_inline_value limit indent (value_line + 1) candidate
                      (indent + 3) (colon_byte + 2) rest
                  in
                  (value, next, colon_span)
                else
                  let child = next_significant lines limit (value_line + 1) in
                  if child < limit && nested_mapping_value indent child then
                    match parse_block limit child lines.(child).indent with
                    | Some value, next -> (value, next, colon_span)
                    | None, next ->
                        ( parse_inline ~file ~line:candidate.number
                            ~column:(indent + 2) ~byte:(colon_byte + 1) "",
                          next,
                          colon_span )
                  else
                    ( parse_inline ~file ~line:candidate.number
                        ~column:(indent + 2) ~byte:(colon_byte + 1) "",
                      value_line + 1,
                      colon_span )
              else
                ( parse_inline ~file ~line:line.number
                    ~column:(String.length line.raw + 1)
                    ~byte:line.stop_byte "",
                  after_key,
                  question_span )
            else
              ( parse_inline ~file ~line:line.number
                  ~column:(String.length line.raw + 1)
                  ~byte:line.stop_byte "",
                after_key,
                question_span )
          in
          let key_node = register_anchors key_node in
          let value = register_anchors value in
          let key = key_projection key_raw key_node in
          entries :=
            {
              key;
              key_node;
              value;
              colon_span;
              span = Span.merge (node_span key_node) (node_span value);
              merge = key.value = "<<";
              duplicate = false;
            }
            :: !entries;
          cursor := next
    done;
    let explicit_entries = List.rev !entries in
    let trailing_entries, next =
      let significant = next_significant lines limit !cursor in
      if significant < limit && lines.(significant).indent = indent then
        match find_mapping_colon (String.trim lines.(significant).content) with
        | Some _ -> (
            match parse_mapping limit significant indent None with
            | Mapping (entries, _), next -> (entries, next)
            | _, next -> ([], next))
        | None -> ([], !cursor)
      else ([], !cursor)
    in
    let entries = explicit_entries @ trailing_entries in
    let span =
      match entries with
      | [] -> Span.none
      | first :: rest ->
          List.fold_left
            (fun span (entry : mapping_entry) -> Span.merge span entry.span)
            first.span rest
    in
    (Mapping (entries, span), next)
  and parse_mapping limit index indent first =
    let entries = ref []
    and seen = ref []
    and cursor = ref index
    and first = ref first
    and finished = ref false in
    while not !finished do
      let candidate =
        match !first with
        | Some (line, content, byte) ->
            first := None;
            Some (line, content, byte, true)
        | None ->
            let significant = next_significant lines limit !cursor in
            if significant >= limit then (
              cursor := significant;
              None)
            else
              let line = lines.(significant) in
              if line.indent <> indent then (
                cursor := significant;
                None)
              else (
                cursor := significant;
                Some (line, String.trim line.content, line.content_byte, false))
      in
      match candidate with
      | None -> finished := true
      | Some (line, content, base_byte, synthetic) -> (
          match find_mapping_colon content with
          | None -> finished := true
          | Some colon ->
              let alias_name_owns_colon =
                colon = String.length content - 1
                && String.length content > 0
                && content.[0] = '*'
              in
              let key_raw =
                if alias_name_owns_colon then content
                else String.sub content 0 colon |> String.trim
              in
              let rest_raw =
                if alias_name_owns_colon then ""
                else
                  String.sub content (colon + 1)
                    (String.length content - colon - 1)
              in
              let rest_leading = ref 0 in
              while
                !rest_leading < String.length rest_raw
                &&
                match rest_raw.[!rest_leading] with
                | ' ' | '\t' -> true
                | _ -> false
              do
                incr rest_leading
              done;
              let rest =
                String.sub rest_raw !rest_leading
                  (String.length rest_raw - !rest_leading)
                |> trim_right
              in
              let key_node =
                parse_inline ~file ~line:line.number
                  ~column:(if synthetic then indent + 1 else line.indent + 1)
                  ~byte:base_byte key_raw
              in
              let key =
                match key_node with
                | Scalar scalar -> scalar
                | _ ->
                    let key_span = node_span key_node in
                    add_problem "YAML-NON-SCALAR-KEY"
                      "complex mapping keys are retained but cannot be lowered"
                      key_span;
                    {
                      value = key_raw;
                      raw = key_raw;
                      style = Plain;
                      anchor = None;
                      tag = None;
                      span = key_span;
                    }
              in
              let duplicate = List.mem key.value !seen in
              if duplicate then
                add_problem "YAML-DUPLICATE-KEY"
                  ("duplicate mapping key: " ^ key.value)
                  key.span;
              seen := key.value :: !seen;
              let colon_byte = base_byte + colon in
              let value_byte = colon_byte + 1 + !rest_leading in
              let value_column =
                (if synthetic then indent else line.indent)
                + colon + 2 + !rest_leading
              in
              let colon_span =
                span_of_range file line.number
                  ((if synthetic then indent else line.indent) + colon + 1)
                  colon_byte
                  ((if synthetic then indent else line.indent) + colon + 2)
                  (colon_byte + 1)
              in
              let value, next =
                if rest = "" then
                  let child_index =
                    next_significant lines limit
                      (if synthetic then !cursor else !cursor + 1)
                  in
                  if
                    child_index < limit
                    && nested_mapping_value indent child_index
                  then
                    match
                      parse_block limit child_index lines.(child_index).indent
                    with
                    | Some child, next -> (child, next)
                    | None, next ->
                        ( parse_inline ~file ~line:line.number
                            ~column:(indent + colon + 2)
                            ~byte:(colon_byte + 1) "",
                          next )
                  else
                    ( parse_inline ~file ~line:line.number
                        ~column:(indent + colon + 2)
                        ~byte:(colon_byte + 1) "",
                      if synthetic then !cursor else !cursor + 1 )
                else
                  let prefix_anchor, prefix_tag, prefix_length =
                    parse_prefixes rest
                  in
                  let prefix_body =
                    if prefix_length = 0 then rest
                    else
                      String.sub rest prefix_length
                        (String.length rest - prefix_length)
                      |> String.trim
                  in
                  if Option.is_some (block_header rest) then
                    parse_block_scalar limit indent
                      (if synthetic then !cursor else !cursor + 1)
                      line value_column value_byte rest
                  else if prefix_length > 0 && prefix_body = "" then
                    let child_index =
                      next_significant lines limit
                        (if synthetic then !cursor else !cursor + 1)
                    in
                    if
                      child_index < limit
                      && nested_mapping_value indent child_index
                    then
                      match
                        parse_block limit child_index lines.(child_index).indent
                      with
                      | Some child, next ->
                          let prefix =
                            parse_inline ~file ~line:line.number
                              ~column:value_column ~byte:value_byte rest
                          in
                          ( Decorated
                              {
                                value = child;
                                anchor = prefix_anchor;
                                tag = prefix_tag;
                                span =
                                  Span.merge (node_span prefix)
                                    (node_span child);
                              },
                            next )
                      | None, next ->
                          ( parse_inline ~file ~line:line.number
                              ~column:value_column ~byte:value_byte rest,
                            next )
                    else
                      ( parse_inline ~file ~line:line.number
                          ~column:value_column ~byte:value_byte rest,
                        if synthetic then !cursor else !cursor + 1 )
                  else
                    let next_index =
                      if synthetic then !cursor else !cursor + 1
                    in
                    parse_inline_value limit indent next_index line value_column
                      value_byte rest
              in
              let value = register_anchors value in
              let entry_span = Span.merge key.span (node_span value) in
              entries :=
                {
                  key;
                  key_node;
                  value;
                  colon_span;
                  span = entry_span;
                  merge = key.value = "<<";
                  duplicate;
                }
                :: !entries;
              cursor := next)
    done;
    let ordered = List.rev !entries in
    let ordered, next =
      let significant = next_significant lines limit !cursor in
      if significant < limit && lines.(significant).indent = indent then
        let content = String.trim lines.(significant).content in
        if indicator_with_separation '?' content then
          match parse_explicit_mapping limit significant indent with
          | Mapping (entries, _), next -> (ordered @ entries, next)
          | _, next -> (ordered, next)
        else (ordered, !cursor)
      else (ordered, !cursor)
    in
    let span =
      match ordered with
      | [] -> Span.none
      | first :: rest ->
          List.fold_left
            (fun span (entry : mapping_entry) -> Span.merge span entry.span)
            first.span rest
    in
    (Mapping (ordered, span), next)
  in
  let trivia = ref [] in
  Array.iter
    (fun line ->
      let trimmed = String.trim line.raw in
      let kind_and_start =
        if trimmed = "" then Some (Blank, line.start_byte)
        else if Util.starts_with ~prefix:"%" trimmed then
          Some (Directive, line.content_byte)
        else if document_start_line line then
          Some
            ( Document_start,
              line.start_byte + if bom && line.number = 1 then 3 else 0 )
        else if document_end_line line then Some (Document_end, line.start_byte)
        else Option.map (fun byte -> (Comment, byte)) line.comment_byte
      in
      match kind_and_start with
      | None -> ()
      | Some (kind, start_byte) ->
          let column = start_byte - line.start_byte + 1 in
          trivia :=
            {
              kind;
              raw =
                (if start_byte <= line.stop_byte then
                   String.sub source start_byte (line.stop_byte - start_byte)
                 else "");
              span =
                span_of_range file line.number column start_byte
                  (String.length line.raw + 1)
                  line.stop_byte;
            }
            :: !trivia)
    lines;
  let boundaries = ref [ 0 ] in
  Array.iteri
    (fun index line ->
      if index > 0 && document_start_line line then (
        let start = ref index
        and scanning = ref true
        and saw_directive = ref false in
        while !start > 0 && !scanning do
          let previous = lines.(!start - 1) in
          let content = String.trim previous.raw in
          if Util.starts_with ~prefix:"%" content then (
            saw_directive := true;
            decr start)
          else if content = "" || Util.starts_with ~prefix:"#" content then
            decr start
          else scanning := false
        done;
        let boundary = if !saw_directive then !start else index in
        if not (List.mem boundary !boundaries) then
          boundaries := boundary :: !boundaries);
      if document_end_line line && index + 1 < line_count then
        boundaries := (index + 1) :: !boundaries)
    lines;
  let boundaries = line_count :: !boundaries |> List.sort_uniq Int.compare in
  let rec pair accumulator = function
    | start :: (stop :: _ as rest) -> pair ((start, stop) :: accumulator) rest
    | _ -> List.rev accumulator
  in
  let documents =
    pair [] boundaries
    |> List.filter_map (fun (start, stop) ->
        let first_line = lines.(start) and last_line = lines.(stop - 1) in
        let span =
          span_of_range file first_line.number 1 first_line.start_byte
            (String.length last_line.raw + 1)
            last_line.stop_byte
        in
        let explicit_start =
          let found = ref None in
          for index = start to stop - 1 do
            if !found = None && document_start_line lines.(index) then
              found := Some lines.(index)
          done;
          !found
        in
        let body_start = next_significant lines stop start in
        let root, parsed_until =
          if body_start < stop then
            parse_block stop body_start lines.(body_start).indent
          else
            ( Option.map
                (fun line ->
                  parse_inline ~file ~line:line.number
                    ~column:(String.length line.raw + 1)
                    ~byte:line.stop_byte "")
                explicit_start,
              stop )
        in
        let unconsumed = next_significant lines stop parsed_until in
        (if unconsumed < stop then
           let line = lines.(unconsumed) in
           add_problem "YAML-SYNTAX" "content remains after the document root"
             (span_of_range file line.number (line.indent + 1) line.content_byte
                (String.length line.raw + 1)
                line.stop_byte));
        if root = None && explicit_start = None then None
        else
          let directives =
            List.filter
              (fun (item : trivia) ->
                item.kind = Directive && Span.contains span item.span.start.byte)
              !trivia
          in
          Some { root; directives; span })
  in
  Yaml_validation.validate ~file source
  |> List.iter (fun (issue : Yaml_validation.issue) ->
      add_problem issue.code issue.message issue.span);
  {
    file;
    source;
    bom;
    newline = newline_style source;
    documents;
    trivia = List.rev !trivia;
    anchors = List.rev !anchors;
    problems = List.rev !problems;
  }

let root tree =
  match tree.documents with
  | document :: _ -> document.root
  | [] -> None

let resolve_alias tree name = List.assoc_opt name tree.anchors

let apply_edits tree (edits : edit list) =
  let ordered =
    List.sort
      (fun (left : edit) (right : edit) ->
        match Int.compare right.start_byte left.start_byte with
        | 0 -> Int.compare right.stop_byte left.stop_byte
        | comparison -> comparison)
      edits
  in
  let rec validate previous_start = function
    | [] -> Ok ()
    | (edit : edit) :: rest ->
        if
          edit.start_byte < 0
          || edit.stop_byte < edit.start_byte
          || edit.stop_byte > String.length tree.source
        then Error "edit span is outside the source"
        else if edit.stop_byte > previous_start then Error "edits overlap"
        else validate edit.start_byte rest
  in
  match validate (String.length tree.source) ordered with
  | Error _ as error -> error
  | Ok () ->
      let result = ref tree.source in
      List.iter
        (fun (edit : edit) ->
          let before = String.sub !result 0 edit.start_byte in
          let after =
            String.sub !result edit.stop_byte
              (String.length !result - edit.stop_byte)
          in
          result := before ^ edit.replacement ^ after)
        ordered;
      Ok !result

let node_to_json node =
  let rec convert = function
    | Scalar scalar ->
        Json.Object
          [
            ( "anchor",
              Option.fold ~none:Json.Null
                ~some:(fun value -> Json.String value)
                scalar.anchor );
            ("kind", Json.String "scalar");
            ("span", Span.to_json scalar.span);
            ( "style",
              Json.String
                (match scalar.style with
                | Plain -> "plain"
                | Single_quoted -> "single-quoted"
                | Double_quoted -> "double-quoted"
                | Literal -> "literal"
                | Folded -> "folded") );
            ( "tag",
              Option.fold ~none:Json.Null
                ~some:(fun value -> Json.String value)
                scalar.tag );
            ("value", Json.String scalar.value);
          ]
    | Alias alias ->
        Json.Object
          [
            ("kind", Json.String "alias");
            ("name", Json.String alias.name);
            ("span", Span.to_json alias.span);
          ]
    | Sequence (items, span) ->
        Json.Object
          [
            ( "items",
              Json.Array
                (List.map
                   (fun (item : sequence_item) -> convert item.value)
                   items) );
            ("kind", Json.String "sequence");
            ("span", Span.to_json span);
          ]
    | Flow_sequence (items, span) ->
        Json.Object
          [
            ("items", Json.Array (List.map convert items));
            ("kind", Json.String "flow-sequence");
            ("span", Span.to_json span);
          ]
    | Decorated decorated ->
        Json.Object
          [
            ( "anchor",
              Option.fold ~none:Json.Null
                ~some:(fun value -> Json.String value)
                decorated.anchor );
            ("kind", Json.String "decorated");
            ("span", Span.to_json decorated.span);
            ( "tag",
              Option.fold ~none:Json.Null
                ~some:(fun value -> Json.String value)
                decorated.tag );
            ("value", convert decorated.value);
          ]
    | Mapping (entries, span) | Flow_mapping (entries, span) ->
        Json.Object
          [
            ( "entries",
              Json.Array
                (List.map
                   (fun (entry : mapping_entry) ->
                     Json.Object
                       [
                         ("duplicate", Json.Bool entry.duplicate);
                         ("key", convert entry.key_node);
                         ("merge", Json.Bool entry.merge);
                         ("value", convert entry.value);
                       ])
                   entries) );
            ("kind", Json.String "mapping");
            ("span", Span.to_json span);
          ]
    | Invalid invalid ->
        Json.Object
          [
            ("kind", Json.String "invalid");
            ("raw", Json.String invalid.raw);
            ("reason", Json.String invalid.reason);
            ("span", Span.to_json invalid.span);
          ]
  in
  convert node
