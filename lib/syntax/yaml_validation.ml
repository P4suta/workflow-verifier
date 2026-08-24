type issue = { code : string; message : string; span : Span.t }
type quote = Single_quote | Double_quote
type flow_quote = Flow_single | Flow_double | Flow_double_escape

type line = {
  number : int;
  start_byte : int;
  stop_byte : int;
  raw : string;
  indent : int;
}

let lines source =
  let length = String.length source in
  let rec loop number start accumulator =
    if start >= length then List.rev accumulator
    else
      let stop = ref start in
      while
        !stop < length && source.[!stop] <> '\n' && source.[!stop] <> '\r'
      do
        incr stop
      done;
      let next = ref !stop in
      if !next < length then
        if
          source.[!next] = '\r'
          && !next + 1 < length
          && source.[!next + 1] = '\n'
        then next := !next + 2
        else incr next;
      let raw = String.sub source start (!stop - start) in
      let indent = ref 0 in
      while !indent < String.length raw && raw.[!indent] = ' ' do
        incr indent
      done;
      loop (number + 1) !next
        ({
           number;
           start_byte = start;
           stop_byte = !stop;
           raw;
           indent = !indent;
         }
        :: accumulator)
  in
  loop 1 0 [] |> Array.of_list

let span file line column length =
  let start_byte = line.start_byte + column in
  Span.make ~file
    { Span.byte = start_byte; line = line.number; column = column + 1 }
    {
      Span.byte = min line.stop_byte (start_byte + max 1 length);
      line = line.number;
      column = column + max 1 length + 1;
    }

let issue file line column length message =
  { code = "YAML-SYNTAX"; message; span = span file line column length }

let separation = function
  | ' ' | '\t' | '\r' | '\n' -> true
  | _ -> false

let indicator indicator value =
  String.length value > 0
  && value.[0] = indicator
  && (String.length value = 1 || separation value.[1])

let trim_left value =
  let index = ref 0 in
  while !index < String.length value && separation value.[!index] do
    incr index
  done;
  String.sub value !index (String.length value - !index)

let words value =
  value |> String.to_seq
  |> Seq.map (function
    | '\t' -> ' '
    | character -> character)
  |> String.of_seq |> String.split_on_char ' '
  |> List.filter (( <> ) "")

let has_separated_comment value =
  let found = ref false in
  String.iteri
    (fun index character ->
      if character = '#' && (index = 0 || separation value.[index - 1]) then
        found := true)
    value;
  !found

let previous_non_separation value index =
  let rec loop stop =
    match stop with
    | 0 -> None
    | _ ->
        let previous = pred stop in
        if separation value.[previous] then loop previous else Some previous
  in
  loop index

let flow_depth_before value index =
  let depth = ref 0 in
  for cursor = 0 to index - 1 do
    match value.[cursor] with
    | '[' | '{' -> incr depth
    | ']' | '}' -> depth := max 0 (pred !depth)
    | _ -> ()
  done;
  !depth

let property_precedes value index previous =
  if previous + 1 = index then false
  else
    let start = ref previous in
    while !start > 0 && not (separation value.[!start - 1]) do
      decr start
    done;
    String.contains "&!" value.[!start]

let quote_starts_node value index =
  match previous_non_separation value index with
  | None -> true
  | Some previous ->
    let separated = previous + 1 < index in
    match value.[previous] with
    | '[' | '{' | ',' -> true
    | '-' | '?' -> separated
    | ':' -> separated || flow_depth_before value index > 0
    | _ -> property_precedes value index previous

let quoted_step value limit index quote =
  let next = succ index in
  match (quote, value.[index]) with
  | Double_quote, '\\' -> (min limit (succ next), Some Double_quote)
  | Double_quote, '"' -> (next, None)
  | Single_quote, '\''
    when next < limit && value.[next] = '\'' ->
      (succ next, Some Single_quote)
  | Single_quote, '\'' -> (next, None)
  | _ -> (next, Some quote)

let separated_comment_start value =
  let limit = String.length value in
  let rec loop index quote =
    if index >= limit then None
    else
      match quote with
      | Some quote ->
          let next, quote = quoted_step value limit index quote in
          loop next quote
      | None ->
          let character = value.[index] in
          if character = '#' && (index = 0 || separation value.[pred index]) then
            Some index
          else if character = '"' && quote_starts_node value index then
            loop (succ index) (Some Double_quote)
          else if character = '\'' && quote_starts_node value index then
            loop (succ index) (Some Single_quote)
          else loop (succ index) None
  in
  loop 0 None

let without_separated_comment value =
  match separated_comment_start value with
  | Some index -> String.sub value 0 index
  | None -> value

let find_mapping_colons value =
  let limit =
    separated_comment_start value |> Option.value ~default:(String.length value)
  in
  let rec loop index quote property_token depth answer =
    if index >= limit then List.rev answer
    else
      match quote with
      | Some quote ->
          let next, quote = quoted_step value limit index quote in
          loop next quote property_token depth answer
      | None ->
          let character = value.[index] in
          if property_token then
            loop (succ index) None
              (not (separation character || String.contains "[],{}" character))
              depth answer
          else
            match character with
            | ('&' | '*' | '!') when quote_starts_node value index ->
                loop (succ index) None true depth answer
            | '"' when quote_starts_node value index ->
                loop (succ index) (Some Double_quote) false depth answer
            | '\'' when quote_starts_node value index ->
                loop (succ index) (Some Single_quote) false depth answer
            | '[' | '{' -> loop (succ index) None false (succ depth) answer
            | ']' | '}' ->
                loop (succ index) None false (max 0 (pred depth)) answer
            | ':'
              when depth = 0
                   && (succ index = String.length value
                      || separation value.[succ index]) ->
                loop (succ index) None property_token depth (index :: answer)
            | _ -> loop (succ index) None false depth answer
  in
  loop 0 None false 0 []

let strip_properties value =
  let value = trim_left value in
  let cursor = ref 0 and scanning = ref true in
  while !cursor < String.length value && !scanning do
    match value.[!cursor] with
    | '!'
      when !cursor + 1 < String.length value
           && (value.[!cursor + 1] = '"' || value.[!cursor + 1] = '\'') ->
        scanning := false
    | '&' | '!' ->
        while
          !cursor < String.length value && not (separation value.[!cursor])
        do
          incr cursor
        done;
        while !cursor < String.length value && separation value.[!cursor] do
          incr cursor
        done
    | _ -> scanning := false
  done;
  String.sub value !cursor (String.length value - !cursor)

let node_fragment raw =
  let rec strip_indicators value =
    let value = trim_left value in
    if Util.starts_with ~prefix:"---" value then
      strip_indicators (String.sub value 3 (String.length value - 3))
    else if indicator '-' value || indicator '?' value then
      strip_indicators (String.sub value 1 (String.length value - 1))
    else value
  in
  let value = String.trim raw |> strip_indicators |> strip_properties in
  let value =
    match find_mapping_colons value with
    | colon :: _ ->
        String.sub value (colon + 1) (String.length value - colon - 1)
        |> trim_left
    | [] -> value
  in
  strip_properties value

let classify_block_header raw =
  let fragment = node_fragment raw in
  Yaml_block_header.classify fragment

let plain_scalar_head raw =
  let fragment = node_fragment (without_separated_comment raw) |> String.trim in
  if fragment = "" then false
  else
    match fragment.[0] with
    | '\'' | '"' | '[' | '{' | ']' | '}' | '*' | '&' | '!' | '#' ->
        false
    | _ ->
        not
          (Util.starts_with ~prefix:"---" fragment
          || Util.starts_with ~prefix:"..." fragment
          || Util.starts_with ~prefix:"%" fragment)

let block_scalar_payload active_indent line =
  match !active_indent with
  | None -> false
  | Some base_indent when line.indent > base_indent -> true
  | Some _ ->
      active_indent := None;
      false

type block_analysis = { payload_lines : bool array; problems : issue list }

let analyze_blocks file source_lines =
  let active_indent = ref None
  and active_plain_indent = ref None
  and payload_lines = Array.make (Array.length source_lines) false
  and problems = ref [] in
  Array.iteri
    (fun index line ->
      if String.trim line.raw = "" then ()
      else if block_scalar_payload active_indent line then
        payload_lines.(index) <- true
      else
        let comment_only =
          Util.starts_with ~prefix:"#" (String.trim line.raw)
        in
        let plain_continuation =
          match !active_plain_indent with
          | Some base_indent ->
              line.indent > base_indent && not comment_only
              && find_mapping_colons line.raw = []
          | None -> false
        in
        if plain_continuation then ()
        else (
          active_plain_indent := None;
          match classify_block_header line.raw with
          | Not_block ->
              if plain_scalar_head line.raw && not (has_separated_comment line.raw)
              then active_plain_indent := Some line.indent
          | Valid _ -> active_indent := Some line.indent
          | Invalid token_length ->
            problems :=
              issue file line line.indent token_length
                "invalid block scalar header"
              :: !problems))
    source_lines;
  { payload_lines; problems = List.rev !problems }

let is_hex = function
  | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
  | _ -> false

let validate_double_escapes file source source_lines payload_lines =
  let problems = ref [] and quote = ref None and index = ref 0 in
  let line_index = ref 0 in
  let rec consume_hex cursor remaining =
    match remaining with
    | 0 -> Some cursor
    | _ when cursor < String.length source && is_hex source.[cursor] ->
        consume_hex (succ cursor) (pred remaining)
    | _ -> None
  in
  while !index < String.length source do
    while
      !line_index + 1 < Array.length source_lines
      && !index >= source_lines.(!line_index + 1).start_byte
    do
      incr line_index
    done;
    let line = source_lines.(!line_index) in
    let character = source.[!index] in
    if payload_lines.(!line_index) then
       index :=
         if !line_index + 1 < Array.length source_lines then
           source_lines.(!line_index + 1).start_byte
         else String.length source
     else (
       (match !quote with
       | None ->
           let column = !index - line.start_byte in
           if
             character = '#'
             && (column = 0 || separation line.raw.[pred column])
           then index := line.stop_byte
           else if character = '"' && quote_starts_node line.raw column then
             quote := Some Double_quote
           else if character = '\'' && quote_starts_node line.raw column then
             quote := Some Single_quote
       | Some Single_quote -> if character = '\'' then quote := None
       | Some Double_quote ->
           if character = '"' then quote := None
           else if character = '\\' then
             if succ !index < String.length source then
               let escaped = source.[succ !index] in
               let hex_stop =
                 match escaped with
                 | 'x' -> consume_hex (succ (succ !index)) 2
                 | 'u' -> consume_hex (succ (succ !index)) 4
                 | 'U' -> consume_hex (succ (succ !index)) 8
                 | _ -> None
               in
               let simple =
                 String.contains "0abtnvfre \"/\\N_LP" escaped
                 || escaped = '\n' || escaped = '\r' || escaped = '\t'
               in
               if simple then incr index
               else
                 match hex_stop with
                 | Some _ -> ()
                 | None ->
                     problems :=
                       issue file source_lines.(!line_index)
                         (!index - source_lines.(!line_index).start_byte)
                         2 "invalid escape in a double-quoted scalar"
                       :: !problems);
       incr index)
  done;
  List.rev !problems

let validate_directives file source_lines payload_lines =
  let problems = ref []
  and in_document = ref false
  and pending_directive = ref None
  and yaml_seen = ref false
  and pending_handles = ref []
  and active_handles = ref [ "!!" ]
  and previous_line = ref None in
  let add line message =
    problems :=
      issue file line line.indent (String.length line.raw) message :: !problems
  in
  Array.iteri
    (fun index line ->
      if not payload_lines.(index) then (
        let content = without_separated_comment line.raw |> String.trim in
        if content = "" || Util.starts_with ~prefix:"#" content then ()
        else if
          line.indent = 0
          &&
          match words content with
          | ("%YAML" | "%TAG") :: _ -> true
          | _ -> false
        then (
          let previous_plain =
            !in_document
            && List.exists
                 (fun previous_line ->
                   let previous = String.trim previous_line.raw in
                   previous <> ""
                   && find_mapping_colons previous = []
                   && (not (has_separated_comment previous))
                   && (not (String.contains "!&'\"[{|>" previous.[0]))
                   && (not (Util.starts_with ~prefix:"---" previous))
                   && not (Util.starts_with ~prefix:"..." previous))
                 (Option.to_list !previous_line)
          in
          if not previous_plain then (
            if !in_document then
              add line "directive appears before document end";
            pending_directive := Some line;
            match words content with
            | [ "%YAML"; version ]
              when String.length version = 3
                   && version.[0] >= '0'
                   && version.[0] <= '9'
                   && version.[1] = '.'
                   && version.[2] >= '0'
                   && version.[2] <= '9' ->
                if !yaml_seen then add line "duplicate YAML directive";
                yaml_seen := true
            | "%YAML" :: _ -> add line "invalid YAML directive"
            | [ "%TAG"; handle; _ ] ->
                if List.mem handle !pending_handles then
                  add line "duplicate TAG directive";
                pending_handles := handle :: !pending_handles
            | _ -> add line "invalid directive"))
        else if String.length content >= 3 && String.sub content 0 3 = "---"
        then (
          active_handles := "!!" :: !pending_handles;
          pending_handles := [];
          yaml_seen := false;
          pending_directive := None;
          in_document := true)
        else if String.length content >= 3 && String.sub content 0 3 = "..."
        then in_document := false
        else (
          if Option.is_some !pending_directive then
            add line "directives require an explicit document start";
          in_document := true);
        if not (Util.starts_with ~prefix:"%" content) then
          let length = String.length content in
          let cursor = ref 0 in
          while !cursor < length do
            if content.[!cursor] = '!' then (
              let stop = ref (!cursor + 1) in
              while
                !stop < length
                && (not (separation content.[!stop]))
                && not (String.contains "[]{}," content.[!stop])
              do
                incr stop
              done;
              let tag = String.sub content !cursor (!stop - !cursor) in
              (match
                 if Util.starts_with ~prefix:"!<" tag then None
                 else String.index_from_opt tag 1 '!'
               with
              | Some ending ->
                  let handle = String.sub tag 0 (ending + 1) in
                  if not (List.mem handle !active_handles) then
                    add line "undefined tag handle"
              | None -> ());
              cursor := !stop)
            else incr cursor
          done);
      previous_line := Some line)
    source_lines;
  Option.iter
    (fun line -> add line "directive is not followed by a document")
    !pending_directive;
  List.rev !problems

let validate_inline_forms file source_lines payload_lines =
  let problems = ref [] in
  let add line message =
    problems :=
      issue file line line.indent (String.length line.raw) message :: !problems
  in
  Array.iteri
    (fun index line ->
      if not payload_lines.(index) then (
        let content = without_separated_comment line.raw |> String.trim in
        let structural_content = strip_properties content in
        let colons = find_mapping_colons structural_content in
        (match colons with
        | _ :: _ :: _
          when not
                 (indicator ':' content || indicator '?' content
                 || Util.starts_with ~prefix:"- ?" content
                 || Util.starts_with ~prefix:"{" content
                 || Util.starts_with ~prefix:"[" content
                 || Util.contains ~needle:"," content) ->
            add line "multiple mapping separators in a plain scalar"
        | _ :: _ :: _ -> ()
        | [ colon ] ->
            let value =
              String.sub structural_content (colon + 1)
                (String.length structural_content - colon - 1)
              |> trim_left
            in
            if
              indicator '-' value
              && not (indicator ':' content || indicator '?' content)
            then add line "block sequence cannot start on a mapping line"
        | [] -> ());
        if
          Util.starts_with ~prefix:"---" content
          &&
          let rest =
            String.sub content 3 (String.length content - 3) |> trim_left
          in
          (Util.starts_with ~prefix:"&" rest
          || Util.starts_with ~prefix:"!" rest)
          && find_mapping_colons rest <> []
        then
          add line
            "collection properties cannot prefix a compact document mapping";
        if
          (Util.starts_with ~prefix:"&" content
          || Util.starts_with ~prefix:"!" content)
          &&
          let rest = strip_properties content in
          indicator '-' rest
        then add line "node property cannot prefix a block sequence indicator";
        let rec adjacent_anchor_alias = function
          | anchor :: alias :: _
            when Util.starts_with ~prefix:"&" anchor
                 && Util.starts_with ~prefix:"*" alias -> true
          | _ :: rest -> adjacent_anchor_alias rest
          | [] -> false
        in
        if adjacent_anchor_alias (words content) then
          add line "an alias cannot carry node properties";
        if
          line.indent = 0
          && words content
             |> List.exists (fun token ->
                 Util.starts_with ~prefix:"!" token
                 && (Util.contains ~needle:"{" token
                    || Util.contains ~needle:"}" token))
        then add line "invalid tag token";
        (match words content with
        | "-" :: tag :: _
          when Util.starts_with ~prefix:"!!" tag
               && Util.ends_with ~suffix:"," tag ->
            add line "tag cannot contain a block-context comma"
        | _ -> ())))
    source_lines;
  List.rev !problems

type flow_frame = {
  opener : char;
  opened_line : int;
  base_indent : int;
  block_prefixed : bool;
  mutable pair_colon_seen : bool;
}

let validate_flow file source_lines payload_lines =
  let problems = ref []
  and stack = ref []
  and quote = ref None
  and last_token = ref `None
  and comment_interrupted = ref false in
  let add line column message =
    problems := issue file line column 1 message :: !problems
  in
  let top () =
    match !stack with
    | frame :: _ -> Some frame
    | [] -> None
  in
  let opener_allowed line index =
    !stack <> []
    ||
    let prefix = String.sub line.raw 0 index in
    node_fragment prefix = ""
  in
  let mapping_separator line index =
    index + 1 = String.length line.raw
    || separation line.raw.[index + 1]
    || String.contains ",]}" line.raw.[index + 1]
  in
  Array.iteri
    (fun line_index line ->
      if not payload_lines.(line_index) then (
        let trimmed = String.trim line.raw in
        (match top () with
        | Some frame when trimmed <> "" ->
            let begins_close =
              match trimmed.[0] with
              | ']' | '}' -> true
              | _ -> false
            in
            if
              frame.block_prefixed && (not begins_close)
              && line.indent <= frame.base_indent
            then add line line.indent "flow continuation is not indented";
            if !comment_interrupted && (not begins_close) && trimmed.[0] <> ':'
            then
              add line line.indent
                "comment terminates a flow scalar before a comma";
            comment_interrupted := false;
            if frame.opener = '[' && trimmed.[0] = ':' && !last_token = `Other
            then
              add line line.indent "implicit flow key crosses a line boundary"
        | _ -> ());
        let index = ref 0 in
        while !index < String.length line.raw do
          let character = line.raw.[!index] in
          (match !quote with
          | Some Flow_double_escape -> quote := Some Flow_double
          | Some Flow_double ->
              if character = '\\' then quote := Some Flow_double_escape
              else if character = '"' then (
                quote := None;
                last_token := `Other)
          | Some Flow_single ->
              if character = '\'' then (
                quote := None;
                last_token := `Other)
          | None -> (
              if !stack <> [] && character = '"' then quote := Some Flow_double
              else if !stack <> [] && character = '\'' then
                quote := Some Flow_single
              else if
                !stack <> [] && character = '#' && !index > 0
                && line.raw.[!index - 1] = ','
              then (
                add line !index "comment after comma requires separation";
                index := String.length line.raw)
              else if
                !stack <> [] && character = '#' && !index > 0
                && separation line.raw.[!index - 1]
              then (
                if !last_token = `Other then comment_interrupted := true;
                index := String.length line.raw)
              else
                match character with
                | ('[' | '{') when opener_allowed line !index ->
                    let prefix = String.sub line.raw 0 !index in
                    let block_prefixed =
                      find_mapping_colons prefix <> []
                      || indicator '-' (String.trim prefix)
                    in
                    stack :=
                      {
                        opener = character;
                        opened_line = line.number;
                        base_indent = line.indent;
                        block_prefixed;
                        pair_colon_seen = false;
                      }
                      :: !stack;
                    last_token := `Open
                | ',' when !stack <> [] ->
                    if !last_token = `Open || !last_token = `Comma then
                      add line !index "empty flow entry";
                    (match top () with
                    | Some frame when frame.opener = '{' ->
                        frame.pair_colon_seen <- false
                    | _ -> ());
                    last_token := `Comma
                | ':' when !stack <> [] && mapping_separator line !index ->
                    (match top () with
                    | Some frame when frame.opener = '{' ->
                        if frame.pair_colon_seen then
                          add line !index "flow mapping entries require a comma";
                        frame.pair_colon_seen <- true
                    | _ -> ());
                    last_token := `Other
                | (']' | '}') as closer -> (
                    let expected = if closer = ']' then '[' else '{' in
                    match !stack with
                    | frame :: rest when frame.opener = expected ->
                        let opened_line = frame.opened_line in
                        stack := rest;
                        last_token := `Other;
                        if rest = [] then (
                          let cursor = ref (!index + 1) in
                          while
                            !cursor < String.length line.raw
                            && separation line.raw.[!cursor]
                          do
                            incr cursor
                          done;
                          if !cursor < String.length line.raw then
                            match line.raw.[!cursor] with
                            | '#' when !cursor > !index + 1 -> ()
                            | '#' ->
                                add line !cursor
                                  "flow comment requires separation";
                                index := String.length line.raw
                            | ':' when opened_line = line.number -> ()
                            | _ ->
                                add line !cursor
                                  "content follows a completed flow collection")
                    | _ when !stack <> [] ->
                        add line !index "unmatched flow closing indicator"
                    | _ -> ())
                | '-' when !stack <> [] ->
                    let previous_allows_node =
                      !last_token = `Open || !last_token = `Comma
                    in
                    let cursor = ref (!index + 1) in
                    while
                      !cursor < String.length line.raw
                      && separation line.raw.[!cursor]
                    do
                      incr cursor
                    done;
                    if
                      previous_allows_node
                      && (!cursor = String.length line.raw
                         || line.raw.[!cursor] = ','
                         || line.raw.[!cursor] = ']')
                    then add line !index "bare dash is not a flow scalar"
                    else last_token := `Other
                | character when !stack <> [] && not (separation character) ->
                    last_token := `Other
                | _ -> ()));
          incr index
        done))
    source_lines;
  List.rev !problems

let validate_layout file source_lines payload_lines =
  let problems = ref [] and quoted_mapping = ref None in
  let add line column message =
    problems := issue file line column 1 message :: !problems
  in
  let closing_double_quote value =
    let rec loop index escaped =
      if index >= String.length value then None
      else if escaped then loop (succ index) false
      else
        match value.[index] with
        | '\\' -> loop (succ index) true
        | '"' -> Some index
        | _ -> loop (succ index) false
    in
    loop 1 false
  in
  Array.iteri
    (fun index line ->
      if not payload_lines.(index) then (
        let content = without_separated_comment line.raw |> String.trim in
        (match !quoted_mapping with
        | Some parent_indent ->
            if content <> "" && line.indent <= parent_indent then
              add line line.indent
                "quoted mapping value continuation is not indented";
            if String.contains content '"' then quoted_mapping := None
        | None -> ());
        (match find_mapping_colons content with
        | colon :: _ ->
            let value =
              String.sub content (colon + 1) (String.length content - colon - 1)
              |> trim_left
            in
            if String.length value > 0 && value.[0] = '"' then (
              match closing_double_quote value with
              | Some closing ->
                  let tail =
                    String.sub value (closing + 1)
                      (String.length value - closing - 1)
                  in
                  let trimmed_tail = String.trim tail in
                  if
                    trimmed_tail <> ""
                    && (not (Util.starts_with ~prefix:"#" trimmed_tail))
                    && not (String.contains ",]}" trimmed_tail.[0])
                  then
                    add line
                      (line.indent + colon + closing + 2)
                      "content follows a quoted scalar"
                  else if
                    Util.starts_with ~prefix:"#" trimmed_tail
                    && tail.[0] = '#'
                  then
                    add line
                      (line.indent + colon + closing + 2)
                      "comment requires separation after a quoted scalar"
              | None -> quoted_mapping := Some line.indent)
        | [] -> ());
        let first_non_space = ref 0 in
        while
          !first_non_space < String.length line.raw
          && line.raw.[!first_non_space] = ' '
        do
          incr first_non_space
        done;
        (if
           !first_non_space < String.length line.raw
           && line.raw.[!first_non_space] = '\t'
         then
           let remainder =
             String.sub line.raw (!first_non_space + 1)
               (String.length line.raw - !first_non_space - 1)
             |> String.trim
           in
           if find_mapping_colons remainder <> [] then
             add line !first_non_space "tab cannot indent a block mapping");
        let rec split_separation saw_tab = function
          | ((' ' | '\t' | '\r' | '\n') as character) :: rest ->
              split_separation (saw_tab || character = '\t') rest
          | rest -> (saw_tab, rest)
        in
        match content |> String.to_seq |> List.of_seq with
        | ('-' | '?' | ':') :: rest ->
            let saw_tab, remainder = split_separation false rest in
            (match (saw_tab, remainder) with
            | true, _ :: _ ->
                let remainder = remainder |> List.to_seq |> String.of_seq in
                if
                  indicator '-' remainder || indicator '?' remainder
                  || indicator ':' remainder
                  || find_mapping_colons remainder <> []
                then add line line.indent "tab cannot indent a nested block node"
            | _ -> ())
        | _ -> ()))
    source_lines;
  List.rev !problems

let validate_block_indentation file source_lines payload_lines =
  let problems = ref [] in
  let add line message =
    problems :=
      issue file line line.indent (String.length line.raw) message :: !problems
  in
  Array.iteri
    (fun index line ->
      let fragment = node_fragment line.raw in
      if
        (not payload_lines.(index))
        && fragment <> ""
        && (fragment.[0] = '|' || fragment.[0] = '>')
      then (
        let cursor = ref (index + 1)
        and leading = ref []
        and reference = ref None
        and scanning = ref true in
        while !cursor < Array.length source_lines && !scanning do
          let candidate = source_lines.(!cursor) in
          let content = String.trim candidate.raw in
          if content = "" then (
            leading := candidate :: !leading;
            incr cursor)
          else if Util.starts_with ~prefix:"#" content then (
            if candidate.indent > line.indent && !reference = None then
              reference := Some candidate.indent;
            incr cursor)
          else if candidate.indent > line.indent then (
            reference := Some candidate.indent;
            scanning := false)
          else scanning := false
        done;
        match !reference with
        | Some reference ->
            List.iter
              (fun leading ->
                if leading.indent > reference then
                  add leading
                    "leading block-scalar whitespace exceeds content \
                     indentation";
                if String.length leading.raw > 0 && leading.raw.[0] = '\t' then
                  add leading "tab cannot provide block scalar indentation")
              !leading
        | None ->
            List.iter
              (fun leading ->
                if String.length leading.raw > 0 && leading.raw.[0] = '\t' then
                  add leading "tab cannot provide block scalar indentation")
              !leading))
    source_lines;
  List.rev !problems

let validate_property_chains file source_lines payload_lines =
  let problems = ref [] in
  Array.iteri
    (fun index line ->
      let content = without_separated_comment line.raw |> String.trim in
      if not payload_lines.(index) then
        match find_mapping_colons content with
        | [ colon ] ->
            let value =
              String.sub content (colon + 1) (String.length content - colon - 1)
              |> String.trim
            in
            if Util.starts_with ~prefix:"&" value then
              let body = strip_properties value in
              if body = "" then (
                let next = ref (index + 1) in
                while
                  !next < Array.length source_lines
                  && String.trim source_lines.(!next).raw = ""
                do
                  incr next
                done;
                if !next < Array.length source_lines then
                  let following = String.trim source_lines.(!next).raw in
                  if
                    Util.starts_with ~prefix:"&" following
                    && find_mapping_colons (strip_properties following) = []
                  then
                    problems :=
                      issue file source_lines.(!next)
                        source_lines.(!next).indent
                        (String.length source_lines.(!next).raw)
                        "a node cannot have two anchors"
                      :: !problems)
        | _ -> ())
    source_lines;
  List.rev !problems

let validate ~file source =
  let source_lines = lines source in
  let blocks = analyze_blocks file source_lines in
  let double_escapes =
    validate_double_escapes file source source_lines blocks.payload_lines
  in
  let directives = validate_directives file source_lines blocks.payload_lines in
  let inline_forms =
    validate_inline_forms file source_lines blocks.payload_lines
  in
  let flow = validate_flow file source_lines blocks.payload_lines in
  let layout = validate_layout file source_lines blocks.payload_lines in
  let block_indentation =
    validate_block_indentation file source_lines blocks.payload_lines
  in
  let property_chains =
    validate_property_chains file source_lines blocks.payload_lines
  in
  blocks.problems @ double_escapes @ directives @ inline_forms @ flow @ layout
  @ block_indentation @ property_chains
