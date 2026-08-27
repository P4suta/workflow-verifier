type reference = {
  name : string;
  raw : string;
  span : Span.t;
  phase : Ir.phase;
  value : Abstract_value.t;
}

let is_identifier_character = function
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '.' | '-' -> true
  | _ -> false

let words expression =
  let values = ref []
  and start = ref None
  and quote = ref None
  and escaped = ref false in
  let flush stop =
    match !start with
    | None -> ()
    | Some offset ->
        let value = String.sub expression offset (stop - offset) in
        if value <> "" then values := (offset, value) :: !values;
        start := None
  in
  String.iteri
    (fun index character ->
      if !escaped then escaped := false
      else
        match (!quote, character) with
        | Some '"', '\\' -> escaped := true
        | Some active, candidate when active = candidate -> quote := None
        | Some _, _ -> ()
        | None, ('\'' | '"') ->
            flush index;
            quote := Some character
        | None, _ when is_identifier_character character ->
            if !start = None then start := Some index
        | None, _ -> flush index)
    expression;
  flush (String.length expression);
  List.rev !values

let looks_like_reference value =
  String.contains value '.'
  || String.length value > 1
     && String.for_all
          (function
            | 'A' .. 'Z' | '0' .. '9' | '_' -> true
            | _ -> false)
          value

let classify_trust provider name =
  let lower = String.lowercase_ascii name in
  let unknown label =
    Abstract_value.Unknown_trust
      [ Unknown.Dynamic_string ("unresolved " ^ label ^ " " ^ name) ]
  in
  match provider with
  | Ir.Github ->
      if
        Util.starts_with ~prefix:"github.event." lower
        || Util.starts_with ~prefix:"inputs." lower
        || List.mem lower
             [
               "github.actor";
               "github.base_ref";
               "github.head_ref";
               "github.ref";
               "github.ref_name";
               "github.triggering_actor";
             ]
      then Abstract_value.Untrusted
      else if
        Util.starts_with ~prefix:"env." lower
        || Util.starts_with ~prefix:"needs." lower
        || Util.starts_with ~prefix:"steps." lower
           && Util.contains ~needle:".outputs." lower
      then unknown "GitHub dataflow value"
      else Abstract_value.Trusted
  | Ir.Gitlab ->
      if lower = "ci_merge_request_diff_base_sha" then Abstract_value.Trusted
      else if
        Util.starts_with ~prefix:"ci_merge_request_" lower
        || Util.starts_with ~prefix:"ci_external_pull_request_" lower
        || List.mem lower
             [
               "ci_commit_branch";
               "ci_commit_message";
               "ci_commit_ref_name";
               "ci_commit_tag";
             ]
      then Abstract_value.Untrusted
      else Abstract_value.Trusted
  | Ir.Azure ->
      if lower = "system.pullrequest.pullrequestnumber" then
        Abstract_value.Trusted
      else if
        Util.starts_with ~prefix:"system.pullrequest." lower
        || List.mem lower
             [
               "build.sourcebranch";
               "build.sourcebranchname";
               "build.sourceversionmessage";
             ]
      then Abstract_value.Untrusted
      else Abstract_value.Trusted
  | Ir.Circleci ->
      if
        Util.starts_with ~prefix:"pipeline.parameters." lower
        || List.mem lower
             [ "circle_branch"; "circle_pull_request"; "circle_tag" ]
      then Abstract_value.Untrusted
      else if Util.starts_with ~prefix:"parameters." lower then
        Abstract_value.Trusted
      else Abstract_value.Trusted

let classify_secrecy name =
  let lower = String.lowercase_ascii name in
  if
    List.exists
      (fun fragment -> Util.contains ~needle:fragment lower)
      [ "secret"; "token"; "password"; "accesskey"; "access_token" ]
  then Abstract_value.Secret
  else Abstract_value.Public

let value_for provider name span =
  Abstract_value.string_constant name
    ~trust:(classify_trust provider name)
    ~secrecy:(classify_secrecy name)
    ~provenance:[ { origin = name; span; operation = "expression reference" } ]

let span_at parent start length =
  let start_position =
    {
      Span.byte = parent.Span.start.byte + start;
      line = parent.start.line;
      column = parent.start.column + start;
    }
  and stop_position =
    {
      Span.byte = parent.Span.start.byte + start + length;
      line = parent.start.line;
      column = parent.start.column + start + length;
    }
  in
  Span.make ~file:parent.file start_position stop_position

let delimited ~open_ ~close ~phase source =
  let results = ref [] and cursor = ref 0 in
  while !cursor < String.length source do
    let suffix = String.sub source !cursor (String.length source - !cursor) in
    match
      let rec find index =
        if index + String.length open_ > String.length suffix then None
        else if String.sub suffix index (String.length open_) = open_ then
          Some index
        else find (index + 1)
      in
      find 0
    with
    | None -> cursor := String.length source
    | Some relative -> (
        let start = !cursor + relative in
        let body_start = start + String.length open_ in
        let remaining =
          String.sub source body_start (String.length source - body_start)
        in
        let rec find_close index =
          if index + String.length close > String.length remaining then None
          else if String.sub remaining index (String.length close) = close then
            Some index
          else find_close (index + 1)
        in
        match find_close 0 with
        | None -> cursor := String.length source
        | Some body_length ->
            let body = String.sub source body_start body_length in
            words body
            |> List.filter (fun (_, name) -> looks_like_reference name)
            |> List.iter (fun (offset, name) ->
                results :=
                  (body_start + offset, name, phase, open_ ^ body ^ close)
                  :: !results);
            cursor := body_start + body_length + String.length close)
  done;
  List.rev !results

let dollar_variables ~phase source =
  let results = ref [] and index = ref 0 in
  while !index < String.length source do
    if source.[!index] = '$' && !index + 1 < String.length source then
      match source.[!index + 1] with
      | '(' ->
          let close = ref (!index + 2) in
          while !close < String.length source && source.[!close] <> ')' do
            incr close
          done;
          if !close < String.length source then (
            let name = String.sub source (!index + 2) (!close - !index - 2) in
            results :=
              (!index + 2, name, phase, "$" ^ "(" ^ name ^ ")") :: !results;
            index := !close + 1)
          else incr index
      | 'A' .. 'Z' | '_' ->
          let stop = ref (!index + 1) in
          while
            !stop < String.length source
            && is_identifier_character source.[!stop]
          do
            incr stop
          done;
          let name = String.sub source (!index + 1) (!stop - !index - 1) in
          results := (!index + 1, name, phase, "$" ^ name) :: !results;
          index := !stop
      | _ -> incr index
    else incr index
  done;
  List.rev !results

let scan provider ~default_phase ~span source =
  let found =
    match provider with
    | Ir.Github ->
        delimited ~open_:"${{" ~close:"}}" ~phase:default_phase source
        @ dollar_variables ~phase:default_phase source
    | Ir.Gitlab -> dollar_variables ~phase:default_phase source
    | Ir.Azure ->
        delimited ~open_:"${{" ~close:"}}" ~phase:Ir.Compile source
        @ dollar_variables ~phase:default_phase source
    | Ir.Circleci ->
        delimited ~open_:"<<" ~close:">>" ~phase:Ir.Compile source
        @ dollar_variables ~phase:default_phase source
  in
  found
  |> List.map (fun (offset, name, phase, raw) ->
      let reference_span = span_at span offset (String.length name) in
      {
        name;
        raw;
        span = reference_span;
        phase;
        value = value_for provider name reference_span;
      })
  |> List.sort_uniq (fun left right ->
      match Int.compare left.span.start.byte right.span.start.byte with
      | 0 -> String.compare left.name right.name
      | comparison -> comparison)

let references_to_attributes references =
  references
  |> List.fold_left
       (fun attributes reference ->
         let key = "reference:" ^ reference.name in
         match List.assoc_opt key attributes with
         | None -> (key, reference.value) :: attributes
         | Some previous ->
             (key, Abstract_value.join previous reference.value)
             :: List.remove_assoc key attributes)
       []
  |> List.sort (fun (left, _) (right, _) -> String.compare left right)

type literal =
  | Null
  | Boolean of bool
  | Number of string
  | String_literal of string
  | Regex of string

type unary_operator = Not | Negate

type binary_operator =
  | Or
  | And
  | Equal
  | Not_equal
  | Less
  | Less_equal
  | Greater
  | Greater_equal
  | Match
  | Not_match

type node =
  | Literal of literal
  | Reference of string * Span.t
  | Call of string * node list
  | Unary of unary_operator * node
  | Binary of binary_operator * node * node

type expression = {
  provider : Ir.provider;
  phase : Ir.phase;
  span : Span.t;
  node : node;
}

type problem = { message : string; span : Span.t }

type token_kind =
  | Tk_ident of string
  | Tk_string of string
  | Tk_regex of string
  | Tk_number of string
  | Tk_true
  | Tk_false
  | Tk_null
  | Tk_lparen
  | Tk_rparen
  | Tk_lbracket
  | Tk_rbracket
  | Tk_comma
  | Tk_not
  | Tk_minus
  | Tk_and
  | Tk_or
  | Tk_equal
  | Tk_not_equal
  | Tk_less
  | Tk_less_equal
  | Tk_greater
  | Tk_greater_equal
  | Tk_match
  | Tk_not_match
  | Tk_end

type token = { kind : token_kind; start : int; stop : int }

let expression_space = function
  | ' ' | '\t' | '\r' | '\n' -> true
  | _ -> false

let trim_bounds source =
  let first = ref 0 and last = ref (String.length source) in
  while !first < !last && expression_space source.[!first] do
    incr first
  done;
  while !last > !first && expression_space source.[!last - 1] do
    decr last
  done;
  (!first, !last)

let wrapped_body source =
  let first, last = trim_bounds source in
  let starts prefix =
    first + String.length prefix <= last
    && String.sub source first (String.length prefix) = prefix
  and ends suffix =
    last - String.length suffix >= first
    && String.sub source (last - String.length suffix) (String.length suffix)
       = suffix
  in
  if starts "${{" && ends "}}" then (first + 3, last - 2)
  else if starts "<<" && ends ">>" then (first + 2, last - 2)
  else if starts "$[" && ends "]" then (first + 2, last - 1)
  else (first, last)

let identifier_start = function
  | 'a' .. 'z' | 'A' .. 'Z' | '_' | '$' -> true
  | _ -> false

let expression_identifier = function
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '$' | '.' | '-' | '*' -> true
  | _ -> false

let lex span source body_start body_stop =
  let tokens = ref [] and problems = ref [] and cursor = ref body_start in
  let add kind start stop = tokens := { kind; start; stop } :: !tokens in
  let problem start stop message =
    problems :=
      { message; span = span_at span start (max 1 (stop - start)) } :: !problems
  in
  let pair left right kind =
    !cursor + 1 < body_stop
    && source.[!cursor] = left
    && source.[!cursor + 1] = right
    &&
    let start = !cursor in
    cursor := !cursor + 2;
    add kind start !cursor;
    true
  in
  while !cursor < body_stop do
    if expression_space source.[!cursor] then incr cursor
    else
      let start = !cursor in
      match source.[!cursor] with
      | '(' ->
          incr cursor;
          add Tk_lparen start !cursor
      | ')' ->
          incr cursor;
          add Tk_rparen start !cursor
      | '[' ->
          incr cursor;
          add Tk_lbracket start !cursor
      | ']' ->
          incr cursor;
          add Tk_rbracket start !cursor
      | ',' ->
          incr cursor;
          add Tk_comma start !cursor
      | '&' when pair '&' '&' Tk_and -> ()
      | '|' when pair '|' '|' Tk_or -> ()
      | '=' when pair '=' '~' Tk_match -> ()
      | '!' when pair '!' '~' Tk_not_match -> ()
      | '=' when pair '=' '=' Tk_equal -> ()
      | '!' when pair '!' '=' Tk_not_equal -> ()
      | '<' when pair '<' '=' Tk_less_equal -> ()
      | '>' when pair '>' '=' Tk_greater_equal -> ()
      | '!' ->
          incr cursor;
          add Tk_not start !cursor
      | '<' ->
          incr cursor;
          add Tk_less start !cursor
      | '>' ->
          incr cursor;
          add Tk_greater start !cursor
      | '-' ->
          incr cursor;
          add Tk_minus start !cursor
      | ('\'' | '"') as quote ->
          incr cursor;
          let buffer = Buffer.create 16 and closed = ref false in
          while !cursor < body_stop && not !closed do
            let character = source.[!cursor] in
            if character = quote then (
              closed := true;
              incr cursor)
            else if character = '\\' && !cursor + 1 < body_stop then (
              Buffer.add_char buffer source.[!cursor + 1];
              cursor := !cursor + 2)
            else (
              Buffer.add_char buffer character;
              incr cursor)
          done;
          if not !closed then
            problem start !cursor "unterminated string literal";
          add (Tk_string (Buffer.contents buffer)) start !cursor
      | '/' ->
          incr cursor;
          let buffer = Buffer.create 16
          and escaped = ref false
          and closed = ref false in
          while !cursor < body_stop && not !closed do
            let character = source.[!cursor] in
            if !escaped then (
              Buffer.add_char buffer character;
              escaped := false;
              incr cursor)
            else if character = '\\' then (
              Buffer.add_char buffer character;
              escaped := true;
              incr cursor)
            else if character = '/' then (
              closed := true;
              incr cursor)
            else (
              Buffer.add_char buffer character;
              incr cursor)
          done;
          if not !closed then problem start !cursor "unterminated regex literal";
          add (Tk_regex (Buffer.contents buffer)) start !cursor
      | '0' .. '9' ->
          while
            !cursor < body_stop
            &&
            match source.[!cursor] with
            | '0' .. '9' | '.' -> true
            | _ -> false
          do
            incr cursor
          done;
          add
            (Tk_number (String.sub source start (!cursor - start)))
            start !cursor
      | character when identifier_start character ->
          while !cursor < body_stop && expression_identifier source.[!cursor] do
            incr cursor
          done;
          let value = String.sub source start (!cursor - start) in
          let kind =
            match String.lowercase_ascii value with
            | "true" -> Tk_true
            | "false" -> Tk_false
            | "null" -> Tk_null
            | _ -> Tk_ident value
          in
          add kind start !cursor
      | character ->
          incr cursor;
          problem start !cursor
            (Printf.sprintf "unexpected expression character %C" character)
  done;
  add Tk_end body_stop body_stop;
  (List.rev !tokens, List.rev !problems)

type parser = {
  tokens : token array;
  mutable cursor : int;
  parent_span : Span.t;
  mutable problems : problem list;
}

let current parser = parser.tokens.(parser.cursor)

let advance parser =
  let token = current parser in
  if parser.cursor + 1 < Array.length parser.tokens then
    parser.cursor <- parser.cursor + 1;
  token

let parser_problem parser token message =
  parser.problems <-
    {
      message;
      span =
        span_at parser.parent_span token.start
          (max 1 (token.stop - token.start));
    }
    :: parser.problems

let normalize_reference name =
  if String.length name > 0 && name.[0] = '$' then
    String.sub name 1 (String.length name - 1)
  else name

let rec parse_or parser =
  let left = ref (parse_and parser) in
  while (current parser).kind = Tk_or do
    ignore (advance parser);
    left := Binary (Or, !left, parse_and parser)
  done;
  !left

and parse_and parser =
  let left = ref (parse_comparison parser) in
  while (current parser).kind = Tk_and do
    ignore (advance parser);
    left := Binary (And, !left, parse_comparison parser)
  done;
  !left

and parse_comparison parser =
  let left = ref (parse_unary parser) and scanning = ref true in
  while !scanning do
    let operator =
      match (current parser).kind with
      | Tk_equal -> Some Equal
      | Tk_not_equal -> Some Not_equal
      | Tk_less -> Some Less
      | Tk_less_equal -> Some Less_equal
      | Tk_greater -> Some Greater
      | Tk_greater_equal -> Some Greater_equal
      | Tk_match -> Some Match
      | Tk_not_match -> Some Not_match
      | _ -> None
    in
    match operator with
    | None -> scanning := false
    | Some operator ->
        ignore (advance parser);
        left := Binary (operator, !left, parse_unary parser)
  done;
  !left

and parse_unary parser =
  match (current parser).kind with
  | Tk_not ->
      ignore (advance parser);
      Unary (Not, parse_unary parser)
  | Tk_minus ->
      ignore (advance parser);
      Unary (Negate, parse_unary parser)
  | _ -> parse_primary parser

and parse_primary parser =
  let token = advance parser in
  match token.kind with
  | Tk_true -> Literal (Boolean true)
  | Tk_false -> Literal (Boolean false)
  | Tk_null -> Literal Null
  | Tk_string value -> Literal (String_literal value)
  | Tk_regex value -> Literal (Regex value)
  | Tk_number value -> Literal (Number value)
  | Tk_lparen ->
      let expression = parse_or parser in
      if (current parser).kind = Tk_rparen then ignore (advance parser)
      else parser_problem parser (current parser) "expected closing parenthesis";
      expression
  | Tk_ident raw_name ->
      let name = normalize_reference raw_name in
      if (current parser).kind = Tk_lparen then (
        ignore (advance parser);
        let arguments = ref [] in
        if (current parser).kind <> Tk_rparen then (
          arguments := parse_or parser :: !arguments;
          while (current parser).kind = Tk_comma do
            ignore (advance parser);
            arguments := parse_or parser :: !arguments
          done);
        if (current parser).kind = Tk_rparen then ignore (advance parser)
        else
          parser_problem parser (current parser) "expected closing parenthesis";
        Call (name, List.rev !arguments))
      else
        let name = ref name and stop = ref token.stop in
        while (current parser).kind = Tk_lbracket do
          ignore (advance parser);
          let key_token = advance parser in
          let key =
            match key_token.kind with
            | Tk_string value | Tk_ident value | Tk_number value -> Some value
            | _ ->
                parser_problem parser key_token "expected property index";
                None
          in
          Option.iter (fun key -> name := !name ^ "." ^ key) key;
          if (current parser).kind = Tk_rbracket then
            stop := (advance parser).stop
          else parser_problem parser (current parser) "expected closing bracket"
        done;
        Reference
          (!name, span_at parser.parent_span token.start (!stop - token.start))
  | Tk_end ->
      parser_problem parser token "expected expression";
      Literal Null
  | _ ->
      parser_problem parser token "expected expression operand";
      Literal Null

let parse provider ~phase ~span source =
  let body_start, body_stop = wrapped_body source in
  let tokens, lexer_problems = lex span source body_start body_stop in
  let parser =
    {
      tokens = Array.of_list tokens;
      cursor = 0;
      parent_span = span;
      problems = List.rev lexer_problems;
    }
  in
  let node = parse_or parser in
  if (current parser).kind <> Tk_end then
    parser_problem parser (current parser)
      "unexpected trailing expression token";
  match List.rev parser.problems with
  | [] -> Ok { provider; phase; span; node }
  | problems -> Error problems

let references expression =
  let rec collect accumulator = function
    | Literal _ -> accumulator
    | Reference (name, span) ->
        {
          name;
          raw = name;
          span;
          phase = expression.phase;
          value = value_for expression.provider name span;
        }
        :: accumulator
    | Call (_, arguments) -> List.fold_left collect accumulator arguments
    | Unary (_, operand) -> collect accumulator operand
    | Binary (_, left, right) -> collect (collect accumulator left) right
  in
  collect [] expression.node
  |> List.sort_uniq (fun left right ->
      match String.compare left.name right.name with
      | 0 -> Span.compare left.span right.span
      | comparison -> comparison)

let rec node_type = function
  | Literal Null -> Abstract_value.Null_type
  | Literal (Boolean _) -> Bool_type
  | Literal (Number _) -> Number_type
  | Literal (String_literal _ | Regex _) -> String_type
  | Reference _ -> Dynamic_type
  | Unary (Not, _) -> Bool_type
  | Unary (Negate, _) -> Number_type
  | Binary _ -> Bool_type
  | Call (name, _) ->
      if
        List.mem
          (String.lowercase_ascii name)
          [
            "always";
            "cancelled";
            "contains";
            "endswith";
            "eq";
            "failed";
            "failure";
            "in";
            "ne";
            "not";
            "notin";
            "or";
            "and";
            "startswith";
            "succeeded";
            "success";
          ]
      then Bool_type
      else if List.mem (String.lowercase_ascii name) [ "format"; "join" ] then
        String_type
      else Dynamic_type

let infer_type expression = node_type expression.node

let binary_name = function
  | Or -> "||"
  | And -> "&&"
  | Equal -> "=="
  | Not_equal -> "!="
  | Less -> "<"
  | Less_equal -> "<="
  | Greater -> ">"
  | Greater_equal -> ">="
  | Match -> "=~"
  | Not_match -> "!~"

let rec render = function
  | Literal Null -> "null"
  | Literal (Boolean value) -> string_of_bool value
  | Literal (Number value) -> value
  | Literal (String_literal value) -> Printf.sprintf "%S" value
  | Literal (Regex value) -> "/" ^ value ^ "/"
  | Reference (name, _) -> name
  | Call (name, arguments) ->
      name ^ "(" ^ String.concat "," (List.map render arguments) ^ ")"
  | Unary (Not, operand) -> "!" ^ render operand
  | Unary (Negate, operand) -> "-" ^ render operand
  | Binary (operator, left, right) ->
      "(" ^ render left ^ binary_name operator ^ render right ^ ")"

let rec condition_of_node = function
  | Literal (Boolean true) -> Condition.true_
  | Literal (Boolean false) | Literal Null -> Condition.false_
  | Unary (Not, operand) -> Condition.not_ (condition_of_node operand)
  | Binary (And, left, right) ->
      Condition.and_ (condition_of_node left) (condition_of_node right)
  | Binary (Or, left, right) ->
      Condition.or_ (condition_of_node left) (condition_of_node right)
  | node -> Condition.atom (render node)

let to_condition expression = condition_of_node expression.node

let phase_rank = function
  | Ir.Source -> 0
  | Compile -> 1
  | Plan -> 2
  | Run -> 3
  | Post -> 4

let minimum_phase provider name =
  let lower = String.lowercase_ascii name in
  match provider with
  | Ir.Github ->
      if
        List.exists
          (fun prefix -> Util.starts_with ~prefix lower)
          [ "steps."; "runner."; "job."; "secrets." ]
      then Ir.Run
      else if
        List.exists
          (fun prefix -> Util.starts_with ~prefix lower)
          [ "needs."; "matrix."; "strategy." ]
      then Ir.Plan
      else if Util.starts_with ~prefix:"github." lower then Ir.Source
      else Ir.Compile
  | Ir.Gitlab ->
      if Util.starts_with ~prefix:"ci_" lower then Ir.Plan else Ir.Run
  | Ir.Azure ->
      if
        List.exists
          (fun prefix -> Util.starts_with ~prefix lower)
          [ "dependencies."; "stagedependencies." ]
      then Ir.Run
      else if Util.starts_with ~prefix:"parameters." lower then Ir.Compile
      else Ir.Plan
  | Ir.Circleci ->
      if Util.starts_with ~prefix:"pipeline.parameters." lower then Ir.Compile
      else Ir.Run

let validate_phase expression =
  references expression
  |> List.filter_map (fun reference ->
      let minimum = minimum_phase expression.provider reference.name in
      if phase_rank expression.phase >= phase_rank minimum then None
      else
        Some
          (Unknown.Phase_unavailable
             (Printf.sprintf "%s is unavailable during %s" reference.name
                (Ir.phase_name expression.phase))))
  |> Util.deduplicate_compare Unknown.compare
