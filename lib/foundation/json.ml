type t =
  | Null
  | Bool of bool
  | Int of int
  | Int64 of int64
  | String of string
  | Array of t list
  | Object of (string * t) list

type error = { offset : int; message : string }

let escape_string value =
  let buffer = Buffer.create 64 in
  String.iter
    (fun character ->
      match character with
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\b' -> Buffer.add_string buffer "\\b"
      | '\012' -> Buffer.add_string buffer "\\f"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character when Char.code character < 0x20 ->
          Buffer.add_string buffer
            (Printf.sprintf "\\u%04x" (Char.code character))
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let rec canonical_to_buffer buffer = function
  | Null -> Buffer.add_string buffer "null"
  | Bool true -> Buffer.add_string buffer "true"
  | Bool false -> Buffer.add_string buffer "false"
  | Int value -> Buffer.add_string buffer (string_of_int value)
  | Int64 value -> Buffer.add_string buffer (Int64.to_string value)
  | String value ->
      Buffer.add_char buffer '"';
      Buffer.add_string buffer (escape_string value);
      Buffer.add_char buffer '"'
  | Array values ->
      Buffer.add_char buffer '[';
      List.iteri
        (fun index value ->
          if index > 0 then Buffer.add_char buffer ',';
          canonical_to_buffer buffer value)
        values;
      Buffer.add_char buffer ']'
  | Object fields ->
      Buffer.add_char buffer '{';
      fields
      |> List.sort (fun (left, _) (right, _) -> String.compare left right)
      |> List.iteri (fun index (key, value) ->
          if index > 0 then Buffer.add_char buffer ',';
          canonical_to_buffer buffer (String key);
          Buffer.add_char buffer ':';
          canonical_to_buffer buffer value);
      Buffer.add_char buffer '}'

let to_string value =
  let buffer = Buffer.create 256 in
  canonical_to_buffer buffer value;
  Buffer.contents buffer

let to_pretty_string value =
  let buffer = Buffer.create 512 in
  let rec emit indent = function
    | (Null | Bool _ | Int _ | Int64 _ | String _) as scalar ->
        canonical_to_buffer buffer scalar
    | Array [] -> Buffer.add_string buffer "[]"
    | Array values ->
        Buffer.add_string buffer "[\n";
        List.iteri
          (fun index child ->
            Buffer.add_string buffer (String.make (indent + 2) ' ');
            emit (indent + 2) child;
            if index + 1 < List.length values then Buffer.add_char buffer ',';
            Buffer.add_char buffer '\n')
          values;
        Buffer.add_string buffer (String.make indent ' ');
        Buffer.add_char buffer ']'
    | Object [] -> Buffer.add_string buffer "{}"
    | Object fields ->
        let fields =
          List.sort
            (fun (left, _) (right, _) -> String.compare left right)
            fields
        in
        Buffer.add_string buffer "{\n";
        List.iteri
          (fun index (key, child) ->
            Buffer.add_string buffer (String.make (indent + 2) ' ');
            canonical_to_buffer buffer (String key);
            Buffer.add_string buffer ": ";
            emit (indent + 2) child;
            if index + 1 < List.length fields then Buffer.add_char buffer ',';
            Buffer.add_char buffer '\n')
          fields;
        Buffer.add_string buffer (String.make indent ' ');
        Buffer.add_char buffer '}'
  in
  emit 0 value;
  Buffer.add_char buffer '\n';
  Buffer.contents buffer

exception Parse_error of error

let parse source =
  let length = String.length source and offset = ref 0 in
  let fail message = raise (Parse_error { offset = !offset; message }) in
  let peek () = if !offset < length then Some source.[!offset] else None in
  let take () =
    match peek () with
    | None -> fail "unexpected end of JSON"
    | Some character ->
        incr offset;
        character
  in
  let rec whitespace () =
    match peek () with
    | Some (' ' | '\t' | '\r' | '\n') ->
        incr offset;
        whitespace ()
    | _ -> ()
  in
  let expect_literal literal value =
    String.iter
      (fun expected -> if take () <> expected then fail ("expected " ^ literal))
      literal;
    value
  in
  let hex_value = function
    | '0' .. '9' as character -> Char.code character - Char.code '0'
    | 'a' .. 'f' as character -> Char.code character - Char.code 'a' + 10
    | 'A' .. 'F' as character -> Char.code character - Char.code 'A' + 10
    | _ -> fail "invalid Unicode escape"
  in
  let add_utf8 buffer codepoint =
    if codepoint <= 0x7f then Buffer.add_char buffer (Char.chr codepoint)
    else if codepoint <= 0x7ff then (
      Buffer.add_char buffer (Char.chr (0xc0 lor (codepoint lsr 6)));
      Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))))
    else (
      Buffer.add_char buffer (Char.chr (0xe0 lor (codepoint lsr 12)));
      Buffer.add_char buffer (Char.chr (0x80 lor ((codepoint lsr 6) land 0x3f)));
      Buffer.add_char buffer (Char.chr (0x80 lor (codepoint land 0x3f))))
  in
  let parse_string () =
    if take () <> '"' then fail "expected string";
    let buffer = Buffer.create 32 in
    let rec loop () =
      match take () with
      | '"' -> Buffer.contents buffer
      | '\\' ->
          (match take () with
          | '"' -> Buffer.add_char buffer '"'
          | '\\' -> Buffer.add_char buffer '\\'
          | '/' -> Buffer.add_char buffer '/'
          | 'b' -> Buffer.add_char buffer '\b'
          | 'f' -> Buffer.add_char buffer '\012'
          | 'n' -> Buffer.add_char buffer '\n'
          | 'r' -> Buffer.add_char buffer '\r'
          | 't' -> Buffer.add_char buffer '\t'
          | 'u' ->
              let value = ref 0 in
              for _ = 1 to 4 do
                value := (!value lsl 4) lor hex_value (take ())
              done;
              add_utf8 buffer !value
          | _ -> fail "invalid string escape");
          loop ()
      | character when Char.code character < 0x20 ->
          fail "unescaped control character"
      | character ->
          Buffer.add_char buffer character;
          loop ()
    in
    loop ()
  in
  let parse_number () =
    let start = !offset in
    (match peek () with
    | Some '-' -> incr offset
    | _ -> ());
    let digits = ref 0 in
    while
      match peek () with
      | Some '0' .. '9' ->
          incr offset;
          incr digits;
          true
      | _ -> false
    do
      ()
    done;
    if !digits = 0 then fail "invalid number";
    if
      match peek () with
      | Some ('.' | 'e' | 'E') -> true
      | _ -> false
    then fail "runner JSON permits integers only";
    let raw = String.sub source start (!offset - start) in
    try
      let value = Int64.of_string raw in
      if value <= Int64.of_int max_int && value >= Int64.of_int min_int then
        Int (Int64.to_int value)
      else Int64 value
    with Failure _ -> fail "integer is out of range"
  in
  let rec value () =
    whitespace ();
    match peek () with
    | Some 'n' -> expect_literal "null" Null
    | Some 't' -> expect_literal "true" (Bool true)
    | Some 'f' -> expect_literal "false" (Bool false)
    | Some '"' -> String (parse_string ())
    | Some '[' -> array ()
    | Some '{' -> object_ ()
    | Some ('-' | '0' .. '9') -> parse_number ()
    | Some _ -> fail "expected a JSON value"
    | None -> fail "expected a JSON value"
  and array () =
    ignore (take ());
    whitespace ();
    if peek () = Some ']' then (
      ignore (take ());
      Array [])
    else
      let rec items accumulator =
        let child = value () in
        whitespace ();
        match take () with
        | ']' -> Array (List.rev (child :: accumulator))
        | ',' -> items (child :: accumulator)
        | _ -> fail "expected ',' or ']'"
      in
      items []
  and object_ () =
    ignore (take ());
    whitespace ();
    if peek () = Some '}' then (
      ignore (take ());
      Object [])
    else
      let rec fields seen accumulator =
        whitespace ();
        let key = parse_string () in
        if List.mem key seen then fail ("duplicate JSON object key: " ^ key);
        whitespace ();
        if take () <> ':' then fail "expected ':'";
        let child = value () in
        whitespace ();
        match take () with
        | '}' -> Object (List.rev ((key, child) :: accumulator))
        | ',' -> fields (key :: seen) ((key, child) :: accumulator)
        | _ -> fail "expected ',' or '}'"
      in
      fields [] []
  in
  try
    let parsed = value () in
    whitespace ();
    if !offset <> length then fail "trailing JSON input";
    Ok parsed
  with Parse_error error -> Error error

let member name = function
  | Object fields -> List.assoc_opt name fields
  | _ -> None

let as_string = function
  | String value -> Some value
  | _ -> None

let as_int = function
  | Int value -> Some value
  | _ -> None

let as_bool = function
  | Bool value -> Some value
  | _ -> None

let as_array = function
  | Array values -> Some values
  | _ -> None

let as_object = function
  | Object fields -> Some fields
  | _ -> None
