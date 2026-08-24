type style = Literal | Folded
type chomping = Clip | Keep | Strip

type header = {
  style : style;
  chomping : chomping;
  indentation : int option;
}

type classification = Not_block | Valid of header | Invalid of int

let separation = function
  | ' ' | '\t' | '\r' | '\n' -> true
  | _ -> false

let trim_left value =
  let cursor = ref 0 in
  while !cursor < String.length value && separation value.[!cursor] do
    incr cursor
  done;
  String.sub value !cursor (String.length value - !cursor)

let classify raw =
  let fragment = trim_left raw in
  if fragment = "" || (fragment.[0] <> '|' && fragment.[0] <> '>') then
    Not_block
  else
    let cursor = ref 1 in
    while
      !cursor < String.length fragment
      && not (separation fragment.[!cursor])
      && fragment.[!cursor] <> '#'
    do
      incr cursor
    done;
    let token = String.sub fragment 0 !cursor in
    let indentation = ref None
    and chomping = ref Clip
    and chomp_seen = ref false
    and valid = ref true in
    String.iteri
      (fun index character ->
        if index > 0 then
          match character with
          | '1' .. '9' when !indentation = None ->
              indentation := Some (Char.code character - Char.code '0')
          | '+' when not !chomp_seen ->
              chomp_seen := true;
              chomping := Keep
          | '-' when not !chomp_seen ->
              chomp_seen := true;
              chomping := Strip
          | _ -> valid := false)
      token;
    let suffix_is_separated =
      !cursor = String.length fragment || separation fragment.[!cursor]
    in
    let trailer =
      String.sub fragment !cursor (String.length fragment - !cursor)
      |> trim_left
    in
    let trailer_is_comment =
      trailer = "" || (String.length trailer > 0 && trailer.[0] = '#')
    in
    if !valid && suffix_is_separated && trailer_is_comment then
      Valid
        {
          style = (if token.[0] = '|' then Literal else Folded);
          chomping = !chomping;
          indentation = !indentation;
        }
    else Invalid (String.length token)
