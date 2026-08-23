type position = { byte : int; line : int; column : int }
type t = { file : string; start : position; stop : position }

let position ?(byte = 0) ?(line = 1) ?(column = 1) () = { byte; line; column }
let make ?(file = "<memory>") start stop = { file; start; stop }

let none =
  let origin = position () in
  { file = "<unknown>"; start = origin; stop = origin }

let compare_position left right =
  match Int.compare left.byte right.byte with
  | 0 -> (
      match Int.compare left.line right.line with
      | 0 -> Int.compare left.column right.column
      | comparison -> comparison)
  | comparison -> comparison

let compare left right =
  match String.compare left.file right.file with
  | 0 -> (
      match compare_position left.start right.start with
      | 0 -> compare_position left.stop right.stop
      | comparison -> comparison)
  | comparison -> comparison

let merge left right =
  if left.file <> right.file then left
  else
    {
      file = left.file;
      start =
        (if compare_position left.start right.start <= 0 then left.start
         else right.start);
      stop =
        (if compare_position left.stop right.stop >= 0 then left.stop
         else right.stop);
    }

let contains span byte = span.start.byte <= byte && byte <= span.stop.byte

let to_string span =
  Printf.sprintf "%s:%d:%d" span.file span.start.line span.start.column

let to_json span =
  let position_json position =
    Json.Object
      [
        ("byte", Json.Int position.byte);
        ("column", Json.Int position.column);
        ("line", Json.Int position.line);
      ]
  in
  Json.Object
    [
      ("file", Json.String (Util.normalize_slashes span.file));
      ("start", position_json span.start);
      ("stop", position_json span.stop);
    ]
