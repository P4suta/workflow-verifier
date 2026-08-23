type t =
  | Null
  | Bool of bool
  | Int of int
  | Int64 of int64
  | String of string
  | Array of t list
  | Object of (string * t) list

type error = { offset : int; message : string }

val to_string : t -> string
val to_pretty_string : t -> string
val parse : string -> (t, error) result
val member : string -> t -> t option
val as_string : t -> string option
val as_int : t -> int option
val as_bool : t -> bool option
val as_array : t -> t list option
val as_object : t -> (string * t) list option
