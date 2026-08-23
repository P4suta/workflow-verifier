type state =
  | Proved
  | Violated
  | Unknown of Unknown.reason list
  | Not_applicable

type t = {
  id : string;
  state : state;
  subject : string option;
  explanation : string;
}

val state_name : state -> string
val compare : t -> t -> int
val combine : state list -> state
val to_json : t -> Json.t
