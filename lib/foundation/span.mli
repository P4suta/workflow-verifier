type position = { byte : int; line : int; column : int }
type t = { file : string; start : position; stop : position }

val position : ?byte:int -> ?line:int -> ?column:int -> unit -> position
val make : ?file:string -> position -> position -> t
val none : t
val compare_position : position -> position -> int
val compare : t -> t -> int
val merge : t -> t -> t
val contains : t -> int -> bool
val to_string : t -> string
val to_json : t -> Json.t
