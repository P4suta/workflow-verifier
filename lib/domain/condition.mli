type truth = False | True | Unknown
type t

val false_ : t
val true_ : t
val atom : string -> t
val not_ : t -> t
val and_ : t -> t -> t
val or_ : t -> t -> t
val equal : t -> t -> bool
val satisfiable : t -> bool
val implies : t -> t -> bool
val evaluate : (string -> bool option) -> t -> truth
val atoms : t -> string list
val to_json : t -> Json.t
val to_string : t -> string
