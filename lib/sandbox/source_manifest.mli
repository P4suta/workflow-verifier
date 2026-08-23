type entry = { path : string; digest : string }
type t = { entries : entry list; canonical_json : string; digest : string }

val generated_directories : string list
val is_generated : root:string -> string -> bool
val create : root:string -> files:(string * string) list -> (t, string) result
