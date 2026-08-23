type t = {
  schema : string;
  key : string;
  exit_code : int;
  report : string;
  integrity : string;
}

val key :
  tool_version:string ->
  config_digest:string ->
  lock_digest:string ->
  (string * string) list ->
  string

val make : key:string -> exit_code:int -> report:string -> t
val to_json : t -> Json.t
val to_canonical_json : t -> string
val parse : string -> (t, string) result
