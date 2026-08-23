type reason =
  | Unsupported_syntax of string
  | External_state of string
  | Unresolved_dependency of string
  | Recursive_call of string
  | Dynamic_string of string
  | Phase_unavailable of string
  | Missing_evidence of string
  | Resource_limit of string

val compare : reason -> reason -> int
val to_string : reason -> string
val to_json : reason -> Json.t
