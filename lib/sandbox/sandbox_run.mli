type outcome =
  | Completed
  | Step_failed of { step : string; code : int option }
  | Timed_out of { step : string }
  | Output_limit_exceeded of { step : string }

type t = { evidence : Evidence.t; outcome : outcome }

val to_json : t -> Json.t
val to_canonical_json : t -> string
val parse : string -> (t, string) result
