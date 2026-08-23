type value_type =
  | Never_type
  | Null_type
  | Bool_type
  | Number_type
  | String_type
  | List_type
  | Object_type
  | Dynamic_type

type truth = False | True | Maybe
type interval = { minimum : int64 option; maximum : int64 option }

type string_value =
  | Bottom
  | Constants of string list
  | Affix of { prefix : string option; suffix : string option }
  | Pattern of string
  | Top

type value =
  | Bottom_value
  | Null
  | Boolean of truth
  | Number of interval
  | String of string_value
  | List of t list option
  | Object of (string * t) list option
  | Unknown_value of Unknown.reason list

and trust = Trusted | Mixed | Untrusted | Unknown_trust of Unknown.reason list

and secrecy =
  | Public
  | Sensitive
  | Secret
  | Unknown_secrecy of Unknown.reason list

and provenance = { origin : string; span : Span.t; operation : string }

and t = {
  value_type : value_type;
  value : value;
  trust : trust;
  secrecy : secrecy;
  provenance : provenance list;
}

val bottom : t

val string_constant :
  string -> trust:trust -> secrecy:secrecy -> provenance:provenance list -> t

val unknown : Unknown.reason -> t
val join : t -> t -> t
val map_trust : trust -> t -> t
val map_secrecy : secrecy -> t -> t
val is_untrusted : t -> bool
val is_secret : t -> bool
val constants : t -> string list option
val to_json : t -> Json.t
