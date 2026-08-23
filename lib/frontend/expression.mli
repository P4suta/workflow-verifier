type reference = {
  name : string;
  raw : string;
  span : Span.t;
  phase : Ir.phase;
  value : Abstract_value.t;
}

type literal =
  | Null
  | Boolean of bool
  | Number of string
  | String_literal of string
  | Regex of string

type unary_operator = Not | Negate

type binary_operator =
  | Or
  | And
  | Equal
  | Not_equal
  | Less
  | Less_equal
  | Greater
  | Greater_equal
  | Match
  | Not_match

type node =
  | Literal of literal
  | Reference of string * Span.t
  | Call of string * node list
  | Unary of unary_operator * node
  | Binary of binary_operator * node * node

type expression = {
  provider : Ir.provider;
  phase : Ir.phase;
  span : Span.t;
  node : node;
}

type problem = { message : string; span : Span.t }

val parse :
  Ir.provider ->
  phase:Ir.phase ->
  span:Span.t ->
  string ->
  (expression, problem list) result

val references : expression -> reference list
val infer_type : expression -> Abstract_value.value_type
val to_condition : expression -> Condition.t
val validate_phase : expression -> Unknown.reason list

val scan :
  Ir.provider ->
  default_phase:Ir.phase ->
  span:Span.t ->
  string ->
  reference list

val references_to_attributes :
  reference list -> (string * Abstract_value.t) list
