type scalar_style = Plain | Single_quoted | Double_quoted | Literal | Folded
type trivia_kind = Comment | Blank | Directive | Document_start | Document_end
type trivia = { kind : trivia_kind; raw : string; span : Span.t }

type scalar = {
  value : string;
  raw : string;
  style : scalar_style;
  anchor : string option;
  tag : string option;
  span : Span.t;
}

type node =
  | Scalar of scalar
  | Alias of { name : string; raw : string; span : Span.t }
  | Sequence of sequence_item list * Span.t
  | Mapping of mapping_entry list * Span.t
  | Flow_sequence of node list * Span.t
  | Flow_mapping of mapping_entry list * Span.t
  | Decorated of {
      value : node;
      anchor : string option;
      tag : string option;
      span : Span.t;
    }
  | Invalid of { raw : string; reason : string; span : Span.t }

and sequence_item = { value : node; dash_span : Span.t; span : Span.t }

and mapping_entry = {
  key : scalar;
  key_node : node;
  value : node;
  colon_span : Span.t;
  span : Span.t;
  merge : bool;
  duplicate : bool;
}

type problem = { code : string; message : string; span : Span.t }
type document = { root : node option; directives : trivia list; span : Span.t }

type t = {
  file : string;
  source : string;
  bom : bool;
  newline : [ `Lf | `CrLf | `Cr | `None ];
  documents : document list;
  trivia : trivia list;
  anchors : (string * node) list;
  problems : problem list;
}

type edit = { start_byte : int; stop_byte : int; replacement : string }

val parse : ?file:string -> string -> t
val print : t -> string
val root : t -> node option
val node_span : node -> Span.t
val scalar_value : node -> string option
val as_mapping : node -> mapping_entry list option
val as_sequence : node -> sequence_item list option
val mapping_find : string -> mapping_entry list -> node option
val mapping_find_entry : string -> mapping_entry list -> mapping_entry option
val get_path : node -> string list -> node option
val structural_equal : t -> t -> bool
val resolve_alias : t -> string -> node option
val apply_edits : t -> edit list -> (string, string) result
val node_to_json : node -> Json.t
