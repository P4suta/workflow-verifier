type t =
  | Stream_start
  | Stream_end
  | Document_start of { explicit : bool }
  | Document_end of { explicit : bool }
  | Sequence_start of {
      flow : bool;
      anchor : string option;
      tag : string option;
    }
  | Sequence_end
  | Mapping_start of {
      flow : bool;
      anchor : string option;
      tag : string option;
    }
  | Mapping_end
  | Scalar of {
      value : string;
      style : Yaml_cst.scalar_style;
      anchor : string option;
      tag : string option;
    }
  | Alias of string

val of_cst : Yaml_cst.t -> t list
val to_line : t -> string
val to_string : t list -> string
