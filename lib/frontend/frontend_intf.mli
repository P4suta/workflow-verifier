type pipeline_phase = Detected | Parsed | Expanded | Resolved | Lowered
type mutability = Immutable | Mutable | Local | Unknown_mutability

type dependency_kind =
  | Action
  | Include
  | Component
  | Container_image
  | Task
  | Orb
  | Repository
  | Template
  | Unknown_dependency_kind

type dependency_status =
  | Locked of { revision : string; digest : string }
  | Unresolved of Unknown.reason

type dependency_locator =
  | Direct_reference
  | Repository_source of {
      repository : string;
      revision : string option;
      repository_type : string option;
    }
  | Repository_file of {
      repository : string;
      revision : string option;
      path : string;
      repository_type : string option;
    }

type dependency = {
  provider : Ir.provider;
  kind : dependency_kind;
  reference : string;
  locator : dependency_locator;
  span : Span.t;
  mutability : mutability;
  status : dependency_status;
}

type problem = { code : string; message : string; span : Span.t }
type source_unit = { path : string; source : string }
type parsed = { unit_ : source_unit; cst : Yaml_cst.t }
type expanded = { parsed : parsed; expansion_unknowns : Unknown.reason list }
type resolved = { expanded : expanded; dependencies : dependency list }

type compilation = {
  provider : Ir.provider;
  phases : pipeline_phase list;
  graph : Ir.t;
  dependencies : dependency list;
  problems : problem list;
  cst : Yaml_cst.t;
}

module type S = sig
  val provider : Ir.provider
  val detect : path:string -> source:string -> bool
  val entrypoint : path:string -> source:string -> bool
  val parse : source_unit -> (parsed, problem list) result
  val expand : parsed -> expanded
  val resolve : expanded -> resolved
  val lower : resolved -> Ir.t * problem list
end

val mutability_name : mutability -> string
val dependency_kind_name : dependency_kind -> string
val dependency_to_json : dependency -> Json.t
