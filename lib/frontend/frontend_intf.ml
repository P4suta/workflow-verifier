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

let mutability_name = function
  | Immutable -> "immutable"
  | Mutable -> "mutable"
  | Local -> "local"
  | Unknown_mutability -> "unknown"

let dependency_kind_name = function
  | Action -> "action"
  | Include -> "include"
  | Component -> "component"
  | Container_image -> "container_image"
  | Task -> "task"
  | Orb -> "orb"
  | Repository -> "repository"
  | Template -> "template"
  | Unknown_dependency_kind -> "unknown"

let optional_string = function
  | None -> Json.Null
  | Some value -> Json.String value

let dependency_locator_to_json = function
  | Direct_reference -> Json.Object [ ("kind", Json.String "reference") ]
  | Repository_source { repository; revision; repository_type } ->
      Json.Object
        [
          ("kind", Json.String "repository");
          ("repository", Json.String repository);
          ("repository_type", optional_string repository_type);
          ("revision", optional_string revision);
        ]
  | Repository_file { repository; revision; path; repository_type } ->
      Json.Object
        [
          ("kind", Json.String "repository_file");
          ("path", Json.String path);
          ("repository", Json.String repository);
          ("repository_type", optional_string repository_type);
          ("revision", optional_string revision);
        ]

let dependency_to_json dependency =
  let status =
    match dependency.status with
    | Locked { revision; digest } ->
        Json.Object
          [
            ("digest", Json.String digest);
            ("revision", Json.String revision);
            ("state", Json.String "locked");
          ]
    | Unresolved reason ->
        Json.Object
          [
            ("reason", Unknown.to_json reason);
            ("state", Json.String "unresolved");
          ]
  in
  Json.Object
    [
      ("kind", Json.String (dependency_kind_name dependency.kind));
      ("locator", dependency_locator_to_json dependency.locator);
      ("mutability", Json.String (mutability_name dependency.mutability));
      ("provider", Json.String (Ir.provider_name dependency.provider));
      ("reference", Json.String dependency.reference);
      ("span", Span.to_json dependency.span);
      ("status", status);
    ]
