type provider = Github | Gitlab | Azure | Circleci
type phase = Source | Compile | Plan | Run | Post

type node_kind =
  | Trigger
  | Parameter
  | Workflow
  | Stage
  | Job
  | Step
  | Call
  | Command
  | Gate
  | Resource
  | Effect
  | Opaque

type edge_kind = Control | Data | Call_edge | Grant | Persist | Read | Write

type capability =
  | Repository_read
  | Repository_write
  | Token_read
  | Token_write
  | Oidc
  | Cloud_credential
  | Secret_access
  | Network
  | Filesystem_read
  | Filesystem_write
  | Shell
  | Artifact_read
  | Artifact_write
  | Cache_read
  | Cache_write
  | Deployment
  | Self_hosted_persistence
  | Ai_tool

type observable_effect =
  | Repository_change
  | Network_request
  | File_read
  | File_write
  | Command_execution
  | Artifact_publish
  | Cache_publish
  | Deployment_change
  | Credential_use
  | Workflow_change
  | Ai_agent_execution

type node = {
  id : string;
  provider : provider;
  kind : node_kind;
  name : string;
  phase : phase;
  span : Span.t;
  condition : Condition.t;
  attributes : (string * Abstract_value.t) list;
  capabilities : capability list;
  effects : observable_effect list;
  unknown : Unknown.reason option;
}

type edge = {
  id : string;
  kind : edge_kind;
  from_ : string;
  to_ : string;
  condition : Condition.t;
  label : string option;
}

type t = {
  provider : provider;
  source : string;
  nodes : node list;
  edges : edge list;
  entrypoints : string list;
}

type issue = { code : string; message : string; node_ids : string list }

val provider_name : provider -> string
val phase_name : phase -> string
val kind_name : node_kind -> string
val capability_name : capability -> string
val effect_name : observable_effect -> string
val edge_kind_name : edge_kind -> string

val make_node :
  provider:provider ->
  kind:node_kind ->
  name:string ->
  phase:phase ->
  span:Span.t ->
  ?condition:Condition.t ->
  ?attributes:(string * Abstract_value.t) list ->
  ?capabilities:capability list ->
  ?effects:observable_effect list ->
  ?unknown:Unknown.reason ->
  unit ->
  node

val make_edge :
  kind:edge_kind ->
  from_:string ->
  to_:string ->
  ?condition:Condition.t ->
  ?label:string ->
  unit ->
  edge

val empty : provider -> string -> t
val add_node : node -> t -> t
val add_edge : edge -> t -> t
val add_entrypoint : string -> t -> t
val finalize : t -> t
val find_node : t -> string -> node option
val successors : ?kind:edge_kind -> t -> string -> node list
val predecessors : ?kind:edge_kind -> t -> string -> node list
val validate : t -> issue list
val to_json : t -> Json.t
