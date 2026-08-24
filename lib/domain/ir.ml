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

let compare_node (left : node) (right : node) = String.compare left.id right.id
let compare_edge (left : edge) (right : edge) = String.compare left.id right.id

let provider_name = function
  | Github -> "github"
  | Gitlab -> "gitlab"
  | Azure -> "azure"
  | Circleci -> "circleci"

let phase_name = function
  | Source -> "source"
  | Compile -> "compile"
  | Plan -> "plan"
  | Run -> "run"
  | Post -> "post"

let kind_name = function
  | Trigger -> "trigger"
  | Parameter -> "parameter"
  | Workflow -> "workflow"
  | Stage -> "stage"
  | Job -> "job"
  | Step -> "step"
  | Call -> "call"
  | Command -> "command"
  | Gate -> "gate"
  | Resource -> "resource"
  | Effect -> "effect"
  | Opaque -> "opaque"

let edge_kind_name = function
  | Control -> "control"
  | Data -> "data"
  | Call_edge -> "call"
  | Grant -> "grant"
  | Persist -> "persist"
  | Read -> "read"
  | Write -> "write"

let capability_name = function
  | Repository_read -> "repository_read"
  | Repository_write -> "repository_write"
  | Token_read -> "token_read"
  | Token_write -> "token_write"
  | Oidc -> "oidc"
  | Cloud_credential -> "cloud_credential"
  | Secret_access -> "secret_access"
  | Network -> "network"
  | Filesystem_read -> "filesystem_read"
  | Filesystem_write -> "filesystem_write"
  | Shell -> "shell"
  | Artifact_read -> "artifact_read"
  | Artifact_write -> "artifact_write"
  | Cache_read -> "cache_read"
  | Cache_write -> "cache_write"
  | Deployment -> "deployment"
  | Self_hosted_persistence -> "self_hosted_persistence"
  | Ai_tool -> "ai_tool"

let effect_name = function
  | Repository_change -> "repository_change"
  | Network_request -> "network_request"
  | File_read -> "file_read"
  | File_write -> "file_write"
  | Command_execution -> "command_execution"
  | Artifact_publish -> "artifact_publish"
  | Cache_publish -> "cache_publish"
  | Deployment_change -> "deployment_change"
  | Credential_use -> "credential_use"
  | Workflow_change -> "workflow_change"
  | Ai_agent_execution -> "ai_agent_execution"

let identifier components =
  "wv_"
  ^ String.sub (Sha256.digest_string (String.concat "\000" components)) 0 20

let make_node ~provider ~kind ~name ~phase ~(span : Span.t)
    ?(condition = Condition.true_) ?(attributes = []) ?(capabilities = [])
    ?(effects = []) ?unknown () =
  let id =
    identifier
      [
        provider_name provider;
        kind_name kind;
        name;
        Util.normalize_slashes span.file;
        string_of_int span.start.byte;
        string_of_int span.stop.byte;
      ]
  in
  {
    id;
    provider;
    kind;
    name;
    phase;
    span;
    condition;
    attributes = List.sort (fun (a, _) (b, _) -> String.compare a b) attributes;
    capabilities = Util.deduplicate_compare Stdlib.compare capabilities;
    effects = Util.deduplicate_compare Stdlib.compare effects;
    unknown;
  }

let make_edge ~kind ~from_ ~to_ ?(condition = Condition.true_) ?label () =
  let id =
    identifier
      [
        "edge";
        edge_kind_name kind;
        from_;
        to_;
        Condition.to_string condition;
        Option.value ~default:"" label;
      ]
  in
  { id; kind; from_; to_; condition; label }

let empty provider source =
  { provider; source; nodes = []; edges = []; entrypoints = [] }

let add_node node graph = { graph with nodes = node :: graph.nodes }
let add_edge edge graph = { graph with edges = edge :: graph.edges }

let add_entrypoint id graph =
  { graph with entrypoints = id :: graph.entrypoints }

let finalize graph =
  {
    graph with
    nodes = List.sort compare_node graph.nodes;
    edges = List.sort compare_edge graph.edges;
    entrypoints = Util.deduplicate_strings graph.entrypoints;
  }

let find_node graph id =
  List.find_opt (fun (node : node) -> node.id = id) graph.nodes

let neighbor selector ?kind graph id =
  graph.edges
  |> List.filter (fun (edge : edge) ->
      selector edge = id
      &&
      match kind with
      | None -> true
      | Some kind -> edge.kind = kind)
  |> List.filter_map (fun (edge : edge) ->
      let other = if selector edge = edge.from_ then edge.to_ else edge.from_ in
      find_node graph other)

let successors ?kind graph id = neighbor (fun edge -> edge.from_) ?kind graph id
let predecessors ?kind graph id = neighbor (fun edge -> edge.to_) ?kind graph id

let phase_rank = function
  | Source -> 0
  | Compile -> 1
  | Plan -> 2
  | Run -> 3
  | Post -> 4

let validate graph =
  let issues = ref [] in
  let add code message node_ids =
    issues := { code; message; node_ids } :: !issues
  in
  let seen = Hashtbl.create (max 1 (List.length graph.nodes))
  and nodes_by_id = Hashtbl.create (max 1 (List.length graph.nodes)) in
  List.iter
    (fun (node : node) ->
      if Hashtbl.mem seen node.id then
        add "IR-DUPLICATE-NODE" ("duplicate node ID " ^ node.id) [ node.id ];
      Hashtbl.replace seen node.id ();
      if not (Hashtbl.mem nodes_by_id node.id) then
        Hashtbl.add nodes_by_id node.id node)
    graph.nodes;
  let indexed_node id = Hashtbl.find_opt nodes_by_id id in
  List.iter
    (fun (edge : edge) ->
      match (indexed_node edge.from_, indexed_node edge.to_) with
      | None, _ | _, None ->
          add "IR-DANGLING-EDGE"
            ("edge " ^ edge.id ^ " has a missing endpoint")
            [ edge.from_; edge.to_ ]
      | Some source, Some target ->
          if
            edge.kind = Data
            && phase_rank source.phase > phase_rank target.phase
          then
            add "IR-PHASE-ORDER"
              (Printf.sprintf "%s data is unavailable during %s"
                 (phase_name source.phase) (phase_name target.phase))
              [ source.id; target.id ])
    graph.edges;
  List.sort
    (fun left right ->
      match String.compare left.code right.code with
      | 0 -> Stdlib.compare left.node_ids right.node_ids
      | comparison -> comparison)
    !issues

let node_json (node : node) =
  Json.Object
    [
      ( "attributes",
        Json.Object
          (List.map
             (fun (key, value) -> (key, Abstract_value.to_json value))
             node.attributes) );
      ( "capabilities",
        Json.Array
          (List.map
             (fun value -> Json.String (capability_name value))
             node.capabilities) );
      ("condition", Condition.to_json node.condition);
      ( "effects",
        Json.Array
          (List.map (fun value -> Json.String (effect_name value)) node.effects)
      );
      ("id", Json.String node.id);
      ("kind", Json.String (kind_name node.kind));
      ("name", Json.String node.name);
      ("phase", Json.String (phase_name node.phase));
      ("provider", Json.String (provider_name node.provider));
      ("span", Span.to_json node.span);
      ("unknown", Option.fold ~none:Json.Null ~some:Unknown.to_json node.unknown);
    ]

let edge_json (edge : edge) =
  Json.Object
    [
      ("condition", Condition.to_json edge.condition);
      ("from", Json.String edge.from_);
      ("id", Json.String edge.id);
      ("kind", Json.String (edge_kind_name edge.kind));
      ( "label",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          edge.label );
      ("to", Json.String edge.to_);
    ]

let to_json graph =
  let graph = finalize graph in
  Json.Object
    [
      ("edges", Json.Array (List.map edge_json graph.edges));
      ( "entrypoints",
        Json.Array (List.map (fun id -> Json.String id) graph.entrypoints) );
      ("nodes", Json.Array (List.map node_json graph.nodes));
      ("provider", Json.String (provider_name graph.provider));
      ("source", Json.String (Util.normalize_slashes graph.source));
    ]
