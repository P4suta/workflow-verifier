type trust = Trusted | Untrusted | Mixed | Unknown

type predicate =
  | Provider of Ir.provider
  | Node_kind of Ir.node_kind
  | Path_prefix of string
  | Trust of trust
  | Effect of Ir.observable_effect
  | Capability of Ir.capability
  | Dependency_mutability of Frontend_intf.mutability
  | Dominated_by_gate of bool

type selector =
  | All of predicate list
  | Any of predicate list
  | None_of of predicate list

type rule_kind = Forbid | Require | Limit of int | Forbid_path

type rule = {
  id : string;
  kind : rule_kind;
  selector : selector;
  message : string;
  severity : Diagnostic.severity;
}

let provider = function
  | "github" -> Some Ir.Github
  | "gitlab" -> Some Ir.Gitlab
  | "azure" -> Some Ir.Azure
  | "circleci" -> Some Ir.Circleci
  | _ -> None

let node_kind = function
  | "trigger" -> Some Ir.Trigger
  | "parameter" -> Some Parameter
  | "workflow" -> Some Workflow
  | "stage" -> Some Stage
  | "job" -> Some Job
  | "step" -> Some Step
  | "call" -> Some Call
  | "command" -> Some Command
  | "gate" -> Some Gate
  | "resource" -> Some Resource
  | "effect" -> Some Effect
  | "opaque" -> Some Opaque
  | _ -> None

let observable_effect = function
  | "repository_change" -> Some Ir.Repository_change
  | "network" | "network_request" -> Some Network_request
  | "file_read" -> Some File_read
  | "file_write" -> Some File_write
  | "command_execution" -> Some Command_execution
  | "artifact_publish" -> Some Artifact_publish
  | "cache_publish" -> Some Cache_publish
  | "deployment" | "deployment_change" -> Some Deployment_change
  | "credential_use" -> Some Credential_use
  | "workflow_change" -> Some Workflow_change
  | "ai_agent_execution" -> Some Ai_agent_execution
  | _ -> None

let capability = function
  | "repository_read" -> Some Ir.Repository_read
  | "repository_write" -> Some Repository_write
  | "token_read" -> Some Token_read
  | "token_write" -> Some Token_write
  | "oidc" -> Some Oidc
  | "cloud_credential" -> Some Cloud_credential
  | "secret_access" -> Some Secret_access
  | "network" -> Some Network
  | "filesystem_read" -> Some Filesystem_read
  | "filesystem_write" -> Some Filesystem_write
  | "shell" -> Some Shell
  | "artifact_read" -> Some Artifact_read
  | "artifact_write" -> Some Artifact_write
  | "cache_read" -> Some Cache_read
  | "cache_write" -> Some Cache_write
  | "deployment" -> Some Deployment
  | "self_hosted_persistence" -> Some Self_hosted_persistence
  | "ai_tool" -> Some Ai_tool
  | _ -> None

let predicate_of_assignment key value =
  let lower = String.lowercase_ascii value in
  match key with
  | "provider" -> (
      match provider lower with
      | Some value -> Ok (Provider value)
      | None -> Error "unknown provider")
  | "kind" | "node_kind" -> (
      match node_kind lower with
      | Some value -> Ok (Node_kind value)
      | None -> Error "unknown node kind")
  | "path" -> Ok (Path_prefix value)
  | "trust" -> (
      match lower with
      | "trusted" -> Ok (Trust Trusted)
      | "untrusted" -> Ok (Trust Untrusted)
      | "mixed" -> Ok (Trust Mixed)
      | "unknown" -> Ok (Trust Unknown)
      | _ -> Error "unknown trust state")
  | "effect" -> (
      match observable_effect lower with
      | Some value -> Ok (Effect value)
      | None -> Error "unknown effect")
  | "capability" -> (
      match capability lower with
      | Some value -> Ok (Capability value)
      | None -> Error "unknown capability")
  | "dependency_mutability" | "mutability" -> (
      match lower with
      | "immutable" -> Ok (Dependency_mutability Frontend_intf.Immutable)
      | "mutable" -> Ok (Dependency_mutability Mutable)
      | "local" -> Ok (Dependency_mutability Local)
      | "unknown" -> Ok (Dependency_mutability Unknown_mutability)
      | _ -> Error "unknown dependency mutability")
  | "dominance" | "dominated_by_gate" -> (
      match lower with
      | "true" -> Ok (Dominated_by_gate true)
      | "false" -> Ok (Dominated_by_gate false)
      | _ -> Error "dominance must be true or false")
  | _ -> Error ("unknown selector field: " ^ key)

let joined_value (node : Ir.node) =
  List.fold_left
    (fun accumulator (_, value) -> Abstract_value.join accumulator value)
    Abstract_value.bottom node.Ir.attributes

let has_valid_lock_digest (node : Ir.node) =
  match
    Option.bind
      (List.assoc_opt "dependency.digest" node.attributes)
      Abstract_value.constants
  with
  | Some (_ :: _ as digests) ->
      List.for_all Dependency_identity.valid_content_digest digests
  | _ -> false

let mutability (node : Ir.node) =
  if node.Ir.kind <> Ir.Call then Frontend_intf.Unknown_mutability
  else if has_valid_lock_digest node then Immutable
  else
    match Dependency_identity.classify_reference node.name with
    | Dependency_identity.Local -> Frontend_intf.Local
    | Dependency_identity.Immutable -> Immutable
    | Dependency_identity.Mutable -> Mutable
    | Dependency_identity.Unknown -> Unknown_mutability

let effects (node : Ir.node) =
  node.Ir.effects
  @
  if node.kind = Ir.Command then (Script_adapter.analyze Bash node.name).effects
  else []

let gate_dominates graph (node : Ir.node) =
  List.exists
    (fun (gate : Ir.node) ->
      gate.kind = Ir.Gate
      && Graph_algorithms.dominates graph ~dominator:gate.id ~node:node.Ir.id)
    graph.Ir.nodes

let predicate_matches graph (node : Ir.node) = function
  | Provider provider -> node.Ir.provider = provider
  | Node_kind kind -> node.kind = kind
  | Path_prefix prefix ->
      Util.starts_with ~prefix (Util.normalize_slashes node.span.file)
  | Trust expected -> (
      match ((joined_value node).trust, expected) with
      | Abstract_value.Trusted, Trusted
      | Untrusted, Untrusted
      | Mixed, Mixed
      | Unknown_trust _, Unknown -> true
      | _ -> false)
  | Effect expected -> List.mem expected (effects node)
  | Capability expected -> List.mem expected node.capabilities
  | Dependency_mutability expected -> mutability node = expected
  | Dominated_by_gate expected -> gate_dominates graph node = expected

let selector_matches graph node = function
  | All predicates -> List.for_all (predicate_matches graph node) predicates
  | Any predicates -> List.exists (predicate_matches graph node) predicates
  | None_of predicates ->
      not (List.exists (predicate_matches graph node) predicates)

let diagnostic rule (node : Ir.node) =
  Diagnostic.make ~rule_id:rule.id ~severity:rule.severity ~confidence:High
    ~message:rule.message ~span:node.Ir.span
    ~trace:
      [
        {
          node_id = node.id;
          label = "policy selector matched";
          span = node.span;
        };
      ]
    ()

let path_diagnostics graph rule sinks =
  let sources =
    List.filter
      (fun (node : Ir.node) -> Abstract_value.is_untrusted (joined_value node))
      graph.Ir.nodes
  in
  sinks
  |> List.filter_map (fun (sink : Ir.node) ->
      sources
      |> List.filter_map (fun (source : Ir.node) ->
          Graph_algorithms.shortest_path graph source.id sink.id)
      |> List.sort (fun left right ->
          Int.compare (List.length left) (List.length right))
      |> function
      | [] -> None
      | path :: _ ->
          Some
            (Diagnostic.make ~rule_id:rule.id ~severity:rule.severity
               ~confidence:High ~message:rule.message ~span:sink.span
               ~trace:
                 (List.mapi
                    (fun index (node : Ir.node) ->
                      {
                        Diagnostic.node_id = node.id;
                        label =
                          (if index = 0 then "untrusted source"
                           else if index = List.length path - 1 then
                             "policy-selected effect"
                           else "reachable semantic path");
                        span = node.span;
                      })
                    path)
               ~capabilities:(Capability_analysis.minimal_for_path path)
               ~evidence:[ "feasible source-to-effect path" ]
               ()))

let evaluate_rule graph rule =
  let matches =
    List.filter
      (fun node -> selector_matches graph node rule.selector)
      graph.Ir.nodes
  in
  match rule.kind with
  | Forbid -> List.map (diagnostic rule) matches
  | Forbid_path -> path_diagnostics graph rule matches
  | Require -> (
      match matches with
      | _ :: _ -> []
      | [] ->
          [
            Diagnostic.make ~rule_id:rule.id ~severity:rule.severity
              ~confidence:High ~message:rule.message ~span:Span.none ();
          ])
  | Limit maximum ->
      List.map (diagnostic rule)
        (Util.take (max 0 (List.length matches - maximum)) matches)

let evaluate rules graph =
  List.concat_map (evaluate_rule graph) rules |> List.sort Diagnostic.compare

let predicate_json = function
  | Provider value ->
      Json.Object [ ("provider", Json.String (Ir.provider_name value)) ]
  | Node_kind value ->
      Json.Object [ ("kind", Json.String (Ir.kind_name value)) ]
  | Path_prefix value -> Json.Object [ ("path", Json.String value) ]
  | Trust value ->
      Json.Object
        [
          ( "trust",
            Json.String
              (match value with
              | Trusted -> "trusted"
              | Untrusted -> "untrusted"
              | Mixed -> "mixed"
              | Unknown -> "unknown") );
        ]
  | Effect value ->
      Json.Object [ ("effect", Json.String (Ir.effect_name value)) ]
  | Capability value ->
      Json.Object [ ("capability", Json.String (Ir.capability_name value)) ]
  | Dependency_mutability value ->
      Json.Object
        [ ("mutability", Json.String (Frontend_intf.mutability_name value)) ]
  | Dominated_by_gate value ->
      Json.Object [ ("dominated_by_gate", Json.Bool value) ]

let rule_to_json rule =
  let selector_kind, predicates =
    match rule.selector with
    | All values -> ("all", values)
    | Any values -> ("any", values)
    | None_of values -> ("none", values)
  and kind, limit =
    match rule.kind with
    | Forbid -> ("forbid", Json.Null)
    | Require -> ("require", Json.Null)
    | Limit value -> ("limit", Json.Int value)
    | Forbid_path -> ("forbid_path", Json.Null)
  in
  Json.Object
    [
      ("id", Json.String rule.id);
      ("kind", Json.String kind);
      ("limit", limit);
      ("message", Json.String rule.message);
      ("severity", Json.String (Diagnostic.severity_name rule.severity));
      ( "selector",
        Json.Object
          [ (selector_kind, Json.Array (List.map predicate_json predicates)) ]
      );
    ]
