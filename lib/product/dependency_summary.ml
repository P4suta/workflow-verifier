type t = {
  complete : bool;
  reasons : string list;
  capabilities : Ir.capability list;
  effects : Ir.observable_effect list;
}

let normalized_strings values =
  values
  |> List.filter (fun value -> String.trim value <> "")
  |> Util.deduplicate_strings |> List.sort String.compare

let make ~complete ~reasons ~capabilities ~effects =
  let reasons = normalized_strings reasons in
  {
    complete;
    reasons =
      (if complete then []
       else if reasons = [] then [ "semantic evidence is incomplete" ]
       else reasons);
    capabilities = Util.deduplicate_compare Stdlib.compare capabilities;
    effects = Util.deduplicate_compare Stdlib.compare effects;
  }

let unknown reason =
  make ~complete:false ~reasons:[ reason ] ~capabilities:[] ~effects:[]

let capability_of_name = function
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

let effect_of_name = function
  | "repository_change" -> Some Ir.Repository_change
  | "network_request" -> Some Network_request
  | "file_read" -> Some File_read
  | "file_write" -> Some File_write
  | "command_execution" -> Some Command_execution
  | "artifact_publish" -> Some Artifact_publish
  | "cache_publish" -> Some Cache_publish
  | "deployment_change" -> Some Deployment_change
  | "credential_use" -> Some Credential_use
  | "workflow_change" -> Some Workflow_change
  | "ai_agent_execution" -> Some Ai_agent_execution
  | _ -> None

let names_to_json name values =
  Json.Array (List.map (fun value -> Json.String (name value)) values)

let to_json summary =
  Json.Object
    [
      ("capabilities", names_to_json Ir.capability_name summary.capabilities);
      ("complete", Json.Bool summary.complete);
      ("effects", names_to_json Ir.effect_name summary.effects);
      ( "reasons",
        Json.Array (List.map (fun value -> Json.String value) summary.reasons)
      );
    ]

let required name convert json =
  match Option.bind (Json.member name json) convert with
  | Some value -> Ok value
  | None -> Error ("dependency summary needs field " ^ name)

let string_list name json =
  let open Util in
  let* values = required name Json.as_array json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | Json.String value :: rest -> loop (value :: accumulator) rest
    | _ -> Error ("dependency summary " ^ name ^ " must contain strings")
  in
  loop [] values

let mapped_list name convert json =
  let open Util in
  let* names = string_list name json in
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | value :: rest -> (
        match convert value with
        | Some mapped -> loop (mapped :: accumulator) rest
        | None ->
            Error ("unknown dependency summary " ^ name ^ " value " ^ value))
  in
  loop [] names

let of_json json =
  let open Util in
  let* () =
    match Json.as_object json with
    | None -> Error "dependency summary must be an object"
    | Some fields -> (
        let names = List.map fst fields in
        if List.length (Util.deduplicate_strings names) <> List.length names
        then Error "dependency summary contains a duplicate field"
        else
          match
            List.find_opt
              (fun name ->
                not
                  (List.mem name
                     [ "complete"; "reasons"; "capabilities"; "effects" ]))
              names
          with
          | Some name ->
              Error ("dependency summary contains unknown field " ^ name)
          | None -> Ok ())
  in
  let* complete = required "complete" Json.as_bool json in
  let* reasons = string_list "reasons" json in
  let* capabilities = mapped_list "capabilities" capability_of_name json in
  let* effects = mapped_list "effects" effect_of_name json in
  let normalized = make ~complete ~reasons ~capabilities ~effects in
  if complete && reasons <> [] then
    Error "complete dependency summaries cannot contain incomplete reasons"
  else if (not complete) && normalized_strings reasons = [] then
    Error "incomplete dependency summaries need a reason"
  else Ok normalized

let action_runtime_reason compilation =
  match Yaml_cst.root compilation.Frontend_intf.cst with
  | None -> []
  | Some root -> (
      match
        Option.bind
          (Frontend_common.field "runs" root)
          (Frontend_common.field_scalar "using")
      with
      | None | Some "composite" -> []
      | Some "docker" ->
          [
            "Docker action implementation is unavailable beyond locked metadata";
          ]
      | Some runtime ->
          [
            Printf.sprintf
              "%s action implementation is unavailable beyond locked metadata"
              runtime;
          ])

let compilation_reasons (compilation : Frontend_intf.compilation) =
  let problems =
    List.map
      (fun problem -> problem.Frontend_intf.code ^ ": " ^ problem.message)
      compilation.problems
  and node_unknowns =
    compilation.graph.nodes
    |> List.filter_map (fun node ->
        Option.map Unknown.to_string node.Ir.unknown)
  and dependency_unknowns =
    compilation.dependencies
    |> List.filter_map (fun dependency ->
        match dependency.Frontend_intf.status with
        | Locked _ -> None
        | Unresolved reason -> Some (Unknown.to_string reason))
  in
  problems @ node_unknowns @ dependency_unknowns

let infer_graph (dependency : Frontend_intf.dependency) ~path ~source =
  match
    Frontend.compile_string ~provider:dependency.Frontend_intf.provider ~path
      ~source ()
  with
  | Error problems ->
      unknown
        (String.concat "; "
           (List.map
              (fun problem ->
                problem.Frontend_intf.code ^ ": " ^ problem.message)
              problems))
  | Ok compilation ->
      let nodes = compilation.graph.nodes in
      let effects = nodes |> List.concat_map Capability_analysis.effects_of_node
      and capabilities =
        (nodes |> List.concat_map (fun node -> node.Ir.capabilities))
        @ Capability_analysis.minimal_for_path nodes
      and reasons =
        compilation_reasons compilation
        @
        if dependency.provider = Ir.Github && dependency.kind = Action then
          action_runtime_reason compilation
        else []
      in
      make ~complete:(reasons = []) ~reasons ~capabilities ~effects

let infer_task_metadata source =
  match Json.parse source with
  | Error error ->
      unknown
        (Printf.sprintf "Azure task metadata JSON byte %d: %s" error.offset
           error.message)
  | Ok json -> (
      match Option.bind (Json.member "execution" json) Json.as_object with
      | Some (_ :: _) ->
          make ~complete:false
            ~reasons:
              [
                "Azure task implementation is unavailable beyond locked \
                 task.json";
              ]
            ~capabilities:[ Ir.Shell; Ir.Filesystem_read ]
            ~effects:[ Ir.Command_execution ]
      | _ -> unknown "Azure task metadata has no declared execution handler")

let infer (dependency : Frontend_intf.dependency) ~path ~source =
  if dependency.Frontend_intf.provider = Ir.Azure && dependency.kind = Task then
    infer_task_metadata source
  else infer_graph dependency ~path ~source
