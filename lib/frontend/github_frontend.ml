let provider = Ir.Github

let has_top_level key source =
  Util.starts_with ~prefix:(key ^ ":") source
  || Util.contains ~needle:("\n" ^ key ^ ":") source

let detect ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  Util.contains ~needle:"/.github/workflows/" path
  || Util.starts_with ~prefix:".github/workflows/" path
  || List.exists
       (fun suffix -> Util.ends_with ~suffix path)
       [ "/action.yml"; "/action.yaml" ]
     && Util.contains ~needle:"runs:" source
  || (has_top_level "on" source && has_top_level "jobs" source)

let entrypoint ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  let prefix = ".github/workflows/" in
  if not (Util.starts_with ~prefix path) then false
  else
    let name =
      String.sub path (String.length prefix)
        (String.length path - String.length prefix)
    in
    detect ~path ~source
    && not (String.contains name '/')
    && List.exists (fun suffix -> Util.ends_with ~suffix name) [ ".yml"; ".yaml" ]

let parse = Frontend_common.parse
let expand = Frontend_common.expand

let rec dependencies_of_node accumulator node =
  match node with
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          let accumulator =
            if entry.key.value = "uses" then
              match Yaml_cst.scalar_value entry.value with
              | Some reference ->
                  let kind =
                    if Util.starts_with ~prefix:"docker://" reference then
                      Frontend_intf.Container_image
                    else Frontend_intf.Action
                  in
                  Frontend_common.dependency ~kind provider reference
                    (Yaml_cst.node_span entry.value)
                  :: accumulator
              | None -> accumulator
            else accumulator
          in
          dependencies_of_node accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          dependencies_of_node accumulator item.value)
        accumulator items
  | Flow_sequence (nodes, _) ->
      List.fold_left dependencies_of_node accumulator nodes
  | Decorated decorated -> dependencies_of_node accumulator decorated.value
  | Scalar _ | Alias _ | Invalid _ -> accumulator

let resolve expanded =
  let dependencies =
    match Yaml_cst.root expanded.Frontend_intf.parsed.cst with
    | None -> []
    | Some root -> dependencies_of_node [] root
  in
  {
    Frontend_intf.expanded;
    dependencies =
      List.sort_uniq
        (fun left right ->
          String.compare left.Frontend_intf.reference right.reference)
        dependencies;
  }

let dependency_unknown (resolved : Frontend_intf.resolved) reference =
  Option.bind
    (List.find_opt
       (fun dependency -> dependency.Frontend_intf.reference = reference)
       resolved.Frontend_intf.dependencies)
    (fun dependency ->
      match dependency.status with
      | Frontend_intf.Unresolved reason -> Some reason
      | Locked _ -> None)

let union left right = Util.deduplicate_compare Stdlib.compare (left @ right)

let access_capabilities name access =
  let name = String.lowercase_ascii name
  and access = String.lowercase_ascii access in
  if access = "none" then []
  else if name = "id-token" && access = "write" then [ Ir.Oidc ]
  else if name = "models" then [ Ir.Ai_tool; Ir.Network ]
  else if name = "attestations" then
    [ Ir.Artifact_read; Ir.Artifact_write; Ir.Token_write ]
  else if name = "deployments" || name = "pages" then
    if access = "write" then [ Ir.Deployment; Ir.Token_write ]
    else [ Ir.Repository_read; Ir.Token_read ]
  else if access = "write" then [ Ir.Repository_write; Ir.Token_write ]
  else [ Ir.Repository_read; Ir.Token_read ]

let permissions node =
  match Frontend_common.field "permissions" node with
  | None -> []
  | Some value -> (
      match Frontend_common.scalar value with
      | Some "write-all" -> [ Ir.Repository_write; Ir.Token_write ]
      | Some "read-all" -> [ Ir.Repository_read; Ir.Token_read ]
      | Some "{}" | Some "none" -> []
      | Some _ -> []
      | None ->
          Frontend_common.mapping value
          |> List.fold_left
               (fun capabilities (entry : Yaml_cst.mapping_entry) ->
                 match Frontend_common.scalar entry.value with
                 | Some access ->
                     union capabilities
                       (access_capabilities entry.key.value access)
                 | None -> capabilities)
               [])

let runner_capabilities body =
  Frontend_support.field_strings "runs-on" body
  |> List.fold_left
       (fun capabilities runner ->
         if Util.contains ~needle:"self-hosted" (String.lowercase_ascii runner)
         then Ir.Self_hosted_persistence :: capabilities
         else capabilities)
       []
  |> Util.deduplicate_compare Stdlib.compare

let call_profile reference =
  let lower = String.lowercase_ascii reference in
  if
    Util.starts_with ~prefix:"./" reference
    || Util.starts_with ~prefix:"../" reference
  then ([], [])
  else if Util.contains ~needle:"actions/checkout" lower then
    ([ Ir.Repository_read; Ir.Filesystem_write ], [ Ir.File_write ])
  else if Util.contains ~needle:"upload-artifact" lower then
    ( [ Ir.Artifact_write; Ir.Filesystem_read; Ir.Network ],
      [ Ir.Artifact_publish; Ir.Network_request ] )
  else if Util.contains ~needle:"download-artifact" lower then
    ( [ Ir.Artifact_read; Ir.Filesystem_write; Ir.Network ],
      [ Ir.File_write; Ir.Network_request ] )
  else if Util.contains ~needle:"cache" lower then
    ( [ Ir.Cache_read; Ir.Cache_write; Ir.Filesystem_read; Ir.Filesystem_write ],
      [ Ir.Cache_publish ] )
  else if
    List.exists
      (fun name -> Util.contains ~needle:name lower)
      [ "openai"; "anthropic"; "copilot"; "ai-agent"; "ai_agent" ]
  then
    ( [ Ir.Ai_tool; Ir.Network; Ir.Secret_access; Ir.Repository_write ],
      [ Ir.Ai_agent_execution; Ir.Network_request; Ir.Workflow_change ] )
  else ([ Ir.Network ], [])

let trigger_entries root =
  match Frontend_common.field "on" root with
  | None -> []
  | Some on_node -> (
      match Frontend_common.scalar on_node with
      | Some name -> [ (name, Yaml_cst.node_span on_node) ]
      | None ->
          let entries = Frontend_common.mapping on_node in
          if entries <> [] then
            List.map
              (fun (entry : Yaml_cst.mapping_entry) ->
                (entry.key.value, entry.span))
              entries
          else
            Frontend_common.sequence_nodes on_node
            |> List.filter_map (fun node ->
                Option.map
                  (fun name -> (name, Yaml_cst.node_span node))
                  (Frontend_common.scalar node)))

let add_matrix_parameters graph (job : Ir.node) matrix =
  Frontend_common.mapping matrix
  |> List.fold_left
       (fun graph (entry : Yaml_cst.mapping_entry) ->
         let values =
           Frontend_common.sequence_nodes entry.value
           |> List.filter_map Frontend_common.scalar
         in
         let value =
           match values with
           | [] ->
               Abstract_value.unknown (Unknown.Dynamic_string entry.key.value)
           | first :: rest ->
               let constant value =
                 Abstract_value.string_constant value
                   ~trust:Abstract_value.Trusted ~secrecy:Abstract_value.Public
                   ~provenance:[]
               in
               List.fold_left
                 (fun accumulator value ->
                   Abstract_value.join accumulator (constant value))
                 (constant first) rest
         in
         let parameter =
           Ir.make_node ~provider ~kind:Ir.Parameter
             ~name:("matrix." ^ entry.key.value)
             ~phase:Ir.Plan ~span:entry.span
             ~attributes:[ ("value", value) ]
             ()
         in
         graph |> Ir.add_node parameter
         |> Ir.add_edge
              (Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:job.Ir.id
                 ~label:entry.key.value ()))
       graph

let rec scalar_nodes accumulator = function
  | Yaml_cst.Scalar _ as node -> node :: accumulator
  | Alias _ | Invalid _ -> accumulator
  | Decorated decorated -> scalar_nodes accumulator decorated.value
  | Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          scalar_nodes accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          scalar_nodes accumulator item.value)
        accumulator items
  | Flow_sequence (nodes, _) -> List.fold_left scalar_nodes accumulator nodes

let add_embedded_references target container graph =
  scalar_nodes [] container
  |> List.fold_left
       (fun graph node ->
         match Frontend_common.scalar node with
         | None -> graph
         | Some source ->
             let references =
               Expression.scan provider ~default_phase:target.Ir.phase
                 ~span:(Yaml_cst.node_span node) source
             in
             Frontend_common.add_references provider target references graph)
       graph

let environment_name body =
  match Frontend_common.field "environment" body with
  | None -> None
  | Some node -> (
      match Frontend_common.scalar node with
      | Some name -> Some (name, Yaml_cst.node_span node)
      | None ->
          Option.map
            (fun name -> (name, Yaml_cst.node_span node))
            (Frontend_common.field_scalar "name" node))

let add_job_resources graph (job : Ir.node) body =
  let graph =
    match environment_name body with
    | None -> graph
    | Some (name, span) ->
        Frontend_support.add_resource ~provider ~owner:job
          ~name:("environment:" ^ name) ~phase:Ir.Run ~span
          ~capabilities:[ Ir.Deployment ] ~effects:[ Ir.Deployment_change ]
          ~edge_kind:Ir.Grant ~resource_to_owner:true graph
        |> fst
  in
  match Frontend_common.field "outputs" body with
  | None -> graph
  | Some outputs ->
      Frontend_common.mapping outputs
      |> List.fold_left
           (fun graph (entry : Yaml_cst.mapping_entry) ->
             let graph, resource =
               Frontend_support.add_resource ~provider ~owner:job
                 ~name:("output:" ^ job.name ^ "." ^ entry.key.value)
                 ~phase:Ir.Post ~span:entry.span ~edge_kind:Ir.Write graph
             in
             add_embedded_references resource entry.value graph)
           graph

type step_record = { body : Yaml_cst.node; node : Ir.node }

let add_steps resolved graph (job : Ir.node) body =
  match Frontend_common.field "steps" body with
  | None -> graph
  | Some steps ->
      let records =
        Frontend_common.sequence_nodes steps
        |> List.mapi (fun index step_body ->
            let name =
              Option.value
                ~default:
                  (Option.value
                     ~default:("step " ^ string_of_int (index + 1))
                     (Frontend_common.field_scalar "id" step_body))
                (Frontend_common.field_scalar "name" step_body)
            in
            {
              body = step_body;
              node =
                Ir.make_node ~provider ~kind:Ir.Step ~name ~phase:Ir.Run
                  ~span:(Yaml_cst.node_span step_body)
                  ();
            })
      in
      let graph =
        List.fold_left
          (fun graph record ->
            graph |> Ir.add_node record.node
            |> Frontend_common.add_control job record.node)
          graph records
      in
      let graph =
        Frontend_support.link_sequence
          (List.map (fun record -> record.node) records)
          graph
      in
      List.fold_left
        (fun graph record ->
          let graph =
            match Frontend_common.field "if" record.body with
            | None -> graph
            | Some expression_node ->
                Frontend_support.add_gate ~provider ~owner:record.node
                  ~name:("if:" ^ job.name ^ ":" ^ record.node.name)
                  ~phase:Ir.Run ~expression_node graph
                |> fst
          in
          let graph =
            match Frontend_common.field "uses" record.body with
            | None -> graph
            | Some uses_node -> (
                match Frontend_common.scalar uses_node with
                | None -> graph
                | Some reference ->
                    let capabilities, effects = call_profile reference in
                    let call =
                      Ir.make_node ~provider ~kind:Ir.Call ~name:reference
                        ~phase:Ir.Run
                        ~span:(Yaml_cst.node_span uses_node)
                        ~capabilities ~effects
                        ?unknown:(dependency_unknown resolved reference)
                        ()
                    in
                    let graph =
                      graph |> Ir.add_node call
                      |> Frontend_common.add_call record.node call
                    in
                    [ "with"; "env" ]
                    |> List.fold_left
                         (fun graph field ->
                           match Frontend_common.field field record.body with
                           | None -> graph
                           | Some values ->
                               add_embedded_references call values graph)
                         graph)
          in
          match Frontend_common.field "run" record.body with
          | None -> graph
          | Some run_node -> (
              match Frontend_common.scalar run_node with
              | None -> graph
              | Some source -> (
                  let value, references =
                    Frontend_common.command_value provider run_node source
                  in
                  let shell =
                    Option.value ~default:"default"
                      (Frontend_common.field_scalar "shell" record.body)
                  in
                  let command =
                    Ir.make_node ~provider ~kind:Ir.Command ~name:source
                      ~phase:Ir.Run
                      ~span:(Yaml_cst.node_span run_node)
                      ~attributes:
                        [
                          ("command", value);
                          ( "shell",
                            Abstract_value.string_constant shell
                              ~trust:Abstract_value.Trusted
                              ~secrecy:Abstract_value.Public ~provenance:[] );
                        ]
                      ~capabilities:
                        [ Ir.Shell; Ir.Filesystem_read; Ir.Filesystem_write ]
                      ~effects:[ Ir.Command_execution ] ()
                  in
                  let graph =
                    graph |> Ir.add_node command
                    |> Frontend_common.add_control record.node command
                    |> Frontend_common.add_references provider command
                         references
                  in
                  match Frontend_common.field "env" record.body with
                  | None -> graph
                  | Some env -> add_embedded_references command env graph)))
        graph records

let lower_action resolved root (workflow : Ir.node) =
  let graph =
    ref
      (Ir.empty provider resolved.Frontend_intf.expanded.parsed.unit_.path
      |> Ir.add_node workflow
      |> Ir.add_entrypoint workflow.id)
  in
  (match Frontend_common.field "inputs" root with
  | None -> ()
  | Some inputs ->
      Frontend_common.mapping inputs
      |> List.iter (fun (entry : Yaml_cst.mapping_entry) ->
          let parameter =
            Ir.make_node ~provider ~kind:Ir.Parameter
              ~name:("input:" ^ entry.key.value)
              ~phase:Ir.Compile ~span:entry.span ()
          in
          let edge =
            Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:workflow.id ()
          in
          graph := Ir.add_edge edge (Ir.add_node parameter !graph)));
  (match Frontend_common.field "outputs" root with
  | None -> ()
  | Some outputs ->
      Frontend_common.mapping outputs
      |> List.iter (fun (entry : Yaml_cst.mapping_entry) ->
          graph :=
            Frontend_support.add_resource ~provider ~owner:workflow
              ~name:("output:action." ^ entry.key.value)
              ~phase:Ir.Post ~span:entry.span ~edge_kind:Ir.Write !graph
            |> fst));
  (match Frontend_common.field "runs" root with
  | None -> ()
  | Some runs -> (
      match Frontend_common.field_scalar "using" runs with
      | Some "composite" ->
          let action_job =
            Ir.make_node ~provider ~kind:Ir.Job ~name:"composite action"
              ~phase:Ir.Plan ~span:(Yaml_cst.node_span runs) ()
          in
          graph :=
            !graph |> Ir.add_node action_job
            |> Frontend_common.add_control workflow action_job;
          graph := add_steps resolved !graph action_job runs
      | Some "docker" ->
          let image =
            Option.value ~default:"Dockerfile"
              (Frontend_common.field_scalar "image" runs)
          in
          let call =
            Ir.make_node ~provider ~kind:Ir.Call ~name:("docker:" ^ image)
              ~phase:Ir.Run ~span:(Yaml_cst.node_span runs)
              ~capabilities:[ Ir.Shell; Ir.Filesystem_read; Ir.Network ]
              ~effects:[ Ir.Command_execution ] ()
          in
          graph :=
            !graph |> Ir.add_node call |> Frontend_common.add_call workflow call
      | Some runtime ->
          [ "main"; "pre"; "post" ]
          |> List.iter (fun key ->
              match Frontend_common.field_scalar key runs with
              | None -> ()
              | Some path ->
                  let call =
                    Ir.make_node ~provider ~kind:Ir.Call
                      ~name:(runtime ^ ":" ^ path)
                      ~phase:Ir.Run ~span:(Yaml_cst.node_span runs)
                      ~capabilities:[ Ir.Shell; Ir.Filesystem_read ]
                      ~effects:[ Ir.Command_execution ] ()
                  in
                  graph :=
                    !graph |> Ir.add_node call
                    |> Frontend_common.add_call workflow call)
      | None -> ()));
  Ir.finalize !graph

let lower resolved =
  match Frontend_common.root resolved with
  | None -> (Ir.empty provider resolved.expanded.parsed.unit_.path, [])
  | Some root ->
      let workflow =
        Frontend_common.workflow_node provider
          resolved.expanded.parsed.unit_.path root
      in
      let root_permissions = permissions root in
      let workflow = { workflow with Ir.capabilities = root_permissions } in
      let yaml_problems =
        Frontend_common.yaml_problems resolved.expanded.parsed.cst
      in
      if Option.is_some (Frontend_common.field "runs" root) then
        (lower_action resolved root workflow, yaml_problems)
      else
        let problems = ref yaml_problems in
        let graph =
          ref
            (Ir.empty provider resolved.expanded.parsed.unit_.path
            |> Ir.add_node workflow
            |> Ir.add_entrypoint workflow.id)
        in
        trigger_entries root
        |> List.iter (fun (name, span) ->
            let trigger =
              Ir.make_node ~provider ~kind:Ir.Trigger ~name ~phase:Ir.Source
                ~span ()
            in
            graph :=
              !graph |> Ir.add_node trigger
              |> Frontend_common.add_control trigger workflow);
        let job_entries =
          match Frontend_common.field "jobs" root with
          | None ->
              problems :=
                {
                  Frontend_intf.code = "GH-SCHEMA-JOBS";
                  message = "a GitHub workflow requires a jobs mapping";
                  span = Yaml_cst.node_span root;
                }
                :: !problems;
              []
          | Some jobs -> Frontend_common.mapping jobs
        in
        let jobs =
          List.map
            (fun (entry : Yaml_cst.mapping_entry) ->
              let body = entry.value in
              let job_permissions =
                if Option.is_some (Frontend_common.field "permissions" body)
                then permissions body
                else root_permissions
              in
              let environment_caps, environment_effects =
                match environment_name body with
                | None -> ([], [])
                | Some _ -> ([ Ir.Deployment ], [ Ir.Deployment_change ])
              in
              let job =
                Ir.make_node ~provider ~kind:Ir.Job ~name:entry.key.value
                  ~phase:Ir.Plan ~span:entry.span
                  ~capabilities:
                    (union job_permissions
                       (union (runner_capabilities body) environment_caps))
                  ~effects:environment_effects ()
              in
              graph :=
                !graph |> Ir.add_node job
                |> Frontend_common.add_control workflow job;
              (entry, job))
            job_entries
        in
        let dependency_specs =
          List.map
            (fun ((entry : Yaml_cst.mapping_entry), job) ->
              ( job.Ir.name,
                Frontend_support.field_strings "needs" entry.value,
                entry.span ))
            jobs
        in
        let linked, dependency_problems =
          Frontend_support.link_dependencies ~unknown_code:"GH-UNKNOWN-NEEDS"
            ~cycle_code:"GH-NEEDS-CYCLE" ~label:"needs"
            ~nodes:(List.map snd jobs) ~dependencies:dependency_specs !graph
        in
        graph := linked;
        problems := dependency_problems @ !problems;
        List.iter
          (fun ((entry : Yaml_cst.mapping_entry), job) ->
            let body = entry.value in
            (match Frontend_common.field "if" body with
            | None -> ()
            | Some expression_node ->
                graph :=
                  Frontend_support.add_gate ~provider ~owner:job
                    ~name:("if:job:" ^ job.name) ~phase:Ir.Plan ~expression_node
                    !graph
                  |> fst);
            (match Frontend_common.field "strategy" body with
            | None -> ()
            | Some strategy -> (
                match Frontend_common.field "matrix" strategy with
                | Some matrix ->
                    graph := add_matrix_parameters !graph job matrix
                | None -> ()));
            graph := add_job_resources !graph job body;
            (match Frontend_common.field "uses" body with
            | None -> ()
            | Some uses_node -> (
                match Frontend_common.scalar uses_node with
                | None -> ()
                | Some reference ->
                    let capabilities, effects = call_profile reference in
                    let call =
                      Ir.make_node ~provider ~kind:Ir.Call ~name:reference
                        ~phase:Ir.Plan
                        ~span:(Yaml_cst.node_span uses_node)
                        ~capabilities ~effects
                        ?unknown:(dependency_unknown resolved reference)
                        ()
                    in
                    graph :=
                      !graph |> Ir.add_node call
                      |> Frontend_common.add_call job call));
            graph := add_steps resolved !graph job body)
          jobs;
        (Ir.finalize !graph, List.rev !problems)
