let provider = Ir.Azure

let path_identity ~path =
  let name = Filename.basename path |> String.lowercase_ascii in
  List.mem name [ "azure-pipelines.yml"; "azure-pipelines.yaml" ]

let detect ~path ~source =
  path_identity ~path
  || Util.contains ~needle:"trigger:" source
     && (Util.contains ~needle:"pool:" source
        || Util.contains ~needle:"stages:" source)

let entrypoint ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  detect ~path ~source
  && List.mem path [ "azure-pipelines.yml"; "azure-pipelines.yaml" ]

let parse = Frontend_common.parse
let expand = Frontend_common.expand

let dependency ?(locator = Frontend_intf.Direct_reference) kind reference node =
  Frontend_common.dependency ~kind ~locator provider reference
    (Yaml_cst.node_span node)

type repository_spec = {
  alias : string;
  repository : string;
  revision : string option;
  repository_type : string option;
  node : Yaml_cst.node;
}

let repository_specs root =
  match
    Option.bind
      (Frontend_common.field "resources" root)
      (Frontend_common.field "repositories")
  with
  | None -> []
  | Some repositories ->
      Frontend_common.sequence_nodes repositories
      |> List.filter_map (fun node ->
          Option.map
            (fun repository ->
              {
                alias =
                  Option.value ~default:repository
                    (Frontend_common.field_scalar "repository" node);
                repository;
                revision = Frontend_common.field_scalar "ref" node;
                repository_type = Frontend_common.field_scalar "type" node;
                node;
              })
            (Frontend_common.field_scalar "name" node))

let template_locator repositories reference =
  match String.rindex_opt reference '@' with
  | None -> Frontend_intf.Direct_reference
  | Some index -> (
      let path = String.sub reference 0 index
      and alias =
        String.sub reference (index + 1) (String.length reference - index - 1)
      in
      if String.lowercase_ascii alias = "self" then Direct_reference
      else
        match
          List.find_opt
            (fun repository -> repository.alias = alias)
            repositories
        with
        | None -> Direct_reference
        | Some repository ->
            Repository_file
              {
                repository = repository.repository;
                revision = repository.revision;
                path;
                repository_type = repository.repository_type;
              })

let rec dependencies repositories accumulator node =
  match node with
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          let accumulator =
            if List.mem entry.key.value [ "template"; "task" ] then
              match Frontend_common.scalar entry.value with
              | Some reference ->
                  let kind =
                    if entry.key.value = "task" then Frontend_intf.Task
                    else Template
                  in
                  let locator =
                    if kind = Frontend_intf.Template then
                      template_locator repositories reference
                    else Frontend_intf.Direct_reference
                  in
                  dependency ~locator kind reference entry.value :: accumulator
              | None -> accumulator
            else accumulator
          in
          dependencies repositories accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          dependencies repositories accumulator item.value)
        accumulator items
  | Flow_sequence (nodes, _) ->
      List.fold_left (dependencies repositories) accumulator nodes
  | Decorated decorated -> dependencies repositories accumulator decorated.value
  | Scalar _ | Alias _ | Invalid _ -> accumulator

let repository_dependencies repositories =
  repositories
  |> List.map (fun repository ->
      let reference =
        repository.repository
        ^ Option.fold ~none:""
            ~some:(fun revision -> "@" ^ revision)
            repository.revision
      in
      dependency
        ~locator:
          (Frontend_intf.Repository_source
             {
               repository = repository.repository;
               revision = repository.revision;
               repository_type = repository.repository_type;
             })
        Frontend_intf.Repository reference repository.node)

let resolve expanded =
  let dependencies =
    match Yaml_cst.root expanded.Frontend_intf.parsed.cst with
    | None -> []
    | Some root ->
        let repositories = repository_specs root in
        dependencies repositories [] root @ repository_dependencies repositories
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

let abstract_scalar phase node =
  match Frontend_common.scalar node with
  | None ->
      Abstract_value.unknown (Unknown.Dynamic_string "non-scalar Azure value")
  | Some source ->
      let span = Yaml_cst.node_span node in
      let value =
        Abstract_value.string_constant source ~trust:Abstract_value.Trusted
          ~secrecy:Abstract_value.Public
          ~provenance:[ { origin = "Azure YAML"; span; operation = "value" } ]
      in
      Expression.scan provider ~default_phase:phase ~span source
      |> List.fold_left
           (fun value reference ->
             Abstract_value.join value reference.Expression.value)
           value

let add_parameter graph (parent : Ir.node) item =
  let name =
    Option.value ~default:"parameter" (Frontend_common.field_scalar "name" item)
  in
  let value =
    match Frontend_common.field "default" item with
    | Some node -> abstract_scalar Ir.Compile node
    | None ->
        Abstract_value.unknown (Unknown.External_state ("parameter " ^ name))
  in
  let parameter =
    Ir.make_node ~provider ~kind:Ir.Parameter ~name ~phase:Ir.Compile
      ~span:(Yaml_cst.node_span item)
      ~attributes:[ ("value", value) ]
      ()
  in
  graph |> Ir.add_node parameter
  |> Ir.add_edge
       (Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:parent.Ir.id ())

let add_variables graph (owner : Ir.node) variables =
  let entries =
    let mapping = Frontend_common.mapping variables in
    if mapping <> [] then
      List.map
        (fun (entry : Yaml_cst.mapping_entry) ->
          (entry.key.value, entry.value, entry.span))
        mapping
    else
      Frontend_common.sequence_nodes variables
      |> List.filter_map (fun node ->
          Option.map
            (fun name ->
              ( name,
                Option.value ~default:node (Frontend_common.field "value" node),
                Yaml_cst.node_span node ))
            (Frontend_common.field_scalar "name" node))
  in
  List.fold_left
    (fun graph (name, value_node, span) ->
      let resource =
        Ir.make_node ~provider ~kind:Ir.Resource ~name:("variable:" ^ name)
          ~phase:owner.phase ~span
          ~attributes:[ ("value", abstract_scalar Ir.Run value_node) ]
          ()
      in
      graph |> Ir.add_node resource
      |> Ir.add_edge
           (Ir.make_edge ~kind:Ir.Data ~from_:resource.id ~to_:owner.id
              ~label:name ()))
    graph entries

let add_repository_resources resolved graph (workflow : Ir.node) root =
  match
    Option.bind
      (Frontend_common.field "resources" root)
      (Frontend_common.field "repositories")
  with
  | None -> graph
  | Some repositories ->
      Frontend_common.sequence_nodes repositories
      |> List.fold_left
           (fun graph repository ->
             let alias =
               Option.value ~default:"repository"
                 (Frontend_common.field_scalar "repository" repository)
             in
             let name =
               Option.value ~default:alias
                 (Frontend_common.field_scalar "name" repository)
             in
             let revision = Frontend_common.field_scalar "ref" repository in
             let reference =
               Option.fold ~none:name
                 ~some:(fun value -> name ^ "@" ^ value)
                 revision
             in
             let resource =
               Ir.make_node ~provider ~kind:Ir.Resource
                 ~name:("repository:" ^ alias) ~phase:Ir.Compile
                 ~span:(Yaml_cst.node_span repository)
                 ~capabilities:[ Ir.Repository_read ] ()
             in
             let call =
               Ir.make_node ~provider ~kind:Ir.Call ~name:reference
                 ~phase:Ir.Compile
                 ~span:(Yaml_cst.node_span repository)
                 ~capabilities:[ Ir.Repository_read; Ir.Network ]
                 ?unknown:(dependency_unknown resolved reference)
                 ()
             in
             graph |> Ir.add_node resource
             |> Ir.add_edge
                  (Ir.make_edge ~kind:Ir.Read ~from_:resource.id
                     ~to_:workflow.id ())
             |> Ir.add_node call
             |> Frontend_common.add_call resource call)
           graph

let dependency_names key body = Frontend_support.field_strings key body

let add_matrix graph (job : Ir.node) body =
  match
    Option.bind
      (Frontend_common.field "strategy" body)
      (Frontend_common.field "matrix")
  with
  | None -> graph
  | Some matrix ->
      Frontend_common.mapping matrix
      |> List.fold_left
           (fun graph (entry : Yaml_cst.mapping_entry) ->
             let parameter =
               Ir.make_node ~provider ~kind:Ir.Parameter
                 ~name:("matrix." ^ entry.key.value)
                 ~phase:Ir.Plan ~span:entry.span ()
             in
             graph |> Ir.add_node parameter
             |> Ir.add_edge
                  (Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:job.id
                     ~label:entry.key.value ()))
           graph

let task_profile reference =
  let lower = String.lowercase_ascii reference in
  if Util.contains ~needle:"publish" lower then
    ([ Ir.Artifact_write; Ir.Network ], [ Ir.Artifact_publish ])
  else if Util.contains ~needle:"download" lower then
    ([ Ir.Artifact_read; Ir.Network ], [ Ir.File_write ])
  else if Util.contains ~needle:"cache" lower then
    ([ Ir.Cache_read; Ir.Cache_write ], [ Ir.Cache_publish ])
  else if
    List.exists
      (fun value -> Util.contains ~needle:value lower)
      [ "azurecli"; "aws"; "gcloud" ]
  then
    ( [ Ir.Cloud_credential; Ir.Network; Ir.Shell ],
      [ Ir.Credential_use; Ir.Network_request; Ir.Command_execution ] )
  else ([ Ir.Shell ], [ Ir.Command_execution ])

let command_keys = [ "script"; "bash"; "pwsh"; "powershell" ]

type step_record = { body : Yaml_cst.node; node : Ir.node }

let add_steps (resolved : Frontend_intf.resolved) graph (job : Ir.node) body =
  match Frontend_common.field "steps" body with
  | None -> graph
  | Some steps ->
      let records =
        Frontend_common.sequence_nodes steps
        |> List.mapi (fun index step_body ->
            let name =
              Option.value
                ~default:("step " ^ string_of_int (index + 1))
                (Frontend_common.field_scalar "displayName" step_body)
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
        |> Frontend_support.link_sequence
             (List.map (fun record -> record.node) records)
      in
      List.fold_left
        (fun graph record ->
          let graph =
            match Frontend_common.field "condition" record.body with
            | None -> graph
            | Some expression_node ->
                Frontend_support.add_gate ~provider ~owner:record.node
                  ~name:("condition:" ^ job.name ^ ":" ^ record.node.name)
                  ~phase:Ir.Run ~expression_node graph
                |> fst
          in
          match Frontend_common.field "checkout" record.body with
          | Some checkout -> (
              match Frontend_common.scalar checkout with
              | None -> graph
              | Some reference ->
                  let call =
                    Ir.make_node ~provider ~kind:Ir.Call
                      ~name:("checkout:" ^ reference) ~phase:Ir.Run
                      ~span:(Yaml_cst.node_span checkout)
                      ~capabilities:[ Ir.Repository_read; Ir.Filesystem_write ]
                      ~effects:[ Ir.File_write ] ()
                  in
                  graph |> Ir.add_node call
                  |> Frontend_common.add_call record.node call)
          | None -> (
              match Frontend_common.field "template" record.body with
              | Some template_node -> (
                  match Frontend_common.scalar template_node with
                  | None -> graph
                  | Some reference ->
                      let call =
                        Ir.make_node ~provider ~kind:Ir.Call ~name:reference
                          ~phase:Ir.Compile
                          ~span:(Yaml_cst.node_span template_node)
                          ?unknown:(dependency_unknown resolved reference)
                          ()
                      in
                      graph |> Ir.add_node call
                      |> Frontend_common.add_call record.node call)
              | None -> (
                  match Frontend_common.field "task" record.body with
                  | Some task_node -> (
                      match Frontend_common.scalar task_node with
                      | None -> graph
                      | Some reference ->
                          let capabilities, effects = task_profile reference in
                          let call =
                            Ir.make_node ~provider ~kind:Ir.Call ~name:reference
                              ~phase:Ir.Run
                              ~span:(Yaml_cst.node_span task_node)
                              ~capabilities ~effects
                              ?unknown:(dependency_unknown resolved reference)
                              ()
                          in
                          graph |> Ir.add_node call
                          |> Frontend_common.add_call record.node call)
                  | None -> (
                      match
                        List.find_map
                          (fun key ->
                            Option.map
                              (fun node -> (key, node))
                              (Frontend_common.field key record.body))
                          command_keys
                      with
                      | None ->
                          let opaque =
                            Ir.make_node ~provider ~kind:Ir.Opaque
                              ~name:
                                ("unsupported Azure step " ^ record.node.name)
                              ~phase:Ir.Run ~span:record.node.span
                              ~unknown:
                                (Unknown.Unsupported_syntax "Azure step kind")
                              ()
                          in
                          graph |> Ir.add_node opaque
                          |> Frontend_common.add_control record.node opaque
                      | Some (shell, command_node) -> (
                          match Frontend_common.scalar command_node with
                          | None -> graph
                          | Some source ->
                              let value, references =
                                Frontend_common.command_value provider
                                  command_node source
                              in
                              let command =
                                Ir.make_node ~provider ~kind:Ir.Command
                                  ~name:source ~phase:Ir.Run
                                  ~span:(Yaml_cst.node_span command_node)
                                  ~attributes:
                                    [
                                      ("command", value);
                                      ( "shell",
                                        Abstract_value.string_constant shell
                                          ~trust:Abstract_value.Trusted
                                          ~secrecy:Abstract_value.Public
                                          ~provenance:[] );
                                    ]
                                  ~capabilities:
                                    [
                                      Ir.Shell;
                                      Ir.Filesystem_read;
                                      Ir.Filesystem_write;
                                    ]
                                  ~effects:[ Ir.Command_execution ] ()
                              in
                              graph |> Ir.add_node command
                              |> Frontend_common.add_control record.node command
                              |> Frontend_common.add_references provider command
                                   references)))))
        graph records

let add_environment graph (job : Ir.node) body =
  match Frontend_common.field "environment" body with
  | None -> graph
  | Some environment ->
      let name =
        Option.value ~default:"dynamic"
          (match Frontend_common.scalar environment with
          | Some _ as value -> value
          | None -> Frontend_common.field_scalar "name" environment)
      in
      Frontend_support.add_resource ~provider ~owner:job
        ~name:("environment:" ^ name) ~phase:Ir.Run
        ~span:(Yaml_cst.node_span environment)
        ~capabilities:[ Ir.Deployment ] ~edge_kind:Ir.Grant
        ~resource_to_owner:true graph
      |> fst

type lowered_job = {
  body : Yaml_cst.node;
  job : Ir.node;
  parent : Ir.node;
  owns_variables : bool;
}

let collect_jobs parent jobs_node =
  Frontend_common.sequence_nodes jobs_node
  |> List.filter_map (fun body ->
      match
        match Frontend_common.field_scalar "job" body with
        | Some _ as value -> value
        | None -> Frontend_common.field_scalar "deployment" body
      with
      | None -> None
      | Some name ->
          let deployment =
            Option.is_some (Frontend_common.field "deployment" body)
            || Option.is_some (Frontend_common.field "environment" body)
          in
          Some
            {
              body;
              job =
                Ir.make_node ~provider ~kind:Ir.Job ~name ~phase:Ir.Plan
                  ~span:(Yaml_cst.node_span body)
                  ~capabilities:(if deployment then [ Ir.Deployment ] else [])
                  ~effects:(if deployment then [ Ir.Deployment_change ] else [])
                  ();
              parent;
              owns_variables = true;
            })

let add_template_directives graph owner root =
  let rec walk graph node =
    match node with
    | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
        List.fold_left
          (fun graph (entry : Yaml_cst.mapping_entry) ->
            let graph =
              if Util.starts_with ~prefix:"${{" entry.key.value then
                let opaque =
                  Ir.make_node ~provider ~kind:Ir.Opaque
                    ~name:("template-directive:" ^ entry.key.value)
                    ~phase:Ir.Compile ~span:entry.span
                    ~unknown:
                      (Unknown.Unsupported_syntax
                         ("Azure template directive " ^ entry.key.value))
                    ()
                in
                graph |> Ir.add_node opaque
                |> Frontend_common.add_control owner opaque
              else graph
            in
            walk graph entry.value)
          graph entries
    | Sequence (items, _) ->
        List.fold_left
          (fun graph (item : Yaml_cst.sequence_item) -> walk graph item.value)
          graph items
    | Flow_sequence (items, _) -> List.fold_left walk graph items
    | Decorated decorated -> walk graph decorated.value
    | Scalar _ | Alias _ | Invalid _ -> graph
  in
  walk graph root

let lower resolved =
  match Frontend_common.root resolved with
  | None -> (Ir.empty provider resolved.expanded.parsed.unit_.path, [])
  | Some root ->
      let problems =
        ref (Frontend_common.yaml_problems resolved.expanded.parsed.cst)
      in
      let workflow =
        Frontend_common.workflow_node provider "Azure pipeline" root
      in
      let graph =
        ref
          (Ir.empty provider resolved.expanded.parsed.unit_.path
          |> Ir.add_node workflow
          |> Ir.add_entrypoint workflow.id)
      in
      [ "trigger"; "pr"; "schedules" ]
      |> List.iter (fun name ->
          match Frontend_common.field name root with
          | None -> ()
          | Some trigger_node ->
              let trigger =
                Ir.make_node ~provider ~kind:Ir.Trigger ~name ~phase:Ir.Source
                  ~span:(Yaml_cst.node_span trigger_node)
                  ()
              in
              graph :=
                !graph |> Ir.add_node trigger
                |> Frontend_common.add_control trigger workflow);
      (match Frontend_common.field "parameters" root with
      | None -> ()
      | Some parameters ->
          Frontend_common.sequence_nodes parameters
          |> List.iter (fun item -> graph := add_parameter !graph workflow item));
      (match Frontend_common.field "variables" root with
      | None -> ()
      | Some variables -> graph := add_variables !graph workflow variables);
      graph := add_repository_resources resolved !graph workflow root;
      graph := add_template_directives !graph workflow root;
      let stage_bodies =
        match Frontend_common.field "stages" root with
        | None -> []
        | Some stages -> Frontend_common.sequence_nodes stages
      in
      let stages =
        stage_bodies
        |> List.filter_map (fun body ->
            Option.map
              (fun name ->
                ( body,
                  Ir.make_node ~provider ~kind:Ir.Stage ~name ~phase:Ir.Plan
                    ~span:(Yaml_cst.node_span body) () ))
              (Frontend_common.field_scalar "stage" body))
      in
      List.iter
        (fun (_, stage) ->
          graph :=
            !graph |> Ir.add_node stage
            |> Frontend_common.add_control workflow stage)
        stages;
      let linked_stages, stage_problems =
        Frontend_support.link_dependencies ~unknown_code:"AZ-UNKNOWN-DEPENDENCY"
          ~cycle_code:"AZ-DEPENDENCY-CYCLE" ~label:"dependsOn"
          ~nodes:(List.map snd stages)
          ~dependencies:
            (List.map
               (fun (body, stage) ->
                 ( stage.Ir.name,
                   dependency_names "dependsOn" body,
                   Yaml_cst.node_span body ))
               stages)
          !graph
      in
      graph := linked_stages;
      problems := stage_problems @ !problems;
      List.iter
        (fun (body, stage) ->
          match Frontend_common.field "condition" body with
          | None -> ()
          | Some expression_node ->
              graph :=
                Frontend_support.add_gate ~provider ~owner:stage
                  ~name:("condition:stage:" ^ stage.name)
                  ~phase:Ir.Plan ~expression_node !graph
                |> fst)
        stages;
      let jobs = ref [] in
      List.iter
        (fun (body, stage) ->
          match Frontend_common.field "jobs" body with
          | None -> ()
          | Some jobs_node -> jobs := collect_jobs stage jobs_node @ !jobs)
        stages;
      (if stages = [] then
         match Frontend_common.field "jobs" root with
         | Some jobs_node -> jobs := collect_jobs workflow jobs_node
         | None ->
             let synthetic =
               Ir.make_node ~provider ~kind:Ir.Job ~name:"pipeline"
                 ~phase:Ir.Plan ~span:(Yaml_cst.node_span root) ()
             in
             jobs :=
               [
                 {
                   body = root;
                   job = synthetic;
                   parent = workflow;
                   owns_variables = false;
                 };
               ]);
      List.iter
        (fun lowered ->
          graph :=
            !graph |> Ir.add_node lowered.job
            |> Frontend_common.add_control lowered.parent lowered.job)
        !jobs;
      let linked_jobs, job_problems =
        Frontend_support.link_dependencies
          ~unknown_code:"AZ-UNKNOWN-JOB-DEPENDENCY"
          ~cycle_code:"AZ-JOB-DEPENDENCY-CYCLE" ~label:"dependsOn"
          ~nodes:(List.map (fun lowered -> lowered.job) !jobs)
          ~dependencies:
            (List.map
               (fun lowered ->
                 ( lowered.job.Ir.name,
                   dependency_names "dependsOn" lowered.body,
                   Yaml_cst.node_span lowered.body ))
               !jobs)
          !graph
      in
      graph := linked_jobs;
      problems := job_problems @ !problems;
      List.iter
        (fun lowered ->
          (match Frontend_common.field "condition" lowered.body with
          | None -> ()
          | Some expression_node ->
              graph :=
                Frontend_support.add_gate ~provider ~owner:lowered.job
                  ~name:("condition:job:" ^ lowered.job.name)
                  ~phase:Ir.Plan ~expression_node !graph
                |> fst);
          (match
             ( lowered.owns_variables,
               Frontend_common.field "variables" lowered.body )
           with
          | false, _ | true, None -> ()
          | true, Some variables ->
              graph := add_variables !graph lowered.job variables);
          graph := add_matrix !graph lowered.job lowered.body;
          graph := add_environment !graph lowered.job lowered.body;
          graph := add_steps resolved !graph lowered.job lowered.body)
        !jobs;
      (Ir.finalize !graph, List.rev !problems)
