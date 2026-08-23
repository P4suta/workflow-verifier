let provider = Ir.Circleci

let detect ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  Util.ends_with ~suffix:"/.circleci/config.yml" path
  || Util.ends_with ~suffix:"/.circleci/config.yaml" path
  || Util.starts_with ~prefix:".circleci/config." path
  || Util.contains ~needle:"version: 2.1" source
     && Util.contains ~needle:"workflows:" source

let entrypoint ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  detect ~path ~source
  && (Util.ends_with ~suffix:"/.circleci/config.yml" path
     || Util.ends_with ~suffix:"/.circleci/config.yaml" path
     || Util.starts_with ~prefix:".circleci/config." path)

let parse = Frontend_common.parse
let expand = Frontend_common.expand

let orb_dependencies root =
  match Frontend_common.field "orbs" root with
  | None -> []
  | Some orbs ->
      Frontend_common.mapping orbs
      |> List.filter_map (fun (entry : Yaml_cst.mapping_entry) ->
          Option.map
            (fun reference ->
              Frontend_common.dependency ~kind:Frontend_intf.Orb provider
                reference
                (Yaml_cst.node_span entry.value))
            (Frontend_common.scalar entry.value))

let rec image_dependencies accumulator node =
  match node with
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          let accumulator =
            if entry.key.value = "image" then
              match Frontend_common.scalar entry.value with
              | Some reference ->
                  Frontend_common.dependency ~kind:Frontend_intf.Container_image
                    provider reference
                    (Yaml_cst.node_span entry.value)
                  :: accumulator
              | None -> accumulator
            else accumulator
          in
          image_dependencies accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          image_dependencies accumulator item.value)
        accumulator items
  | Flow_sequence (items, _) ->
      List.fold_left image_dependencies accumulator items
  | Decorated decorated -> image_dependencies accumulator decorated.value
  | Scalar _ | Alias _ | Invalid _ -> accumulator

let resolve expanded =
  let dependencies =
    match Yaml_cst.root expanded.Frontend_intf.parsed.cst with
    | None -> []
    | Some root -> orb_dependencies root @ image_dependencies [] root
  in
  {
    Frontend_intf.expanded;
    dependencies =
      List.sort_uniq
        (fun left right ->
          String.compare left.Frontend_intf.reference right.reference)
        dependencies;
  }

let dependency_unknown dependency =
  match dependency.Frontend_intf.status with
  | Frontend_intf.Unresolved reason -> Some reason
  | Locked _ -> None

let add_parameters graph (owner : Ir.node) prefix parameters =
  Frontend_common.mapping parameters
  |> List.fold_left
       (fun graph (entry : Yaml_cst.mapping_entry) ->
         let default = Frontend_common.field "default" entry.value in
         let value =
           match Option.bind default Frontend_common.scalar with
           | Some value ->
               Abstract_value.string_constant value
                 ~trust:
                   (if prefix = "pipeline" then Abstract_value.Untrusted
                    else Abstract_value.Trusted)
                 ~secrecy:Abstract_value.Public
                 ~provenance:
                   [
                     {
                       origin = prefix ^ " parameter";
                       span = entry.span;
                       operation = "default";
                     };
                   ]
           | None ->
               Abstract_value.unknown
                 (Unknown.External_state
                    (prefix ^ " parameter " ^ entry.key.value))
         in
         let parameter =
           Ir.make_node ~provider ~kind:Ir.Parameter
             ~name:(prefix ^ "." ^ entry.key.value)
             ~phase:Ir.Compile ~span:entry.span
             ~attributes:[ ("value", value) ]
             ()
         in
         graph |> Ir.add_node parameter
         |> Ir.add_edge
              (Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:owner.id
                 ~label:entry.key.value ()))
       graph

let add_executors graph (config : Ir.node) root =
  match Frontend_common.field "executors" root with
  | None -> (graph, [])
  | Some executors ->
      Frontend_common.mapping executors
      |> List.fold_left
           (fun (graph, resources) (entry : Yaml_cst.mapping_entry) ->
             let resource =
               Ir.make_node ~provider ~kind:Ir.Resource
                 ~name:("executor:" ^ entry.key.value)
                 ~phase:Ir.Compile ~span:entry.span
                 ~capabilities:[ Ir.Filesystem_read; Ir.Filesystem_write ]
                 ()
             in
             ( graph |> Ir.add_node resource
               |> Ir.add_edge
                    (Ir.make_edge ~kind:Ir.Control ~from_:config.id
                       ~to_:resource.id ()),
               (entry.key.value, resource) :: resources ))
           (graph, [])

let add_commands graph (config : Ir.node) root =
  match Frontend_common.field "commands" root with
  | None -> (graph, [])
  | Some commands ->
      Frontend_common.mapping commands
      |> List.fold_left
           (fun (graph, definitions) (entry : Yaml_cst.mapping_entry) ->
             let resource =
               Ir.make_node ~provider ~kind:Ir.Resource
                 ~name:("command-definition:" ^ entry.key.value)
                 ~phase:Ir.Compile ~span:entry.span ()
             in
             let graph =
               graph |> Ir.add_node resource
               |> Ir.add_edge
                    (Ir.make_edge ~kind:Ir.Control ~from_:config.id
                       ~to_:resource.id ())
             in
             let graph =
               match Frontend_common.field "parameters" entry.value with
               | None -> graph
               | Some parameters ->
                   add_parameters graph resource entry.key.value parameters
             in
             (graph, (entry.key.value, entry.value, resource) :: definitions))
           (graph, [])

let builtin_profile name =
  match String.lowercase_ascii name with
  | "checkout" ->
      ([ Ir.Repository_read; Ir.Filesystem_write ], [ Ir.File_write ], Ir.Read)
  | "save_cache" ->
      ([ Ir.Cache_write; Ir.Filesystem_read ], [ Ir.Cache_publish ], Ir.Write)
  | "restore_cache" ->
      ([ Ir.Cache_read; Ir.Filesystem_write ], [ Ir.File_write ], Ir.Read)
  | "store_artifacts" | "store_test_results" ->
      ( [ Ir.Artifact_write; Ir.Filesystem_read ],
        [ Ir.Artifact_publish ],
        Ir.Write )
  | "persist_to_workspace" ->
      ( [ Ir.Artifact_write; Ir.Filesystem_read ],
        [ Ir.Artifact_publish ],
        Ir.Persist )
  | "attach_workspace" ->
      ([ Ir.Artifact_read; Ir.Filesystem_write ], [ Ir.File_write ], Ir.Read)
  | _ -> ([], [], Ir.Call_edge)

let add_run graph (parent : Ir.node) run =
  let command_node, name =
    match Frontend_common.scalar run with
    | Some source -> (run, source)
    | None ->
        let node =
          Option.value ~default:run (Frontend_common.field "command" run)
        in
        ( node,
          Option.value ~default:"run" (Frontend_common.field_scalar "name" run)
        )
  in
  match Frontend_common.scalar command_node with
  | None -> graph
  | Some source ->
      let value, references =
        Frontend_common.command_value provider command_node source
      in
      let command =
        Ir.make_node ~provider ~kind:Ir.Command ~name ~phase:Ir.Run
          ~span:(Yaml_cst.node_span command_node)
          ~attributes:[ ("command", value) ]
          ~capabilities:[ Ir.Shell; Ir.Filesystem_read; Ir.Filesystem_write ]
          ~effects:[ Ir.Command_execution ] ()
      in
      graph |> Ir.add_node command
      |> Frontend_common.add_control parent command
      |> Frontend_common.add_references provider command references

let mapping_head node =
  match Frontend_common.mapping node with
  | (entry : Yaml_cst.mapping_entry) :: _ -> Some (entry.key.value, entry.value)
  | [] -> None

let orb_references root =
  match Frontend_common.field "orbs" root with
  | None -> []
  | Some orbs ->
      Frontend_common.mapping orbs
      |> List.filter_map (fun (entry : Yaml_cst.mapping_entry) ->
          Option.map
            (fun reference -> (entry.key.value, reference))
            (Frontend_common.scalar entry.value))

let orb_target orbs name =
  match String.index_opt name '/' with
  | None -> None
  | Some index ->
      let alias = String.sub name 0 index in
      List.find_opt (fun (candidate, _, _) -> candidate = alias) orbs

let orb_attributes span = function
  | None -> []
  | Some (_, reference, _) ->
      [
        ( "dependency.reference",
          Abstract_value.string_constant reference ~trust:Abstract_value.Trusted
            ~secrecy:Abstract_value.Public
            ~provenance:
              [
                {
                  origin = "CircleCI orb alias";
                  span;
                  operation = "resolve immutable dependency identity";
                };
              ] );
      ]

let add_steps ~commands ~orbs graph (job : Ir.node) body =
  match Frontend_common.field "steps" body with
  | None -> graph
  | Some steps ->
      let records =
        Frontend_common.sequence_nodes steps
        |> List.mapi (fun index step_body ->
            let name =
              match Frontend_common.scalar step_body with
              | Some name -> name
              | None -> (
                  match mapping_head step_body with
                  | Some (name, _) -> name
                  | None -> "step " ^ string_of_int (index + 1))
            in
            ( step_body,
              Ir.make_node ~provider ~kind:Ir.Step ~name ~phase:Ir.Run
                ~span:(Yaml_cst.node_span step_body)
                () ))
      in
      let graph =
        List.fold_left
          (fun graph (_, step) ->
            graph |> Ir.add_node step |> Frontend_common.add_control job step)
          graph records
        |> Frontend_support.link_sequence (List.map snd records)
      in
      List.fold_left
        (fun graph (body, step) ->
          match Frontend_common.scalar body with
          | Some builtin -> (
              let orb_target = orb_target orbs builtin in
              let orb = Option.is_some orb_target in
              let span = Yaml_cst.node_span body in
              let capabilities, effects, edge_kind = builtin_profile builtin in
              let call =
                Ir.make_node ~provider ~kind:Ir.Call
                  ~name:((if orb then "orb:" else "builtin:") ^ builtin)
                  ~phase:Ir.Run ~span ~capabilities ~effects
                  ~attributes:(orb_attributes span orb_target)
                  ?unknown:
                    (Option.bind orb_target (fun (_, _, target) ->
                         target.Ir.unknown))
                  ()
              in
              let graph =
                graph |> Ir.add_node call
                |> Ir.add_edge
                     (Ir.make_edge ~kind:edge_kind ~from_:step.id ~to_:call.id
                        ())
                |> Frontend_common.add_control step call
              in
              match orb_target with
              | None -> graph
              | Some (_, _, target) ->
                  Ir.add_edge
                    (Ir.make_edge ~kind:Ir.Call_edge ~from_:call.id
                       ~to_:target.id ())
                    graph)
          | None -> (
              match Frontend_common.field "run" body with
              | Some run -> add_run graph step run
              | None -> (
                  match mapping_head body with
                  | None -> graph
                  | Some (name, arguments) ->
                      let local_definition =
                        List.find_opt
                          (fun (command_name, _, _) -> command_name = name)
                          commands
                      in
                      let local = Option.is_some local_definition in
                      let orb_target = orb_target orbs name in
                      let orb = Option.is_some orb_target in
                      let span = Yaml_cst.node_span body in
                      let call_name =
                        if local then "command:" ^ name
                        else if orb then "orb:" ^ name
                        else "builtin:" ^ name
                      in
                      let capabilities, effects, _ = builtin_profile name in
                      let call =
                        Ir.make_node ~provider ~kind:Ir.Call ~name:call_name
                          ~phase:Ir.Run ~span ~capabilities ~effects
                          ~attributes:(orb_attributes span orb_target)
                          ?unknown:
                            (Option.bind orb_target (fun (_, _, target) ->
                                 target.Ir.unknown))
                          ()
                      in
                      let graph =
                        graph |> Ir.add_node call
                        |> Frontend_common.add_call step call
                      in
                      let graph =
                        match (local_definition, orb_target) with
                        | Some (_, _, (definition : Ir.node)), _ ->
                            Ir.add_edge
                              (Ir.make_edge ~kind:Ir.Call_edge ~from_:call.id
                                 ~to_:definition.id ())
                              graph
                        | None, Some (_, _, target) ->
                            Ir.add_edge
                              (Ir.make_edge ~kind:Ir.Call_edge ~from_:call.id
                                 ~to_:target.id ())
                              graph
                        | None, None -> graph
                      in
                      let scalar_arguments =
                        Frontend_common.mapping arguments
                        |> List.filter_map
                             (fun (entry : Yaml_cst.mapping_entry) ->
                               Option.map
                                 (fun value -> (entry.value, value))
                                 (Frontend_common.scalar entry.value))
                      in
                      List.fold_left
                        (fun graph (node, source) ->
                          let references =
                            Expression.scan provider ~default_phase:Ir.Run
                              ~span:(Yaml_cst.node_span node) source
                          in
                          Frontend_common.add_references provider call
                            references graph)
                        graph scalar_arguments)))
        graph records

let add_job_executor graph (executors : (string * Ir.node) list) (job : Ir.node)
    body =
  match Frontend_common.field_scalar "executor" body with
  | None -> graph
  | Some name -> (
      match List.assoc_opt name executors with
      | None -> graph
      | Some (resource : Ir.node) ->
          Ir.add_edge
            (Ir.make_edge ~kind:Ir.Read ~from_:resource.Ir.id ~to_:job.id ())
            graph)

let add_job_matrix graph (job : Ir.node) invocation =
  match
    Option.bind
      (Frontend_common.field "matrix" invocation)
      (Frontend_common.field "parameters")
  with
  | None -> graph
  | Some parameters ->
      Frontend_common.mapping parameters
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

type invocation = {
  alias : string;
  target : Ir.node;
  body : Yaml_cst.node;
  requires : string list;
  span : Span.t;
}

let link_invocations invocations graph =
  let problems = ref [] and graph = ref graph in
  let find alias =
    List.find_opt (fun invocation -> invocation.alias = alias) invocations
  in
  List.iter
    (fun invocation ->
      List.iter
        (fun requirement ->
          match find requirement with
          | Some predecessor ->
              graph :=
                Ir.add_edge
                  (Ir.make_edge ~kind:Ir.Control ~from_:predecessor.target.id
                     ~to_:invocation.target.id ~label:"requires" ())
                  !graph
          | None ->
              problems :=
                {
                  Frontend_intf.code = "CC-UNKNOWN-REQUIREMENT";
                  message =
                    invocation.alias ^ " requires unknown " ^ requirement;
                  span = invocation.span;
                }
                :: !problems)
        invocation.requires)
    invocations;
  let visiting = ref [] and visited = ref [] and cycle = ref false in
  let rec visit name =
    if List.mem name !visiting then cycle := true
    else if not (List.mem name !visited) then (
      visiting := name :: !visiting;
      Option.iter
        (fun invocation -> List.iter visit invocation.requires)
        (find name);
      visiting := List.filter (( <> ) name) !visiting;
      visited := name :: !visited)
  in
  List.iter (fun invocation -> visit invocation.alias) invocations;
  if !cycle then
    problems :=
      {
        Frontend_intf.code = "CC-REQUIRES-CYCLE";
        message = "CircleCI workflow requirements contain a cycle";
        span =
          (match invocations with
          | value :: _ -> value.span
          | [] -> Span.none);
      }
      :: !problems;
  (!graph, List.rev !problems)

let lower resolved =
  match Frontend_common.root resolved with
  | None -> (Ir.empty provider resolved.expanded.parsed.unit_.path, [])
  | Some root ->
      let problems =
        ref (Frontend_common.yaml_problems resolved.expanded.parsed.cst)
      in
      let config =
        Frontend_common.workflow_node provider "CircleCI config" root
      in
      let graph =
        ref
          (Ir.empty provider resolved.expanded.parsed.unit_.path
          |> Ir.add_node config
          |> Ir.add_entrypoint config.id)
      in
      let dependency_calls =
        List.map
          (fun dependency ->
            let call =
              Ir.make_node ~provider ~kind:Ir.Call
                ~name:dependency.Frontend_intf.reference ~phase:Ir.Compile
                ~span:dependency.span
                ?unknown:(dependency_unknown dependency)
                ()
            in
            graph :=
              !graph |> Ir.add_node call |> Frontend_common.add_call config call;
            (dependency.Frontend_intf.reference, call))
          resolved.dependencies
      in
      (match Frontend_common.field "setup" root with
      | Some setup when Frontend_common.scalar setup = Some "true" ->
          let effect_node =
            Ir.make_node ~provider ~kind:Ir.Effect ~name:"dynamic config"
              ~phase:Ir.Compile ~span:(Yaml_cst.node_span setup)
              ~effects:[ Ir.Workflow_change ] ()
          in
          graph :=
            !graph |> Ir.add_node effect_node
            |> Frontend_common.add_control config effect_node
      | _ -> ());
      (match Frontend_common.field "parameters" root with
      | None -> ()
      | Some parameters ->
          graph := add_parameters !graph config "pipeline" parameters);
      let graph_with_executors, executors = add_executors !graph config root in
      graph := graph_with_executors;
      let graph_with_commands, commands = add_commands !graph config root in
      graph := graph_with_commands;
      let orbs =
        orb_references root
        |> List.filter_map (fun (alias, reference) ->
            Option.map
              (fun target -> (alias, reference, target))
              (List.assoc_opt reference dependency_calls))
      in
      graph :=
        List.fold_left
          (fun graph (_, body, definition) ->
            add_steps ~commands ~orbs graph definition body)
          !graph commands;
      let job_entries =
        match Frontend_common.field "jobs" root with
        | None -> []
        | Some jobs -> Frontend_common.mapping jobs
      in
      let jobs =
        List.map
          (fun (entry : Yaml_cst.mapping_entry) ->
            let job =
              Ir.make_node ~provider ~kind:Ir.Job ~name:entry.key.value
                ~phase:Ir.Plan ~span:entry.span ()
            in
            graph := Ir.add_node job !graph;
            graph := add_job_executor !graph executors job entry.value;
            (match Frontend_common.field "parameters" entry.value with
            | None -> ()
            | Some parameters ->
                graph := add_parameters !graph job entry.key.value parameters);
            graph := add_steps ~commands ~orbs !graph job entry.value;
            (entry.key.value, entry.value, job))
          job_entries
      in
      let find_job name =
        List.find_opt (fun (job_name, _, _) -> job_name = name) jobs
      in
      let workflow_entries =
        match Frontend_common.field "workflows" root with
        | None -> []
        | Some workflows ->
            Frontend_common.mapping workflows
            |> List.filter (fun (entry : Yaml_cst.mapping_entry) ->
                entry.key.value <> "version")
      in
      List.iter
        (fun (entry : Yaml_cst.mapping_entry) ->
          let workflow =
            Ir.make_node ~provider ~kind:Ir.Workflow ~name:entry.key.value
              ~phase:Ir.Plan ~span:entry.span ()
          in
          graph :=
            !graph |> Ir.add_node workflow
            |> Frontend_common.add_control config workflow;
          (match Frontend_common.field "when" entry.value with
          | None -> ()
          | Some expression_node ->
              graph :=
                Frontend_support.add_gate ~provider ~owner:workflow
                  ~name:("when:" ^ workflow.name) ~phase:Ir.Plan
                  ~expression_node !graph
                |> fst);
          let invocations = ref [] in
          (match Frontend_common.field "jobs" entry.value with
          | None -> ()
          | Some workflow_jobs ->
              Frontend_common.sequence_nodes workflow_jobs
              |> List.iter (fun item ->
                  let alias, invocation_body =
                    match Frontend_common.scalar item with
                    | Some name -> (name, item)
                    | None -> (
                        match mapping_head item with
                        | Some pair -> pair
                        | None -> ("<unknown>", item))
                  in
                  let requires =
                    Frontend_support.field_strings "requires" invocation_body
                  in
                  let target =
                    if
                      Frontend_common.field_scalar "type" invocation_body
                      = Some "approval"
                    then
                      let condition =
                        Condition.atom ("circleci:approval:" ^ alias)
                      in
                      Ir.make_node ~provider ~kind:Ir.Gate
                        ~name:("approval:" ^ alias) ~phase:Ir.Plan
                        ~span:(Yaml_cst.node_span item) ~condition ()
                    else
                      match find_job alias with
                      | Some (_, _, job) -> job
                      | None ->
                          problems :=
                            {
                              Frontend_intf.code = "CC-UNKNOWN-JOB";
                              message =
                                workflow.name ^ " invokes unknown job " ^ alias;
                              span = Yaml_cst.node_span item;
                            }
                            :: !problems;
                          Ir.make_node ~provider ~kind:Ir.Opaque
                            ~name:("unknown-job:" ^ alias) ~phase:Ir.Plan
                            ~span:(Yaml_cst.node_span item)
                            ~unknown:(Unknown.Unresolved_dependency alias) ()
                  in
                  if Option.is_none (Ir.find_node !graph target.id) then
                    graph := Ir.add_node target !graph;
                  graph := Frontend_common.add_control workflow target !graph;
                  graph := add_job_matrix !graph target invocation_body;
                  invocations :=
                    {
                      alias;
                      target;
                      body = invocation_body;
                      requires;
                      span = Yaml_cst.node_span item;
                    }
                    :: !invocations));
          let linked, invocation_problems =
            link_invocations (List.rev !invocations) !graph
          in
          graph := linked;
          List.iter
            (fun invocation ->
              match Frontend_common.field "filters" invocation.body with
              | None -> ()
              | Some expression_node ->
                  graph :=
                    Frontend_support.add_gate ~provider ~owner:invocation.target
                      ~name:("filter:" ^ workflow.name ^ ":" ^ invocation.alias)
                      ~phase:Ir.Plan ~expression_node !graph
                    |> fst)
            !invocations;
          problems := invocation_problems @ !problems)
        workflow_entries;
      (Ir.finalize !graph, List.rev !problems)
