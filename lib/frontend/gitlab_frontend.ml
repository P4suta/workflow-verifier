let provider = Ir.Gitlab

let path_identity ~path =
  let name = Filename.basename path |> String.lowercase_ascii in
  name = ".gitlab-ci.yml" || name = ".gitlab-ci.yaml"

let detect ~path ~source =
  path_identity ~path
  || Util.contains ~needle:"stages:" source
     && Util.contains ~needle:"script:" source

let entrypoint ~path ~source =
  let path = Util.normalize_slashes path |> String.lowercase_ascii in
  detect ~path ~source && List.mem path [ ".gitlab-ci.yml"; ".gitlab-ci.yaml" ]

let parse = Frontend_common.parse
let expand = Frontend_common.expand

let dependency ?(locator = Frontend_intf.Direct_reference) kind reference node =
  Frontend_common.dependency ~kind ~locator provider reference
    (Yaml_cst.node_span node)

let field_values name node =
  match Frontend_common.field name node with
  | None -> []
  | Some value ->
      Frontend_common.sequence_nodes value
      |> List.filter_map Frontend_common.scalar

let project_include_references node project =
  let revision = Frontend_common.field_scalar "ref" node in
  match field_values "file" node with
  | [] ->
      let reference =
        project ^ Option.fold ~none:"" ~some:(fun value -> "@" ^ value) revision
      in
      [
        ( Frontend_intf.Repository,
          reference,
          Frontend_intf.Repository_source
            { repository = project; revision; repository_type = None } );
      ]
  | files ->
      List.map
        (fun path ->
          let reference =
            project ^ ":" ^ path
            ^ Option.fold ~none:"" ~some:(fun value -> "@" ^ value) revision
          in
          ( Frontend_intf.Repository,
            reference,
            Frontend_intf.Repository_file
              { repository = project; revision; path; repository_type = None }
          ))
        files

let include_references node =
  match Frontend_common.scalar node with
  | Some reference ->
      [ (Frontend_intf.Include, reference, Frontend_intf.Direct_reference) ]
  | None -> (
      match Frontend_common.field_scalar "project" node with
      | Some project -> project_include_references node project
      | None ->
          [
            ("remote", Frontend_intf.Include);
            ("component", Component);
            ("template", Template);
            ("local", Include);
          ]
          |> List.find_map (fun (key, kind) ->
              Option.map
                (fun reference ->
                  [ (kind, reference, Frontend_intf.Direct_reference) ])
                (Frontend_common.field_scalar key node))
          |> Option.value ~default:[])

let include_reference node =
  match include_references node with
  | (kind, reference, _) :: _ -> Some (kind, reference)
  | [] -> None

let include_dependencies root =
  match Frontend_common.field "include" root with
  | None -> []
  | Some include_node ->
      Frontend_common.sequence_nodes include_node
      |> List.concat_map (fun item ->
          include_references item
          |> List.map (fun (kind, reference, locator) ->
              dependency ~locator kind reference item))

let rec child_dependencies accumulator node =
  match node with
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          let accumulator =
            if entry.key.value <> "trigger" then accumulator
            else
              match Frontend_common.field "include" entry.value with
              | None -> accumulator
              | Some includes ->
                  Frontend_common.sequence_nodes includes
                  |> List.concat_map (fun item ->
                      include_references item
                      |> List.map (fun (kind, reference, locator) ->
                          dependency ~locator kind reference item))
                  |> List.rev_append accumulator
          in
          child_dependencies accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          child_dependencies accumulator item.value)
        accumulator items
  | Flow_sequence (nodes, _) ->
      List.fold_left child_dependencies accumulator nodes
  | Decorated decorated -> child_dependencies accumulator decorated.value
  | Scalar _ | Alias _ | Invalid _ -> accumulator

let rec execution_dependencies accumulator node =
  match node with
  | Yaml_cst.Mapping (entries, _) | Flow_mapping (entries, _) ->
      List.fold_left
        (fun accumulator (entry : Yaml_cst.mapping_entry) ->
          let accumulator =
            match (entry.key.value, Frontend_common.scalar entry.value) with
            | "image", Some reference ->
                dependency Frontend_intf.Container_image reference entry.value
                :: accumulator
            | _ -> accumulator
          in
          execution_dependencies accumulator entry.value)
        accumulator entries
  | Sequence (items, _) ->
      List.fold_left
        (fun accumulator (item : Yaml_cst.sequence_item) ->
          execution_dependencies accumulator item.value)
        accumulator items
  | Flow_sequence (nodes, _) ->
      List.fold_left execution_dependencies accumulator nodes
  | Decorated decorated -> execution_dependencies accumulator decorated.value
  | Scalar _ | Alias _ | Invalid _ -> accumulator

let resolve expanded =
  let dependencies =
    match Yaml_cst.root expanded.Frontend_intf.parsed.cst with
    | None -> []
    | Some root ->
        include_dependencies root @ child_dependencies [] root
        @ execution_dependencies [] root
  in
  {
    Frontend_intf.expanded;
    dependencies =
      List.sort_uniq
        (fun left right ->
          String.compare left.Frontend_intf.reference right.reference)
        dependencies;
  }

let reserved =
  [
    "include";
    "stages";
    "variables";
    "workflow";
    "default";
    "image";
    "services";
    "cache";
    "before_script";
    "after_script";
    "spec";
    "pages";
  ]

let dependency_unknown (dependency : Frontend_intf.dependency) =
  match dependency.Frontend_intf.status with
  | Unresolved reason -> Some reason
  | Locked _ -> None

let unresolved (resolved : Frontend_intf.resolved) reference =
  resolved.Frontend_intf.dependencies
  |> List.find_opt (fun dependency ->
      dependency.Frontend_intf.reference = reference)
  |> fun dependency -> Option.bind dependency dependency_unknown

let effective_field templates name body =
  let rec lookup visited body =
    match Frontend_common.field name body with
    | Some _ as value -> value
    | None ->
        Frontend_support.field_strings "extends" body
        |> List.rev
        |> List.find_map (fun template_name ->
            if List.mem template_name visited then None
            else
              match List.assoc_opt template_name templates with
              | None -> None
              | Some template -> lookup (template_name :: visited) template)
  in
  lookup [] body

let effective_field_scalar templates name body =
  Option.bind (effective_field templates name body) Frontend_common.scalar

let rule_expression_nodes templates body =
  match effective_field templates "rules" body with
  | None -> []
  | Some rules ->
      Frontend_common.sequence_nodes rules
      |> List.filter_map (Frontend_common.field "if")

let add_first_rule_gate templates graph (owner : Ir.node) prefix body =
  match rule_expression_nodes templates body with
  | [] -> graph
  | expression_node :: _ ->
      Frontend_support.add_gate ~provider ~owner
        ~name:(prefix ^ ":" ^ owner.name)
        ~phase:owner.phase ~expression_node graph
      |> fst

let add_manual_gate templates graph (owner : Ir.node) body =
  match effective_field templates "when" body with
  | Some expression_node
    when Option.value ~default:"" (Frontend_common.scalar expression_node)
         |> String.lowercase_ascii = "manual" ->
      Frontend_support.add_static_gate ~provider ~owner
        ~name:("manual:" ^ owner.name) ~phase:owner.phase
        ~span:(Yaml_cst.node_span expression_node)
        ~mechanism:"manual" graph
      |> fst
  | Some _ | None -> graph

let needs templates body =
  match effective_field templates "needs" body with
  | None -> []
  | Some node ->
      Frontend_common.sequence_nodes node
      |> List.filter_map (fun item ->
          match Frontend_common.scalar item with
          | Some name -> Some name
          | None -> Frontend_common.field_scalar "job" item)

let add_matrix templates graph (job : Ir.node) body =
  match
    Option.bind
      (effective_field templates "parallel" body)
      (Frontend_common.field "matrix")
  with
  | None -> graph
  | Some matrix ->
      let rec entries accumulator node =
        match node with
        | Yaml_cst.Mapping (items, _) | Flow_mapping (items, _) ->
            List.fold_left
              (fun accumulator (entry : Yaml_cst.mapping_entry) ->
                (entry.key.value, entry.span) :: entries accumulator entry.value)
              accumulator items
        | Sequence (items, _) ->
            List.fold_left
              (fun accumulator (item : Yaml_cst.sequence_item) ->
                entries accumulator item.value)
              accumulator items
        | Flow_sequence (items, _) -> List.fold_left entries accumulator items
        | Decorated decorated -> entries accumulator decorated.value
        | Scalar _ | Alias _ | Invalid _ -> accumulator
      in
      entries [] matrix
      |> List.sort_uniq (fun (left, _) (right, _) -> String.compare left right)
      |> List.fold_left
           (fun graph (name, span) ->
             let parameter =
               Ir.make_node ~provider ~kind:Ir.Parameter
                 ~name:("matrix." ^ name) ~phase:Ir.Plan ~span ()
             in
             graph |> Ir.add_node parameter
             |> Ir.add_edge
                  (Ir.make_edge ~kind:Ir.Data ~from_:parameter.id ~to_:job.Ir.id
                     ~label:name ()))
           graph

let script_nodes root templates body =
  let defaults = Frontend_common.field "default" root in
  [ "before_script"; "script"; "after_script" ]
  |> List.concat_map (fun key ->
      let value =
        match effective_field templates key body with
        | Some _ as value -> value
        | None -> Option.bind defaults (Frontend_common.field key)
      in
      value |> Option.fold ~none:[] ~some:Frontend_common.sequence_nodes)

let add_scripts root templates graph (job : Ir.node) body =
  let records =
    script_nodes root templates body
    |> List.filter_map (fun node ->
        Option.map (fun source -> (node, source)) (Frontend_common.scalar node))
    |> List.mapi (fun index (node, source) ->
        let step =
          Ir.make_node ~provider ~kind:Ir.Step
            ~name:("script:" ^ string_of_int (index + 1))
            ~phase:Ir.Run ~span:(Yaml_cst.node_span node) ()
        in
        (step, node, source))
  in
  let graph =
    List.fold_left
      (fun graph (step, _, _) ->
        graph |> Ir.add_node step |> Frontend_common.add_control job step)
      graph records
    |> Frontend_support.link_sequence
         (List.map (fun (step, _, _) -> step) records)
  in
  List.fold_left
    (fun graph (step, node, source) ->
      let value, references =
        Frontend_common.command_value provider node source
      in
      let command =
        Ir.make_node ~provider ~kind:Ir.Command ~name:source ~phase:Ir.Run
          ~span:(Yaml_cst.node_span node)
          ~attributes:[ ("command", value) ]
          ~capabilities:[ Ir.Shell; Ir.Filesystem_read; Ir.Filesystem_write ]
          ~effects:[ Ir.Command_execution ] ()
      in
      graph |> Ir.add_node command
      |> Frontend_common.add_control step command
      |> Frontend_common.add_references provider command references)
    graph records

let add_variable_resources graph (owner : Ir.node) variables =
  Frontend_common.mapping variables
  |> List.fold_left
       (fun graph (entry : Yaml_cst.mapping_entry) ->
         let resource =
           Ir.make_node ~provider ~kind:Ir.Resource
             ~name:("variable:" ^ entry.key.value)
             ~phase:owner.phase ~span:entry.span ()
         in
         graph |> Ir.add_node resource
         |> Ir.add_edge
              (Ir.make_edge ~kind:Ir.Data ~from_:resource.id ~to_:owner.id
                 ~label:entry.key.value ()))
       graph

let add_job_resources templates graph (job : Ir.node) body =
  let graph =
    match effective_field templates "variables" body with
    | None -> graph
    | Some variables -> add_variable_resources graph job variables
  in
  let graph =
    match effective_field templates "environment" body with
    | None -> graph
    | Some environment ->
        let name =
          Option.value ~default:"dynamic"
            (match Frontend_common.scalar environment with
            | Some _ as name -> name
            | None -> Frontend_common.field_scalar "name" environment)
        in
        Frontend_support.add_resource ~provider ~owner:job
          ~name:("environment:" ^ name) ~phase:Ir.Run
          ~span:(Yaml_cst.node_span environment)
          ~capabilities:[ Ir.Deployment ] ~edge_kind:Ir.Grant
          ~resource_to_owner:true graph
        |> fst
  in
  let graph =
    match effective_field templates "cache" body with
    | None -> graph
    | Some cache ->
        let graph, resource =
          Frontend_support.add_resource ~provider ~owner:job
            ~name:("cache:" ^ job.name) ~phase:Ir.Run
            ~span:(Yaml_cst.node_span cache)
            ~capabilities:[ Ir.Cache_read; Ir.Cache_write ]
            ~effects:[ Ir.Cache_publish ] ~edge_kind:Ir.Write graph
        in
        Ir.add_edge
          (Ir.make_edge ~kind:Ir.Read ~from_:resource.id ~to_:job.id ())
          graph
  in
  match effective_field templates "artifacts" body with
  | None -> graph
  | Some artifacts ->
      Frontend_support.add_resource ~provider ~owner:job
        ~name:("artifact:" ^ job.name) ~phase:Ir.Post
        ~span:(Yaml_cst.node_span artifacts)
        ~capabilities:[ Ir.Artifact_write ] ~effects:[ Ir.Artifact_publish ]
        ~edge_kind:Ir.Write graph
      |> fst

let child_reference trigger =
  match Frontend_common.scalar trigger with
  | Some value -> Some value
  | None -> (
      match Frontend_common.field "include" trigger with
      | Some include_node ->
          Frontend_common.sequence_nodes include_node
          |> List.find_map (fun item -> Option.map snd (include_reference item))
      | None -> Frontend_common.field_scalar "project" trigger)

let lower resolved =
  match Frontend_common.root resolved with
  | None -> (Ir.empty provider resolved.expanded.parsed.unit_.path, [])
  | Some root ->
      let problems =
        ref (Frontend_common.yaml_problems resolved.expanded.parsed.cst)
      in
      let workflow =
        Frontend_common.workflow_node provider "GitLab pipeline" root
      in
      let graph =
        ref
          (Ir.empty provider resolved.expanded.parsed.unit_.path
          |> Ir.add_node workflow
          |> Ir.add_entrypoint workflow.id)
      in
      List.iter
        (fun dependency ->
          let call =
            Ir.make_node ~provider ~kind:Ir.Call
              ~name:dependency.Frontend_intf.reference ~phase:Ir.Compile
              ~span:dependency.span
              ?unknown:(dependency_unknown dependency)
              ()
          in
          graph :=
            !graph |> Ir.add_node call |> Frontend_common.add_call workflow call)
        resolved.dependencies;
      (match Frontend_common.field "variables" root with
      | None -> ()
      | Some variables ->
          graph := add_variable_resources !graph workflow variables);
      (match Frontend_common.field "workflow" root with
      | None -> ()
      | Some workflow_body ->
          graph :=
            add_first_rule_gate [] !graph workflow "workflow-rule" workflow_body);
      let root_entries = Frontend_common.mapping root in
      let templates =
        root_entries
        |> List.filter_map (fun (entry : Yaml_cst.mapping_entry) ->
            if Util.starts_with ~prefix:"." entry.key.value then
              Some (entry.key.value, entry.value)
            else None)
      in
      List.iter
        (fun (name, body) ->
          let template =
            Ir.make_node ~provider ~kind:Ir.Resource ~name:("template:" ^ name)
              ~phase:Ir.Compile ~span:(Yaml_cst.node_span body) ()
          in
          graph := Ir.add_node template !graph)
        templates;
      let job_entries =
        root_entries
        |> List.filter (fun (entry : Yaml_cst.mapping_entry) ->
            (not (List.mem entry.key.value reserved))
            && (not (Util.starts_with ~prefix:"." entry.key.value))
            && Frontend_common.mapping entry.value <> [])
      in
      let explicit_stages =
        match Frontend_common.field "stages" root with
        | None -> []
        | Some stages -> Frontend_support.scalar_strings stages
      in
      let used_stages =
        job_entries
        |> List.map (fun (entry : Yaml_cst.mapping_entry) ->
            Option.value ~default:"test"
              (effective_field_scalar templates "stage" entry.value))
      in
      let stage_names =
        if explicit_stages <> [] then Util.deduplicate_strings explicit_stages
        else
          Util.deduplicate_strings
            ([ ".pre"; "build"; "test"; "deploy"; ".post" ] @ used_stages)
      in
      let stages =
        List.mapi
          (fun index name ->
            Ir.make_node ~provider ~kind:Ir.Stage ~name ~phase:Ir.Plan
              ~span:
                (match Frontend_common.field "stages" root with
                | Some node -> Yaml_cst.node_span node
                | None -> Yaml_cst.node_span root)
              ~attributes:
                [
                  ( "order",
                    Abstract_value.string_constant (string_of_int index)
                      ~trust:Abstract_value.Trusted
                      ~secrecy:Abstract_value.Public ~provenance:[] );
                ]
              ())
          stage_names
      in
      List.iter (fun stage -> graph := Ir.add_node stage !graph) stages;
      (match stages with
      | first :: _ -> graph := Frontend_common.add_control workflow first !graph
      | [] -> ());
      graph := Frontend_support.link_sequence stages !graph;
      let jobs =
        List.map
          (fun (entry : Yaml_cst.mapping_entry) ->
            let environment =
              Option.is_some
                (effective_field templates "environment" entry.value)
            in
            let job =
              Ir.make_node ~provider ~kind:Ir.Job ~name:entry.key.value
                ~phase:Ir.Plan ~span:entry.span
                ~capabilities:(if environment then [ Ir.Deployment ] else [])
                ~effects:(if environment then [ Ir.Deployment_change ] else [])
                ()
            in
            graph := Ir.add_node job !graph;
            let stage_name =
              Option.value ~default:"test"
                (effective_field_scalar templates "stage" entry.value)
            in
            (match
               List.find_opt (fun stage -> stage.Ir.name = stage_name) stages
             with
            | Some stage ->
                graph := Frontend_common.add_control stage job !graph
            | None ->
                problems :=
                  {
                    Frontend_intf.code = "GL-UNKNOWN-STAGE";
                    message =
                      entry.key.value ^ " uses unknown stage " ^ stage_name;
                    span = entry.span;
                  }
                  :: !problems);
            (entry, job))
          job_entries
      in
      let linked, dependency_problems =
        Frontend_support.link_dependencies ~unknown_code:"GL-UNKNOWN-NEEDS"
          ~cycle_code:"GL-NEEDS-CYCLE" ~label:"needs" ~nodes:(List.map snd jobs)
          ~dependencies:
            (List.map
               (fun ((entry : Yaml_cst.mapping_entry), job) ->
                 (job.Ir.name, needs templates entry.value, entry.span))
               jobs)
          !graph
      in
      graph := linked;
      problems := dependency_problems @ !problems;
      List.iter
        (fun ((entry : Yaml_cst.mapping_entry), job) ->
          let body = entry.value in
          graph := add_first_rule_gate templates !graph job "rule" body;
          graph := add_manual_gate templates !graph job body;
          Frontend_support.field_strings "extends" body
          |> List.iter (fun template_name ->
              if
                not
                  (List.exists
                     (fun (name, _) -> name = template_name)
                     templates)
              then
                problems :=
                  {
                    Frontend_intf.code = "GL-UNKNOWN-EXTENDS";
                    message = job.name ^ " extends unknown " ^ template_name;
                    span = entry.span;
                  }
                  :: !problems;
              let call =
                Ir.make_node ~provider ~kind:Ir.Call
                  ~name:("extends:" ^ template_name)
                  ~phase:Ir.Compile ~span:entry.span ()
              in
              graph :=
                !graph |> Ir.add_node call |> Frontend_common.add_call job call);
          (match effective_field templates "trigger" body with
          | None -> ()
          | Some trigger -> (
              match child_reference trigger with
              | None -> ()
              | Some reference ->
                  let call =
                    Ir.make_node ~provider ~kind:Ir.Call
                      ~name:("child:" ^ reference) ~phase:Ir.Compile
                      ~span:(Yaml_cst.node_span trigger)
                      ?unknown:(unresolved resolved reference)
                      ()
                  in
                  graph :=
                    !graph |> Ir.add_node call
                    |> Frontend_common.add_call job call));
          graph := add_matrix templates !graph job body;
          graph := add_job_resources templates !graph job body;
          graph := add_scripts root templates !graph job body)
        jobs;
      (Ir.finalize !graph, List.rev !problems)
