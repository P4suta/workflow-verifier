type t = {
  steps : Sandbox_protocol.step list;
  selected_jobs : string list;
  incomplete_reasons : string list;
}

let attribute_constant name (node : Ir.node) =
  Option.bind (List.assoc_opt name node.attributes) (fun value ->
      match Abstract_value.constants value with
      | Some [ constant ] -> Some constant
      | _ -> None)

let source_matches expected actual =
  let expected = Util.normalize_slashes expected
  and actual = Util.normalize_slashes actual in
  actual = expected || Util.ends_with ~suffix:("/" ^ expected) actual

type concrete = Null | Boolean of bool | Number of string | String of string

let concrete_text = function
  | Null -> ""
  | Boolean value -> string_of_bool value
  | Number value | String value -> value

let concrete_truth = function
  | Null -> Some false
  | Boolean value -> Some value
  | Number "0" | String "" -> Some false
  | Number _ | String _ -> Some true

let scenario_values (scenario : Scenario.t) =
  let matrix =
    scenario.matrix
    |> List.filter_map (fun (key, value) ->
        let value =
          match value with
          | Json.String value -> Some (String value)
          | Json.Bool value -> Some (Boolean value)
          | Json.Int value -> Some (Number (string_of_int value))
          | Json.Int64 value -> Some (Number (Int64.to_string value))
          | _ -> None
        in
        Option.map (fun value -> ("matrix." ^ key, value)) value)
  in
  let inputs =
    scenario.inputs
    |> List.concat_map (fun (key, value) ->
        [
          ("inputs." ^ key, String value);
          ("parameters." ^ key, String value);
          ("pipeline.parameters." ^ key, String value);
        ])
  and variables =
    scenario.variables
    |> List.concat_map (fun (key, value) ->
        [
          (key, String value);
          ("vars." ^ key, String value);
          ("variables." ^ key, String value);
        ])
  in
  matrix @ inputs @ variables
  @ [
      ("event", String scenario.event);
      ("event.name", String scenario.event);
      ("github.event_name", String scenario.event);
      ("CI_PIPELINE_SOURCE", String scenario.event);
      ("Build.Reason", String scenario.event);
    ]

let compare_concrete operator left right =
  let equal = concrete_text left = concrete_text right in
  let compare_numbers comparison =
    match
      ( Int64.of_string_opt (concrete_text left),
        Int64.of_string_opt (concrete_text right) )
    with
    | Some left, Some right -> Some (comparison left right)
    | _ -> None
  in
  match operator with
  | Expression.Equal -> Some equal
  | Not_equal -> Some (not equal)
  | Less -> compare_numbers ( < )
  | Less_equal -> compare_numbers ( <= )
  | Greater -> compare_numbers ( > )
  | Greater_equal -> compare_numbers ( >= )
  | Or | And | Match | Not_match -> None

let evaluate_expression values node =
  let rec value = function
    | Expression.Literal Null -> Some Null
    | Literal (Boolean value) -> Some (Boolean value)
    | Literal (Number value) -> Some (Number value)
    | Literal (String_literal value) -> Some (String value)
    | Literal (Regex _) -> None
    | Reference (name, _) -> List.assoc_opt name values
    | Unary (Not, operand) ->
        Option.bind (value operand) (fun value ->
            Option.map (fun truth -> Boolean (not truth)) (concrete_truth value))
    | Unary (Negate, operand) ->
        Option.bind (value operand) (fun value ->
            Option.map
              (fun number -> Number (Int64.to_string (Int64.neg number)))
              (Int64.of_string_opt (concrete_text value)))
    | Binary (((And | Or) as operator), left, right) ->
        Option.bind (value left) (fun left ->
            Option.bind (concrete_truth left) (fun left ->
                Option.bind (value right) (fun right ->
                    Option.map
                      (fun right ->
                        Boolean
                          (if operator = And then left && right
                           else left || right))
                      (concrete_truth right))))
    | Binary (operator, left, right) ->
        Option.bind (value left) (fun left ->
            Option.bind (value right) (fun right ->
                Option.map
                  (fun result -> Boolean result)
                  (compare_concrete operator left right)))
    | Call (name, []) when String.lowercase_ascii name = "always" ->
        Some (Boolean true)
    | Call _ -> None
  in
  Option.bind (value node) concrete_truth

let scenario_facts (scenario : Scenario.t) =
  let values = scenario_values scenario in
  fun atom ->
    match List.assoc_opt atom values with
    | Some value -> concrete_truth value
    | None -> (
        match
          Expression.parse scenario.provider ~phase:Ir.Plan ~span:Span.none atom
        with
        | Ok expression -> evaluate_expression values expression.node
        | Error _ -> None)

let replace_expression expression value source =
  Util.replace_all ~needle:expression ~replacement:value source

let valid_environment_name name =
  let valid_first = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and valid_rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' -> true
    | _ -> false
  in
  String.length name > 0
  && valid_first name.[0]
  && String.for_all valid_rest name

let concretize scenario ~shell source =
  let source =
    scenario.Scenario.inputs
    |> List.fold_left
         (fun source (name, value) ->
           source
           |> replace_expression ("${{ inputs." ^ name ^ " }}") value
           |> replace_expression ("${{inputs." ^ name ^ "}}") value
           |> replace_expression ("${{ parameters." ^ name ^ " }}") value
           |> replace_expression
                ("<< pipeline.parameters." ^ name ^ " >>")
                value
           |> replace_expression ("<< parameters." ^ name ^ " >>") value)
         source
  in
  let source =
    scenario.matrix
    |> List.fold_left
         (fun source (name, value) ->
           let value =
             match value with
             | Json.String value -> value
             | Json.Bool value -> string_of_bool value
             | Json.Int value -> string_of_int value
             | Json.Int64 value -> Int64.to_string value
             | _ -> ""
           in
           source
           |> replace_expression ("${{ matrix." ^ name ^ " }}") value
           |> replace_expression ("${{matrix." ^ name ^ "}}") value)
         source
  in
  let source =
    scenario.variables
    |> List.fold_left
         (fun source (name, value) ->
           source
           |> replace_expression ("${{ vars." ^ name ^ " }}") value
           |> replace_expression ("${{ variables." ^ name ^ " }}") value
           |> replace_expression ("$[ variables." ^ name ^ " ]") value
           |> replace_expression ("${{ " ^ name ^ " }}") value
           |> replace_expression ("${{" ^ name ^ "}}") value)
         source
  in
  scenario.secret_names
  |> List.fold_left
       (fun source name ->
         let reference =
           match shell with
           | "pwsh" | "powershell" | "default-windows" -> "$env:" ^ name
           | "cmd" | "cmd.exe" -> "%" ^ name ^ "%"
           | _ -> "\"${" ^ name ^ "}\""
         in
         source
         |> replace_expression ("${{ secrets." ^ name ^ " }}") reference
         |> replace_expression ("${{secrets." ^ name ^ "}}") reference)
       source

let relevant_edge (edge : Ir.edge) =
  edge.kind = Ir.Control || edge.kind = Ir.Call_edge

let job_predecessors (graph : Ir.t) (job : Ir.node) : Ir.node list =
  graph.Ir.edges
  |> List.filter_map (fun edge ->
      if edge.Ir.kind = Ir.Control && edge.to_ = job.Ir.id then
        Option.bind (Ir.find_node graph edge.from_) (fun node ->
            if node.Ir.kind = Ir.Job then Some node else None)
      else None)

let job_closure graph selected =
  let rec visit (seen : Ir.node list) (job : Ir.node) =
    if List.exists (fun (node : Ir.node) -> node.Ir.id = job.Ir.id) seen then
      seen
    else job_predecessors graph job |> List.fold_left visit (job :: seen)
  in
  visit [] selected

let descendant_ids graph jobs =
  let selected_job_ids = List.map (fun (node : Ir.node) -> node.Ir.id) jobs in
  let rec visit seen allow_local_jobs id =
    if List.mem id seen then seen
    else
      let seen = id :: seen in
      graph.Ir.edges
      |> List.filter (fun edge -> relevant_edge edge && edge.from_ = id)
      |> List.fold_left
           (fun seen (edge : Ir.edge) ->
             let allow_local_jobs =
               allow_local_jobs || edge.label = Some "local-unit"
             in
             match Ir.find_node graph edge.to_ with
             | Some node
               when node.kind = Ir.Job
                    && not (List.mem node.id selected_job_ids) ->
                 if allow_local_jobs then visit seen allow_local_jobs node.id
                 else seen
             | Some node -> visit seen allow_local_jobs node.id
             | None -> seen)
           seen
  in
  List.fold_left
    (fun seen (job : Ir.node) -> visit seen false job.Ir.id)
    [] jobs

let topological_nodes (graph : Ir.t) selected_ids =
  let nodes =
    graph.Ir.nodes
    |> List.filter (fun (node : Ir.node) -> List.mem node.Ir.id selected_ids)
  in
  let edges =
    graph.Ir.edges
    |> List.filter (fun edge ->
        relevant_edge edge
        && List.mem edge.from_ selected_ids
        && List.mem edge.to_ selected_ids)
  in
  let indegree id =
    List.fold_left
      (fun count (edge : Ir.edge) ->
        if edge.Ir.to_ = id then count + 1 else count)
      0 edges
  in
  let rec loop emitted remaining =
    match
      remaining
      |> List.filter (fun (node : Ir.node) ->
          indegree node.Ir.id = 0
          || List.for_all
               (fun (edge : Ir.edge) ->
                 edge.Ir.to_ <> node.id
                 || List.exists
                      (fun (done_ : Ir.node) -> done_.Ir.id = edge.from_)
                      emitted)
               edges)
      |> List.sort Ir.compare_node
    with
    | [] -> List.rev_append emitted remaining |> List.rev
    | ready ->
        let ready_ids = List.map (fun (node : Ir.node) -> node.Ir.id) ready in
        let remaining =
          List.filter
            (fun (node : Ir.node) -> not (List.mem node.Ir.id ready_ids))
            remaining
        in
        loop (List.rev_append ready emitted) remaining
  in
  loop [] nodes

let shell_step ~scenario ~image (node : Ir.node) =
  let os = Scenario.runner_os scenario.Scenario.runner_platform in
  let shell =
    attribute_constant "shell" node
    |> Option.value ~default:"default"
    |> String.lowercase_ascii
  in
  let shell_for_values =
    if os = "windows" && shell = "default" then "default-windows" else shell
  in
  let command = concretize scenario ~shell:shell_for_values node.name in
  let unresolved_expression =
    Util.contains ~needle:"${{" command
    || Util.contains ~needle:"$[[" command
    || Util.contains ~needle:"<<" command
  in
  let argv, supported =
    match (os, shell) with
    | ("linux" | "macos"), ("default" | "bash") ->
        ([ "/bin/bash"; "-euo"; "pipefail"; "-c"; command ], true)
    | ("linux" | "macos"), ("sh" | "posix") ->
        ([ "/bin/sh"; "-eu"; "-c"; command ], true)
    | "windows", ("default" | "pwsh" | "powershell") ->
        ([ "pwsh.exe"; "-NoLogo"; "-NonInteractive"; "-Command"; command ], true)
    | "windows", ("cmd" | "cmd.exe") ->
        ([ "cmd.exe"; "/D"; "/S"; "/C"; command ], true)
    | _, ("python" | "python3" | "pwsh" | "powershell") ->
        ([ "<capsule-tool-not-declared>"; shell; command ], false)
    | _, other -> ([ "<unsupported-shell>"; other; command ], false)
  in
  let working_directory =
    attribute_constant "working_directory" node
    |> Option.value ~default:"/workspace"
    |> Util.normalize_slashes
  in
  let confined_workdir =
    working_directory = "/workspace"
    || Util.starts_with ~prefix:"/workspace/" working_directory
  in
  {
    Sandbox_protocol.id = node.id;
    image;
    argv;
    environment =
      List.filter
        (fun (name, _) -> valid_environment_name name)
        scenario.variables;
    working_directory;
    supported = supported && confined_workdir && not unresolved_expression;
  }

let unsupported_reason (node : Ir.node) =
  let location = Span.to_string node.span in
  match node.kind with
  | Ir.Call when Option.is_some node.unknown ->
      Some
        (Printf.sprintf "Incomplete.Unresolved_call at %s: %s" location
           node.name)
  | Ir.Opaque when node.phase = Ir.Run ->
      Some
        (Printf.sprintf "Incomplete.Unsupported_feature at %s: %s" location
           node.name)
  | Ir.Resource ->
      let lower = String.lowercase_ascii node.name in
      if
        Util.contains ~needle:"service" lower
        || Util.contains ~needle:"cache" lower
        || Util.contains ~needle:"artifact" lower
        || Util.contains ~needle:"deployment" lower
      then
        Some
          (Printf.sprintf "Incomplete.Unsupported_feature at %s: %s" location
             node.name)
      else None
  | _ -> None

let plan ~scenario ~image ~graphs =
  let candidates =
    graphs
    |> List.filter (fun graph ->
        graph.Ir.provider = scenario.Scenario.provider
        && source_matches scenario.workflow_entrypoint graph.source)
  in
  match candidates with
  | [] ->
      Error
        ("scenario workflow entrypoint was not compiled: "
       ^ scenario.workflow_entrypoint)
  | _ :: _ :: _ ->
      Error
        ("scenario workflow entrypoint is ambiguous: "
       ^ scenario.workflow_entrypoint)
  | [ entry_graph ] -> (
      let jobs =
        entry_graph.Ir.nodes
        |> List.filter (fun (node : Ir.node) ->
            node.Ir.kind = Ir.Job && node.name = scenario.job)
      in
      match jobs with
      | [] -> Error ("scenario job was not found: " ^ scenario.job)
      | _ :: _ :: _ -> Error ("scenario job is ambiguous: " ^ scenario.job)
      | [ selected ] ->
          (* Local reusable workflows and composite actions are linked by
             call edges between compilation units. Planning over only the
             entry workflow would silently drop their concrete commands. *)
          let program = Program_graph.compose graphs in
          let jobs = job_closure program selected in
          let selected_ids = descendant_ids program jobs in
          let facts = scenario_facts scenario in
          let nodes = topological_nodes program selected_ids in
          let steps, reasons =
            nodes
            |> List.fold_left
                 (fun (steps, reasons) (node : Ir.node) ->
                   let truth = Condition.evaluate facts node.Ir.condition in
                   let reasons =
                     match (truth, unsupported_reason node) with
                     | Condition.False, _ | _, None -> reasons
                     | _, Some reason -> reason :: reasons
                   in
                   match (node.kind, truth) with
                   | Ir.Command, Condition.True ->
                       let step = shell_step ~scenario ~image node in
                       let reasons =
                         if step.supported then reasons
                         else
                           Printf.sprintf
                             "Incomplete.Unsupported_shell at %s: %s"
                             (Span.to_string node.span) node.name
                           :: reasons
                       in
                       (step :: steps, reasons)
                   | Ir.Command, Condition.Unknown ->
                       ( steps,
                         Printf.sprintf "Incomplete.Unknown_expression at %s"
                           (Span.to_string node.span)
                         :: reasons )
                   | _ -> (steps, reasons))
                 ([], [])
          in
          Ok
            {
              steps = List.rev steps;
              selected_jobs =
                jobs
                |> List.map (fun (node : Ir.node) -> node.Ir.name)
                |> List.sort String.compare;
              incomplete_reasons =
                reasons |> List.rev |> Util.deduplicate_strings;
            })
