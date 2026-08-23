let module_for_provider = function
  | Ir.Github -> (module Github_frontend : Frontend_intf.S)
  | Ir.Gitlab -> (module Gitlab_frontend : Frontend_intf.S)
  | Ir.Azure -> (module Azure_frontend : Frontend_intf.S)
  | Ir.Circleci -> (module Circleci_frontend : Frontend_intf.S)

let providers = [ Ir.Github; Ir.Gitlab; Ir.Azure; Ir.Circleci ]

let detect ~path ~source =
  List.find_opt
    (fun provider ->
      let module Compiler = (val module_for_provider provider) in
      Compiler.detect ~path ~source)
    providers

let entrypoint ~provider ~path ~source =
  let module Compiler = (val module_for_provider provider) in
  Compiler.entrypoint ~path ~source

let compile_string ~provider ~path ~source () =
  let module Compiler = (val module_for_provider provider) in
  let unit_ = { Frontend_intf.path; source } in
  match Compiler.parse unit_ with
  | Error _ as error -> error
  | Ok parsed ->
      let expanded = Compiler.expand parsed in
      let resolved = Compiler.resolve expanded in
      let graph, problems = Compiler.lower resolved in
      Ok
        {
          Frontend_intf.provider;
          phases = [ Detected; Parsed; Expanded; Resolved; Lowered ];
          graph;
          dependencies = resolved.dependencies;
          problems;
          cst = parsed.cst;
        }

let compile_auto ~path ~source () =
  match detect ~path ~source with
  | Some provider -> compile_string ~provider ~path ~source ()
  | None ->
      Error
        [
          {
            Frontend_intf.code = "FRONTEND-UNDETECTED";
            message =
              "the path and document shape do not identify a supported CI \
               provider";
            span = Span.none;
          };
        ]

type semantic_shape = {
  workflows : int;
  stages : int;
  jobs : int;
  steps : int;
  calls : int;
  commands : int;
  parameters : int;
  control_edges : int;
  data_edges : int;
  call_edges : int;
}

let semantic_shape graph =
  let count_node kind =
    List.length
      (List.filter (fun (node : Ir.node) -> node.kind = kind) graph.Ir.nodes)
  and count_edge kind =
    List.length
      (List.filter (fun (edge : Ir.edge) -> edge.kind = kind) graph.Ir.edges)
  in
  {
    workflows = count_node Ir.Workflow;
    stages = count_node Ir.Stage;
    jobs = count_node Ir.Job;
    steps = count_node Ir.Step;
    calls = count_node Ir.Call;
    commands = count_node Ir.Command;
    parameters = count_node Ir.Parameter;
    control_edges = count_edge Ir.Control;
    data_edges = count_edge Ir.Data;
    call_edges = count_edge Ir.Call_edge;
  }
