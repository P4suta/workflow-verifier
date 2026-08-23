type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let read_fixture relative =
  let path =
    Filename.concat (Sys.getcwd ()) (Filename.concat "fixtures" relative)
  in
  match Util.read_file path with
  | Ok value -> (path, value)
  | Error message -> fail "%s" message

let compile provider relative =
  let path, source = read_fixture relative in
  match Frontend.compile_string ~provider ~path ~source () with
  | Ok compilation -> compilation
  | Error problems ->
      fail "frontend rejected fixture: %s"
        (String.concat "; "
           (List.map (fun problem -> problem.Frontend_intf.message) problems))

let count_kind kind graph =
  List.length
    (List.filter (fun (node : Ir.node) -> node.kind = kind) graph.Ir.nodes)

let require_node kind graph =
  match
    List.find_opt (fun (node : Ir.node) -> node.kind = kind) graph.Ir.nodes
  with
  | Some node -> node
  | None -> fail "missing %s node" (Ir.kind_name kind)

let pipeline_contract_test () =
  let fixtures =
    [
      (Ir.Github, "github/workflow.yml");
      (Ir.Gitlab, "gitlab/.gitlab-ci.yml");
      (Ir.Azure, "azure/azure-pipelines.yml");
      (Ir.Circleci, "circleci/config.yml");
    ]
  in
  List.iter
    (fun (provider, fixture) ->
      let result = compile provider fixture in
      expect "every compiler must expose all five phases"
        (result.phases
        = [ Frontend_intf.Detected; Parsed; Expanded; Resolved; Lowered ]);
      expect "one workflow is required"
        (count_kind Ir.Workflow result.graph >= 1);
      expect "one job is required" (count_kind Ir.Job result.graph >= 1);
      expect "one executable step is required"
        (count_kind Ir.Command result.graph + count_kind Ir.Call result.graph
        >= 1);
      expect "lowered IR must validate" (Ir.validate result.graph = []))
    fixtures

let detection_test () =
  let cases =
    [
      (".github/workflows/ci.yml", "name: ci\njobs: {}\n", Some Ir.Github);
      ( "fixtures/workflow.yml",
        "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        Some Ir.Github );
      (".gitlab-ci.yml", "stages: [test]\n", Some Ir.Gitlab);
      ("azure-pipelines.yaml", "pool: default\nsteps: []\n", Some Ir.Azure);
      (".circleci/config.yml", "version: 2.1\nworkflows: {}\n", Some Ir.Circleci);
      ( ".github/workflows/adversarial.yml",
        "stages: [test]\nbuild:\n  script: echo github\n",
        Some Ir.Github );
      ( ".gitlab-ci.yml",
        "trigger: [main]\npool: hosted\nstages: [test]\n",
        Some Ir.Gitlab );
      ( "nested/azure-pipelines.yml",
        "stages:\n  - stage: Verify\n    jobs:\n      - job: test\n        steps:\n          - script: echo azure\n",
        Some Ir.Azure );
      ( ".circleci/config.yml",
        "on: push\njobs: {}\nversion: 2.1\nworkflows: {}\n",
        Some Ir.Circleci );
      ("notes.yml", "title: notes\n", None);
    ]
  in
  List.iter
    (fun (path, source, expected) ->
      expect
        ("wrong detection for " ^ path)
        (Frontend.detect ~path ~source = expected))
    cases

let expression_contract_test () =
  let span = Span.none in
  let cases =
    [
      ( Ir.Github,
        "${{ github.event.pull_request.title }} ${{ secrets.TOKEN }}",
        "github.event.pull_request.title",
        "secrets.TOKEN" );
      ( Ir.Gitlab,
        "$CI_MERGE_REQUEST_TITLE $CI_JOB_TOKEN",
        "CI_MERGE_REQUEST_TITLE",
        "CI_JOB_TOKEN" );
      ( Ir.Azure,
        "$(System.PullRequest.Title) $(System.AccessToken)",
        "System.PullRequest.Title",
        "System.AccessToken" );
      ( Ir.Circleci,
        "<< pipeline.parameters.branch >> $CIRCLE_TOKEN",
        "pipeline.parameters.branch",
        "CIRCLE_TOKEN" );
    ]
  in
  List.iter
    (fun (provider, source, untrusted_name, secret_name) ->
      let references =
        Expression.scan provider ~default_phase:Ir.Run ~span source
      in
      let lookup name =
        match
          List.find_opt
            (fun reference -> reference.Expression.name = name)
            references
        with
        | Some value -> value
        | None ->
            fail "missing expression reference %s (found: %s)" name
              (String.concat ", "
                 (List.map
                    (fun reference -> reference.Expression.name)
                    references))
      in
      expect
        (untrusted_name ^ " must be untrusted")
        ((lookup untrusted_name).value.trust = Abstract_value.Untrusted);
      expect
        (secret_name ^ " must be secret")
        ((lookup secret_name).value.secrecy = Abstract_value.Secret))
    cases;
  let azure =
    Expression.scan Ir.Azure ~default_phase:Ir.Run ~span
      "${{ parameters.image }} and $(runtime)"
  in
  expect "Azure template expressions are compile-time"
    (List.exists
       (fun reference ->
         reference.Expression.name = "parameters.image"
         && reference.phase = Ir.Compile)
       azure)

let unresolved_dependency_test () =
  let cases =
    [
      (Ir.Github, "github/workflow.yml");
      (Ir.Gitlab, "gitlab/.gitlab-ci.yml");
      (Ir.Azure, "azure/azure-pipelines.yml");
      (Ir.Circleci, "circleci/config.yml");
    ]
  in
  List.iter
    (fun (provider, fixture) ->
      let result = compile provider fixture in
      expect "remote units must be represented as dependencies"
        (result.dependencies <> []);
      expect "an unlocked remote unit remains explicitly unresolved"
        (List.exists
           (fun dependency ->
             match dependency.Frontend_intf.status with
             | Unresolved _ -> true
             | Locked _ -> false)
           result.dependencies);
      expect "unresolved calls carry an Unknown reason"
        (List.exists
           (fun (node : Ir.node) ->
             node.kind = Ir.Call && Option.is_some node.unknown)
           result.graph.nodes))
    cases

let matrix_and_shape_test () =
  let github = compile Ir.Github "github/workflow.yml"
  and gitlab = compile Ir.Gitlab "gitlab/.gitlab-ci.yml" in
  expect "GitHub matrix must lower to parameters"
    (count_kind Ir.Parameter github.graph >= 1);
  expect "GitLab matrix must lower to parameters"
    (count_kind Ir.Parameter gitlab.graph >= 1);
  let github_shape = Frontend.semantic_shape github.graph
  and gitlab_shape = Frontend.semantic_shape gitlab.graph in
  expect "common shape must include control edges"
    (github_shape.control_edges > 0 && gitlab_shape.control_edges > 0);
  ignore (require_node Ir.Workflow github.graph)

let tests : test list =
  [
    ( "four frontends execute the same five phase pipeline",
      pipeline_contract_test );
    ("provider detection is path and schema aware", detection_test);
    ("expressions retain phase trust and secrecy", expression_contract_test);
    ( "unlocked dependencies become call plus Unknown",
      unresolved_dependency_test );
    ("matrix and graph shape lower into shared concepts", matrix_and_shape_test);
  ]

let () =
  let failures = ref 0 in
  List.iter
    (fun (name, run) ->
      try
        run ();
        Printf.printf "ok - %s\n%!" name
      with
      | Failed message ->
          incr failures;
          Printf.eprintf "not ok - %s: %s\n%!" name message
      | error ->
          incr failures;
          Printf.eprintf "not ok - %s: unexpected %s\n%!" name
            (Printexc.to_string error))
    tests;
  if !failures > 0 then exit 1
