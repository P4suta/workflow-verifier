exception Failed of string

let fail format = Printf.ksprintf (fun message -> raise (Failed message)) format
let expect message condition = if not condition then fail "%s" message

let parse provider phase source =
  match Expression.parse provider ~phase ~span:Span.none source with
  | Ok expression -> expression
  | Error problems ->
      fail "expression rejected: %s"
        (String.concat "; "
           (List.map (fun problem -> problem.Expression.message) problems))

let names expression =
  Expression.references expression
  |> List.map (fun reference -> reference.Expression.name)
  |> List.sort_uniq String.compare

let github () =
  let expression =
    parse Ir.Github Ir.Plan
      "${{ github.event.pull_request.title != '' && !cancelled() }}"
  in
  expect "GitHub comparison is boolean"
    (Expression.infer_type expression = Abstract_value.Bool_type);
  expect "GitHub property chain is one reference"
    (List.mem "github.event.pull_request.title" (names expression));
  let condition = Expression.to_condition expression in
  expect "logical structure reaches the ROBDD" (Condition.atoms condition <> [])

let gitlab () =
  let expression =
    parse Ir.Gitlab Ir.Plan
      "$CI_COMMIT_BRANCH =~ /^release\\// && $CI_PIPELINE_SOURCE == \"push\""
  in
  expect "GitLab regex and equality are boolean"
    (Expression.infer_type expression = Abstract_value.Bool_type);
  expect "both GitLab variables are retained"
    (names expression = [ "CI_COMMIT_BRANCH"; "CI_PIPELINE_SOURCE" ])

let azure () =
  let expression =
    parse Ir.Azure Ir.Compile "and(succeeded(), eq(parameters.deploy, true))"
  in
  expect "Azure function syntax is boolean"
    (Expression.infer_type expression = Abstract_value.Bool_type);
  expect "Azure parameters are compile-time references"
    (List.mem "parameters.deploy" (names expression));
  let runtime =
    parse Ir.Azure Ir.Compile "dependencies.Build.outputs['publish.digest']"
  in
  expect "runtime outputs are unavailable at compile time"
    (Expression.validate_phase runtime <> [])

let circleci () =
  let expression =
    parse Ir.Circleci Ir.Compile "<< pipeline.parameters.deploy >>"
  in
  expect "CircleCI delimiters are stripped"
    (names expression = [ "pipeline.parameters.deploy" ]);
  expect "pipeline parameters are available during compilation"
    (Expression.validate_phase expression = [])

let malformed () =
  match
    Expression.parse Ir.Github ~phase:Ir.Plan ~span:Span.none
      "${{ github.ref == }}"
  with
  | Error (_ :: _) -> ()
  | Error [] -> fail "malformed expression needs a diagnostic"
  | Ok _ -> fail "malformed expression was accepted"

let tests =
  [
    ("GitHub expression AST", github);
    ("GitLab rule expression AST", gitlab);
    ("Azure phase-aware expression AST", azure);
    ("CircleCI parameter expression AST", circleci);
    ("malformed expression diagnostics", malformed);
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
