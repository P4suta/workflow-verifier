type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let compile provider path source =
  match Frontend.compile_string ~provider ~path ~source () with
  | Ok compilation -> compilation
  | Error problems ->
      fail "frontend rejected input: %s"
        (String.concat "; "
           (List.map (fun problem -> problem.Frontend_intf.message) problems))

let nodes kind graph =
  List.filter (fun (node : Ir.node) -> node.kind = kind) graph.Ir.nodes

let named kind name graph =
  List.find_opt
    (fun (node : Ir.node) -> node.kind = kind && node.name = name)
    graph.Ir.nodes

let require kind name graph =
  match named kind name graph with
  | Some node -> node
  | None -> fail "missing %s %S" (Ir.kind_name kind) name

let edge ?label kind (source : Ir.node) (target : Ir.node) graph =
  List.exists
    (fun (candidate : Ir.edge) ->
      candidate.kind = kind
      && candidate.from_ = source.Ir.id
      && candidate.to_ = target.Ir.id
      && Option.fold ~none:true
           ~some:(fun value -> candidate.label = Some value)
           label)
    graph.Ir.edges

let dependency_reaches label (source : Ir.node) (target : Ir.node) graph =
  let rec reachable visited id =
    id = target.id
    ||
    if List.mem id visited then false
    else
      graph.Ir.edges
      |> List.filter (fun (edge : Ir.edge) ->
          edge.kind = Ir.Control && edge.from_ = id)
      |> List.exists (fun (edge : Ir.edge) ->
          reachable (id :: visited) edge.to_)
  in
  graph.Ir.edges
  |> List.filter (fun (edge : Ir.edge) ->
      edge.kind = Ir.Control && edge.from_ = source.id
      && edge.label = Some label)
  |> List.exists (fun (edge : Ir.edge) -> reachable [] edge.to_)

let problem code compilation =
  List.exists
    (fun (candidate : Frontend_intf.problem) -> candidate.code = code)
    compilation.Frontend_intf.problems

let dependency_kind kind compilation =
  List.exists
    (fun (dependency : Frontend_intf.dependency) -> dependency.kind = kind)
    compilation.Frontend_intf.dependencies

let find_dependency reference compilation =
  List.find_opt
    (fun (dependency : Frontend_intf.dependency) ->
      dependency.reference = reference)
    compilation.Frontend_intf.dependencies

let expect_valid graph =
  let describe id =
    match Ir.find_node graph id with
    | Some node ->
        Ir.kind_name node.kind ^ ":" ^ node.name ^ ":"
        ^ Ir.phase_name node.phase
    | None -> id
  in
  match Ir.validate graph with
  | [] -> ()
  | issues ->
      fail "invalid IR: %s"
        (String.concat "; "
           (List.map
              (fun issue ->
                issue.Ir.code ^ "["
                ^ String.concat "," (List.map describe issue.node_ids)
                ^ "]")
              issues))

let github_semantics () =
  let source =
    {|
name: secure delivery
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: make lint
  deploy:
    needs: lint
    if: github.event.pull_request.draft == false
    environment: production
    runs-on: [self-hosted, linux]
    strategy:
      matrix:
        target: [staging, production]
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - id: build
        if: matrix.target == 'production'
        uses: owner/action@v1
        with:
          title: ${{ github.event.pull_request.title }}
      - run: deploy ${{ secrets.DEPLOY_TOKEN }}
|}
  in
  let result = compile Ir.Github ".github/workflows/delivery.yml" source in
  let graph = result.graph in
  expect "GitHub events lower to triggers"
    (List.length (nodes Ir.Trigger graph) = 2);
  let lint = require Ir.Job "lint" graph
  and deploy = require Ir.Job "deploy" graph in
  expect "needs becomes an ordered control dependency"
    (dependency_reaches "needs" lint deploy graph);
  expect "job and step if expressions become gates"
    (List.length (nodes Ir.Gate graph) >= 2);
  expect "gates retain symbolic conditions"
    (List.for_all
       (fun (node : Ir.node) -> Condition.atoms node.condition <> [])
       (nodes Ir.Gate graph));
  let workflow = List.hd (nodes Ir.Workflow graph) in
  expect "contents read is represented"
    (List.mem Ir.Repository_read workflow.capabilities);
  expect "id-token write is OIDC, not repository write"
    (List.mem Ir.Oidc workflow.capabilities
    && not (List.mem Ir.Repository_write workflow.capabilities));
  expect "self-hosted runner persistence is explicit"
    (List.mem Ir.Self_hosted_persistence deploy.capabilities);
  let environment = require Ir.Resource "environment:production" graph in
  expect "an environment grants deployment without duplicating its effect"
    (environment.effects = []
    && List.mem Ir.Deployment environment.capabilities
    && List.mem Ir.Deployment_change deploy.effects);
  ignore (require Ir.Resource "output:deploy.digest" graph);
  expect "matrix is planned explicitly"
    (Option.is_some (named Ir.Parameter "matrix.target" graph));
  expect "GitHub uses is typed as an action dependency"
    (dependency_kind Frontend_intf.Action result);
  expect_valid graph

let github_attestation_profile () =
  let revision = String.make 40 'a' in
  let reference = "actions/attest@" ^ revision in
  let source =
    "on: workflow_dispatch\n"
    ^ "jobs:\n  attest:\n    runs-on: ubuntu-latest\n"
    ^ "    permissions:\n      id-token: write\n"
    ^ "      attestations: write\n      artifact-metadata: write\n"
    ^ "    steps:\n      - uses: " ^ reference ^ "\n"
    ^ "        with:\n          subject-checksums: dist/SHA256SUMS\n"
  in
  let result = compile Ir.Github ".github/workflows/attest.yml" source in
  let call = require Ir.Call reference result.graph
  and job = require Ir.Job "attest" result.graph in
  expect "attestation permissions lower to artifact and OIDC capabilities"
    (List.mem Ir.Oidc job.capabilities
    && List.mem Ir.Artifact_write job.capabilities
    && not (List.mem Ir.Repository_write job.capabilities));
  expect "actions/attest publishes an artifact using an OIDC credential"
    (List.mem Ir.Artifact_publish call.effects
    && List.mem Ir.Credential_use call.effects
    && List.mem Ir.Network_request call.effects);
  expect_valid result.graph

let gitlab_semantics () =
  let source =
    {|
include:
  - component: gitlab.example/components/build@1.2
variables:
  GLOBAL_MODE: strict
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
stages: [build, deploy]
.base:
  before_script: [prepare]
lint:
  stage: build
  script: [make lint]
deploy:
  extends: .base
  stage: deploy
  needs: [lint]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  environment: production
  cache:
    key: shared
    paths: [vendor]
  artifacts:
    paths: [dist]
  script: [publish]
child:
  trigger:
    include: child.yml
|}
  in
  let result = compile Ir.Gitlab ".gitlab-ci.yml" source in
  let graph = result.graph in
  expect "declared stages are nodes" (List.length (nodes Ir.Stage graph) = 2);
  let lint = require Ir.Job "lint" graph
  and deploy = require Ir.Job "deploy" graph in
  expect "GitLab needs is a control dependency"
    (dependency_reaches "needs" lint deploy graph);
  expect "rules become gates" (List.length (nodes Ir.Gate graph) >= 2);
  ignore (require Ir.Call "extends:.base" graph);
  ignore (require Ir.Call "child:child.yml" graph);
  let environment = require Ir.Resource "environment:production" graph in
  expect "GitLab environment effects occur on the deployment job"
    (environment.effects = []
    && List.mem Ir.Deployment_change deploy.effects);
  ignore (require Ir.Resource "cache:deploy" graph);
  ignore (require Ir.Resource "artifact:deploy" graph);
  expect "hidden templates are not executable jobs"
    (Option.is_none (named Ir.Job ".base" graph));
  expect "GitLab component includes retain their dependency kind"
    (dependency_kind Frontend_intf.Component result);
  expect_valid graph

let azure_semantics () =
  let source =
    {|
trigger: [main]
pr: [main]
resources:
  repositories:
    - repository: shared
      type: github
      name: org/templates
      ref: refs/tags/v1
variables:
  configuration: Release
parameters:
  - name: deploy
    type: boolean
    default: false
stages:
  - stage: Build
    jobs:
      - job: compile
        strategy:
          matrix:
            linux:
              image: ubuntu-latest
        steps:
          - checkout: self
          - task: Bash@3
          - template: shared.yml@shared
  - stage: Deploy
    dependsOn: Build
    condition: and(succeeded(), eq(${{ parameters.deploy }}, true))
    jobs:
      - deployment: production
        environment: production
        steps:
          - pwsh: ./deploy.ps1 $(System.AccessToken)
|}
  in
  let result = compile Ir.Azure "azure-pipelines.yml" source in
  let graph = result.graph in
  expect "CI and PR triggers are distinct"
    (List.length (nodes Ir.Trigger graph) = 2);
  let build = require Ir.Stage "Build" graph
  and deploy = require Ir.Stage "Deploy" graph in
  expect "stage dependsOn is explicit"
    (dependency_reaches "dependsOn" build deploy graph);
  expect "stage condition is a gate" (List.length (nodes Ir.Gate graph) >= 1);
  ignore (require Ir.Resource "repository:shared" graph);
  ignore (require Ir.Resource "variable:configuration" graph);
  let environment = require Ir.Resource "environment:production" graph
  and production = require Ir.Job "production" graph in
  expect "Azure environment effects occur on the deployment job"
    (environment.effects = []
    && List.mem Ir.Deployment_change production.effects);
  ignore (require Ir.Parameter "matrix.linux" graph);
  ignore (require Ir.Call "checkout:self" graph);
  ignore (require Ir.Call "Bash@3" graph);
  ignore (require Ir.Call "shared.yml@shared" graph);
  expect "Azure resolver inputs distinguish repositories tasks and templates"
    (dependency_kind Frontend_intf.Repository result
    && dependency_kind Frontend_intf.Task result
    && dependency_kind Frontend_intf.Template result);
  expect_valid graph

let circleci_semantics () =
  let source =
    {|
version: 2.1
setup: true
parameters:
  deploy:
    type: boolean
    default: false
orbs:
  node: circleci/node@5
executors:
  linux:
    docker:
      - image: cimg/base:current
commands:
  greet:
    parameters:
      subject:
        type: string
    steps:
      - run: echo hello
jobs:
  build:
    executor: linux
    steps:
      - greet:
          subject: world
      - node/test
workflows:
  delivery:
    jobs:
      - approve:
          type: approval
      - build:
          requires: [approve]
          filters:
            branches:
              only: main
          matrix:
            parameters:
              image: [one, two]
|}
  in
  let result = compile Ir.Circleci ".circleci/config.yml" source in
  let graph = result.graph in
  ignore (require Ir.Parameter "pipeline.deploy" graph);
  ignore (require Ir.Resource "executor:linux" graph);
  let command_call = require Ir.Call "command:greet" graph
  and command_definition =
    require Ir.Resource "command-definition:greet" graph
  in
  ignore (require Ir.Command "echo hello" graph);
  expect "local command calls link to their lowered definitions"
    (edge Ir.Call_edge command_call command_definition graph);
  ignore (require Ir.Call "orb:node/test" graph);
  let approval = require Ir.Gate "approval:approve" graph
  and build = require Ir.Job "build" graph in
  expect "workflow requires preserves authorization order"
    (dependency_reaches "requires" approval build graph);
  expect "filters lower to a gate" (List.length (nodes Ir.Gate graph) >= 2);
  ignore (require Ir.Parameter "matrix.image" graph);
  expect "dynamic config is an explicit workflow-changing effect"
    (List.exists
       (fun (node : Ir.node) -> List.mem Ir.Workflow_change node.effects)
       graph.nodes);
  expect "CircleCI resolver inputs distinguish orbs and images"
    (dependency_kind Frontend_intf.Orb result
    && dependency_kind Frontend_intf.Container_image result);
  expect_valid graph

let correctness_diagnostics () =
  let github =
    compile Ir.Github ".github/workflows/bad.yml" "name: bad\non: push\n"
  and gitlab =
    compile Ir.Gitlab ".gitlab-ci.yml"
      "a:\n  needs: [b]\n  script: x\nb:\n  needs: [a]\n  script: y\n"
  and azure =
    compile Ir.Azure "azure-pipelines.yml"
      "stages:\n\
      \  - stage: A\n\
      \    dependsOn: B\n\
      \  - stage: B\n\
      \    dependsOn: A\n"
  and circle =
    compile Ir.Circleci ".circleci/config.yml"
      "version: 2.1\nworkflows:\n  main:\n    jobs: [missing]\njobs: {}\n"
  in
  expect "GitHub requires jobs" (problem "GH-SCHEMA-JOBS" github);
  expect "GitLab needs cycles are diagnosed" (problem "GL-NEEDS-CYCLE" gitlab);
  expect "Azure dependency cycles are diagnosed"
    (problem "AZ-DEPENDENCY-CYCLE" azure);
  expect "CircleCI workflow references are checked"
    (problem "CC-UNKNOWN-JOB" circle)

let dependency_locator_semantics () =
  let image_digest = String.make 64 'a' in
  let github =
    compile Ir.Github ".github/workflows/container.yml"
      ("name: container\n\
        on: push\n\
        jobs:\n\
       \  run:\n\
       \    runs-on: ubuntu-latest\n\
       \    steps:\n\
       \      - uses: docker://ghcr.io/acme/tool@sha256:" ^ image_digest ^ "\n"
      )
  in
  expect "docker:// uses is a container image, not an action"
    (match
       find_dependency
         ("docker://ghcr.io/acme/tool@sha256:" ^ image_digest)
         github
     with
    | Some dependency -> dependency.kind = Frontend_intf.Container_image
    | None -> false);
  let revision = String.make 40 'b' in
  let gitlab =
    compile Ir.Gitlab ".gitlab-ci.yml"
      ("include:\n  - project: acme/ci\n    ref: " ^ revision
     ^ "\n\
       \    file:\n\
       \      - /templates/build.yml\n\
       \      - /templates/test.yml\n\
        job:\n\
       \  script: echo root\n\
        child:\n\
       \  trigger:\n\
       \    include:\n\
       \      - local: /child.yml\n")
  in
  let project_reference file = "acme/ci:" ^ file ^ "@" ^ revision in
  List.iter
    (fun file ->
      match find_dependency (project_reference file) gitlab with
      | Some
          {
            locator =
              Frontend_intf.Repository_file
                {
                  repository = "acme/ci";
                  revision = Some actual_revision;
                  path;
                  repository_type = None;
                };
            _;
          } ->
          expect "GitLab project include retains its exact repository file"
            (actual_revision = revision && path = file)
      | _ -> fail "missing typed GitLab project include %s" file)
    [ "/templates/build.yml"; "/templates/test.yml" ];
  expect "a local child pipeline participates in dependency resolution"
    (match find_dependency "/child.yml" gitlab with
    | Some dependency -> dependency.kind = Frontend_intf.Include
    | None -> false);
  let azure =
    compile Ir.Azure "azure-pipelines.yml"
      "resources:\n\
      \  repositories:\n\
      \    - repository: shared\n\
      \      type: github\n\
      \      name: org/templates\n\
      \      ref: refs/tags/v1\n\
       jobs:\n\
      \  - job: build\n\
      \    steps:\n\
      \      - template: shared.yml@shared\n"
  in
  expect "Azure template aliases retain repository type path and revision"
    (match find_dependency "shared.yml@shared" azure with
    | Some
        {
          locator =
            Frontend_intf.Repository_file
              {
                repository = "org/templates";
                revision = Some "refs/tags/v1";
                path = "shared.yml";
                repository_type = Some "github";
              };
          _;
        } -> true
    | _ -> false)

let tests : test list =
  [
    ("GitHub semantic surface", github_semantics);
    ( "GitHub attestation capability/effect profile",
      github_attestation_profile );
    ("GitLab semantic surface", gitlab_semantics);
    ("Azure semantic surface", azure_semantics);
    ("CircleCI semantic surface", circleci_semantics);
    ("provider correctness diagnostics", correctness_diagnostics);
    ( "provider dependencies retain typed resolution locators",
      dependency_locator_semantics );
  ]

let () =
  Printexc.record_backtrace true;
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
          Printf.eprintf "not ok - %s: unexpected %s\n%s%!" name
            (Printexc.to_string error)
            (Printexc.get_backtrace ()))
    tests;
  if !failures > 0 then exit 1
