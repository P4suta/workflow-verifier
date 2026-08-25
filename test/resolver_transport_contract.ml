type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let dependency ?(locator = Frontend_intf.Direct_reference) provider kind
    reference =
  {
    Frontend_intf.provider;
    kind;
    reference;
    locator;
    span = Span.none;
    mutability = Frontend_intf.Mutable;
    status = Frontend_intf.Unresolved (Unknown.Unresolved_dependency reference);
  }

let response ?(status = 200) url body =
  {
    Resolver_transport.status;
    body;
    effective_url = url;
    peer_ip = "93.184.216.34";
  }

let github_action_test () =
  let revision = String.make 40 'a' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request :: !requests;
    if
      Util.starts_with
        ~prefix:"https://api.github.com/repos/actions/checkout/commits/"
        request.url
    then Ok (response request.url (revision ^ "\n"))
    else if
      request.url
      = "https://codeload.github.com/actions/checkout/tar.gz/" ^ revision
    then Ok (response request.url "immutable archive")
    else if
      request.url
      = "https://raw.githubusercontent.com/actions/checkout/" ^ revision
        ^ "/action.yml"
    then
      Ok
        (response request.url
           "name: checkout\nruns:\n  using: node20\n  main: dist/index.js\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.Resolver.fetch
        (dependency Ir.Github Frontend_intf.Action "actions/checkout@v4")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "GitHub ref resolves to an exact commit" (fetched.revision = revision);
  expect "the complete immutable source archive is hashed"
    (fetched.content = "immutable archive");
  expect "source provenance names the immutable tree"
    (fetched.source = "https://github.com/actions/checkout/tree/" ^ revision);
  expect "exact action metadata is retained for semantic inference"
    (match fetched.semantic_source with
    | Some source ->
        source.path = "action.yml"
        && Util.contains ~needle:"node20" source.content
    | None -> false);
  expect "resolution performs commit, archive, and metadata requests"
    (List.length !requests = 3)

let gitlab_component_test () =
  let revision = String.make 40 'b' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request.url :: !requests;
    if Util.contains ~needle:"/repository/commits/1.2.3" request.url then
      Ok (response request.url ("{\"id\":\"" ^ revision ^ "\"}"))
    else if Util.contains ~needle:"/repository/archive.tar.gz?sha=" request.url
    then Ok (response request.url "gitlab archive")
    else if
      Util.contains ~needle:"templates%2Faws%2Ftemplate.yml/raw" request.url
    then Ok (response request.url "deploy:\n  script: echo exact\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency Ir.Gitlab Frontend_intf.Component
           "gitlab.com/acme/components/deploy/aws@1.2.3")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "GitLab component resolves its project commit"
    (fetched.revision = revision);
  expect "GitLab component snapshots the project archive"
    (fetched.content = "gitlab archive");
  expect "GitLab component retains its exact template source"
    (Option.is_some fetched.semantic_source);
  expect "GitLab resolver performs commit, archive, and template requests"
    (List.length !requests = 3)

let gitlab_project_file_test () =
  let revision = String.make 40 'd' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request.url :: !requests;
    if Util.contains ~needle:("/repository/commits/" ^ revision) request.url
    then Ok (response request.url ("{\"id\":\"" ^ revision ^ "\"}"))
    else if Util.contains ~needle:("archive.tar.gz?sha=" ^ revision) request.url
    then Ok (response request.url "project include archive")
    else if
      Util.contains ~needle:"repository/files/templates%2Fbuild.yml/raw"
        request.url
    then Ok (response request.url "build:\n  script: echo exact\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency
           ~locator:
             (Frontend_intf.Repository_file
                {
                  repository = "acme/ci";
                  revision = Some revision;
                  path = "/templates/build.yml";
                  repository_type = None;
                })
           Ir.Gitlab Frontend_intf.Repository
           ("acme/ci:/templates/build.yml@" ^ revision))
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "GitLab project include resolves the declared immutable revision"
    (fetched.revision = revision);
  expect "GitLab project include provenance identifies the exact file"
    (Util.ends_with ~suffix:(revision ^ "/templates/build.yml") fetched.source);
  expect "GitLab project file retains exact semantic source"
    (match fetched.semantic_source with
    | Some source -> source.path = "templates/build.yml"
    | None -> false);
  expect "GitLab project file adds one exact raw-file request"
    (List.length !requests = 3)

let azure_task_test () =
  let revision = String.make 40 'c' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request.url :: !requests;
    if
      Util.contains ~needle:"/microsoft/azure-pipelines-tasks/commits/main"
        request.url
    then Ok (response request.url revision)
    else if Util.contains ~needle:("/tar.gz/" ^ revision) request.url then
      Ok (response request.url "azure task archive")
    else if
      Util.contains
        ~needle:(revision ^ "/Tasks/UsePythonVersionV0/task.json")
        request.url
    then
      Ok
        (response request.url
           "{\"execution\":{\"Node20_1\":{\"target\":\"main.js\"}}}")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency Ir.Azure Frontend_intf.Task "UsePythonVersion@0")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "Azure task source is commit pinned" (fetched.revision = revision);
  expect "Azure task provenance includes its task directory"
    (Util.ends_with
       ~suffix:(revision ^ "/Tasks/UsePythonVersionV0")
       fetched.source);
  expect "Azure task retains exact task.json metadata"
    (match fetched.semantic_source with
    | Some source ->
        Util.ends_with ~suffix:"task.json" source.path
        && Util.contains ~needle:"Node20_1" source.content
    | None -> false);
  expect "Azure task performs commit, archive, and metadata requests"
    (List.length !requests = 3)

let azure_github_template_test () =
  let revision = String.make 40 'e' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request.url :: !requests;
    if
      Util.contains ~needle:"/repos/org/templates/commits/refs%2Ftags%2Fv1"
        request.url
    then Ok (response request.url revision)
    else if Util.ends_with ~suffix:("/tar.gz/" ^ revision) request.url then
      Ok (response request.url "GitHub template archive")
    else if Util.ends_with ~suffix:(revision ^ "/shared.yml") request.url then
      Ok (response request.url "steps:\n  - script: echo exact\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency
           ~locator:
             (Frontend_intf.Repository_file
                {
                  repository = "org/templates";
                  revision = Some "refs/tags/v1";
                  path = "shared.yml";
                  repository_type = Some "github";
                })
           Ir.Azure Frontend_intf.Template "shared.yml@shared")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "Azure GitHub template alias resolves through an exact commit"
    (fetched.revision = revision);
  expect "Azure template provenance includes the selected path"
    (Util.ends_with ~suffix:(revision ^ "/shared.yml") fetched.source);
  expect "Azure GitHub template retains exact template source"
    (match fetched.semantic_source with
    | Some source -> source.path = "shared.yml"
    | None -> false);
  expect "Azure GitHub template adds one exact raw-file request"
    (List.length !requests = 3)

let azure_native_template_test () =
  let revision = String.make 40 'f' and requests = ref [] in
  let get (request : Resolver_transport.request) =
    requests := request.url :: !requests;
    if Util.contains ~needle:"/commits?" request.url then
      Ok
        (response request.url
           ("{\"value\":[{\"commitId\":\"" ^ revision ^ "\"}]}"))
    else if Util.contains ~needle:"recursionLevel=Full" request.url then
      Ok (response request.url "Azure Repos archive")
    else if Util.contains ~needle:"path=%2Fshared.yml" request.url then
      Ok (response request.url "steps:\n  - script: echo exact\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency
           ~locator:
             (Frontend_intf.Repository_file
                {
                  repository = "org/project/templates";
                  revision = Some "refs/tags/v1";
                  path = "shared.yml";
                  repository_type = Some "azurereposgit";
                })
           Ir.Azure Frontend_intf.Template "shared.yml@templates")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "native Azure template resolves to an exact commit"
    (fetched.revision = revision);
  expect "native Azure template retains exact file content"
    (match fetched.semantic_source with
    | Some source ->
        source.path = "shared.yml"
        && Util.contains ~needle:"echo exact" source.content
    | None -> false);
  expect "native Azure template performs commit, archive, and file requests"
    (List.length !requests = 3)

let circleci_orb_test () =
  let version_id = "7a09fb7b-4415-4aee-bc0f-a2f7f8395824" in
  let get (request : Resolver_transport.request) =
    if Util.contains ~needle:"/api/v3/orb/versions?filter%5Bref%5D=" request.url
    then
      Ok
        (response request.url
           ("{\"data\":[{\"attributes\":{\"version\":\"5.0.3\"},\"id\":\""
          ^ version_id ^ "\"}]}"))
    else if Util.ends_with ~suffix:(version_id ^ "/source") request.url then
      Ok (response request.url "version: 2.1\ncommands: {}\n")
    else Error ("unexpected URL " ^ request.url)
  in
  let network = Resolver_transport.make ~get ~allowed_sources:[] in
  let fetched =
    match
      network.fetch
        (dependency Ir.Circleci Frontend_intf.Orb "circleci/node@5.0.3")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "CircleCI production orb retains its immutable SemVer"
    (fetched.revision = "5.0.3");
  expect "CircleCI source endpoint supplies the lock content"
    (Util.contains ~needle:"commands" fetched.content);
  expect "CircleCI orb source is also semantic evidence"
    (match fetched.semantic_source with
    | Some source -> source.path = ".circleci/config.yml"
    | None -> false)

let direct_and_network_boundary_test () =
  let calls = ref 0 in
  let get (request : Resolver_transport.request) =
    incr calls;
    Ok (response request.url "remote include")
  in
  let network =
    Resolver_transport.make ~get
      ~allowed_sources:[ "https://ci.example.test/includes/" ]
  in
  let fetched =
    match
      network.fetch
        (dependency Ir.Gitlab Frontend_intf.Include
           "https://ci.example.test/includes/base.yml")
    with
    | Ok value -> value
    | Error message -> fail "%s" message
  in
  expect "direct include is locked by its exact content digest"
    (Util.starts_with ~prefix:"sha256:" fetched.revision);
  expect "direct include content is available to semantic inference"
    (Option.is_some fetched.semantic_source);
  let blocked =
    network.fetch
      (dependency Ir.Gitlab Frontend_intf.Include "https://127.0.0.1/internal")
  in
  expect "untrusted network origins fail before transport"
    (Result.is_error blocked && !calls = 1);
  let redirecting request =
    Ok
      {
        Resolver_transport.status = 200;
        body = "stolen";
        effective_url = "https://evil.example/redirect";
        peer_ip = "93.184.216.34";
      }
  in
  let redirected =
    (Resolver_transport.make ~get:redirecting
       ~allowed_sources:[ "https://ci.example.test/" ])
      .fetch
      (dependency Ir.Gitlab Frontend_intf.Include
         "https://ci.example.test/base.yml")
  in
  expect "redirects are checked against the same source boundary"
    (Result.is_error redirected)

let tests =
  [
    ("GitHub actions resolve to immutable source trees", github_action_test);
    ( "GitLab components resolve to immutable source trees",
      gitlab_component_test );
    ( "GitLab project includes resolve typed repository files",
      gitlab_project_file_test );
    ("Azure tasks resolve to the official immutable task tree", azure_task_test);
    ( "Azure template aliases resolve typed GitHub files",
      azure_github_template_test );
    ( "Azure Repos templates retain exact semantic source",
      azure_native_template_test );
    ( "CircleCI production orbs resolve through the source API",
      circleci_orb_test );
    ( "resolver transport enforces the network origin boundary",
      direct_and_network_boundary_test );
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
