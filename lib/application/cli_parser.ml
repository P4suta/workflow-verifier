open Cmdliner

type invocation = { command : string; arguments : string list }

type outcome =
  | Invoke of invocation
  | Help of string
  | Version of string
  | Error of string

let option name = function
  | None -> []
  | Some value -> [ "--" ^ name; value ]

let flag name = function
  | true -> [ "--" ^ name ]
  | false -> []

let repeated name values =
  List.concat_map (fun value -> [ "--" ^ name; value ]) values

let positional_value value = "\000" ^ value

let positional = function
  | None -> []
  | Some value -> [ positional_value value ]

let positionals values = List.map positional_value values

let invocation command arguments =
  { command; arguments = List.concat arguments }

let string_opt name docv doc =
  Arg.(value & opt (some string) None & info [ name ] ~docv ~doc)

let enum_opt name values default doc =
  Arg.(
    value
    & opt (enum (List.map (fun value -> (value, value)) values)) default
    & info [ name ] ~docv:(String.uppercase_ascii name) ~doc)

let enum_optional name values doc =
  Arg.(
    value
    & opt (some (enum (List.map (fun value -> (value, value)) values))) None
    & info [ name ] ~docv:(String.uppercase_ascii name) ~doc)

let bool_flag name doc = Arg.(value & flag & info [ name ] ~doc)

let target =
  Arg.(
    value
    & pos 0 (some string) None
    & info [] ~docv:"TARGET" ~doc:"Workflow file or repository root.")

let common_term =
  let config =
    string_opt "config" "FILE" "Read repository config-v2 from $(docv)."
  and policy =
    string_opt "policy" "FILE" "Read trusted policy config-v2 from $(docv)."
  and trusted =
    bool_flag "trust-repository-config"
      "Treat the repository config as trusted policy. This is an explicit \
       privilege grant."
  and lockfile =
    string_opt "lockfile" "FILE" "Read the immutable lock from $(docv)."
  in
  let make config policy trusted lockfile =
    if Option.is_some config && Option.is_some policy then
      `Error (true, "--config and --policy are mutually exclusive")
    else
      `Ok
        (option "config" config @ option "policy" policy
        @ flag "trust-repository-config" trusted
        @ option "lockfile" lockfile)
  in
  Term.(ret (const make $ config $ policy $ trusted $ lockfile))

let exits =
  [
    Cmd.Exit.info 0 ~doc:"Pass.";
    Cmd.Exit.info 1 ~doc:"A finding or scenario step failure.";
    Cmd.Exit.info 2 ~doc:"Invalid command input, config, or protocol.";
    Cmd.Exit.info 3 ~doc:"Strict incomplete result.";
    Cmd.Exit.info 4 ~doc:"Internal product error.";
    Cmd.Exit.info 5
      ~doc:"Sandbox infrastructure could not enforce the requested controls.";
  ]

let command_info name doc =
  Cmd.info name ~doc ~exits
    ~man:
      [
        `S Manpage.s_bugs;
        `P
          "Report defects at \
           https://github.com/P4suta/workflow-verifier/issues.";
      ]

let check_cmd =
  let format =
    enum_opt "format" [ "text"; "json"; "sarif" ] "text" "Output format."
  and output = string_opt "output" "FILE" "Atomically write output to $(docv)."
  and persona =
    enum_optional "persona"
      [ "gate"; "audit"; "paranoid" ]
      "Override the configured analysis persona."
  and strict = bool_flag "strict" "Return 3 when analysis is incomplete."
  and cache_mode =
    enum_opt "cache-mode" [ "off"; "user" ] "off"
      "Cache mode; CI should use off."
  in
  let make common format output persona strict cache_mode target =
    invocation "check"
      [
        common;
        option "format" (Some format);
        option "output" output;
        option "persona" persona;
        flag "strict" strict;
        option "cache-mode" (Some cache_mode);
        positional target;
      ]
  in
  Cmd.v
    (command_info "check" "Run static analysis and the policy gate.")
    Term.(
      const make $ common_term $ format $ output $ persona $ strict $ cache_mode
      $ target)

let resolve_cmd =
  let allow_network =
    bool_flag "allow-network"
      "Permit resolver HTTPS requests for this invocation."
  and update = bool_flag "update" "Refresh immutable dependency identities." in
  let make common allow_network update target =
    invocation "resolve"
      [
        common;
        flag "allow-network" allow_network;
        flag "update" update;
        positional target;
      ]
  in
  Cmd.v
    (command_info "resolve" "Resolve and lock remote dependencies.")
    Term.(const make $ common_term $ allow_network $ update $ target)

let explain_cmd =
  let rule =
    Arg.(
      required
      & pos 0 (some string) None
      & info [] ~docv:"RULE_ID" ~doc:"Finding rule identifier.")
  and target =
    Arg.(value & pos 1 (some string) None & info [] ~docv:"TARGET")
  in
  let make common rule target =
    invocation "explain" [ common; positionals [ rule ]; positional target ]
  in
  Cmd.v
    (command_info "explain" "Explain a finding with its trace.")
    Term.(const make $ common_term $ rule $ target)

let graph_cmd =
  let kind =
    enum_opt "kind"
      [ "all"; "control"; "dataflow"; "call"; "capability" ]
      "all" "Graph view."
  and format =
    enum_opt "format" [ "json"; "dot" ] "json" "Graph output format."
  in
  let make common kind format target =
    invocation "graph"
      [
        common;
        option "kind" (Some kind);
        option "format" (Some format);
        positional target;
      ]
  in
  Cmd.v
    (command_info "graph" "Emit a semantic graph.")
    Term.(const make $ common_term $ kind $ format $ target)

let diff_cmd =
  let base = Arg.(required & pos 0 (some string) None & info [] ~docv:"BASE")
  and head = Arg.(required & pos 1 (some string) None & info [] ~docv:"HEAD") in
  let make common base head =
    invocation "diff" [ common; positionals [ base; head ] ]
  in
  Cmd.v
    (command_info "diff" "Compare two semantic workflow snapshots.")
    Term.(const make $ common_term $ base $ head)

let fix_cmd =
  let apply =
    bool_flag "apply" "Apply the complete validated edit transaction."
  in
  let make common apply target =
    invocation "fix" [ common; flag "apply" apply; positional target ]
  in
  Cmd.v
    (command_info "fix" "Propose or apply behavior-preserving fixes.")
    Term.(const make $ common_term $ apply $ target)

let policy_test_cmd =
  let fixtures =
    Arg.(required & pos 0 (some string) None & info [] ~docv:"FIXTURES")
  in
  let make common fixtures =
    invocation "policy" [ [ "test" ]; common; positionals [ fixtures ] ]
  in
  Cmd.v
    (command_info "test" "Evaluate policy expectation fixtures.")
    Term.(const make $ common_term $ fixtures)

let policy_cmd =
  Cmd.group
    (command_info "policy" "Work with trusted organization policy.")
    [ policy_test_cmd ]

let sandbox_plan_term mode common scenario job event runner inputs matrix
    variables secrets backend allow_network network_destination target =
  if
    Option.is_some scenario
    && (Option.is_some job || Option.is_some event || Option.is_some runner
      || inputs <> [] || matrix <> [] || variables <> [])
  then
    `Error (true, "--scenario cannot be combined with scenario shortcut options")
  else if Option.is_none scenario && Option.is_none job then
    `Error (true, "sandbox plan/run requires --scenario FILE or --job JOB")
  else if allow_network && network_destination = [] then
    `Error
      ( true,
        "--allow-workflow-network requires --network-destination \
         HTTPS_ORIGIN/PATH" )
  else if (not allow_network) && network_destination <> [] then
    `Error (true, "--network-destination requires --allow-workflow-network")
  else
    `Ok
      (invocation "sandbox"
         [
           [ mode ];
           common;
           option "scenario" scenario;
           option "job" job;
           option "event" event;
           option "runner" runner;
           repeated "input" inputs;
           repeated "matrix" matrix;
           repeated "variable" variables;
           repeated "secret" secrets;
           option "backend" backend;
           flag "allow-workflow-network" allow_network;
           repeated "network-destination" network_destination;
           positional target;
         ])

let sandbox_exec_cmd name =
  let scenario = string_opt "scenario" "FILE" "Read scenario-v1 from $(docv)."
  and job = string_opt "job" "JOB" "Select exactly one job."
  and event = string_opt "event" "EVENT" "Concrete provider event."
  and runner = string_opt "runner" "PLATFORM" "Concrete runner platform."
  and inputs =
    Arg.(value & opt_all string [] & info [ "input" ] ~docv:"NAME=VALUE")
  and matrix =
    Arg.(value & opt_all string [] & info [ "matrix" ] ~docv:"NAME=VALUE")
  and variables =
    Arg.(value & opt_all string [] & info [ "variable" ] ~docv:"NAME=VALUE")
  and secrets = Arg.(value & opt_all string [] & info [ "secret" ] ~docv:"NAME")
  and backend = string_opt "backend" "BACKEND" "Typed sandbox backend."
  and allow_network =
    bool_flag "allow-workflow-network"
      "Grant policy-constrained scenario egress."
  and destinations =
    Arg.(
      value & opt_all string []
      & info [ "network-destination" ] ~docv:"HTTPS_ORIGIN/PATH")
  in
  let make common scenario job event runner inputs matrix variables secrets
      backend allow_network destinations target =
    sandbox_plan_term name common scenario job event runner inputs matrix
      variables secrets backend allow_network destinations target
  in
  Cmd.v
    (command_info name
       (if name = "plan" then "Create a scenario-bound runner-v2 plan."
        else "Execute a complete runner-v2 plan."))
    Term.(
      ret
        (const make $ common_term $ scenario $ job $ event $ runner $ inputs
       $ matrix $ variables $ secrets $ backend $ allow_network $ destinations
       $ target))

let sandbox_replay_cmd =
  let evidence =
    Arg.(required & pos 0 (some string) None & info [] ~docv:"EVIDENCE")
  in
  Cmd.v
    (command_info "replay" "Read and authenticate evidence-v2 offline.")
    Term.(
      const (fun evidence ->
          invocation "sandbox" [ [ "replay" ]; positionals [ evidence ] ])
      $ evidence)

let sandbox_verify_cmd =
  let plan = Arg.(required & pos 0 (some string) None & info [] ~docv:"PLAN")
  and evidence =
    Arg.(required & pos 1 (some string) None & info [] ~docv:"EVIDENCE")
  in
  Cmd.v
    (command_info "verify"
       "Verify evidence-v2 and referenced artifacts offline.")
    Term.(
      const (fun plan evidence ->
          invocation "sandbox" [ [ "verify" ]; positionals [ plan; evidence ] ])
      $ plan $ evidence)

let sandbox_audit_cmd =
  let plan = Arg.(required & pos 0 (some string) None & info [] ~docv:"PLAN")
  and evidence =
    Arg.(required & pos 1 (some string) None & info [] ~docv:"EVIDENCE")
  and target =
    Arg.(value & pos 2 (some string) None & info [] ~docv:"TARGET")
  in
  let make common plan evidence target =
    invocation "sandbox"
      [ [ "audit" ]; common; positionals [ plan; evidence ]; positional target ]
  in
  Cmd.v
    (command_info "audit" "Reconcile static facts with authenticated evidence.")
    Term.(const make $ common_term $ plan $ evidence $ target)

let sandbox_cmd =
  Cmd.group
    (command_info "sandbox" "Plan, run, and verify concrete scenarios.")
    [
      sandbox_exec_cmd "plan";
      sandbox_exec_cmd "run";
      sandbox_replay_cmd;
      sandbox_verify_cmd;
      sandbox_audit_cmd;
    ]

let doctor_cmd =
  let format =
    enum_opt "format" [ "text"; "json" ] "text" "Doctor output format."
  in
  Cmd.v
    (command_info "doctor" "Inspect every backend and its fail-closed reason.")
    Term.(
      const (fun format ->
          invocation "doctor" [ option "format" (Some format) ])
      $ format)

let completion_cmd =
  let shell =
    Arg.(
      required
      & pos 0
          (some
             (enum
                [
                  ("bash", "bash");
                  ("zsh", "zsh");
                  ("fish", "fish");
                  ("powershell", "powershell");
                ]))
          None
      & info [] ~docv:"SHELL")
  in
  Cmd.v
    (command_info "completion" "Emit a shell completion script.")
    Term.(const (fun shell -> invocation "completion" [ [ shell ] ]) $ shell)

let migrate_cmd =
  let input =
    Arg.(
      required & pos 0 (some string) None & info [] ~docv:"OLD_CONFIG_OR_LOCK")
  and output =
    string_opt "output" "FILE"
      "Atomically write migrated config-v2 or lock-v2 to $(docv)."
  and suppression_owner =
    string_opt "suppression-owner" "OWNER"
      "Owner to attach to every legacy suppression. Required when suppressions \
       exist."
  and suppression_expiry =
    string_opt "suppression-expiry" "YYYY-MM-DD"
      "Expiry to attach to every legacy suppression. Required when \
       suppressions exist."
  in
  let make input output suppression_owner suppression_expiry =
    invocation "migrate"
      [
        option "output" output;
        option "suppression-owner" suppression_owner;
        option "suppression-expiry" suppression_expiry;
        positionals [ input ];
      ]
  in
  Cmd.v
    (command_info "migrate"
       "Validate and migrate unpublished config-v1 or lock-v1 input.")
    Term.(const make $ input $ output $ suppression_owner $ suppression_expiry)

let version_cmd =
  Cmd.v
    (command_info "version" "Print the product version.")
    Term.(const { command = "version"; arguments = [] })

let root =
  let doc =
    "semantic verifier and concrete-scenario sandbox for CI workflows"
  in
  let man =
    [
      `S Manpage.s_description;
      `P
        "workflow-verifier is offline and telemetry-free by default. Network, \
         secrets, writes, and execution each require explicit grants.";
      `P
        "The sandbox replays only a concrete scenario. Unsupported runner \
         behavior is reported as Incomplete and is never guessed.";
      `S "TRUST";
      `P
        "Repository configuration may only make diagnostics stricter unless \
         --trust-repository-config or an external --policy is supplied.";
      `S "DOCUMENTATION";
      `P "https://workflow-verifier.dev/docs/cli-v0.1";
    ]
  in
  let default = Term.(ret (const (`Help (`Pager, None)))) in
  Cmd.group ~default
    (Cmd.info "workflow-verifier" ~version:"0.1.0" ~doc ~man ~exits)
    [
      check_cmd;
      resolve_cmd;
      explain_cmd;
      graph_cmd;
      diff_cmd;
      fix_cmd;
      policy_cmd;
      sandbox_cmd;
      doctor_cmd;
      completion_cmd;
      migrate_cmd;
      version_cmd;
    ]

let parse ~argv =
  let help_buffer = Buffer.create 2048 and error_buffer = Buffer.create 1024 in
  let help = Format.formatter_of_buffer help_buffer
  and err = Format.formatter_of_buffer error_buffer in
  (match Option.bind (Sys.getenv_opt "COLUMNS") int_of_string_opt with
  | Some columns when columns >= 40 && columns <= 240 ->
      Format.pp_set_margin help columns;
      Format.pp_set_margin err columns
  | _ -> ());
  let result = Cmd.eval_value ~help ~err ~catch:false ~argv root in
  Format.pp_print_flush help ();
  Format.pp_print_flush err ();
  let help_text = Buffer.contents help_buffer
  and error_text = Buffer.contents error_buffer in
  match result with
  | Ok (`Ok invocation) -> Invoke invocation
  | Ok `Help -> Help help_text
  | Ok `Version -> Version help_text
  | Error (`Parse | `Term | `Exn) -> Error error_text
