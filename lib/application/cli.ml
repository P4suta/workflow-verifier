type io = {
  cwd : unit -> string;
  read_file : string -> (string, string) result;
  write_file : string -> string -> (unit, string) result;
  exists : string -> bool;
  is_directory : string -> bool;
  list_files : string -> string list;
  stdout : string -> unit;
  stderr : string -> unit;
}

type services = {
  resolver_network : (allowed_sources:string list -> Resolver.network) option;
  sandbox_execute :
    (source_root:string ->
    Sandbox_protocol.plan ->
    (Sandbox_run.t, string) result)
    option;
  platform : string;
  backend_probes : Sandbox_backend.probe list;
}

let help =
  "workflow-verifier 0.1.0-dev\n\n"
  ^ "Usage: workflow-verifier <command> [options] [path]\n\n" ^ "Commands:\n"
  ^ "  check             run static analysis and policy gate\n"
  ^ "  resolve           resolve and lock remote dependencies\n"
  ^ "  explain           show a rule's complete trace and capabilities\n"
  ^ "  graph             emit control/dataflow/call/capability graph\n"
  ^ "  diff              compare two semantic snapshots\n"
  ^ "  fix               print or explicitly apply safe CST edits\n"
  ^ "  policy test       run policy fixtures\n"
  ^ "  sandbox plan      create a content-addressed execution plan\n"
  ^ "  sandbox run       execute a complete plan in the selected backend\n"
  ^ "  sandbox replay    replay stored evidence\n"
  ^ "  sandbox audit     validate evidence and reconcile static facts\n"
  ^ "  doctor            inspect frontends, resolver, and sandbox controls\n\n"
  ^ "Exit codes: 0 pass, 1 finding, 2 input/config, 3 incomplete, 4 internal, \
     5 sandbox.\n"

type analysis = {
  config : Config.t;
  lock : Lockfile.t;
  sources : (string * string) list;
  compilations : Frontend_intf.compilation list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  report : Report.t;
}

let normalize = Util.normalize_slashes

let option_value name arguments =
  let rec loop = function
    | current :: value :: _ when current = name -> Some value
    | _ :: rest -> loop rest
    | [] -> None
  in
  loop arguments

let has name arguments = List.mem name arguments

let first_or default = function
  | value :: _ -> value
  | [] -> default

let option_names_with_values =
  [
    "--format";
    "--output";
    "--persona";
    "--kind";
    "--backend";
    "--lockfile";
    "--config";
    "--secret";
    "--fixtures";
    "--cache";
  ]

let positional arguments =
  let rec loop accumulator = function
    | [] -> List.rev accumulator
    | option :: _value :: rest when List.mem option option_names_with_values ->
        loop accumulator rest
    | option :: rest when Util.starts_with ~prefix:"-" option ->
        loop accumulator rest
    | value :: rest -> loop (value :: accumulator) rest
  in
  loop [] arguments

let path_join root name =
  if root = "." || root = "" then name
  else normalize (Filename.concat root name)

let root_for_target io target =
  if io.is_directory target then target
  else
    let parent = Filename.dirname target |> normalize in
    if parent = "" then "." else parent

type discovery = {
  candidates : (string * string) list;
  entrypoints : (string * string) list;
}

let yaml_path path =
  match Util.extension_lower path with
  | ".yml" | ".yaml" -> true
  | _ -> false

let relative_to root path =
  let root = normalize root and path = normalize path in
  let root =
    if Util.ends_with ~suffix:"/" root then
      String.sub root 0 (String.length root - 1)
    else root
  in
  if root = "." || root = "" then path
  else
    let prefix = root ^ "/" in
    if Util.starts_with ~prefix path then
      String.sub path (String.length prefix)
        (String.length path - String.length prefix)
    else path

let generated_descendant ~root path = Source_manifest.is_generated ~root path

let discover io target =
  let directory = io.is_directory target in
  let paths = if directory then io.list_files target else [ target ] in
  let candidates =
    paths |> List.map normalize |> Util.deduplicate_strings
    |> List.filter (fun path ->
        ((not directory) || yaml_path path)
        && ((not directory) || not (generated_descendant ~root:target path)))
    |> List.filter_map (fun path ->
        match io.read_file path with
        | Ok source -> Some (path, source)
        | Error _ -> None)
  in
  let entrypoints =
    candidates
    |> List.filter (fun (path, source) ->
        match Frontend.detect ~path ~source with
        | None -> false
        | Some provider ->
            (not directory)
            || Frontend.entrypoint ~provider
                 ~path:(relative_to target path) ~source)
  in
  { candidates; entrypoints }

let load_config io explicit root =
  let path =
    match explicit with
    | Some value -> Some value
    | None ->
        let candidate = path_join root ".workflow-verifier.toml" in
        if io.exists candidate then Some candidate else None
  in
  match path with
  | None -> Ok Config.default
  | Some path -> (
      match io.read_file path with
      | Error message -> Error [ message ]
      | Ok source -> Config.parse source)

let persona_of_string = function
  | "gate" -> Some Verifier.Gate
  | "audit" -> Some Audit
  | "paranoid" -> Some Paranoid
  | _ -> None

let load_lock io path =
  if not (io.exists path) then Ok (Lockfile.make [])
  else
    match io.read_file path with
    | Error _ as error -> error
    | Ok source -> Lockfile.parse source

let problem_messages problems =
  List.map (fun problem -> problem.Frontend_intf.message) problems

let compile_entrypoints sources =
  let rec compile compilations = function
    | [] -> Ok (List.rev compilations)
    | (path, source) :: rest -> (
        match Frontend.compile_auto ~path ~source () with
        | Ok compilation -> compile (compilation :: compilations) rest
        | Error problems -> Error (problem_messages problems))
  in
  compile [] sources

let compilation_sources compilations =
  compilations
  |> List.map (fun (compilation : Frontend_intf.compilation) ->
      (compilation.graph.source, compilation.cst.source))
  |> List.sort_uniq (fun (left, _) (right, _) -> String.compare left right)

let analyze io arguments target =
  let ( let* ) = Util.( let* ) in
  let discovery = discover io target in
  if discovery.entrypoints = [] then
    Error [ "no supported workflow files found under " ^ target ]
  else
    let root = root_for_target io target in
    let* config = load_config io (option_value "--config" arguments) root in
    let config =
      match option_value "--persona" arguments with
      | None -> config
      | Some name -> (
          match persona_of_string (String.lowercase_ascii name) with
          | Some persona -> { config with persona }
          | None -> config)
    in
    let entrypoints =
      discovery.entrypoints
      |> List.filter (fun (path, source) ->
          match Frontend.detect ~path ~source with
          | Some provider -> List.mem provider config.frontends
          | None -> false)
    in
    if entrypoints = [] then
      Error
        [
          "no supported workflow files are enabled by the configured frontends";
        ]
    else
      let* roots = compile_entrypoints entrypoints in
      let workspace_sources =
        List.map
          (fun (path, source) -> { Frontend_intf.path; source })
          discovery.candidates
      in
      let* linked =
        match Local_linker.link ~root ~sources:workspace_sources roots with
        | Ok value -> Ok value
        | Error problems -> Error (problem_messages problems)
      in
      let lock_path =
        option_value "--lockfile" arguments
        |> Option.value ~default:(path_join root "workflow-verifier.lock")
      in
      let* lock =
        match load_lock io lock_path with
        | Ok value -> Ok value
        | Error message -> Error [ message ]
      in
      let compilations = List.map (Locked_program.apply lock) linked in
      let sources = compilation_sources compilations in
      let graphs =
        List.map
          (fun compilation -> compilation.Frontend_intf.graph)
          compilations
      in
      let verifications =
        [ Verifier.verify_program ~persona:config.persona graphs ]
        |> List.map (fun (result : Verifier.result) ->
            {
              result with
              diagnostics =
                List.filter
                  (fun diagnostic -> not (Config.suppressed config diagnostic))
                  result.diagnostics;
            })
      in
      let frontend_diagnostics =
        compilations
        |> List.concat_map (fun compilation ->
            compilation.Frontend_intf.problems
            |> List.map (fun (problem : Frontend_intf.problem) ->
                Diagnostic.make ~rule_id:problem.code ~severity:Error
                  ~confidence:High ~message:problem.message ~span:problem.span
                  ~evidence:[ "frontend compiler" ] ()))
      in
      let policy_diagnostics =
        frontend_diagnostics
        @ Policy.evaluate config.rules (Program_graph.compose graphs)
        |> List.filter (fun diagnostic ->
            not (Config.suppressed config diagnostic))
        |> List.sort Diagnostic.compare
      in
      let report =
        Report.make ~persona:config.persona
          ~inputs:
            (List.map
               (fun (path, source) ->
                 (path, "sha256:" ^ Sha256.digest_string source))
               sources)
          ~graphs ~verifications ~policy_diagnostics
      in
      Ok
        {
          config;
          lock;
          sources;
          compilations;
          verifications;
          policy_diagnostics;
          report;
        }

let output_or_write io arguments text =
  match option_value "--output" arguments with
  | None ->
      io.stdout text;
      Ok ()
  | Some path -> io.write_file path text

let text_report report =
  let diagnostics = Report.diagnostics report in
  let buffer = Buffer.create 512 in
  if diagnostics = [] then Buffer.add_string buffer "workflow-verifier: pass\n"
  else
    List.iter
      (fun diagnostic ->
        Printf.bprintf buffer "%s [%s] %s: %s\n"
          (Span.to_string diagnostic.Diagnostic.span)
          diagnostic.rule_id
          (Diagnostic.severity_name diagnostic.severity)
          diagnostic.message)
      diagnostics;
  Buffer.contents buffer

let report_output format report =
  match String.lowercase_ascii format with
  | "json" -> Ok (Report.to_canonical_json report)
  | "sarif" -> Ok (Sarif.to_canonical_json report)
  | "text" -> Ok (text_report report)
  | other -> Error ("unknown report format: " ^ other)

type cache_context = { cache_path : string; cache_key : string }

let cache_context io arguments target =
  let root = root_for_target io target in
  let discovery = discover io target in
  match load_config io (option_value "--config" arguments) root with
  | Error _ -> None
  | Ok config -> (
      let config =
        match option_value "--persona" arguments with
        | None -> config
        | Some value -> (
            match persona_of_string (String.lowercase_ascii value) with
            | Some persona -> { config with persona }
            | None -> config)
      in
      let entrypoints =
        discovery.entrypoints
        |> List.filter (fun (path, source) ->
            match Frontend.detect ~path ~source with
            | Some provider -> List.mem provider config.frontends
            | None -> false)
      in
      if entrypoints = [] then None
      else
        let lock_path =
          option_value "--lockfile" arguments
          |> Option.value ~default:(path_join root "workflow-verifier.lock")
        in
        match load_lock io lock_path with
        | Error _ -> None
        | Ok lock ->
            let config_material =
              Json.Object
                [
                  ("config", Config.to_json config);
                  ("strict", Json.Bool (has "--strict" arguments));
                ]
              |> Json.to_string
            in
            Some
              {
                cache_path =
                  option_value "--cache" arguments
                  |> Option.value
                       ~default:
                         (path_join root ".workflow-verifier-cache-v1.json");
                cache_key =
                  Incremental_cache.key ~tool_version:"0.1.0-dev"
                    ~config_digest:
                      ("sha256:" ^ Sha256.digest_string config_material)
                    ~lock_digest:lock.integrity
                    (List.map
                       (fun (path, source) ->
                         (path, "sha256:" ^ Sha256.digest_string source))
                       discovery.candidates);
              })

let cached_check io arguments format context =
  if
    String.lowercase_ascii format <> "json"
    || has "--no-cache" arguments
    || not (io.exists context.cache_path)
  then None
  else
    match io.read_file context.cache_path with
    | Error _ -> None
    | Ok source -> (
        match Incremental_cache.parse source with
        | Ok entry when entry.key = context.cache_key -> Some entry
        | Ok _ | Error _ -> None)

let check io arguments =
  let target = positional arguments |> List.rev |> first_or "." in
  let format = option_value "--format" arguments |> Option.value ~default:"text"
  and context = cache_context io arguments target in
  match Option.bind context (cached_check io arguments format) with
  | Some entry -> (
      match output_or_write io arguments entry.Incremental_cache.report with
      | Ok () -> entry.exit_code
      | Error message ->
          io.stderr (message ^ "\n");
          2)
  | None -> (
      match analyze io arguments target with
      | Error errors ->
          List.iter (fun message -> io.stderr (message ^ "\n")) errors;
          2
      | Ok analysis -> (
          match report_output format analysis.report with
          | Error message ->
              io.stderr (message ^ "\n");
              2
          | Ok text -> (
              match output_or_write io arguments text with
              | Error message ->
                  io.stderr (message ^ "\n");
                  2
              | Ok () ->
                  let fails =
                    List.exists
                      (Verifier.should_fail analysis.config.persona)
                      analysis.verifications
                    || analysis.config.persona <> Verifier.Audit
                       && analysis.policy_diagnostics <> []
                  in
                  let exit_code =
                    if fails then 1
                    else if
                      has "--strict" arguments
                      && (List.exists
                            (fun result -> not result.Verifier.complete)
                            analysis.verifications
                         || List.exists
                              (fun compilation ->
                                List.exists
                                  (fun dependency ->
                                    match dependency.Frontend_intf.status with
                                    | Unresolved _ -> true
                                    | Locked _ -> false)
                                  compilation.Frontend_intf.dependencies)
                              analysis.compilations)
                    then 3
                    else 0
                  in
                  (match context with
                  | Some context
                    when has "--write-cache" arguments
                         && String.lowercase_ascii format = "json" -> (
                      let entry =
                        Incremental_cache.make ~key:context.cache_key ~exit_code
                          ~report:text
                      in
                      match
                        io.write_file context.cache_path
                          (Incremental_cache.to_canonical_json entry)
                      with
                      | Ok () -> ()
                      | Error message -> io.stderr ("cache: " ^ message ^ "\n"))
                  | _ -> ());
                  exit_code)))

let explain io arguments =
  match positional arguments with
  | rule :: rest -> (
      let target =
        match rest with
        | path :: _ -> path
        | [] -> "."
      in
      match analyze io arguments target with
      | Error errors ->
          List.iter (fun value -> io.stderr (value ^ "\n")) errors;
          2
      | Ok analysis ->
          let diagnostics =
            Report.diagnostics analysis.report
            |> List.filter (fun diagnostic ->
                diagnostic.Diagnostic.rule_id = rule)
          in
          if diagnostics = [] then (
            io.stderr ("no finding for " ^ rule ^ "\n");
            2)
          else (
            List.iter
              (fun (diagnostic : Diagnostic.t) ->
                io.stdout
                  (Printf.sprintf "%s: %s\n" diagnostic.rule_id
                     diagnostic.message);
                io.stdout "trace:\n";
                List.iter
                  (fun (hop : Diagnostic.trace_hop) ->
                    io.stdout
                      (Printf.sprintf "  - %s %s\n" hop.Diagnostic.label
                         (Span.to_string hop.span)))
                  diagnostic.trace;
                io.stdout
                  ("capabilities: "
                  ^ String.concat ", "
                      (List.map Ir.capability_name diagnostic.capabilities)
                  ^ "\n"))
              diagnostics;
            0))
  | [] ->
      io.stderr "explain requires a rule ID\n";
      2

let graph_command io arguments =
  let target = positional arguments |> first_or "." in
  match analyze io ("--persona" :: "audit" :: arguments) target with
  | Error errors ->
      List.iter (fun value -> io.stderr (value ^ "\n")) errors;
      2
  | Ok analysis ->
      let kind =
        match
          option_value "--kind" arguments |> Option.value ~default:"all"
        with
        | "control" -> Graph_output.Control
        | "dataflow" | "data" -> Dataflow
        | "call" -> Call
        | "capability" -> Capability
        | _ -> All
      and format =
        option_value "--format" arguments |> Option.value ~default:"json"
      in
      let program =
        analysis.compilations
        |> List.map (fun (compilation : Frontend_intf.compilation) ->
            compilation.graph)
        |> Program_graph.compose
      in
      let rendered =
        if format = "dot" then Graph_output.to_dot ~kind program
        else Graph_output.to_canonical_json ~kind program
      in
      io.stdout rendered;
      0

let resolve_command io services arguments =
  let target = positional arguments |> first_or "." in
  match analyze io ("--persona" :: "audit" :: arguments) target with
  | Error errors ->
      List.iter (fun value -> io.stderr (value ^ "\n")) errors;
      2
  | Ok analysis -> (
      let lock_path =
        option_value "--lockfile" arguments
        |> Option.value
             ~default:
               (path_join (root_for_target io target) "workflow-verifier.lock")
      in
      match load_lock io lock_path with
      | Error message ->
          io.stderr (message ^ "\n");
          2
      | Ok lock ->
          let network =
            if has "--allow-network" arguments then
              Option.map
                (fun make ->
                  make ~allowed_sources:analysis.config.resolver.allowed_sources)
                services.resolver_network
            else None
          in
          let dependencies =
            List.concat_map
              (fun compilation -> compilation.Frontend_intf.dependencies)
              analysis.compilations
          in
          let result =
            Resolver.resolve
              ~allowed_sources:analysis.config.resolver.allowed_sources
              ~refresh:(has "--update" arguments) ~network ~lock dependencies
          in
          List.iter (fun message -> io.stderr (message ^ "\n")) result.errors;
          if result.errors <> [] then (
            io.stdout (Lockfile.to_canonical_json result.lockfile);
            3)
          else if has "--allow-network" arguments then (
            match
              io.write_file lock_path
                (Lockfile.to_canonical_json result.lockfile)
            with
            | Error message ->
                io.stderr (message ^ "\n");
                2
            | Ok () ->
                io.stdout (Lockfile.to_canonical_json result.lockfile);
                if result.unresolved = [] then 0 else 3)
          else (
            io.stdout (Lockfile.to_canonical_json result.lockfile);
            if result.unresolved = [] then 0 else 3))

let attribute_constant name (node : Ir.node) =
  Option.bind (List.assoc_opt name node.attributes) (fun value ->
      match Abstract_value.constants value with
      | Some (constant :: _) -> Some constant
      | _ -> None)

let script_shell (node : Ir.node) =
  match
    attribute_constant "shell" node
    |> Option.value ~default:"bash"
    |> String.lowercase_ascii
  with
  | "default" | "bash" -> Script_adapter.Bash
  | "sh" | "posix" -> Posix
  | "pwsh" | "powershell" -> PowerShell
  | "cmd" | "cmd.exe" -> Cmd
  | "python" | "python3" -> Python
  | name -> Unknown_shell name

let fix_command io arguments =
  let target = positional arguments |> first_or "." in
  match analyze io ("--persona" :: "audit" :: arguments) target with
  | Error errors ->
      List.iter (fun value -> io.stderr (value ^ "\n")) errors;
      2
  | Ok analysis ->
      let verification_diagnostics =
        analysis.verifications
        |> List.concat_map (fun result -> result.Verifier.diagnostics)
      in
      let proposals =
        analysis.compilations
        |> List.filter_map (fun (compilation : Frontend_intf.compilation) ->
            let pin_proposals =
              compilation.dependencies
              |> List.filter_map (fun (dependency : Frontend_intf.dependency) ->
                  Option.bind
                    (Lockfile.find analysis.lock dependency.provider
                       dependency.reference) (fun entry ->
                      Fixer.pin_dependency ~cst:compilation.cst
                        ~reference:dependency.reference
                        ~revision:entry.Lockfile.revision))
            and permission_proposals =
              let unused =
                verification_diagnostics
                |> List.filter (fun diagnostic ->
                    diagnostic.Diagnostic.rule_id = "WV-PERM-001"
                    && Util.normalize_slashes diagnostic.span.file
                       = Util.normalize_slashes compilation.graph.source)
                |> List.concat_map (fun diagnostic ->
                    diagnostic.Diagnostic.capabilities)
                |> Util.deduplicate_compare Stdlib.compare
              in
              match
                Fixer.reduce_write_all ~cst:compilation.cst
                  ~unused_capabilities:unused
              with
              | None -> []
              | Some proposal -> [ proposal ]
            and environment_proposals =
              verification_diagnostics
              |> List.filter_map (fun diagnostic ->
                  if diagnostic.Diagnostic.rule_id <> "WV-SEC-001" then None
                  else
                    diagnostic.trace |> List.rev
                    |> List.find_map (fun hop ->
                        match
                          Ir.find_node compilation.graph hop.Diagnostic.node_id
                        with
                        | Some node when node.kind = Ir.Command -> Some node
                        | _ -> None))
              |> List.filter_map (fun command ->
                  let expressions =
                    (Script_adapter.analyze (script_shell command) command.name)
                      .expansions
                    |> List.map (fun (expansion : Script_adapter.expansion) ->
                        expansion.expansion_text)
                    |> List.filter (fun expression ->
                        Util.starts_with ~prefix:"${{" expression
                        || Util.starts_with ~prefix:"$[[" expression)
                    |> Util.deduplicate_strings
                  in
                  match expressions with
                  | [ expression ] ->
                      let name =
                        "WV_UNTRUSTED_"
                        ^ ( Sha256.digest_string (command.id ^ expression)
                          |> fun digest ->
                            String.sub digest 0 12 |> String.uppercase_ascii )
                      in
                      Fixer.bind_expression_to_environment ~cst:compilation.cst
                        ~shell:(script_shell command) ~expression ~name
                  | _ -> None)
            in
            match
              pin_proposals @ permission_proposals @ environment_proposals
            with
            | [] -> None
            | proposals -> (
                match Fixer.combine proposals with
                | Ok proposal -> Some (compilation, proposal)
                | Error message ->
                    io.stderr (compilation.graph.source ^ ": " ^ message ^ "\n");
                    None))
      in
      if proposals = [] then (
        io.stdout "no behavior-preserving fixes available\n";
        0)
      else if not (has "--apply" arguments) then (
        List.iter
          (fun (compilation, proposal) ->
            match Fixer.apply ~cst:compilation.Frontend_intf.cst proposal with
            | Error message -> io.stderr (message ^ "\n")
            | Ok after ->
                io.stdout
                  (Fixer.unified_diff ~path:compilation.graph.source
                     ~before:compilation.cst.source ~after))
          proposals;
        0)
      else
        let prepared, preparation_errors =
          proposals
          |> List.fold_left
               (fun (prepared, errors) (compilation, proposal) ->
                 match
                   Fixer.apply ~cst:compilation.Frontend_intf.cst proposal
                 with
                 | Ok source ->
                     ((compilation.graph.source, source) :: prepared, errors)
                 | Error message -> (prepared, message :: errors))
               ([], [])
        in
        if preparation_errors <> [] then (
          List.rev preparation_errors
          |> List.iter (fun value -> io.stderr (value ^ "\n"));
          2)
        else
          let failures = ref [] in
          List.rev prepared
          |> List.iter (fun (path, source) ->
              match io.write_file path source with
              | Ok () -> ()
              | Error message -> failures := message :: !failures);
          if !failures = [] then 0
          else (
            List.rev !failures
            |> List.iter (fun value -> io.stderr (value ^ "\n"));
            2)

let diff_command io arguments =
  match positional arguments with
  | base :: head :: _ -> (
      match
        ( analyze io ("--persona" :: "audit" :: arguments) base,
          analyze io ("--persona" :: "audit" :: arguments) head )
      with
      | Ok base_result, Ok head_result ->
          let difference =
            Semantic_diff.compare_program
              (List.map
                 (fun compilation -> compilation.Frontend_intf.graph)
                 base_result.compilations)
              (List.map
                 (fun compilation -> compilation.Frontend_intf.graph)
                 head_result.compilations)
          in
          io.stdout (Semantic_diff.to_canonical_json difference);
          0
      | Error errors, _ | _, Error errors ->
          List.iter (fun value -> io.stderr (value ^ "\n")) errors;
          2)
  | _ ->
      io.stderr "diff requires BASE and HEAD paths\n";
      2

let backend_of_argument = function
  | "linux-native" -> Sandbox_protocol.Linux_native
  | "windows-native" -> Windows_native
  | "macos-vm" -> Macos_vm
  | value when Util.starts_with ~prefix:"oci:" value ->
      Oci (String.sub value 4 (String.length value - 4))
  | engine -> Oci engine

let option_values name arguments =
  let rec loop accumulator = function
    | current :: value :: rest when current = name ->
        loop (value :: accumulator) rest
    | _ :: rest -> loop accumulator rest
    | [] -> List.rev accumulator
  in
  loop [] arguments

let command_step image (node : Ir.node) =
  let shell =
    attribute_constant "shell" node
    |> Option.value ~default:"bash"
    |> String.lowercase_ascii
  in
  let argv, supported =
    match shell with
    | "default" | "bash" ->
        ([ "/bin/bash"; "-euo"; "pipefail"; "-c"; node.name ], true)
    | "sh" | "posix" -> ([ "/bin/sh"; "-eu"; "-c"; node.name ], true)
    | "pwsh" | "powershell" ->
        ([ "pwsh"; "-NoLogo"; "-NonInteractive"; "-Command"; node.name ], true)
    | "cmd" | "cmd.exe" -> ([ "cmd.exe"; "/D"; "/S"; "/C"; node.name ], true)
    | "python" | "python3" -> ([ "python3"; "-c"; node.name ], true)
    | _ -> ([ "<unsupported-shell>"; shell; node.name ], false)
  in
  {
    Sandbox_protocol.id = node.id;
    image;
    argv;
    environment = [];
    working_directory = "/workspace";
    supported;
  }

let required_controls backend ~allow_workflow_network =
  let base =
    [
      Sandbox_protocol.Source_read_only;
      Scratch_overlay;
      Process_isolation;
      Resource_limits;
      Secret_redaction;
    ]
    @ if allow_workflow_network then [] else [ Network_deny ]
  in
  match backend with
  | Sandbox_protocol.Oci _ -> base
  | Linux_native -> base @ [ Namespace; Seccomp; Landlock; Cgroup_v2 ]
  | Windows_native -> base @ [ App_container; Restricted_token; Job_object ]
  | Macos_vm -> base @ [ Virtual_machine ]

let sandbox_plan io arguments target =
  match analyze io ("--persona" :: "audit" :: arguments) target with
  | Error errors -> Error (String.concat "; " errors)
  | Ok analysis -> (
      let root = root_for_target io target in
      let lock_path =
        option_value "--lockfile" arguments
        |> Option.value ~default:(path_join root "workflow-verifier.lock")
      in
      match load_lock io lock_path with
      | Error message -> Error message
      | Ok lock -> (
          let backend =
            option_value "--backend" arguments
            |> Option.value ~default:analysis.config.sandbox.backend
            |> backend_of_argument
          in
          let dependency_records =
            analysis.compilations
            |> List.concat_map (fun compilation ->
                compilation.Frontend_intf.dependencies)
            |> List.sort_uniq
                 (fun
                   (left : Frontend_intf.dependency)
                   (right : Frontend_intf.dependency)
                 ->
                   match
                     String.compare
                       (Ir.provider_name left.Frontend_intf.provider)
                       (Ir.provider_name right.Frontend_intf.provider)
                   with
                   | 0 -> String.compare left.reference right.reference
                   | comparison -> comparison)
          in
          let dependencies =
            dependency_records
            |> List.map (fun (dependency : Frontend_intf.dependency) ->
                match dependency.status with
                | Locked { digest; _ } ->
                    {
                      Sandbox_protocol.reference = dependency.reference;
                      digest = Some digest;
                      available = true;
                    }
                | Unresolved _ ->
                    {
                      Sandbox_protocol.reference = dependency.reference;
                      digest = None;
                      available = false;
                    })
          and steps =
            analysis.compilations
            |> List.concat_map (fun compilation ->
                compilation.Frontend_intf.graph.nodes)
            |> List.filter_map (fun (node : Ir.node) ->
                match node.kind with
                | Ir.Command ->
                    Some (command_step analysis.config.sandbox.image node)
                | Call
                  when node.effects <> [] || node.capabilities <> []
                       || Option.is_some node.unknown ->
                    Some
                      {
                        Sandbox_protocol.id = node.id;
                        image = analysis.config.sandbox.image;
                        argv = [ "<unsupported-call>"; node.name ];
                        environment = [];
                        working_directory = "/workspace";
                        supported = false;
                      }
                | Opaque when node.phase = Ir.Run ->
                    Some
                      {
                        Sandbox_protocol.id = node.id;
                        image = analysis.config.sandbox.image;
                        argv = [ "<unsupported-opaque>"; node.name ];
                        environment = [];
                        working_directory = "/workspace";
                        supported = false;
                      }
                | _ -> None)
          in
          let source_files =
            io.list_files root |> List.map normalize |> Util.deduplicate_strings
            |> List.filter (fun path -> not (generated_descendant ~root path))
            |> List.fold_left
                 (fun result path ->
                   match result with
                   | Error _ as error -> error
                   | Ok files -> (
                       match io.read_file path with
                       | Ok contents -> Ok ((path, contents) :: files)
                       | Error message -> Error message))
                 (Ok [])
          in
          match source_files with
          | Error _ as error -> error
          | Ok files -> (
              match Source_manifest.create ~root ~files with
              | Error _ as error -> error
              | Ok manifest ->
                  Sandbox_protocol.make_plan ~backend
                    ~source_digest:manifest.digest ~lock_digest:lock.integrity
                    ~controls:
                      (required_controls backend
                         ~allow_workflow_network:
                           (has "--allow-workflow-network" arguments))
                    ~limits:
                      {
                        cpu_seconds = analysis.config.sandbox.cpu_seconds;
                        memory_mb = analysis.config.sandbox.memory_mb;
                        processes = analysis.config.sandbox.processes;
                        output_bytes = analysis.config.sandbox.output_bytes;
                      }
                    ~secret_names:(option_values "--secret" arguments)
                    ~dependencies ~steps)))

let sandbox_audit_result io arguments target plan evidence =
  match target with
  | None -> Sandbox_audit.evaluate ~plan ~evidence
  | Some target -> (
      match sandbox_plan io arguments target with
      | Error _ as error -> error
      | Ok current when current.source_digest <> plan.source_digest ->
          Error "audit target source digest does not match the execution plan"
      | Ok _ -> (
          match analyze io ("--persona" :: "audit" :: arguments) target with
          | Error errors -> Error (String.concat "; " errors)
          | Ok analysis ->
              let graphs =
                List.map
                  (fun compilation -> compilation.Frontend_intf.graph)
                  analysis.compilations
              in
              Sandbox_audit.evaluate_with_graphs ~graphs ~plan ~evidence))

let sandbox_command io services arguments =
  match arguments with
  | subcommand :: rest -> (
      let target = positional rest |> first_or "." in
      match subcommand with
      | "plan" -> (
          match sandbox_plan io rest target with
          | Error message ->
              io.stderr (message ^ "\n");
              2
          | Ok plan ->
              io.stdout (Sandbox_protocol.to_canonical_json plan);
              0)
      | "run" -> (
          match services.sandbox_execute with
          | None ->
              io.stderr "sandbox executor is unavailable\n";
              5
          | Some execute -> (
              match sandbox_plan io rest target with
              | Error message ->
                  io.stderr (message ^ "\n");
                  2
              | Ok { status = Incomplete reasons; _ } ->
                  List.iter (fun reason -> io.stderr (reason ^ "\n")) reasons;
                  3
              | Ok plan -> (
                  match
                    Sandbox_backend.select
                      {
                        backend = plan.backend;
                        required_controls = plan.controls;
                      }
                      (services.backend_probes
                      |> List.filter_map (fun probe ->
                          if probe.Sandbox_backend.available then
                            Some probe.attestation
                          else None))
                  with
                  | Error missing ->
                      io.stderr
                        ("sandbox controls unavailable: "
                        ^ String.concat ", "
                            (List.map Sandbox_protocol.control_name missing)
                        ^ "\n");
                      5
                  | Ok _ -> (
                      match
                        execute ~source_root:(root_for_target io target) plan
                      with
                      | Error message ->
                          io.stderr (message ^ "\n");
                          5
                      | Ok execution -> (
                          let evidence = execution.Sandbox_run.evidence in
                          if evidence.Evidence.plan_digest <> plan.digest then (
                            io.stderr "sandbox evidence plan digest mismatch\n";
                            5)
                          else
                            match Evidence.validate evidence with
                            | Error message ->
                                io.stderr (message ^ "\n");
                                5
                            | Ok () -> (
                                io.stdout
                                  (Sandbox_run.to_canonical_json execution);
                                match execution.outcome with
                                | Completed -> 0
                                | Step_failed _
                                | Timed_out _
                                | Output_limit_exceeded _ -> 1))))))
      | "replay" -> (
          match positional rest with
          | evidence_path :: _ -> (
              match io.read_file evidence_path with
              | Error message ->
                  io.stderr (message ^ "\n");
                  2
              | Ok source -> (
                  match Evidence.parse source with
                  | Error message ->
                      io.stderr (message ^ "\n");
                      2
                  | Ok evidence ->
                      io.stdout (Evidence.to_canonical_json evidence);
                      0))
          | [] ->
              io.stderr "sandbox replay requires EVIDENCE\n";
              2)
      | "audit" -> (
          match positional rest with
          | plan_path :: evidence_path :: targets -> (
              let target =
                match targets with
                | value :: _ -> Some value
                | [] -> None
              in
              match (io.read_file plan_path, io.read_file evidence_path) with
              | Error message, _ | _, Error message ->
                  io.stderr (message ^ "\n");
                  2
              | Ok plan_source, Ok evidence_source -> (
                  match
                    ( Sandbox_protocol.parse plan_source,
                      Evidence.parse evidence_source )
                  with
                  | Error message, _ | _, Error message ->
                      io.stderr (message ^ "\n");
                      2
                  | Ok plan, Ok evidence -> (
                      match
                        sandbox_audit_result io rest target plan evidence
                      with
                      | Error message ->
                          io.stderr (message ^ "\n");
                          2
                      | Ok audit -> (
                          io.stdout (Sandbox_audit.to_canonical_json audit);
                          match audit.status with
                          | Verified -> 0
                          | Incomplete _ -> 3))))
          | _ ->
              io.stderr "sandbox audit requires PLAN and EVIDENCE [TARGET]\n";
              2)
      | _ ->
          io.stderr "sandbox requires plan, run, replay, or audit\n";
          2)
  | [] ->
      io.stderr "sandbox requires a subcommand\n";
      2

let doctor io services arguments =
  let json =
    Json.Object
      [
        ( "backends",
          Json.Array
            (List.map Sandbox_backend.probe_to_json services.backend_probes) );
        ( "frontends",
          Json.Array
            (List.map
               (fun value -> Json.String (Ir.provider_name value))
               [ Ir.Github; Gitlab; Azure; Circleci ]) );
        ("platform", Json.String services.platform);
        ( "resolver_network",
          Json.Bool (Option.is_some services.resolver_network) );
        ("sandbox_executor", Json.Bool (Option.is_some services.sandbox_execute));
        ("schema", Json.String "doctor-v1");
      ]
  in
  if option_value "--format" arguments = Some "json" then
    io.stdout (Json.to_string json ^ "\n")
  else
    io.stdout
      (Printf.sprintf
         "frontends: github, gitlab, azure, circleci\n\
          platform: %s\n\
          resolver network: %s\n\
          sandbox executor: %s\n"
         services.platform
         (if Option.is_some services.resolver_network then "available"
          else "unavailable")
         (if Option.is_some services.sandbox_execute then "available"
          else "unavailable"));
  0

let policy_command io arguments =
  match arguments with
  | "test" :: rest -> (
      let target = positional rest |> first_or "." in
      match
        load_config io
          (option_value "--config" rest)
          (root_for_target io target)
      with
      | Error errors ->
          List.iter (fun value -> io.stderr (value ^ "\n")) errors;
          2
      | Ok config ->
          let suffix = ".expect.json" in
          let expectation_paths =
            (if io.is_directory target then io.list_files target else [ target ])
            |> List.map normalize |> Util.deduplicate_strings
            |> List.filter (Util.ends_with ~suffix)
          in
          if expectation_paths = [] then (
            io.stderr "policy test found no *.expect.json fixture sidecars\n";
            2)
          else
            let results = ref [] and errors = ref [] in
            List.iter
              (fun expectation_path ->
                let workflow_path =
                  String.sub expectation_path 0
                    (String.length expectation_path - String.length suffix)
                in
                match
                  (io.read_file expectation_path, io.read_file workflow_path)
                with
                | Error message, _ | _, Error message ->
                    errors := message :: !errors
                | Ok expectation_source, Ok workflow_source -> (
                    match
                      ( Policy_fixture.parse expectation_source,
                        Frontend.compile_auto ~path:workflow_path
                          ~source:workflow_source () )
                    with
                    | Error message, _ ->
                        errors := (expectation_path ^ ": " ^ message) :: !errors
                    | _, Error problems ->
                        errors :=
                          (workflow_path ^ ": "
                          ^ String.concat "; "
                              (List.map
                                 (fun problem -> problem.Frontend_intf.message)
                                 problems))
                          :: !errors
                    | Ok expectation, Ok compilation ->
                        let diagnostics =
                          Policy.evaluate config.rules compilation.graph
                          |> List.filter (fun diagnostic ->
                              not (Config.suppressed config diagnostic))
                        in
                        results :=
                          Policy_fixture.evaluate ~fixture:workflow_path
                            expectation diagnostics
                          :: !results))
              expectation_paths;
            if !errors <> [] then (
              List.rev !errors
              |> List.iter (fun message -> io.stderr (message ^ "\n"));
              2)
            else
              let results =
                List.rev !results
                |> List.sort (fun left right ->
                    String.compare left.Policy_fixture.fixture right.fixture)
              in
              let json =
                Json.Object
                  [
                    ( "cases",
                      Json.Array (List.map Policy_fixture.to_json results) );
                    ( "passed",
                      Json.Bool
                        (List.for_all
                           (fun result -> result.Policy_fixture.passed)
                           results) );
                    ("schema", Json.String "policy-test-v1");
                  ]
              in
              io.stdout (Json.to_string json ^ "\n");
              if
                List.for_all
                  (fun result -> result.Policy_fixture.passed)
                  results
              then 0
              else 1)
  | _ ->
      io.stderr "policy requires the test subcommand\n";
      2

let command_help command arguments =
  let usage value = Some ("Usage: workflow-verifier " ^ value ^ "\n") in
  match (command, arguments) with
  | "check", _ ->
      usage
        "check [--format text|json|sarif] [--output FILE] [--persona \
         gate|audit|paranoid] [--config FILE] [--lockfile FILE] [--strict] \
         [--cache FILE] [--no-cache] [--write-cache] [TARGET]"
  | "resolve", _ ->
      usage
        "resolve [--allow-network] [--update] [--config FILE] [--lockfile \
         FILE] [TARGET]"
  | "explain", _ ->
      usage "explain RULE_ID [--config FILE] [--lockfile FILE] [TARGET]"
  | "graph", _ ->
      usage
        "graph [--kind all|control|dataflow|call|capability] [--format \
         json|dot] [--config FILE] [TARGET]"
  | "diff", _ -> usage "diff [--config FILE] BASE HEAD"
  | "fix", _ -> usage "fix [--apply] [--config FILE] [--lockfile FILE] [TARGET]"
  | "policy", "test" :: _ -> usage "policy test [--config FILE] FIXTURES"
  | "policy", _ -> usage "policy test [--config FILE] FIXTURES"
  | "sandbox", "plan" :: _ ->
      usage
        "sandbox plan [--backend BACKEND] [--secret NAME] \
         [--allow-workflow-network] [--config FILE] [--lockfile FILE] [TARGET]"
  | "sandbox", "run" :: _ ->
      usage
        "sandbox run [--backend BACKEND] [--secret NAME] \
         [--allow-workflow-network] [--config FILE] [--lockfile FILE] [TARGET]"
  | "sandbox", "replay" :: _ -> usage "sandbox replay EVIDENCE"
  | "sandbox", "audit" :: _ -> usage "sandbox audit PLAN EVIDENCE [TARGET]"
  | "sandbox", _ -> usage "sandbox plan|run|replay|audit [OPTIONS]"
  | "doctor", _ -> usage "doctor [--format text|json]"
  | _ -> None

let run ~io ~services argv =
  try
    if Array.length argv < 2 then (
      io.stdout help;
      0)
    else
      let command = argv.(1) in
      let arguments =
        Array.to_list (Array.sub argv 2 (Array.length argv - 2))
      in
      if has "--help" arguments || has "-h" arguments then (
        match command_help command arguments with
        | Some text ->
            io.stdout text;
            0
        | None ->
            io.stderr ("unknown command: " ^ command ^ "\n");
            2)
      else
        match command with
        | "--help" | "-h" | "help" ->
            io.stdout help;
            0
        | "--version" | "version" ->
            io.stdout "workflow-verifier 0.1.0-dev\n";
            0
        | "check" -> check io arguments
        | "explain" -> explain io arguments
        | "graph" -> graph_command io arguments
        | "diff" -> diff_command io arguments
        | "fix" -> fix_command io arguments
        | "resolve" -> resolve_command io services arguments
        | "policy" -> policy_command io arguments
        | "sandbox" -> sandbox_command io services arguments
        | "doctor" -> doctor io services arguments
        | unknown ->
            io.stderr ("unknown command: " ^ unknown ^ "\n");
            2
  with exception_ ->
    io.stderr ("internal error: " ^ Printexc.to_string exception_ ^ "\n");
    4
