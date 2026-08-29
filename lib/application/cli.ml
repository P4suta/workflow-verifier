type source_snapshot = {
  manifest : Source_manifest.t;
  files : (string * string) list;
}

type backend_inventory = {
  probe : Sandbox_backend.probe;
  path : string option;
  digest : string option;
  signature : string;
  protocol : string;
  required_features : string list;
}

type io = {
  cwd : unit -> string;
  today : unit -> string;
  user_cache_dir : unit -> string option;
  read_file : string -> (string, string) result;
  write_file : string -> string -> (unit, string) result;
  remove_file : string -> (unit, string) result;
  exists : string -> bool;
  is_directory : string -> bool;
  list_files : string -> string list;
  snapshot :
    trusted_exclusions:string list -> string -> (source_snapshot, string) result;
  binary_digest : unit -> string;
  source_commit : unit -> string option;
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
  backend_inventory : backend_inventory list;
}

type analysis = {
  config : Config.t;
  lock : Lockfile.t;
  sources : (string * string) list;
  compilations : Frontend_intf.compilation list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  report : Report.t;
  manifest : Source_manifest.t;
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
    "--policy";
    "--secret";
    "--fixtures";
    "--cache";
    "--scenario";
    "--job";
    "--event";
    "--runner";
    "--input";
    "--matrix";
    "--variable";
    "--network-destination";
  ]

let positional arguments =
  let rec loop accumulator = function
    | [] -> List.rev accumulator
    | value :: rest when String.length value > 0 && value.[0] = '\000' ->
        loop (String.sub value 1 (String.length value - 1) :: accumulator) rest
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
  let rec without_current_directory path =
    if Util.starts_with ~prefix:"./" path then
      without_current_directory (String.sub path 2 (String.length path - 2))
    else path
  in
  let root =
    if Util.ends_with ~suffix:"/" root then
      String.sub root 0 (String.length root - 1)
    else root
  in
  if root = "." || root = "" then without_current_directory path
  else
    let prefix = root ^ "/" in
    if Util.starts_with ~prefix path then
      String.sub path (String.length prefix)
        (String.length path - String.length prefix)
    else path

let generated_descendant ~root path = Source_manifest.is_generated ~root path

let discover io ~root target captured_files =
  let directory = io.is_directory target in
  let candidates =
    captured_files
    |> List.map (fun (path, source) -> (normalize path, source))
    |> List.sort_uniq (fun (left, _) (right, _) -> String.compare left right)
    |> List.filter (fun (path, _) ->
        if directory then
          yaml_path path && not (generated_descendant ~root:target path)
        else normalize path = normalize target)
    |> List.map (fun (path, source) -> (relative_to root path, source))
  in
  let entrypoints =
    candidates
    |> List.filter (fun (path, source) ->
        match Frontend.detect ~path ~source with
        | None -> false
        | Some provider ->
            (not directory)
            || Frontend.entrypoint ~provider ~path:(relative_to target path)
                 ~source)
  in
  { candidates; entrypoints }

let safe_snapshot_relative path =
  Filename.is_relative path
  && (not (Util.starts_with ~prefix:"/" path))
  && (not (String.length path >= 2 && path.[1] = ':'))
  && path |> String.split_on_char '/'
     |> List.for_all (fun segment ->
         segment <> "" && segment <> "." && segment <> "..")

let snapshot_relative_path ~root path =
  let root = normalize root and path = normalize path in
  let relative = relative_to root path |> normalize in
  let contained =
    if root = "." || root = "" then safe_snapshot_relative relative
    else
      Util.starts_with ~prefix:(root ^ "/") path
      && safe_snapshot_relative relative
  in
  if contained then Some relative else None

let snapshot_source ~root files path =
  match snapshot_relative_path ~root path with
  | None -> `External
  | Some relative ->
      `Local
        (files
        |> List.find_map (fun (candidate, source) ->
            if normalize (relative_to root candidate) = relative then
              Some source
            else None))

let load_config ?captured io arguments root =
  let exists path =
    match captured with
    | None -> io.exists path
    | Some files -> (
        match snapshot_source ~root files path with
        | `External -> io.exists path
        | `Local source -> Option.is_some source)
  in
  let path, trust =
    match option_value "--policy" arguments with
    | Some value -> (Some value, Config.Trusted_policy)
    | None ->
        let explicit = option_value "--config" arguments in
        let path =
          match explicit with
          | Some value -> Some value
          | None ->
              let candidate = path_join root ".workflow-verifier.toml" in
              if exists candidate then Some candidate else None
        in
        ( path,
          if has "--trust-repository-config" arguments then
            Config.Trusted_policy
          else Config.Repository )
  in
  match path with
  | None -> Ok Config.default
  | Some path
    when Option.is_some (option_value "--policy" arguments)
         && Option.is_some (snapshot_relative_path ~root path) ->
      Error [ "--policy must be outside the analyzed source tree" ]
  | Some path -> (
      let source =
        match captured with
        | None -> io.read_file path
        | Some files -> (
            match snapshot_source ~root files path with
            | `External -> io.read_file path
            | `Local (Some source) -> Ok source
            | `Local None ->
                Error (path ^ ": config is absent from the source snapshot"))
      in
      match source with
      | Error message -> Error [ message ]
      | Ok source ->
          let relative = relative_to root path |> Util.normalize_slashes in
          let safe_relative =
            Filename.is_relative relative
            && (not (Util.starts_with ~prefix:"/" relative))
            && (not (String.length relative >= 2 && relative.[1] = ':'))
            && relative |> String.split_on_char '/'
               |> List.for_all (fun segment -> segment <> "..")
          in
          let label =
            (match trust with
              | Config.Repository -> "repository:"
              | Trusted_policy -> "trusted-policy:"
              | Built_in -> "built-in:")
            ^ if safe_relative then relative else Filename.basename path
          in
          Config.parse ~origin:label ~trust ~today:(io.today ()) source)

let persona_of_string = function
  | "gate" -> Some Verifier.Gate
  | "audit" -> Some Audit
  | "paranoid" -> Some Paranoid
  | _ -> None

let load_lock io ~root ~captured path =
  match snapshot_source ~root captured path with
  | `Local None -> Ok Lockfile.empty
  | `Local (Some source) -> Lockfile.parse source
  | `External -> (
      if not (io.exists path) then Ok Lockfile.empty
      else
        match io.read_file path with
        | Error _ as error -> error
        | Ok source -> Lockfile.parse source)

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
  let root = root_for_target io target in
  let* preliminary_config = load_config io arguments root in
  let trusted_exclusions =
    match preliminary_config.provenance.trust with
    | Config.Trusted_policy -> preliminary_config.source_exclusions
    | Built_in | Repository -> []
  in
  let* captured =
    match io.snapshot ~trusted_exclusions root with
    | Ok value -> Ok value
    | Error message -> Error [ message ]
  in
  let manifest = captured.manifest in
  let discovery = discover io ~root target captured.files in
  if discovery.entrypoints = [] then
    Error [ "no supported workflow files found under " ^ target ]
  else
    let* config = load_config ~captured:captured.files io arguments root in
    let* config =
      if
        config.provenance.digest = preliminary_config.provenance.digest
        && config.provenance.trust = preliminary_config.provenance.trust
      then Ok config
      else
        Error [ "configuration changed while the source snapshot was created" ]
    in
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
        match Local_linker.link ~root:"." ~sources:workspace_sources roots with
        | Ok value -> Ok value
        | Error problems -> Error (problem_messages problems)
      in
      let lock_path =
        option_value "--lockfile" arguments
        |> Option.value ~default:(path_join root "workflow-verifier.lock")
      in
      let* lock =
        match load_lock io ~root ~captured:captured.files lock_path with
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
      let completeness_reasons =
        (if
           List.exists
             (fun result -> not result.Verifier.complete)
             verifications
         then [ "Incomplete.Static_analysis" ]
         else [])
        @ (compilations
          |> List.concat_map (fun compilation ->
              compilation.Frontend_intf.dependencies
              |> List.filter_map (fun dependency ->
                  match dependency.Frontend_intf.status with
                  | Locked _ -> None
                  | Unresolved _ ->
                      Some
                        ("Incomplete.Unresolved_dependency: "
                       ^ dependency.reference))))
        @
        match io.source_commit () with
        | Some _ -> []
        | None -> [ "Incomplete.Unbound_build_source_commit" ]
      in
      let fails =
        List.exists (Verifier.should_fail config.persona) verifications
        || (config.persona <> Verifier.Audit && policy_diagnostics <> [])
      in
      let gate_result, exit_code =
        if fails then (Report.Finding, 1)
        else if has "--strict" arguments && completeness_reasons <> [] then
          (Report.Incomplete, 3)
        else (Report.Pass, 0)
      in
      let report =
        Report.create ~persona:config.persona
          ~inputs:
            (List.map
               (fun (path, source) ->
                 (path, "sha256:" ^ Sha256.digest_string source))
               sources)
          ~graphs ~verifications ~policy_diagnostics
          ~binary_digest:(io.binary_digest ())
          ~source_commit:(io.source_commit ()) ~config
          ~lock_digest:lock.integrity ~source_manifest_digest:manifest.digest
          ~provider_profiles:
            (graphs
            |> List.map (fun graph ->
                Ir.provider_name graph.Ir.provider ^ "-semantic-v1"))
          ~completeness_reasons ~gate_result ~exit_code
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
          manifest;
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

let check io arguments =
  let target = positional arguments |> List.rev |> first_or "." in
  let format =
    option_value "--format" arguments |> Option.value ~default:"text"
  in
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
          | Ok () -> analysis.report.provenance.exit_code))

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
  | Ok analysis ->
      let lock_path =
        option_value "--lockfile" arguments
        |> Option.value
             ~default:
               (path_join (root_for_target io target) "workflow-verifier.lock")
      in
      let lock = analysis.lock in
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
          io.write_file lock_path (Lockfile.to_canonical_json result.lockfile)
        with
        | Error message ->
            io.stderr (message ^ "\n");
            2
        | Ok () ->
            io.stdout (Lockfile.to_canonical_json result.lockfile);
            if result.unresolved = [] then 0 else 3)
      else (
        io.stdout (Lockfile.to_canonical_json result.lockfile);
        if result.unresolved = [] then 0 else 3)

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

type fix_entry = {
  path : string;
  before : string;
  before_digest : string;
  after : string;
  after_digest : string;
}

type fix_journal_state = Committing | Committed

let fix_entry_json (entry : fix_entry) =
  Json.Object
    [
      ("after", Json.String entry.after);
      ("after_digest", Json.String entry.after_digest);
      ("before", Json.String entry.before);
      ("before_digest", Json.String entry.before_digest);
      ("path", Json.String (normalize entry.path));
    ]

let fix_journal_fields state entries =
  [
    ("entries", Json.Array (List.map fix_entry_json entries));
    ( "state",
      Json.String
        (match state with
        | Committing -> "committing"
        | Committed -> "committed") );
    ("schema", Json.String "fix-journal-v1");
  ]

let fix_journal_unsigned state entries =
  Json.Object (fix_journal_fields state entries)

let fix_journal_json state entries =
  let unsigned = fix_journal_unsigned state entries in
  let digest = "sha256:" ^ Sha256.digest_string (Json.to_string unsigned) in
  Json.to_string
    (Json.Object
       (("digest", Json.String digest) :: fix_journal_fields state entries))
  ^ "\n"

let parse_fix_journal source =
  let open Util in
  let required name converter json =
    match Option.bind (Json.member name json) converter with
    | Some value -> Ok value
    | None -> Error ("fix journal needs field " ^ name)
  in
  let* json =
    match Json.parse source with
    | Ok value -> Ok value
    | Error error ->
        Error
          (Printf.sprintf "fix journal JSON byte %d: %s" error.offset
             error.message)
  in
  let* _ =
    Json.exact_object ~context:"fix-journal-v1"
      ~allowed:[ "digest"; "entries"; "schema"; "state" ]
      json
  in
  let* schema = required "schema" Json.as_string json in
  if schema <> "fix-journal-v1" then Error "unsupported fix journal schema"
  else
    let* digest = required "digest" Json.as_string json in
    let* state =
      match required "state" Json.as_string json with
      | Ok "committing" -> Ok Committing
      | Ok "committed" -> Ok Committed
      | Ok value -> Error ("unknown fix journal state " ^ value)
      | Error _ as error -> error
    in
    let* values = required "entries" Json.as_array json in
    let rec parse_entries accumulator = function
      | [] -> Ok (List.rev accumulator)
      | value :: rest ->
          let* _ =
            Json.exact_object ~context:"fix journal entry"
              ~allowed:
                [ "after"; "after_digest"; "before"; "before_digest"; "path" ]
              value
          in
          let* path = required "path" Json.as_string value in
          let* before = required "before" Json.as_string value in
          let* before_digest = required "before_digest" Json.as_string value in
          let* after = required "after" Json.as_string value in
          let* after_digest = required "after_digest" Json.as_string value in
          let segments = String.split_on_char '/' (normalize path) in
          if
            path = ""
            || (not (Filename.is_relative path))
            || List.exists (fun segment -> segment = "..") segments
            || before_digest <> "sha256:" ^ Sha256.digest_string before
            || after_digest <> "sha256:" ^ Sha256.digest_string after
          then Error "fix journal entry failed path or digest validation"
          else
            parse_entries
              ({ path; before; before_digest; after; after_digest }
              :: accumulator)
              rest
    in
    let* entries = parse_entries [] values in
    if entries = [] then Error "fix journal must contain entries"
    else
      let expected =
        "sha256:"
        ^ Sha256.digest_string
            (Json.to_string (fix_journal_unsigned state entries))
      in
      if digest <> expected then Error "fix journal digest mismatch"
      else Ok (state, entries)

let read_digest io path =
  match io.read_file path with
  | Error _ as error -> error
  | Ok source -> Ok (source, "sha256:" ^ Sha256.digest_string source)

let fix_disk_path root path = path_join root path

let verify_fix_entries io ~root expected entries =
  let rec loop = function
    | [] -> Ok ()
    | (entry : fix_entry) :: rest -> (
        match read_digest io (fix_disk_path root entry.path) with
        | Error _ as error -> error
        | Ok (_, digest) when digest = expected entry -> loop rest
        | Ok (_, digest) ->
            Error
              (Printf.sprintf "%s changed concurrently (found %s)" entry.path
                 digest))
  in
  loop entries

let rollback_fix_entries io ~root entries =
  let rec loop failures = function
    | [] ->
        if failures = [] then Ok ()
        else Error (String.concat "; " (List.rev failures))
    | (entry : fix_entry) :: rest -> (
        let path = fix_disk_path root entry.path in
        match read_digest io path with
        | Ok (_, digest) when digest = entry.before_digest -> loop failures rest
        | Ok (_, digest) when digest = entry.after_digest -> (
            match io.write_file path entry.before with
            | Ok () -> loop failures rest
            | Error message -> loop (message :: failures) rest)
        | Ok (_, digest) ->
            loop
              (Printf.sprintf "%s has conflicting digest %s" entry.path digest
              :: failures)
              rest
        | Error message -> loop (message :: failures) rest)
  in
  loop [] entries

let recover_fix_journal io ~root journal_path =
  if not (io.exists journal_path) then Ok ()
  else
    let open Util in
    let* source = io.read_file journal_path in
    let* state, entries = parse_fix_journal source in
    match state with
    | Committed ->
        let* () =
          verify_fix_entries io ~root (fun entry -> entry.after_digest) entries
        in
        io.remove_file journal_path
    | Committing ->
        let* () = rollback_fix_entries io ~root entries in
        io.remove_file journal_path

let validate_staged_fixes ~root analysis entries =
  let open Util in
  let replacement path =
    entries
    |> List.find_map (fun (entry : fix_entry) ->
        if normalize entry.path = relative_to root path then Some entry.after
        else None)
  in
  let rec rebuild accumulator = function
    | [] -> Ok (List.rev accumulator)
    | (compilation : Frontend_intf.compilation) :: rest -> (
        match replacement compilation.graph.source with
        | None -> rebuild (compilation :: accumulator) rest
        | Some source -> (
            match
              Frontend.compile_string ~provider:compilation.provider
                ~path:compilation.graph.source ~source ()
            with
            | Error problems ->
                Error (String.concat "; " (problem_messages problems))
            | Ok staged -> rebuild (staged :: accumulator) rest))
  in
  let* compilations = rebuild [] analysis.compilations in
  let original_problems =
    analysis.compilations
    |> List.concat_map (fun compilation -> compilation.Frontend_intf.problems)
  in
  let new_frontend_problems =
    compilations
    |> List.concat_map (fun compilation -> compilation.Frontend_intf.problems)
    |> List.filter (fun (problem : Frontend_intf.problem) ->
        not
          (List.exists
             (fun (original : Frontend_intf.problem) ->
               original.Frontend_intf.code = problem.code
               && original.message = problem.message)
             original_problems))
  in
  if new_frontend_problems <> [] then
    Error
      ("staged fix introduced frontend problems: "
      ^ String.concat "; " (problem_messages new_frontend_problems))
  else
    let graphs =
      List.map (fun compilation -> compilation.Frontend_intf.graph) compilations
    in
    let verification =
      Verifier.verify_program ~persona:analysis.config.persona graphs
    and policy =
      Policy.evaluate analysis.config.rules (Program_graph.compose graphs)
    in
    let before_diagnostics =
      analysis.policy_diagnostics
      @ (analysis.verifications
        |> List.concat_map (fun result -> result.Verifier.diagnostics))
    in
    let new_severe =
      verification.diagnostics @ policy
      |> List.filter (fun diagnostic ->
          List.mem diagnostic.Diagnostic.severity [ Diagnostic.Critical; Error ]
          && not
               (List.exists
                  (fun original ->
                    original.Diagnostic.rule_id = diagnostic.rule_id
                    && original.message = diagnostic.message)
                  before_diagnostics))
    in
    if new_severe <> [] then
      Error "staged fix introduced a new critical/error diagnostic"
    else if
      List.for_all
        (fun result -> result.Verifier.complete)
        analysis.verifications
      && not verification.complete
    then Error "staged fix made a complete analysis incomplete"
    else Ok ()

let fix_command io arguments =
  let target = positional arguments |> first_or "." in
  let root = root_for_target io target in
  let journal_path = path_join root ".workflow-verifier/fix-journal-v1.json" in
  match recover_fix_journal io ~root journal_path with
  | Error message ->
      io.stderr ("fix recovery: " ^ message ^ "\n");
      2
  | Ok () -> (
      match analyze io ("--persona" :: "audit" :: arguments) target with
      | Error errors ->
          List.iter (fun value -> io.stderr (value ^ "\n")) errors;
          2
      | Ok analysis -> (
          let verification_diagnostics =
            analysis.verifications
            |> List.concat_map (fun result -> result.Verifier.diagnostics)
          in
          let proposals =
            analysis.compilations
            |> List.filter_map (fun (compilation : Frontend_intf.compilation) ->
                let pin_proposals =
                  compilation.dependencies
                  |> List.filter_map
                       (fun (dependency : Frontend_intf.dependency) ->
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
                              Ir.find_node compilation.graph
                                hop.Diagnostic.node_id
                            with
                            | Some node when node.kind = Ir.Command -> Some node
                            | _ -> None))
                  |> List.filter_map (fun command ->
                      let expressions =
                        (Script_adapter.analyze (script_shell command)
                           command.name)
                          .expansions
                        |> List.map
                             (fun (expansion : Script_adapter.expansion) ->
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
                                String.sub digest 0 12 |> String.uppercase_ascii
                              )
                          in
                          Fixer.bind_expression_to_environment
                            ~cst:compilation.cst ~shell:(script_shell command)
                            ~expression ~name
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
                        io.stderr
                          (compilation.graph.source ^ ": " ^ message ^ "\n");
                        None))
          in
          if proposals = [] then (
            io.stdout "no behavior-preserving fixes available\n";
            0)
          else if not (has "--apply" arguments) then (
            List.iter
              (fun (compilation, proposal) ->
                match
                  Fixer.apply ~cst:compilation.Frontend_intf.cst proposal
                with
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
                         let before = compilation.cst.source in
                         let entry =
                           {
                             path = relative_to root compilation.graph.source;
                             before;
                             before_digest =
                               "sha256:" ^ Sha256.digest_string before;
                             after = source;
                             after_digest =
                               "sha256:" ^ Sha256.digest_string source;
                           }
                         in
                         (entry :: prepared, errors)
                     | Error message -> (prepared, message :: errors))
                   ([], [])
            in
            if preparation_errors <> [] then (
              List.rev preparation_errors
              |> List.iter (fun value -> io.stderr (value ^ "\n"));
              2)
            else
              let entries = List.rev prepared in
              let result =
                let open Util in
                let* () = validate_staged_fixes ~root analysis entries in
                let* () =
                  verify_fix_entries io ~root
                    (fun entry -> entry.before_digest)
                    entries
                in
                let* () =
                  io.write_file journal_path
                    (fix_journal_json Committing entries)
                in
                let* () =
                  match
                    verify_fix_entries io ~root
                      (fun entry -> entry.before_digest)
                      entries
                  with
                  | Ok () -> Ok ()
                  | Error message ->
                      let _ = io.remove_file journal_path in
                      Error message
                in
                let rec commit = function
                  | [] -> Ok ()
                  | (entry : fix_entry) :: rest ->
                      let* () =
                        io.write_file
                          (fix_disk_path root entry.path)
                          entry.after
                      in
                      commit rest
                in
                match commit entries with
                | Error message -> (
                    match rollback_fix_entries io ~root entries with
                    | Ok () ->
                        let _ = io.remove_file journal_path in
                        Error message
                    | Error rollback ->
                        Error (message ^ "; rollback: " ^ rollback))
                | Ok () ->
                    let* () =
                      io.write_file journal_path
                        (fix_journal_json Committed entries)
                    in
                    io.remove_file journal_path
              in
              match result with
              | Ok () -> 0
              | Error message ->
                  io.stderr (message ^ "\n");
                  2))

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
    @ if allow_workflow_network then [ Egress_broker ] else [ Network_deny ]
  in
  match backend with
  | Sandbox_protocol.Oci _ -> base
  | Linux_native -> base @ [ Namespace; Seccomp; Landlock; Cgroup_v2 ]
  | Windows_native -> base @ [ App_container; Restricted_token; Job_object ]
  | Macos_vm -> base @ [ Virtual_machine ]

let default_event = function
  | Ir.Github -> "workflow_dispatch"
  | Gitlab -> "web"
  | Azure -> "manual"
  | Circleci -> "api"

let default_runner = function
  | Sandbox_protocol.Oci _ | Linux_native -> Scenario.Linux_x86_64
  | Windows_native -> Scenario.Windows_x86_64
  | Macos_vm -> Scenario.Macos_arm64

let parse_assignments values =
  let rec loop accumulator = function
    | [] -> Ok (List.rev accumulator)
    | value :: rest -> (
        match Scenario.parse_assignment value with
        | Ok pair -> loop (pair :: accumulator) rest
        | Error _ as error -> error)
  in
  loop [] values

let scenario_for_analysis io arguments root backend analysis =
  match option_value "--scenario" arguments with
  | Some path -> (
      match io.read_file path with
      | Error _ as error -> error
      | Ok source -> Scenario.parse source)
  | None -> (
      let job = option_value "--job" arguments |> Option.value ~default:"" in
      let matching =
        analysis.compilations
        |> List.filter (fun compilation ->
            List.exists
              (fun (node : Ir.node) -> node.kind = Ir.Job && node.name = job)
              compilation.Frontend_intf.graph.nodes)
      in
      match matching with
      | [] -> Error ("selected job was not found: " ^ job)
      | _ :: _ :: _ ->
          Error ("selected job is ambiguous; use --scenario: " ^ job)
      | [ compilation ] ->
          let ( let* ) = Util.( let* ) in
          let* inputs = parse_assignments (option_values "--input" arguments) in
          let* matrix_values =
            parse_assignments (option_values "--matrix" arguments)
          in
          let matrix =
            List.map
              (fun (name, value) -> (name, Json.String value))
              matrix_values
          in
          let* variables =
            parse_assignments (option_values "--variable" arguments)
          in
          let runner =
            match option_value "--runner" arguments with
            | None -> Ok (default_runner backend)
            | Some name -> (
                match Scenario.runner_of_string name with
                | Some value -> Ok value
                | None -> Error ("unknown runner platform " ^ name))
          in
          let* runner_platform = runner in
          let entrypoint = relative_to root compilation.graph.source in
          Scenario.make ~provider:compilation.graph.provider
            ~workflow_entrypoint:entrypoint ~job
            ~event:
              (option_value "--event" arguments
              |> Option.value
                   ~default:(default_event compilation.graph.provider))
            ~inputs ~matrix ~variables ~runner_platform
            ~secret_names:(option_values "--secret" arguments))

let selected_compilations scenario compilations =
  compilations
  |> List.filter (fun compilation ->
      let source = Util.normalize_slashes compilation.Frontend_intf.graph.source
      and expected =
        Util.normalize_slashes scenario.Scenario.workflow_entrypoint
      in
      compilation.graph.provider = scenario.provider
      && (source = expected || Util.ends_with ~suffix:("/" ^ expected) source))

let sandbox_plan io arguments target =
  match analyze io ("--persona" :: "audit" :: arguments) target with
  | Error errors -> Error (String.concat "; " errors)
  | Ok analysis -> (
      let root = root_for_target io target in
      let backend =
        option_value "--backend" arguments
        |> Option.value ~default:analysis.config.sandbox.backend
        |> backend_of_argument
      in
      match scenario_for_analysis io arguments root backend analysis with
      | Error _ as error -> error
      | Ok scenario -> (
          let compilations =
            selected_compilations scenario analysis.compilations
          in
          let dependency_records =
            compilations
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
          in
          let graphs =
            List.map
              (fun compilation -> compilation.Frontend_intf.graph)
              analysis.compilations
          in
          match
            Scenario_planner.plan ~scenario ~image:analysis.config.sandbox.image
              ~graphs
          with
          | Error _ as error -> error
          | Ok planned ->
              let grants = option_values "--secret" arguments in
              let undeclared =
                grants
                |> List.filter (fun name ->
                    not (List.mem name scenario.secret_names))
              and missing =
                scenario.secret_names
                |> List.filter (fun name -> not (List.mem name grants))
              in
              if undeclared <> [] then
                Error
                  ("secret grant is not declared by scenario: "
                  ^ String.concat ", " undeclared)
              else
                let incomplete_reasons =
                  planned.incomplete_reasons
                  @ List.map
                      (fun name -> "Incomplete.Missing_secret_grant: " ^ name)
                      missing
                in
                Sandbox_protocol.make_scenario_plan ~backend
                  ~scenario_digest:scenario.digest
                  ~provider_profile:
                    (Ir.provider_name scenario.provider ^ "-semantic-v1")
                  ~selected_jobs:planned.selected_jobs
                  ~runner_platform:
                    (Scenario.runner_name scenario.runner_platform)
                  ~source_digest:analysis.manifest.digest
                  ~lock_digest:analysis.lock.integrity
                  ~controls:
                    (required_controls backend
                       ~allow_workflow_network:
                         (has "--allow-workflow-network" arguments))
                  ~limits:Sandbox_protocol.portable_limits
                  ~network_destinations:
                    (option_values "--network-destination" arguments)
                  ~secret_names:grants ~dependencies ~steps:planned.steps
                  ~incomplete_reasons))

let sandbox_audit_result io arguments target plan evidence =
  match target with
  | None -> Sandbox_audit.evaluate ~plan ~evidence
  | Some target -> (
      match analyze io ("--persona" :: "audit" :: arguments) target with
      | Error errors -> Error (String.concat "; " errors)
      | Ok analysis when analysis.manifest.digest <> plan.source_digest ->
          Error "audit target source digest does not match the execution plan"
      | Ok analysis ->
          let graphs =
            List.map
              (fun compilation -> compilation.Frontend_intf.graph)
              analysis.compilations
          in
          Sandbox_audit.evaluate_with_graphs ~graphs ~plan ~evidence)

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
                            match Evidence.validate_for_plan plan evidence with
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
      | "verify" -> (
          match positional rest with
          | plan_path :: evidence_path :: _ -> (
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
                      match Evidence.validate_for_plan plan evidence with
                      | Error message ->
                          io.stderr (message ^ "\n");
                          2
                      | Ok () ->
                          io.stdout (Evidence.to_canonical_json evidence);
                          0)))
          | _ ->
              io.stderr "sandbox verify requires PLAN EVIDENCE\n";
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
                      match Evidence.validate_for_plan plan evidence with
                      | Error message ->
                          io.stderr (message ^ "\n");
                          2
                      | Ok () -> (
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
                              | Incomplete _ -> 3)))))
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
  let optional_string = function
    | None -> Json.Null
    | Some value -> Json.String (Util.normalize_slashes value)
  in
  let backend_to_json inventory =
    let probe = inventory.probe in
    Json.Object
      [
        ("available", Json.Bool probe.available);
        ( "capabilities",
          Json.Array
            (List.map
               (fun control ->
                 Json.String (Sandbox_protocol.control_name control))
               probe.attestation.controls) );
        ("digest", optional_string inventory.digest);
        ("id", Json.String probe.attestation.id);
        ("path", optional_string inventory.path);
        ("platform", Json.String probe.attestation.platform);
        ("protocol", Json.String inventory.protocol);
        ( "reasons",
          Json.Array (List.map (fun reason -> Json.String reason) probe.reasons)
        );
        ( "required_features",
          Json.Array
            (List.map
               (fun feature -> Json.String feature)
               inventory.required_features) );
        ("signature", Json.String inventory.signature);
        ("version", Json.String probe.attestation.version);
      ]
  in
  let json =
    Json.Object
      [
        ( "backends",
          Json.Array (List.map backend_to_json services.backend_inventory) );
        ( "frontends",
          Json.Array
            (List.map
               (fun value -> Json.String (Ir.provider_name value))
               [ Ir.Github; Gitlab; Azure; Circleci ]) );
        ("platform", Json.String services.platform);
        ( "resolver_network",
          Json.Bool (Option.is_some services.resolver_network) );
        ("sandbox_executor", Json.Bool (Option.is_some services.sandbox_execute));
        ("schema", Json.String "doctor-v2");
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
          sandbox executor: %s\n\
          %s"
         services.platform
         (if Option.is_some services.resolver_network then "available"
          else "unavailable")
         (if Option.is_some services.sandbox_execute then "available"
          else "unavailable")
         (services.backend_inventory
         |> List.map (fun inventory ->
             let probe = inventory.probe in
             Printf.sprintf "backend %s: %s (%s)\n" probe.attestation.id
               (if probe.available then "available" else "unavailable")
               (if probe.reasons = [] then inventory.signature
                else String.concat "; " probe.reasons))
         |> String.concat ""));
  0

let policy_command io arguments =
  match arguments with
  | "test" :: rest -> (
      let target = positional rest |> first_or "." in
      match load_config io rest (root_for_target io target) with
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

let completion_script = function
  | "bash" ->
      {|_workflow_verifier() {
  local commands="check resolve explain graph diff fix policy sandbox doctor completion version"
  COMPREPLY=( $(compgen -W "$commands" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _workflow_verifier workflow-verifier
|}
  | "zsh" ->
      {|#compdef workflow-verifier
_arguments '1:command:(check resolve explain graph diff fix policy sandbox doctor completion version)' '*::argument:->args'
|}
  | "fish" ->
      "complete -c workflow-verifier -f -a 'check resolve explain graph diff \
       fix policy sandbox doctor completion version'\n"
  | "powershell" ->
      {|Register-ArgumentCompleter -Native -CommandName workflow-verifier -ScriptBlock {
  param($wordToComplete)
  'check','resolve','explain','graph','diff','fix','policy','sandbox','doctor','completion','version' |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
}
|}
  | _ -> ""

let dispatch io services (invocation : Cli_parser.invocation) =
  match invocation.command with
  | "version" ->
      io.stdout "workflow-verifier 0.1.0\n";
      0
  | "check" -> check io invocation.arguments
  | "explain" -> explain io invocation.arguments
  | "graph" -> graph_command io invocation.arguments
  | "diff" -> diff_command io invocation.arguments
  | "fix" -> fix_command io invocation.arguments
  | "resolve" -> resolve_command io services invocation.arguments
  | "policy" -> policy_command io invocation.arguments
  | "sandbox" -> sandbox_command io services invocation.arguments
  | "doctor" -> doctor io services invocation.arguments
  | "completion" -> (
      match invocation.arguments with
      | [ shell ] ->
          io.stdout (completion_script shell);
          0
      | _ -> 2)
  | unknown ->
      io.stderr ("internal error: unhandled parsed command " ^ unknown ^ "\n");
      4

let semantic_conformance_command io arguments =
  let target = positional arguments |> List.rev |> first_or (io.cwd ()) in
  match analyze io arguments target with
  | Ok analysis ->
      io.stdout (Semantic_conformance.to_canonical_json analysis.report);
      0
  | Error messages ->
      List.iter (fun message -> io.stderr (message ^ "\n")) messages;
      2

let run ~io ~services argv =
  let input_footer =
    "hint: correct the named argument or input at the reported location\n\
     docs: https://workflow-verifier.dev/docs/cli-v0.1#input-errors\n"
  in
  try
    if Array.length argv >= 2 && argv.(1) = "__semantic-conformance" then
      semantic_conformance_command io
        (Array.sub argv 2 (Array.length argv - 2) |> Array.to_list)
    else
      match Cli_parser.parse ~argv with
      | Help text | Version text ->
          io.stdout text;
          0
      | Error text ->
          io.stderr text;
          if not (Util.ends_with ~suffix:"\n" text) then io.stderr "\n";
          io.stderr input_footer;
          2
      | Invoke invocation ->
          let errors = Buffer.create 256 in
          let buffered_io =
            {
              io with
              stderr = (fun message -> Buffer.add_string errors message);
            }
          in
          let code = dispatch buffered_io services invocation in
          let error_text = Buffer.contents errors in
          if error_text <> "" then io.stderr error_text;
          if code = 2 then io.stderr input_footer;
          code
  with exception_ ->
    io.stderr
      ("internal error: "
      ^ Printexc.to_string exception_
      ^ "\nSee https://workflow-verifier.dev/docs/troubleshooting-v0.1\n");
    4
