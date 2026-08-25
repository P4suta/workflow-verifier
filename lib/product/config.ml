type trust = Built_in | Trusted_policy | Repository
type provenance = { origin : string; trust : trust; digest : string }

type suppression = {
  rule : string;
  path : string;
  reason : string;
  owner : string;
  expiry : string;
}

type resolver_origin = { origin : string; path_prefixes : string list }

type resolver = {
  require_immutable : bool;
  allowed_origins : resolver_origin list;
  allowed_sources : string list;
}

type analysis_budget = {
  max_file_bytes : int;
  max_entries : int;
  max_snapshot_bytes : int64;
  max_yaml_depth : int;
  max_yaml_aliases : int;
  max_expansion_depth : int;
  max_graph_nodes : int;
  max_bdd_nodes : int;
  max_resolver_bytes : int;
  max_report_bytes : int;
}

type sandbox = {
  backend : string;
  image : string;
  network : string;
  cpu_seconds : int;
  cpu_cores : int;
  memory_mb : int;
  processes : int;
  output_bytes : int;
  scratch_bytes : int64;
  scratch_entries : int;
}

type allowlist_entry = { kind : string; value : string; reason : string }

type t = {
  version : int;
  persona : Verifier.persona;
  frontends : Ir.provider list;
  offline : bool;
  source_exclusions : string list;
  resolver : resolver;
  analysis : analysis_budget;
  sandbox : sandbox;
  allowlist : allowlist_entry list;
  rules : Policy.rule list;
  suppressions : suppression list;
  provenance : provenance;
}

let trust_name = function
  | Built_in -> "built-in"
  | Trusted_policy -> "trusted-policy"
  | Repository -> "repository"

let default_analysis =
  {
    max_file_bytes = 16 * 1024 * 1024;
    max_entries = 100_000;
    max_snapshot_bytes = 4_294_967_296L;
    max_yaml_depth = 256;
    max_yaml_aliases = 10_000;
    max_expansion_depth = 64;
    max_graph_nodes = 1_000_000;
    max_bdd_nodes = 2_000_000;
    max_resolver_bytes = 16 * 1024 * 1024;
    max_report_bytes = 256 * 1024 * 1024;
  }

let default_sandbox =
  {
    backend = "oci:docker";
    image = "sha256:unresolved";
    network = "deny";
    cpu_seconds = 900;
    cpu_cores = 1;
    memory_mb = 2048;
    processes = 128;
    output_bytes = 16 * 1024 * 1024;
    scratch_bytes = 4_294_967_296L;
    scratch_entries = 100_000;
  }

let default =
  {
    version = 2;
    persona = Verifier.Gate;
    frontends = [ Ir.Github; Ir.Gitlab; Ir.Azure; Ir.Circleci ];
    offline = true;
    source_exclusions = [];
    resolver =
      { require_immutable = true; allowed_origins = []; allowed_sources = [] };
    analysis = default_analysis;
    sandbox = default_sandbox;
    allowlist = [];
    rules = [];
    suppressions = [];
    provenance =
      {
        origin = "built-in";
        trust = Built_in;
        digest = "sha256:" ^ Sha256.digest_string "config-v2:built-in";
      };
  }

let toml_type_name = function
  | Otoml.TomlString _ -> "string"
  | Otoml.TomlInteger _ -> "integer"
  | Otoml.TomlFloat _ -> "float"
  | Otoml.TomlBoolean _ -> "boolean"
  | Otoml.TomlOffsetDateTime _ -> "offset datetime"
  | Otoml.TomlLocalDateTime _ -> "local datetime"
  | Otoml.TomlLocalDate _ -> "local date"
  | Otoml.TomlLocalTime _ -> "local time"
  | Otoml.TomlArray _ -> "array"
  | Otoml.TomlTable _ -> "table"
  | Otoml.TomlInlineTable _ -> "inline table"
  | Otoml.TomlTableArray _ -> "table array"

let table = function
  | Otoml.TomlTable fields | Otoml.TomlInlineTable fields -> Ok fields
  | value ->
      Error
        (Printf.sprintf "expected TOML table, found %s" (toml_type_name value))

let table_array = function
  | Otoml.TomlTableArray values -> Ok values
  | Otoml.TomlArray [] -> Ok []
  | value ->
      Error
        (Printf.sprintf "expected TOML table array, found %s"
           (toml_type_name value))

let string = function
  | Otoml.TomlString value -> Ok value
  | value ->
      Error
        (Printf.sprintf "expected TOML string, found %s" (toml_type_name value))

let integer = function
  | Otoml.TomlInteger value -> Ok value
  | value ->
      Error
        (Printf.sprintf "expected TOML integer, found %s" (toml_type_name value))

let boolean = function
  | Otoml.TomlBoolean value -> Ok value
  | value ->
      Error
        (Printf.sprintf "expected TOML boolean, found %s" (toml_type_name value))

let strings = function
  | Otoml.TomlArray values ->
      let rec loop accumulator = function
        | [] -> Ok (List.rev accumulator)
        | value :: rest -> (
            match string value with
            | Ok value -> loop (value :: accumulator) rest
            | Error _ as error -> error)
      in
      loop [] values
  | value ->
      Error
        (Printf.sprintf "expected TOML string array, found %s"
           (toml_type_name value))

let find key fields = List.assoc_opt key fields

let exact_fields errors context allowed fields =
  List.iter
    (fun (key, _) ->
      if not (List.mem key allowed) then
        errors := Printf.sprintf "%s has unknown key %s" context key :: !errors)
    fields

let get errors context accessor key fallback fields =
  match find key fields with
  | None -> fallback
  | Some value -> (
      match accessor value with
      | Ok value -> value
      | Error message ->
          errors := Printf.sprintf "%s.%s: %s" context key message :: !errors;
          fallback)

let nonempty errors context value =
  if String.trim value = "" then (
    errors := (context ^ " must not be empty") :: !errors;
    false)
  else true

let valid_identifier value =
  let first = function
    | 'A' .. 'Z' | 'a' .. 'z' | '_' -> true
    | _ -> false
  and rest = function
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '_' | '-' | '.' -> true
    | _ -> false
  in
  String.length value > 0
  && first value.[0]
  && String.sub value 1 (String.length value - 1) |> String.for_all rest

let valid_date value =
  let leap year = year mod 400 = 0 || (year mod 4 = 0 && year mod 100 <> 0) in
  let days year = function
    | 1 | 3 | 5 | 7 | 8 | 10 | 12 -> 31
    | 4 | 6 | 9 | 11 -> 30
    | 2 -> if leap year then 29 else 28
    | _ -> 0
  in
  if String.length value <> 10 || value.[4] <> '-' || value.[7] <> '-' then
    false
  else
    match
      ( int_of_string_opt (String.sub value 0 4),
        int_of_string_opt (String.sub value 5 2),
        int_of_string_opt (String.sub value 8 2) )
    with
    | Some year, Some month, Some day ->
        year >= 1970 && month >= 1 && month <= 12 && day >= 1
        && day <= days year month
    | _ -> false

let encoded_delimiter value =
  let lower = String.lowercase_ascii value in
  List.exists
    (fun needle -> Util.contains ~needle lower)
    [ "%2f"; "%5c"; "%3f"; "%23"; "%40"; "%25" ]

let normalize_origin value =
  let prefix = "https://" in
  if not (Util.starts_with ~prefix value) then Error "origin must use https"
  else
    let authority =
      String.sub value (String.length prefix)
        (String.length value - String.length prefix)
    in
    if authority = "" then Error "origin needs a host"
    else if
      String.exists
        (function
          | '/' | '?' | '#' | '@' | '\\' -> true
          | _ -> false)
        authority
      || encoded_delimiter authority
    then
      Error
        "origin must not contain path, userinfo, query, fragment, or encoded \
         delimiter"
    else
      let host = String.lowercase_ascii authority in
      if host = "localhost" || Util.ends_with ~suffix:".localhost" host then
        Error "localhost is not a resolver origin"
      else if
        String.contains host ':' && not (Util.ends_with ~suffix:":443" host)
      then Error "resolver origin ports must be 443"
      else
        let host =
          if Util.ends_with ~suffix:":443" host then
            String.sub host 0 (String.length host - 4)
          else host
        in
        if
          host = ""
          || String.for_all
               (function
                 | '0' .. '9' | '.' -> true
                 | _ -> false)
               host
        then Error "literal and empty resolver hosts are forbidden"
        else Ok (prefix ^ host)

let normalize_path_prefix value =
  if value = "" || value.[0] <> '/' then Error "path prefix must start with /"
  else if
    String.contains value '\\' || String.contains value '?'
    || String.contains value '#' || encoded_delimiter value
    || List.exists
         (fun segment -> segment = "." || segment = "..")
         (String.split_on_char '/' value)
  then Error "path prefix contains an unsafe segment or delimiter"
  else if Util.ends_with ~suffix:"/" value then Ok value
  else Ok (value ^ "/")

let parse_origin errors value =
  match table value with
  | Error message ->
      errors := ("resolver.allowed_origins: " ^ message) :: !errors;
      None
  | Ok fields ->
      exact_fields errors "resolver.allowed_origins[]"
        [ "origin"; "path_prefixes" ]
        fields;
      let raw_origin =
        get errors "resolver.allowed_origins[]" string "origin" "" fields
      and raw_prefixes =
        get errors "resolver.allowed_origins[]" strings "path_prefixes" []
          fields
      in
      let origin =
        match normalize_origin raw_origin with
        | Ok value -> Some value
        | Error message ->
            errors :=
              ("resolver.allowed_origins[].origin: " ^ message) :: !errors;
            None
      and path_prefixes =
        raw_prefixes
        |> List.filter_map (fun prefix ->
            match normalize_path_prefix prefix with
            | Ok value -> Some value
            | Error message ->
                errors :=
                  ("resolver.allowed_origins[].path_prefixes: " ^ message)
                  :: !errors;
                None)
        |> Util.deduplicate_strings
      in
      Option.map (fun origin -> { origin; path_prefixes }) origin

let provider errors = function
  | "github" -> Some Ir.Github
  | "gitlab" -> Some Ir.Gitlab
  | "azure" -> Some Ir.Azure
  | "circleci" -> Some Ir.Circleci
  | value ->
      errors := ("unknown frontend: " ^ value) :: !errors;
      None

let parse_rule errors value =
  match table value with
  | Error message ->
      errors := ("rules[]: " ^ message) :: !errors;
      None
  | Ok fields ->
      exact_fields errors "rules[]"
        [ "id"; "kind"; "limit"; "message"; "severity"; "selector" ]
        fields;
      let id = get errors "rules[]" string "id" "" fields
      and kind_name = get errors "rules[]" string "kind" "" fields in
      ignore (nonempty errors "rules[].id" id);
      let selector =
        match find "selector" fields with
        | None -> Policy.All []
        | Some value -> (
            match table value with
            | Error message ->
                errors := ("rules[].selector: " ^ message) :: !errors;
                Policy.All []
            | Ok selector_fields -> (
                let mode =
                  get errors "rules[].selector" string "mode" "all"
                    selector_fields
                in
                let predicates =
                  selector_fields
                  |> List.filter_map (fun (key, raw) ->
                      if key = "mode" then None
                      else
                        match string raw with
                        | Error message ->
                            errors :=
                              Printf.sprintf "rules[].selector.%s: %s" key
                                message
                              :: !errors;
                            None
                        | Ok value -> (
                            match Policy.predicate_of_assignment key value with
                            | Ok predicate -> Some predicate
                            | Error message ->
                                errors := (id ^ ": " ^ message) :: !errors;
                                None))
                in
                match mode with
                | "all" -> Policy.All predicates
                | "any" -> Policy.Any predicates
                | "none" -> Policy.None_of predicates
                | _ ->
                    errors :=
                      (id ^ ": selector.mode must be all, any, or none")
                      :: !errors;
                    Policy.All predicates))
      in
      let kind =
        match String.lowercase_ascii kind_name with
        | "forbid" -> Some Policy.Forbid
        | "require" -> Some Policy.Require
        | "forbid_path" -> Some Policy.Forbid_path
        | "limit" ->
            Some (Policy.Limit (get errors "rules[]" integer "limit" 0 fields))
        | _ ->
            errors := (id ^ ": unknown rule kind") :: !errors;
            None
      and severity =
        match get errors "rules[]" string "severity" "error" fields with
        | "critical" -> Diagnostic.Critical
        | "error" -> Diagnostic.Error
        | "warning" -> Diagnostic.Warning
        | "note" -> Diagnostic.Note
        | _ ->
            errors := (id ^ ": unknown severity") :: !errors;
            Diagnostic.Error
      in
      Option.map
        (fun kind ->
          {
            Policy.id;
            kind;
            selector;
            message =
              get errors "rules[]" string "message"
                ("policy " ^ id ^ " failed")
                fields;
            severity;
          })
        kind

let parse_suppression errors ?today value =
  match table value with
  | Error message ->
      errors := ("suppressions[]: " ^ message) :: !errors;
      None
  | Ok fields ->
      exact_fields errors "suppressions[]"
        [ "rule"; "path"; "reason"; "owner"; "expiry" ]
        fields;
      let required key =
        let value = get errors "suppressions[]" string key "" fields in
        ignore (nonempty errors ("suppressions[]." ^ key) value);
        value
      in
      let rule = required "rule"
      and path = required "path"
      and reason = required "reason"
      and owner = required "owner"
      and expiry = required "expiry" in
      if not (valid_identifier owner) then
        errors :=
          "suppressions[].owner must be a portable identifier" :: !errors;
      if not (valid_date expiry) then
        errors :=
          "suppressions[].expiry must be a valid YYYY-MM-DD date" :: !errors;
      Option.iter
        (fun today ->
          if
            valid_date expiry && valid_date today
            && String.compare expiry today < 0
          then
            errors :=
              Printf.sprintf "suppression %s expired on %s" rule expiry
              :: !errors)
        today;
      Some { rule; path = Util.normalize_slashes path; reason; owner; expiry }

let parse_allowlist errors value =
  match table value with
  | Error message ->
      errors := ("allowlist[]: " ^ message) :: !errors;
      None
  | Ok fields ->
      exact_fields errors "allowlist[]" [ "kind"; "value"; "reason" ] fields;
      let get_required key = get errors "allowlist[]" string key "" fields in
      let kind = get_required "kind"
      and value = get_required "value"
      and reason = get_required "reason" in
      if not (List.mem kind [ "dependency"; "network_host"; "source" ]) then
        errors := ("unknown allowlist kind: " ^ kind) :: !errors;
      ignore (nonempty errors "allowlist[].value" value);
      ignore (nonempty errors "allowlist[].reason" reason);
      Some { kind; value; reason }

let sources_of_origins origins =
  origins
  |> List.concat_map (fun entry ->
      match entry.path_prefixes with
      | [] -> [ entry.origin ^ "/" ]
      | prefixes -> List.map (fun prefix -> entry.origin ^ prefix) prefixes)
  |> Util.deduplicate_strings

let validate_repository_config errors config =
  if config.persona = Verifier.Audit then
    errors := "repository config cannot weaken persona to audit" :: !errors;
  if config.frontends <> default.frontends then
    errors := "repository config cannot disable provider frontends" :: !errors;
  if config.resolver.allowed_origins <> [] then
    errors := "repository config cannot grant resolver origins" :: !errors;
  if config.suppressions <> [] then
    errors := "repository config cannot add suppressions" :: !errors;
  if config.allowlist <> [] then
    errors := "repository config cannot add allowlist entries" :: !errors;
  if config.source_exclusions <> [] then
    errors := "repository config cannot exclude source paths" :: !errors;
  if config.sandbox.backend <> default.sandbox.backend then
    errors := "repository config cannot select a sandbox backend" :: !errors;
  if config.sandbox.image <> default.sandbox.image then
    errors := "repository config cannot select a workload capsule" :: !errors

let analysis_of_table errors fields =
  exact_fields errors "analysis"
    [
      "max_file_bytes";
      "max_entries";
      "max_snapshot_bytes";
      "max_yaml_depth";
      "max_yaml_aliases";
      "max_expansion_depth";
      "max_graph_nodes";
      "max_bdd_nodes";
      "max_resolver_bytes";
      "max_report_bytes";
    ]
    fields;
  {
    max_file_bytes =
      get errors "analysis" integer "max_file_bytes"
        default_analysis.max_file_bytes fields;
    max_entries =
      get errors "analysis" integer "max_entries" default_analysis.max_entries
        fields;
    max_snapshot_bytes =
      Int64.of_int
        (get errors "analysis" integer "max_snapshot_bytes"
           (Int64.to_int default_analysis.max_snapshot_bytes)
           fields);
    max_yaml_depth =
      get errors "analysis" integer "max_yaml_depth"
        default_analysis.max_yaml_depth fields;
    max_yaml_aliases =
      get errors "analysis" integer "max_yaml_aliases"
        default_analysis.max_yaml_aliases fields;
    max_expansion_depth =
      get errors "analysis" integer "max_expansion_depth"
        default_analysis.max_expansion_depth fields;
    max_graph_nodes =
      get errors "analysis" integer "max_graph_nodes"
        default_analysis.max_graph_nodes fields;
    max_bdd_nodes =
      get errors "analysis" integer "max_bdd_nodes"
        default_analysis.max_bdd_nodes fields;
    max_resolver_bytes =
      get errors "analysis" integer "max_resolver_bytes"
        default_analysis.max_resolver_bytes fields;
    max_report_bytes =
      get errors "analysis" integer "max_report_bytes"
        default_analysis.max_report_bytes fields;
  }

let resolver_of_table errors fields =
  exact_fields errors "resolver"
    [ "require_immutable"; "allowed_origins" ]
    fields;
  let require_immutable =
    get errors "resolver" boolean "require_immutable" true fields
  in
  if not require_immutable then
    errors := "resolver.require_immutable must remain true" :: !errors;
  let allowed_origins =
    match find "allowed_origins" fields with
    | None -> []
    | Some value -> (
        match table_array value with
        | Error message ->
            errors := ("resolver.allowed_origins: " ^ message) :: !errors;
            []
        | Ok values -> List.filter_map (parse_origin errors) values)
  in
  {
    require_immutable;
    allowed_origins;
    allowed_sources = sources_of_origins allowed_origins;
  }

let sandbox_of_table errors fields =
  exact_fields errors "sandbox"
    [
      "backend";
      "capsule_digest";
      "network";
      "wall_time_seconds";
      "cpu_cores";
      "memory_bytes";
      "processes";
      "output_bytes";
      "scratch_bytes";
      "scratch_entries";
    ]
    fields;
  let memory_bytes =
    get errors "sandbox" integer "memory_bytes"
      (default_sandbox.memory_mb * 1024 * 1024)
      fields
  in
  {
    backend =
      get errors "sandbox" string "backend" default_sandbox.backend fields;
    image =
      get errors "sandbox" string "capsule_digest" default_sandbox.image fields;
    network =
      get errors "sandbox" string "network" default_sandbox.network fields;
    cpu_seconds =
      get errors "sandbox" integer "wall_time_seconds"
        default_sandbox.cpu_seconds fields;
    cpu_cores =
      get errors "sandbox" integer "cpu_cores" default_sandbox.cpu_cores fields;
    memory_mb = memory_bytes / (1024 * 1024);
    processes =
      get errors "sandbox" integer "processes" default_sandbox.processes fields;
    output_bytes =
      get errors "sandbox" integer "output_bytes" default_sandbox.output_bytes
        fields;
    scratch_bytes =
      Int64.of_int
        (get errors "sandbox" integer "scratch_bytes"
           (Int64.to_int default_sandbox.scratch_bytes)
           fields);
    scratch_entries =
      get errors "sandbox" integer "scratch_entries"
        default_sandbox.scratch_entries fields;
  }

let validate_budgets errors analysis sandbox =
  let analysis_values =
    [
      analysis.max_file_bytes;
      analysis.max_entries;
      analysis.max_yaml_depth;
      analysis.max_yaml_aliases;
      analysis.max_expansion_depth;
      analysis.max_graph_nodes;
      analysis.max_bdd_nodes;
      analysis.max_resolver_bytes;
      analysis.max_report_bytes;
    ]
  in
  if List.exists (( >= ) 0) analysis_values || analysis.max_snapshot_bytes <= 0L
  then errors := "analysis budgets must be positive" :: !errors;
  if
    analysis.max_file_bytes < 16 * 1024 * 1024
    || analysis.max_entries < 100_000
    || analysis.max_snapshot_bytes < 4_294_967_296L
  then
    errors :=
      "analysis snapshot budgets must meet the published 16 MiB/file, \
       100000-entry, 4 GiB floor" :: !errors;
  let valid_backend value =
    List.mem value [ "linux-native"; "windows-native"; "macos-vm" ]
    || (Util.starts_with ~prefix:"oci:" value && String.length value > 4)
  in
  if not (valid_backend sandbox.backend) then
    errors := "sandbox.backend is not a supported typed backend" :: !errors;
  if
    sandbox.image <> "sha256:unresolved"
    && not (Dependency_identity.valid_content_digest sandbox.image)
  then errors := "sandbox.capsule_digest must be sha256" :: !errors;
  if sandbox.network <> "deny" then
    errors :=
      "sandbox.network must be deny; egress is a scenario grant" :: !errors;
  if
    sandbox.cpu_seconds <> 900 || sandbox.cpu_cores <> 1
    || sandbox.memory_mb <> 2048 || sandbox.processes <> 128
    || sandbox.output_bytes <> 16 * 1024 * 1024
    || sandbox.scratch_bytes <> 4_294_967_296L
    || sandbox.scratch_entries <> 100_000
  then errors := "sandbox portable limits are fixed by runner-v2" :: !errors

let source_exclusions errors root =
  let values = get errors "config-v2" strings "source_exclusions" [] root in
  let valid value =
    value <> "" && Util.valid_utf8 value
    && (not (String.contains value '\\'))
    && Filename.is_relative value
    && (not (Util.starts_with ~prefix:"/" value))
    && (not (String.contains value ':'))
    && value |> String.split_on_char '/'
       |> List.for_all (fun segment ->
           segment <> "" && segment <> "." && segment <> "..")
  in
  List.iter
    (fun value ->
      if not (valid value) then
        errors :=
          ("source_exclusions entries must be portable relative path prefixes: "
         ^ value)
          :: !errors;
      if value = ".workflow-verifier.toml" || value = "workflow-verifier.lock"
      then
        errors :=
          ("source_exclusions cannot remove configuration or lock evidence: "
         ^ value)
          :: !errors)
    values;
  let folded = List.map String.lowercase_ascii values in
  if List.length folded <> List.length (Util.deduplicate_strings folded) then
    errors :=
      "source_exclusions must be unique under portable case folding" :: !errors;
  values

let parse ?(origin = "explicit") ?(trust = Trusted_policy) ?today source =
  match Otoml.Parser.from_string_result source with
  | Error message -> Error [ "config-v2 TOML: " ^ message ]
  | Ok document -> (
      match table document with
      | Error message -> Error [ "config-v2: " ^ message ]
      | Ok root ->
          let errors = ref [] in
          exact_fields errors "config-v2"
            [
              "version";
              "persona";
              "frontends";
              "offline";
              "source_exclusions";
              "analysis";
              "resolver";
              "sandbox";
              "allowlist";
              "rules";
              "suppressions";
            ]
            root;
          if Option.is_none (find "version" root) then
            errors := "configuration must declare version = 2" :: !errors;
          let version = get errors "config-v2" integer "version" 2 root in
          if version <> 2 then
            errors := "configuration version must be 2" :: !errors;
          let persona =
            match get errors "config-v2" string "persona" "gate" root with
            | "gate" -> Verifier.Gate
            | "audit" -> Verifier.Audit
            | "paranoid" -> Verifier.Paranoid
            | _ ->
                errors := "persona must be gate, audit, or paranoid" :: !errors;
                Verifier.Gate
          and frontends =
            get errors "config-v2" strings "frontends"
              [ "github"; "gitlab"; "azure"; "circleci" ]
              root
            |> List.filter_map (provider errors)
          and offline = get errors "config-v2" boolean "offline" true root
          and source_exclusions = source_exclusions errors root in
          if not offline then
            errors :=
              "offline must remain true; network requires a per-command grant"
              :: !errors;
          if
            List.length frontends
            <> List.length (Util.deduplicate_compare Stdlib.compare frontends)
          then errors := "frontends must be unique" :: !errors;
          let analysis =
            match find "analysis" root with
            | None -> default_analysis
            | Some raw -> (
                match table raw with
                | Ok fields -> analysis_of_table errors fields
                | Error message ->
                    errors := ("analysis: " ^ message) :: !errors;
                    default_analysis)
          and resolver =
            match find "resolver" root with
            | None -> default.resolver
            | Some raw -> (
                match table raw with
                | Ok fields -> resolver_of_table errors fields
                | Error message ->
                    errors := ("resolver: " ^ message) :: !errors;
                    default.resolver)
          and sandbox =
            match find "sandbox" root with
            | None -> default_sandbox
            | Some raw -> (
                match table raw with
                | Ok fields -> sandbox_of_table errors fields
                | Error message ->
                    errors := ("sandbox: " ^ message) :: !errors;
                    default_sandbox)
          in
          validate_budgets errors analysis sandbox;
          let parse_array name parser =
            match find name root with
            | None -> []
            | Some value -> (
                match table_array value with
                | Error message ->
                    errors := (name ^ ": " ^ message) :: !errors;
                    []
                | Ok values -> List.filter_map (parser errors) values)
          in
          let rules = parse_array "rules" parse_rule
          and suppressions =
            parse_array "suppressions" (parse_suppression ?today)
          and allowlist = parse_array "allowlist" parse_allowlist in
          let config =
            {
              version;
              persona;
              frontends;
              offline;
              source_exclusions;
              resolver;
              analysis;
              sandbox;
              allowlist;
              rules;
              suppressions;
              provenance =
                {
                  origin = Util.normalize_slashes origin;
                  trust;
                  digest = "sha256:" ^ Sha256.digest_string source;
                };
            }
          in
          if trust = Repository then validate_repository_config errors config;
          if !errors = [] then Ok config else Error (List.rev !errors))

let suppressed config (diagnostic : Diagnostic.t) =
  let path = Util.normalize_slashes diagnostic.span.file in
  List.exists
    (fun suppression ->
      suppression.rule = diagnostic.rule_id
      && (suppression.path = "**" || suppression.path = path))
    config.suppressions

let origin_json entry =
  Json.Object
    [
      ("origin", Json.String entry.origin);
      ( "path_prefixes",
        Json.Array
          (List.map (fun value -> Json.String value) entry.path_prefixes) );
    ]

let to_json config =
  Json.Object
    [
      ( "allowlist",
        Json.Array
          (List.map
             (fun entry ->
               Json.Object
                 [
                   ("kind", Json.String entry.kind);
                   ("reason", Json.String entry.reason);
                   ("value", Json.String entry.value);
                 ])
             config.allowlist) );
      ( "analysis",
        Json.Object
          [
            ("max_bdd_nodes", Json.Int config.analysis.max_bdd_nodes);
            ("max_entries", Json.Int config.analysis.max_entries);
            ("max_expansion_depth", Json.Int config.analysis.max_expansion_depth);
            ("max_file_bytes", Json.Int config.analysis.max_file_bytes);
            ("max_graph_nodes", Json.Int config.analysis.max_graph_nodes);
            ("max_report_bytes", Json.Int config.analysis.max_report_bytes);
            ("max_resolver_bytes", Json.Int config.analysis.max_resolver_bytes);
            ("max_snapshot_bytes", Json.Int64 config.analysis.max_snapshot_bytes);
            ("max_yaml_aliases", Json.Int config.analysis.max_yaml_aliases);
            ("max_yaml_depth", Json.Int config.analysis.max_yaml_depth);
          ] );
      ( "frontends",
        Json.Array
          (List.map
             (fun value -> Json.String (Ir.provider_name value))
             config.frontends) );
      ("offline", Json.Bool config.offline);
      ("persona", Json.String (Verifier.persona_name config.persona));
      ( "source_exclusions",
        Json.Array
          (List.map (fun value -> Json.String value) config.source_exclusions)
      );
      ( "provenance",
        Json.Object
          [
            ("digest", Json.String config.provenance.digest);
            ("origin", Json.String config.provenance.origin);
            ("trust", Json.String (trust_name config.provenance.trust));
          ] );
      ( "resolver",
        Json.Object
          [
            ( "allowed_origins",
              Json.Array (List.map origin_json config.resolver.allowed_origins)
            );
            ("require_immutable", Json.Bool config.resolver.require_immutable);
          ] );
      ("rules", Json.Array (List.map Policy.rule_to_json config.rules));
      ( "sandbox",
        Json.Object
          [
            ("backend", Json.String config.sandbox.backend);
            ("capsule_digest", Json.String config.sandbox.image);
            ("cpu_cores", Json.Int config.sandbox.cpu_cores);
            ("memory_bytes", Json.Int (config.sandbox.memory_mb * 1024 * 1024));
            ("network", Json.String config.sandbox.network);
            ("output_bytes", Json.Int config.sandbox.output_bytes);
            ("processes", Json.Int config.sandbox.processes);
            ("scratch_bytes", Json.Int64 config.sandbox.scratch_bytes);
            ("scratch_entries", Json.Int config.sandbox.scratch_entries);
            ("wall_time_seconds", Json.Int config.sandbox.cpu_seconds);
          ] );
      ( "suppressions",
        Json.Array
          (List.map
             (fun suppression ->
               Json.Object
                 [
                   ("expiry", Json.String suppression.expiry);
                   ("owner", Json.String suppression.owner);
                   ("path", Json.String suppression.path);
                   ("reason", Json.String suppression.reason);
                   ("rule", Json.String suppression.rule);
                 ])
             config.suppressions) );
      ("version", Json.Int config.version);
    ]
