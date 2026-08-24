type suppression = { rule : string; path : string option; reason : string }
type resolver = { require_immutable : bool; allowed_sources : string list }

type sandbox = {
  backend : string;
  image : string;
  network : string;
  cpu_seconds : int;
  memory_mb : int;
  processes : int;
  output_bytes : int;
}

type allowlist_entry = { kind : string; value : string; reason : string }

type t = {
  version : int;
  persona : Verifier.persona;
  frontends : Ir.provider list;
  offline : bool;
  resolver : resolver;
  sandbox : sandbox;
  allowlist : allowlist_entry list;
  rules : Policy.rule list;
  suppressions : suppression list;
}

let default =
  {
    version = 1;
    persona = Verifier.Gate;
    frontends = [ Ir.Github; Ir.Gitlab; Ir.Azure; Ir.Circleci ];
    offline = true;
    resolver = { require_immutable = true; allowed_sources = [] };
    sandbox =
      {
        backend = "oci:docker";
        image = "sha256:unresolved";
        network = "deny";
        cpu_seconds = 900;
        memory_mb = 2048;
        processes = 128;
        output_bytes = 10_000_000;
      };
    allowlist = [];
    rules = [];
    suppressions = [];
  }

let strip_comment line =
  let quote = ref false and answer = ref (String.length line) in
  String.iteri
    (fun index character ->
      if character = '"' then quote := not !quote
      else if character = '#' && (not !quote) && !answer = String.length line
      then answer := index)
    line;
  String.sub line 0 !answer |> String.trim

let unquote value =
  let value = String.trim value in
  if
    String.length value >= 2
    && value.[0] = '"'
    && value.[String.length value - 1] = '"'
  then Ok (String.sub value 1 (String.length value - 2))
  else Error ("expected a quoted string: " ^ value)

let string_array value =
  let value = String.trim value in
  if
    String.length value < 2
    || value.[0] <> '['
    || value.[String.length value - 1] <> ']'
  then Error "expected an array"
  else
    let body = String.sub value 1 (String.length value - 2) |> String.trim in
    if body = "" then Ok []
    else
      let rec collect accumulator = function
        | [] -> Ok (List.rev accumulator)
        | item :: rest -> (
            match unquote item with
            | Ok value -> collect (value :: accumulator) rest
            | Error _ as error -> error)
      in
      collect [] (String.split_on_char ',' body)

let assignment line =
  match String.index_opt line '=' with
  | None -> Error ("expected key = value: " ^ line)
  | Some index ->
      Ok
        ( String.sub line 0 index |> String.trim,
          String.sub line (index + 1) (String.length line - index - 1)
          |> String.trim )

type section =
  | Root
  | Resolver
  | Sandbox
  | Rule
  | Suppression
  | Allowlist
  | Other

let parse source =
  let root_fields = ref []
  and resolver_fields = ref []
  and sandbox_fields = ref []
  and rule_blocks = ref []
  and suppression_blocks = ref []
  and allowlist_blocks = ref []
  and current = ref Root
  and current_fields = ref []
  and resolver_declared = ref false
  and sandbox_declared = ref false
  and errors = ref [] in
  let flush () =
    (match !current with
    | Rule when !current_fields <> [] ->
        rule_blocks := List.rev !current_fields :: !rule_blocks
    | Suppression when !current_fields <> [] ->
        suppression_blocks := List.rev !current_fields :: !suppression_blocks
    | Allowlist when !current_fields <> [] ->
        allowlist_blocks := List.rev !current_fields :: !allowlist_blocks
    | Resolver when !current_fields <> [] ->
        resolver_fields := List.rev_append !current_fields !resolver_fields
    | Sandbox when !current_fields <> [] ->
        sandbox_fields := List.rev_append !current_fields !sandbox_fields
    | _ -> ());
    current_fields := []
  in
  source |> String.split_on_char '\n'
  |> List.iteri (fun line_number raw ->
      let line = strip_comment raw in
      if line = "" then ()
      else if line = "[[rules]]" then (
        flush ();
        current := Rule)
      else if line = "[[suppressions]]" then (
        flush ();
        current := Suppression)
      else if line = "[[allowlist]]" then (
        flush ();
        current := Allowlist)
      else if line = "[resolver]" then (
        flush ();
        if !resolver_declared then
          errors := "resolver section must occur at most once" :: !errors;
        resolver_declared := true;
        current := Resolver)
      else if line = "[sandbox]" then (
        flush ();
        if !sandbox_declared then
          errors := "sandbox section must occur at most once" :: !errors;
        sandbox_declared := true;
        current := Sandbox)
      else if Util.starts_with ~prefix:"[" line then (
        flush ();
        current := Other;
        errors := ("unknown configuration section: " ^ line) :: !errors)
      else
        match assignment line with
        | Error message ->
            errors :=
              Printf.sprintf "line %d: %s" (line_number + 1) message :: !errors
        | Ok (key, value) -> (
            if Util.contains ~needle:"eval" (String.lowercase_ascii key) then
              errors :=
                Printf.sprintf "line %d: string evaluation is forbidden"
                  (line_number + 1)
                :: !errors
            else
              match !current with
              | Root -> root_fields := (key, value) :: !root_fields
              | Resolver | Sandbox | Rule | Suppression | Allowlist ->
                  current_fields := (key, value) :: !current_fields
              | Other -> ()));
  flush ();
  let lookup key fields = List.assoc_opt key fields in
  let parse_int key default fields =
    match lookup key fields with
    | None -> default
    | Some value -> (
        match int_of_string_opt value with
        | Some value -> value
        | None ->
            errors := (key ^ " must be an integer") :: !errors;
            default)
  and parse_bool key default fields =
    match lookup key fields with
    | None -> default
    | Some value -> (
        match bool_of_string_opt value with
        | Some value -> value
        | None ->
            errors := (key ^ " must be true or false") :: !errors;
            default)
  in
  let known_root = [ "version"; "persona"; "frontends"; "offline" ] in
  let root_keys = List.map fst !root_fields in
  if List.length root_keys <> List.length (Util.deduplicate_strings root_keys)
  then errors := "root configuration keys must be unique" :: !errors;
  List.iter
    (fun (key, _) ->
      if not (List.mem key known_root) then
        errors := ("unknown configuration key: " ^ key) :: !errors)
    !root_fields;
  let persona =
    match lookup "persona" !root_fields |> Option.map unquote with
    | None | Some (Ok "gate") -> Verifier.Gate
    | Some (Ok "audit") -> Audit
    | Some (Ok "paranoid") -> Paranoid
    | Some _ ->
        errors := "persona must be gate, audit, or paranoid" :: !errors;
        Gate
  in
  let frontends =
    match lookup "frontends" !root_fields with
    | None -> default.frontends
    | Some raw -> (
        match string_array raw with
        | Error message ->
            errors := message :: !errors;
            default.frontends
        | Ok names ->
            let providers =
              names
              |> List.filter_map (fun name ->
                  match String.lowercase_ascii name with
                  | "github" -> Some Ir.Github
                  | "gitlab" -> Some Gitlab
                  | "azure" -> Some Azure
                  | "circleci" -> Some Circleci
                  | _ ->
                      errors := ("unknown frontend: " ^ name) :: !errors;
                      None)
            in
            if
              List.length providers
              <> List.length (Util.deduplicate_compare Stdlib.compare providers)
            then errors := "frontends must be unique" :: !errors;
            providers)
  in
  let unique_fields section fields =
    let keys = List.map fst fields in
    if List.length keys <> List.length (Util.deduplicate_strings keys) then
      errors := (section ^ " keys must be unique") :: !errors
  in
  unique_fields "resolver" !resolver_fields;
  unique_fields "sandbox" !sandbox_fields;
  List.iter
    (fun (key, _) ->
      if not (List.mem key [ "require_immutable"; "allowed_sources" ]) then
        errors := ("unknown resolver key: " ^ key) :: !errors)
    !resolver_fields;
  List.iter
    (fun (key, _) ->
      if
        not
          (List.mem key
             [
               "backend";
               "image";
               "network";
               "cpu_seconds";
               "memory_mb";
               "processes";
               "output_bytes";
             ])
      then errors := ("unknown sandbox key: " ^ key) :: !errors)
    !sandbox_fields;
  let require_immutable =
    parse_bool "require_immutable" true !resolver_fields
  in
  if not require_immutable then
    errors := "resolver.require_immutable must remain true" :: !errors;
  let allowed_sources =
    match lookup "allowed_sources" !resolver_fields with
    | None -> []
    | Some raw -> (
        match string_array raw with
        | Ok values -> Util.deduplicate_strings values
        | Error message ->
            errors := ("resolver.allowed_sources: " ^ message) :: !errors;
            [])
  in
  let resolver = { require_immutable; allowed_sources } in
  let sandbox_string key fallback =
    match lookup key !sandbox_fields with
    | None -> fallback
    | Some raw -> (
        match unquote raw with
        | Ok value -> value
        | Error message ->
            errors := message :: !errors;
            fallback)
  in
  let backend = sandbox_string "backend" default.sandbox.backend
  and image = sandbox_string "image" default.sandbox.image
  and network = sandbox_string "network" default.sandbox.network in
  let valid_backend value =
    List.mem value [ "linux-native"; "windows-native"; "macos-vm" ]
    || Util.starts_with ~prefix:"oci:" value
       && String.length value > String.length "oci:"
  in
  if not (valid_backend backend) then
    errors := "sandbox.backend is not a supported backend identity" :: !errors;
  if
    image <> "sha256:unresolved"
    && (String.length image <> 71
       || not (Util.starts_with ~prefix:"sha256:" image))
  then errors := "sandbox.image must be a sha256 content digest" :: !errors;
  if network <> "deny" then
    errors :=
      "sandbox.network must be deny; execution network is an explicit CLI \
       opt-in" :: !errors;
  let sandbox =
    {
      backend;
      image;
      network;
      cpu_seconds =
        parse_int "cpu_seconds" default.sandbox.cpu_seconds !sandbox_fields;
      memory_mb =
        parse_int "memory_mb" default.sandbox.memory_mb !sandbox_fields;
      processes =
        parse_int "processes" default.sandbox.processes !sandbox_fields;
      output_bytes =
        parse_int "output_bytes" default.sandbox.output_bytes !sandbox_fields;
    }
  in
  if
    List.exists (( >= ) 0)
      [
        sandbox.cpu_seconds;
        sandbox.memory_mb;
        sandbox.processes;
        sandbox.output_bytes;
      ]
  then errors := "sandbox limits must be positive" :: !errors;
  let parse_rule fields =
    let get_string key =
      match lookup key fields with
      | Some value -> (
          match unquote value with
          | Ok value -> Some value
          | Error message ->
              errors := message :: !errors;
              None)
      | None -> None
    in
    List.iter
      (fun (key, _) ->
        if
          not
            (List.mem key [ "id"; "kind"; "limit"; "message"; "severity" ]
            || Util.starts_with ~prefix:"selector." key)
        then errors := ("unknown policy key: " ^ key) :: !errors)
      fields;
    match (get_string "id", get_string "kind") with
    | Some id, Some kind ->
        let predicates =
          fields
          |> List.filter_map (fun (key, raw) ->
              if
                Util.starts_with ~prefix:"selector." key
                && key <> "selector.mode"
              then
                let selector_key = String.sub key 9 (String.length key - 9) in
                match unquote raw with
                | Error message ->
                    errors := message :: !errors;
                    None
                | Ok value -> (
                    match Policy.predicate_of_assignment selector_key value with
                    | Ok predicate -> Some predicate
                    | Error message ->
                        errors := (id ^ ": " ^ message) :: !errors;
                        None)
              else None)
        in
        let selector =
          match get_string "selector.mode" with
          | None | Some "all" -> Policy.All predicates
          | Some "any" -> Policy.Any predicates
          | Some "none" -> Policy.None_of predicates
          | Some _ ->
              errors :=
                (id ^ ": selector.mode must be all, any, or none") :: !errors;
              Policy.All predicates
        in
        let kind =
          match String.lowercase_ascii kind with
          | "forbid" -> Some Policy.Forbid
          | "require" -> Some Require
          | "forbid_path" -> Some Forbid_path
          | "limit" -> Some (Limit (parse_int "limit" 0 fields))
          | _ ->
              errors := (id ^ ": unknown rule kind") :: !errors;
              None
        in
        Option.map
          (fun kind ->
            {
              Policy.id;
              kind;
              selector;
              message =
                Option.value
                  ~default:("policy " ^ id ^ " failed")
                  (get_string "message");
              severity =
                (match get_string "severity" with
                | None | Some "error" -> Diagnostic.Error
                | Some "critical" -> Critical
                | Some "warning" -> Warning
                | Some "note" -> Note
                | Some _ ->
                    errors := (id ^ ": unknown severity") :: !errors;
                    Error);
            })
          kind
    | _ ->
        errors := "every policy rule needs quoted id and kind" :: !errors;
        None
  in
  let rules = List.rev !rule_blocks |> List.filter_map parse_rule in
  let parse_suppression fields =
    List.iter
      (fun (key, _) ->
        if not (List.mem key [ "rule"; "path"; "reason" ]) then
          errors := ("unknown suppression key: " ^ key) :: !errors)
      fields;
    let get key =
      Option.bind (lookup key fields) (fun raw ->
          match unquote raw with
          | Ok x -> Some x
          | Error _ -> None)
    in
    match (get "rule", get "reason") with
    | Some rule, Some reason when String.trim reason <> "" ->
        Some { rule; path = get "path"; reason }
    | _ ->
        errors := "suppression needs a rule and non-empty reason" :: !errors;
        None
  in
  let suppressions =
    List.rev !suppression_blocks |> List.filter_map parse_suppression
  in
  let parse_allowlist fields =
    unique_fields "allowlist" fields;
    List.iter
      (fun (key, _) ->
        if not (List.mem key [ "kind"; "value"; "reason" ]) then
          errors := ("unknown allowlist key: " ^ key) :: !errors)
      fields;
    let get key =
      match lookup key fields with
      | None -> None
      | Some raw -> (
          match unquote raw with
          | Ok value -> Some value
          | Error message ->
              errors := message :: !errors;
              None)
    in
    match (get "kind", get "value", get "reason") with
    | Some kind, Some value, Some reason
      when String.trim value <> "" && String.trim reason <> "" ->
        if List.mem kind [ "dependency"; "network_host"; "source" ] then
          Some { kind; value; reason }
        else (
          errors := ("unknown allowlist kind: " ^ kind) :: !errors;
          None)
    | _ ->
        errors :=
          "allowlist entries need kind, value, and non-empty reason" :: !errors;
        None
  in
  let allowlist =
    List.rev !allowlist_blocks |> List.filter_map parse_allowlist
  in
  let version = parse_int "version" 1 !root_fields
  and offline = parse_bool "offline" true !root_fields in
  if version <> 1 then errors := "configuration version must be 1" :: !errors;
  if not offline then
    errors := "offline must remain true; network is a command opt-in" :: !errors;
  if !errors <> [] then Error (List.rev !errors)
  else
    Ok
      {
        version;
        persona;
        frontends;
        offline;
        resolver;
        sandbox;
        allowlist;
        rules;
        suppressions;
      }

let suppressed config (diagnostic : Diagnostic.t) =
  let path = Util.normalize_slashes diagnostic.span.file in
  List.exists
    (fun suppression ->
      suppression.rule = diagnostic.rule_id
      &&
      match suppression.path with
      | None -> true
      | Some expected -> Util.normalize_slashes expected = path)
    config.suppressions

let to_json config =
  Json.Object
    [
      ( "frontends",
        Json.Array
          (List.map
             (fun value -> Json.String (Ir.provider_name value))
             config.frontends) );
      ("offline", Json.Bool config.offline);
      ("persona", Json.String (Verifier.persona_name config.persona));
      ( "resolver",
        Json.Object
          [
            ( "allowed_sources",
              Json.Array
                (List.map
                   (fun value -> Json.String value)
                   config.resolver.allowed_sources) );
            ("require_immutable", Json.Bool config.resolver.require_immutable);
          ] );
      ( "sandbox",
        Json.Object
          [
            ("backend", Json.String config.sandbox.backend);
            ("image", Json.String config.sandbox.image);
            ("cpu_seconds", Json.Int config.sandbox.cpu_seconds);
            ("memory_mb", Json.Int config.sandbox.memory_mb);
            ("network", Json.String config.sandbox.network);
            ("output_bytes", Json.Int config.sandbox.output_bytes);
            ("processes", Json.Int config.sandbox.processes);
          ] );
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
      ("rules", Json.Array (List.map Policy.rule_to_json config.rules));
      ( "suppressions",
        Json.Array
          (List.map
             (fun suppression ->
               Json.Object
                 [
                   ( "path",
                     Option.fold ~none:Json.Null
                       ~some:(fun value -> Json.String value)
                       suppression.path );
                   ("reason", Json.String suppression.reason);
                   ("rule", Json.String suppression.rule);
                 ])
             config.suppressions) );
      ("version", Json.Int config.version);
    ]
