open Otoml

let table = function
  | Otoml.TomlTable fields | TomlInlineTable fields -> Ok fields
  | _ -> Error "expected a TOML table"

let find name fields = List.assoc_opt name fields
let replace name value fields = (name, value) :: List.remove_assoc name fields

let remove names fields =
  List.filter (fun (name, _) -> not (List.mem name names)) fields

let rec normalize_for_printer = function
  | TomlTable fields -> TomlTable (order_fields fields)
  | TomlTableArray tables ->
      TomlTableArray (List.map normalize_for_printer tables)
  | value -> value

and order_fields fields =
  let fields =
    List.map (fun (name, value) -> (name, normalize_for_printer value)) fields
  in
  let scalar, sections =
    List.partition
      (fun (_, value) ->
        match value with
        | TomlTable _ | TomlTableArray _ -> false
        | _ -> true)
      fields
  in
  scalar @ sections

let strings = function
  | Otoml.TomlArray values ->
      let rec loop accumulator = function
        | [] -> Ok (List.rev accumulator)
        | Otoml.TomlString value :: rest -> loop (value :: accumulator) rest
        | _ -> Error "expected an array of strings"
      in
      loop [] values
  | _ -> Error "expected an array of strings"

let split_https_url value =
  let prefix = "https://" in
  if not (Util.starts_with ~prefix value) then
    Error ("legacy resolver source must be an HTTPS URL: " ^ value)
  else
    let rest =
      String.sub value (String.length prefix)
        (String.length value - String.length prefix)
    in
    let authority, path =
      match String.index_opt rest '/' with
      | None -> (rest, "/")
      | Some index ->
          ( String.sub rest 0 index,
            String.sub rest index (String.length rest - index) )
    in
    if
      authority = ""
      || String.exists (fun c -> List.mem c [ '@'; '?'; '#'; '\\' ]) value
      || Util.contains ~needle:".." path
    then Error ("unsafe legacy resolver source: " ^ value)
    else
      let path = if Util.ends_with ~suffix:"/" path then path else path ^ "/" in
      Ok (String.lowercase_ascii (prefix ^ authority), path)

let migrate_resolver errors = function
  | raw -> (
      match table raw with
      | Error message ->
          errors := ("resolver: " ^ message) :: !errors;
          raw
      | Ok fields ->
          let origins =
            match find "allowed_sources" fields with
            | None -> []
            | Some raw_sources -> (
                match strings raw_sources with
                | Error message ->
                    errors :=
                      ("resolver.allowed_sources: " ^ message) :: !errors;
                    []
                | Ok sources ->
                    sources
                    |> List.filter_map (fun source ->
                        match split_https_url source with
                        | Error message ->
                            errors := message :: !errors;
                            None
                        | Ok (origin, path) ->
                            Some
                              (Otoml.TomlTable
                                 [
                                   ("origin", TomlString origin);
                                   ( "path_prefixes",
                                     TomlArray [ TomlString path ] );
                                 ])))
          in
          fields
          |> remove [ "allowed_sources"; "allowed_origins" ]
          |> replace "require_immutable" (TomlBoolean true)
          |> replace "allowed_origins" (TomlTableArray origins)
          |> fun fields -> Otoml.TomlTable fields)

let migrate_sandbox errors = function
  | raw -> (
      match table raw with
      | Error message ->
          errors := ("sandbox: " ^ message) :: !errors;
          raw
      | Ok fields ->
          let capsule =
            match (find "capsule_digest" fields, find "image" fields) with
            | Some value, _ | None, Some value -> value
            | None, None -> TomlString "sha256:unresolved"
          in
          fields
          |> remove
               [
                 "image";
                 "cpu_seconds";
                 "memory_mb";
                 "wall_time_seconds";
                 "cpu_cores";
                 "memory_bytes";
                 "processes";
                 "output_bytes";
                 "scratch_bytes";
                 "scratch_entries";
                 "capsule_digest";
               ]
          |> replace "capsule_digest" capsule
          |> replace "network" (TomlString "deny")
          |> replace "wall_time_seconds" (TomlInteger 900)
          |> replace "cpu_cores" (TomlInteger 1)
          |> replace "memory_bytes" (TomlInteger 2_147_483_648)
          |> replace "processes" (TomlInteger 128)
          |> replace "output_bytes" (TomlInteger 16_777_216)
          |> replace "scratch_bytes" (TomlInteger 4_294_967_296)
          |> replace "scratch_entries" (TomlInteger 100_000)
          |> fun fields -> Otoml.TomlTable fields)

let migrate_suppressions errors ~owner ~expiry = function
  | Otoml.TomlTableArray values ->
      if values <> [] && (Option.is_none owner || Option.is_none expiry) then (
        errors :=
          "legacy suppressions require --suppression-owner and \
           --suppression-expiry" :: !errors;
        TomlTableArray values)
      else
        TomlTableArray
          (List.map
             (fun value ->
               match table value with
               | Error message ->
                   errors := ("suppressions[]: " ^ message) :: !errors;
                   value
               | Ok fields ->
                   ( ( fields |> fun fields ->
                       Option.fold ~none:fields
                         ~some:(fun value ->
                           replace "owner" (TomlString value) fields)
                         owner )
                   |> fun fields ->
                     Option.fold ~none:fields
                       ~some:(fun value ->
                         replace "expiry" (TomlString value) fields)
                       expiry )
                   |> fun fields -> TomlTable fields)
             values)
  | value ->
      errors := "suppressions must be an array of tables" :: !errors;
      value

let default_analysis =
  Otoml.TomlTable
    [
      ("max_file_bytes", TomlInteger 16_777_216);
      ("max_entries", TomlInteger 100_000);
      ("max_snapshot_bytes", TomlInteger 4_294_967_296);
      ("max_yaml_depth", TomlInteger 256);
      ("max_yaml_aliases", TomlInteger 10_000);
      ("max_expansion_depth", TomlInteger 64);
      ("max_graph_nodes", TomlInteger 1_000_000);
      ("max_bdd_nodes", TomlInteger 2_000_000);
      ("max_resolver_bytes", TomlInteger 16_777_216);
      ("max_report_bytes", TomlInteger 268_435_456);
    ]

let migrate_v1 ?suppression_owner ?suppression_expiry ~today source =
  match Otoml.Parser.from_string_result source with
  | Error message -> Error [ "config-v1 TOML: " ^ message ]
  | Ok document -> (
      match table document with
      | Error message -> Error [ "config-v1: " ^ message ]
      | Ok fields -> (
          let errors = ref [] in
          (match find "version" fields with
          | Some (Otoml.TomlInteger 1) -> ()
          | Some (TomlInteger 2) ->
              errors := "input is already config-v2" :: !errors
          | _ ->
              errors :=
                "legacy configuration must declare version = 1" :: !errors);
          let fields = replace "version" (TomlInteger 2) fields in
          let fields =
            match find "resolver" fields with
            | None -> fields
            | Some value ->
                replace "resolver" (migrate_resolver errors value) fields
          in
          let fields =
            match find "sandbox" fields with
            | None -> fields
            | Some value ->
                replace "sandbox" (migrate_sandbox errors value) fields
          in
          let fields =
            match find "suppressions" fields with
            | None -> fields
            | Some value ->
                replace "suppressions"
                  (migrate_suppressions errors ~owner:suppression_owner
                     ~expiry:suppression_expiry value)
                  fields
          in
          let fields =
            if Option.is_some (find "analysis" fields) then fields
            else replace "analysis" default_analysis fields
          in
          if !errors <> [] then Error (List.rev !errors)
          else
            let output =
              Otoml.Printer.to_string ~indent_width:2 ~indent_subtables:false
                ~newline_before_table:true ~collapse_tables:false
                ~force_table_arrays:true
                (normalize_for_printer (TomlTable fields))
              |> fun value ->
              if Util.ends_with ~suffix:"\n" value then value else value ^ "\n"
            in
            match
              Config.parse ~origin:"migration:config-v1"
                ~trust:Config.Trusted_policy ~today output
            with
            | Ok _ -> Ok output
            | Error validation -> Error validation))
