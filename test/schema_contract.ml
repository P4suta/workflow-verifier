let fail format =
  Printf.ksprintf
    (fun value ->
      prerr_endline value;
      exit 1)
    format

let schemas =
  [
    ( "workflow-verifier-report-1.schema.json",
      "https://workflow-verifier.dev/schema/workflow-verifier-report-1.json" );
    ( "workflow-verifier-graph-1.schema.json",
      "https://workflow-verifier.dev/schema/workflow-verifier-graph-1.json" );
    ( "semantic-conformance-1.schema.json",
      "https://workflow-verifier.dev/schema/semantic-conformance-1.json" );
    ( "source-manifest-v2.schema.json",
      "https://workflow-verifier.dev/schema/source-manifest-v2.json" );
    ( "scenario-v1.schema.json",
      "https://workflow-verifier.dev/schema/scenario-v1.json" );
    ("lock-v2.schema.json", "https://workflow-verifier.dev/schema/lock-v2.json");
    ( "config-v2.schema.json",
      "https://workflow-verifier.dev/schema/config-v2.json" );
    ( "runner-v2.schema.json",
      "https://workflow-verifier.dev/schema/runner-v2.json" );
    ( "evidence-v2.schema.json",
      "https://workflow-verifier.dev/schema/evidence-v2.json" );
    ( "sandbox-run-v2.schema.json",
      "https://workflow-verifier.dev/schema/sandbox-run-v2.json" );
    ( "sandbox-audit-v1.schema.json",
      "https://workflow-verifier.dev/schema/sandbox-audit-v1.json" );
    ( "backend-attestation-v1.schema.json",
      "https://workflow-verifier.dev/schema/backend-attestation-v1.json" );
    ( "vm-image-v1.schema.json",
      "https://workflow-verifier.dev/schema/vm-image-v1.json" );
    ( "vm-observation-v1.schema.json",
      "https://workflow-verifier.dev/schema/vm-observation-v1.json" );
    ( "vm-shim-request-v1.schema.json",
      "https://workflow-verifier.dev/schema/vm-shim-request-v1.json" );
    ( "corpus-v1.schema.json",
      "https://workflow-verifier.dev/schema/corpus-v1.json" );
    ( "corpus-report-v1.schema.json",
      "https://workflow-verifier.dev/schema/corpus-report-v1.json" );
    ( "corpus-review-v1.schema.json",
      "https://workflow-verifier.dev/schema/corpus-review-v1.json" );
    ( "performance-v2.schema.json",
      "https://workflow-verifier.dev/schema/performance-v2.json" );
    ( "performance-comparison-v2.schema.json",
      "https://workflow-verifier.dev/schema/performance-comparison-v2.json" );
    ( "performance-suite-v2.schema.json",
      "https://workflow-verifier.dev/schema/performance-suite-v2.json" );
    ( "mutation-gate-v1.schema.json",
      "https://workflow-verifier.dev/schema/mutation-gate-v1.json" );
    ( "mutation-campaign-v1.schema.json",
      "https://workflow-verifier.dev/schema/mutation-campaign-v1.json" );
    ( "determinism-v2.schema.json",
      "https://workflow-verifier.dev/schema/determinism-v2.json" );
    ( "determinism-comparison-v2.schema.json",
      "https://workflow-verifier.dev/schema/determinism-comparison-v2.json" );
    ( "dogfood-v1.schema.json",
      "https://workflow-verifier.dev/schema/dogfood-v1.json" );
    ( "doctor-v2.schema.json",
      "https://workflow-verifier.dev/schema/doctor-v2.json" );
    ( "release-evidence-v3.schema.json",
      "https://workflow-verifier.dev/schema/release-evidence-v3.json" );
    ( "release-evidence-v4.schema.json",
      "https://workflow-verifier.dev/schema/release-evidence-v4.json" );
    ( "crate-package-v1.schema.json",
      "https://workflow-verifier.dev/schema/crate-package-v1.json" );
    ( "release-index-v1.schema.json",
      "https://workflow-verifier.dev/schema/release-index-v1.json" );
    ( "release-gate-v1.schema.json",
      "https://workflow-verifier.dev/schema/release-gate-v1.json" );
    ( "reproducibility-fragment-v1.schema.json",
      "https://workflow-verifier.dev/schema/reproducibility-fragment-v1.json" );
    ( "reproducibility-fragment-v2.schema.json",
      "https://workflow-verifier.dev/schema/reproducibility-fragment-v2.json" );
    ( "maintainer-self-audit-v2.schema.json",
      "https://workflow-verifier.dev/schema/maintainer-self-audit-v2.json" );
    ( "network-profile-v1.schema.json",
      "https://workflow-verifier.dev/schema/network-profile-v1.json" );
    ( "sbom-components-v1.schema.json",
      "https://workflow-verifier.dev/schema/sbom-components-v1.json" );
  ]

let schema_root =
  let direct = Filename.concat (Sys.getcwd ()) "schema" in
  if Sys.file_exists direct then direct
  else Filename.concat (Sys.getcwd ()) "../schema"

let () =
  List.iter
    (fun (name, expected_id) ->
      let path = Filename.concat schema_root name in
      let source =
        match Util.read_file path with
        | Ok value -> value
        | Error message -> fail "%s" message
      in
      let json =
        match Json.parse source with
        | Ok value -> value
        | Error error -> fail "%s byte %d: %s" name error.offset error.message
      in
      if Json.member "$id" json <> Some (Json.String expected_id) then
        fail "%s has wrong or missing $id" name;
      if
        Json.member "$schema" json
        <> Some (Json.String "https://json-schema.org/draft/2020-12/schema")
      then fail "%s does not use JSON Schema 2020-12" name;
      Printf.printf "ok - %s is canonical JSON Schema 2020-12\n" name)
    schemas;
  let runner_path = Filename.concat schema_root "runner-v2.schema.json" in
  let runner =
    match Util.read_file runner_path with
    | Ok value -> value
    | Error error -> fail "%s" error
  in
  if Util.contains ~needle:"secret_values" runner then
    fail "runner schema must never transport secret values";
  let config_path = Filename.concat schema_root "config-v2.schema.json" in
  let config =
    match Util.read_file config_path with
    | Error message -> fail "%s" message
    | Ok source -> (
        match Json.parse source with
        | Ok value -> value
        | Error error ->
            fail "config schema byte %d: %s" error.offset error.message)
  in
  let definitions = Json.member "$defs" config in
  let predicate = Option.bind definitions (Json.member "predicate") in
  let one_of = Option.bind predicate (Json.member "oneOf") in
  let predicate_variants = Option.bind one_of Json.as_array in
  if
    Option.fold ~none:true
      ~some:(fun values -> List.length values <> 8)
      predicate_variants
  then fail "config schema must strictly type all eight policy predicates";
  let selector = Option.bind definitions (Json.member "selector") in
  [ "all"; "any"; "none" ]
  |> List.iter (fun mode ->
      let reference =
        let properties = Option.bind selector (Json.member "properties") in
        let collection = Option.bind properties (Json.member mode) in
        let items = Option.bind collection (Json.member "items") in
        let reference = Option.bind items (Json.member "$ref") in
        Option.bind reference Json.as_string
      in
      if reference <> Some "#/$defs/predicate" then
        fail "config selector.%s must reference the strict predicate schema"
          mode);
  Printf.printf "%d versioned schemas passed\n" (List.length schemas)
