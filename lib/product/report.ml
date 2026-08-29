type input = { path : string; digest : string }
type gate_result = Pass | Finding | Incomplete

type provenance = {
  binary_digest : string;
  source_commit : string option;
  config_origin : string;
  config_trust : string;
  config_digest : string;
  lock_digest : string;
  source_manifest_digest : string;
  provider_profiles : string list;
  completeness_reasons : string list;
  gate_result : gate_result;
  exit_code : int;
}

type t = {
  schema : string;
  tool_version : string;
  persona : Verifier.persona;
  inputs : input list;
  graphs : Ir.t list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  provenance : provenance;
  digest : string;
}

let gate_result_name = function
  | Pass -> "pass"
  | Finding -> "finding"
  | Incomplete -> "incomplete"

let diagnostics report =
  List.concat_map
    (fun result -> result.Verifier.diagnostics)
    report.verifications
  @ report.policy_diagnostics
  |> List.sort Diagnostic.compare

let option_string = function
  | None -> Json.Null
  | Some value -> Json.String value

let body_json ~digest report =
  let properties =
    List.concat_map
      (fun result -> result.Verifier.properties)
      report.verifications
    |> List.sort Property.compare
  in
  let complete = report.provenance.completeness_reasons = [] in
  Json.Object
    [
      ( "completeness",
        Json.Object
          [
            ( "reasons",
              Json.Array
                (List.map
                   (fun value -> Json.String value)
                   report.provenance.completeness_reasons) );
            ( "state",
              Json.String (if complete then "complete" else "incomplete") );
          ] );
      ( "configuration",
        Json.Object
          [
            ("digest", Json.String report.provenance.config_digest);
            ("origin", Json.String report.provenance.config_origin);
            ("trust", Json.String report.provenance.config_trust);
          ] );
      ( "diagnostics",
        Json.Array (List.map Diagnostic.to_json (diagnostics report)) );
      ( "digest",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          digest );
      ( "gate",
        Json.Object
          [
            ("exit_code", Json.Int report.provenance.exit_code);
            ( "result",
              Json.String (gate_result_name report.provenance.gate_result) );
          ] );
      ("graphs", Json.Array (List.map Ir.to_json report.graphs));
      ( "inputs",
        Json.Array
          (List.map
             (fun (input : input) ->
               Json.Object
                 [
                   ("digest", Json.String input.digest);
                   ("path", Json.String (Util.normalize_slashes input.path));
                 ])
             report.inputs) );
      ( "lock",
        Json.Object [ ("digest", Json.String report.provenance.lock_digest) ] );
      ("persona", Json.String (Verifier.persona_name report.persona));
      ( "provider_profiles",
        Json.Array
          (List.map
             (fun value -> Json.String value)
             report.provenance.provider_profiles) );
      ("properties", Json.Array (List.map Property.to_json properties));
      ("schema", Json.String report.schema);
      ( "snapshot",
        Json.Object
          [
            ("digest", Json.String report.provenance.source_manifest_digest);
            ("schema", Json.String "source-manifest-v2");
          ] );
      ( "summary",
        Json.Object
          [
            ("diagnostics", Json.Int (List.length (diagnostics report)));
            ("graphs", Json.Int (List.length report.graphs));
            ("inputs", Json.Int (List.length report.inputs));
            ( "unknown_properties",
              Json.Int
                (List.length
                   (List.filter
                      (fun property ->
                        match property.Property.state with
                        | Unknown _ -> true
                        | _ -> false)
                      properties)) );
          ] );
      ( "tool",
        Json.Object
          [
            ("binary_digest", Json.String report.provenance.binary_digest);
            ( "build",
              Json.Object
                [
                  ("dune", Json.String "3.24.2");
                  ("ocaml", Json.String Sys.ocaml_version);
                  ( "source_commit",
                    option_string report.provenance.source_commit );
                ] );
            ("name", Json.String "workflow-verifier");
            ("version", Json.String report.tool_version);
          ] );
    ]

let normalize_inputs inputs =
  inputs
  |> List.map (fun (path, digest) ->
      { path = Util.normalize_slashes path; digest })
  |> List.sort (fun (left : input) (right : input) ->
      String.compare left.path right.path)

let normalize_graphs graphs =
  List.sort
    (fun (left : Ir.t) (right : Ir.t) ->
      String.compare left.source right.source)
    graphs

let build ~persona ~inputs ~graphs ~verifications ~policy_diagnostics provenance
    =
  let provisional =
    {
      schema = "workflow-verifier-report/1";
      tool_version = "0.1.0";
      persona;
      inputs = normalize_inputs inputs;
      graphs = normalize_graphs graphs;
      verifications;
      policy_diagnostics;
      provenance;
      digest = "";
    }
  in
  let digest =
    "sha256:"
    ^ Sha256.digest_string (Json.to_string (body_json ~digest:None provisional))
  in
  { provisional with digest }

let create ~persona ~inputs ~graphs ~verifications ~policy_diagnostics
    ~binary_digest ~source_commit ~config ~lock_digest ~source_manifest_digest
    ~provider_profiles ~completeness_reasons ~gate_result ~exit_code =
  let public_origin origin =
    let origin = Util.normalize_slashes origin in
    if
      Filename.is_relative origin
      && (not (Util.starts_with ~prefix:"/" origin))
      && (not (String.length origin >= 2 && origin.[1] = ':'))
      && origin |> String.split_on_char '/'
         |> List.for_all (fun segment -> segment <> "..")
    then origin
    else "external:" ^ Filename.basename origin
  in
  let provenance =
    {
      binary_digest;
      source_commit;
      config_origin = public_origin config.Config.provenance.origin;
      config_trust = Config.trust_name config.provenance.trust;
      config_digest = config.provenance.digest;
      lock_digest;
      source_manifest_digest;
      provider_profiles = Util.deduplicate_strings provider_profiles;
      completeness_reasons = Util.deduplicate_strings completeness_reasons;
      gate_result;
      exit_code;
    }
  in
  build ~persona ~inputs ~graphs ~verifications ~policy_diagnostics provenance

let to_json report = body_json ~digest:(Some report.digest) report
let to_canonical_json report = Json.to_string (to_json report) ^ "\n"
