type input = { path : string; digest : string }

type t = {
  schema : string;
  tool_version : string;
  persona : Verifier.persona;
  inputs : input list;
  graphs : Ir.t list;
  verifications : Verifier.result list;
  policy_diagnostics : Diagnostic.t list;
  digest : string;
}

let diagnostics report =
  List.concat_map
    (fun result -> result.Verifier.diagnostics)
    report.verifications
  @ report.policy_diagnostics
  |> List.sort Diagnostic.compare

let body_json ~digest report =
  let properties =
    List.concat_map
      (fun result -> result.Verifier.properties)
      report.verifications
    |> List.sort Property.compare
  in
  Json.Object
    [
      ( "diagnostics",
        Json.Array (List.map Diagnostic.to_json (diagnostics report)) );
      ( "digest",
        Option.fold ~none:Json.Null
          ~some:(fun value -> Json.String value)
          digest );
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
      ("persona", Json.String (Verifier.persona_name report.persona));
      ("properties", Json.Array (List.map Property.to_json properties));
      ("schema", Json.String report.schema);
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
            ("name", Json.String "workflow-verifier");
            ("version", Json.String report.tool_version);
          ] );
    ]

let make ~persona ~inputs ~graphs ~verifications ~policy_diagnostics =
  let inputs =
    inputs
    |> List.map (fun (path, digest) ->
        { path = Util.normalize_slashes path; digest })
    |> List.sort (fun (left : input) (right : input) ->
        String.compare left.path right.path)
  and graphs =
    List.sort
      (fun (left : Ir.t) (right : Ir.t) ->
        String.compare left.source right.source)
      graphs
  in
  let provisional =
    {
      schema = "report-v1";
      tool_version = "0.1.0";
      persona;
      inputs;
      graphs;
      verifications;
      policy_diagnostics;
      digest = "";
    }
  in
  let digest =
    Sha256.digest_string (Json.to_string (body_json ~digest:None provisional))
  in
  { provisional with digest = "sha256:" ^ digest }

let to_json report = body_json ~digest:(Some report.digest) report
let to_canonical_json report = Json.to_string (to_json report) ^ "\n"
