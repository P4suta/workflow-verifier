let level = function
  | Diagnostic.Critical | Error -> "error"
  | Warning -> "warning"
  | Note -> "note"

let region span =
  Json.Object
    [
      ("endColumn", Json.Int span.Span.stop.column);
      ("endLine", Json.Int span.stop.line);
      ("startColumn", Json.Int span.start.column);
      ("startLine", Json.Int span.start.line);
    ]

let physical_location span =
  Json.Object
    [
      ( "artifactLocation",
        Json.Object
          [ ("uri", Json.String (Util.normalize_slashes span.Span.file)) ] );
      ("region", region span);
    ]

let location span = Json.Object [ ("physicalLocation", physical_location span) ]

let rule_descriptor diagnostic =
  Json.Object
    [
      ("id", Json.String diagnostic.Diagnostic.rule_id);
      ("name", Json.String diagnostic.rule_id);
      ( "helpUri",
        Json.String
          ("https://workflow-verifier.dev/rules/"
          ^ String.lowercase_ascii diagnostic.rule_id) );
      ( "shortDescription",
        Json.Object [ ("text", Json.String diagnostic.message) ] );
    ]

let trace_location index (hop : Diagnostic.trace_hop) =
  Json.Object
    [
      ( "location",
        Json.Object
          [
            ("message", Json.Object [ ("text", Json.String hop.label) ]);
            ("physicalLocation", physical_location hop.span);
          ] );
      ("nestingLevel", Json.Int index);
    ]

let code_flows trace =
  Json.Array
    [
      Json.Object
        [
          ( "threadFlows",
            Json.Array
              [
                Json.Object
                  [ ("locations", Json.Array (List.mapi trace_location trace)) ];
              ] );
        ];
    ]

let fix_json (fix : Diagnostic.fix) =
  let artifact_changes =
    match (fix.replacement, fix.span) with
    | Some replacement, Some span ->
        Json.Array
          [
            Json.Object
              [
                ( "artifactLocation",
                  Json.Object
                    [
                      ( "uri",
                        Json.String (Util.normalize_slashes span.Span.file) );
                    ] );
                ( "replacements",
                  Json.Array
                    [
                      Json.Object
                        [
                          ("deletedRegion", region span);
                          ( "insertedContent",
                            Json.Object [ ("text", Json.String replacement) ] );
                        ];
                    ] );
              ];
          ]
    | _ -> Json.Array []
  in
  Json.Object
    [
      ("artifactChanges", artifact_changes);
      ("description", Json.Object [ ("text", Json.String fix.description) ]);
      ("properties", Json.Object [ ("kind", Json.String fix.kind) ]);
    ]

let result diagnostic =
  let fields =
    [
      ("codeFlows", code_flows diagnostic.Diagnostic.trace);
      ("level", Json.String (level diagnostic.Diagnostic.severity));
      ("locations", Json.Array [ location diagnostic.span ]);
      ("message", Json.Object [ ("text", Json.String diagnostic.message) ]);
      ( "partialFingerprints",
        Json.Object [ ("workflowVerifier/v1", Json.String diagnostic.id) ] );
      ( "properties",
        Json.Object
          [
            ( "confidence",
              Json.String (Diagnostic.confidence_name diagnostic.confidence) );
            ( "capabilities",
              Json.Array
                (List.map
                   (fun capability ->
                     Json.String (Ir.capability_name capability))
                   diagnostic.capabilities) );
            ( "evidence",
              Json.Array
                (List.map (fun value -> Json.String value) diagnostic.evidence)
            );
            ("diagnosticId", Json.String diagnostic.id);
          ] );
      ("ruleId", Json.String diagnostic.rule_id);
    ]
  in
  let fields =
    match diagnostic.fix with
    | None -> fields
    | Some fix -> ("fixes", Json.Array [ fix_json fix ]) :: fields
  in
  Json.Object fields

let to_json report =
  let diagnostics = Report.diagnostics report in
  let rules =
    diagnostics
    |> List.sort_uniq (fun left right ->
        String.compare left.Diagnostic.rule_id right.rule_id)
    |> List.map rule_descriptor
  in
  Json.Object
    [
      ( "$schema",
        Json.String
          "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
      );
      ( "runs",
        Json.Array
          [
            Json.Object
              [
                ( "automationDetails",
                  Json.Object [ ("id", Json.String report.Report.digest) ] );
                ( "invocations",
                  Json.Array
                    [
                      Json.Object
                        [
                          ( "executionSuccessful",
                            Json.Bool
                              (report.provenance.exit_code <> 4
                              && report.provenance.exit_code <> 5) );
                          ("exitCode", Json.Int report.provenance.exit_code);
                          ( "exitCodeDescription",
                            Json.String
                              (Report.gate_result_name
                                 report.provenance.gate_result) );
                          ( "properties",
                            Json.Object
                              [
                                ("reportDigest", Json.String report.digest);
                                ( "sourceManifestDigest",
                                  Json.String
                                    report.provenance.source_manifest_digest );
                              ] );
                        ];
                    ] );
                ("results", Json.Array (List.map result diagnostics));
                ( "tool",
                  Json.Object
                    [
                      ( "driver",
                        Json.Object
                          [
                            ( "informationUri",
                              Json.String
                                "https://github.com/P4suta/workflow-verifier" );
                            ("name", Json.String "workflow-verifier");
                            ("rules", Json.Array rules);
                            ("version", Json.String report.Report.tool_version);
                          ] );
                    ] );
              ];
          ] );
      ("version", Json.String "2.1.0");
    ]

let to_canonical_json report = Json.to_string (to_json report) ^ "\n"
