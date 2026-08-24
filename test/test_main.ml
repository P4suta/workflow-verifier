type test = { name : string; run : unit -> unit }

exception Assertion_failed of string

let fail format =
  Printf.ksprintf (fun message -> raise (Assertion_failed message)) format

let expect_equal_string ~expected actual =
  if expected <> actual then fail "expected %S, got %S" expected actual

let expect_equal_int ~expected actual =
  if expected <> actual then fail "expected %d, got %d" expected actual

let expect_true message condition = if not condition then fail "%s" message

let require_some label = function
  | Some value -> value
  | None -> fail "expected %s" label

let foundation_tests =
  [
    {
      name = "canonical JSON sorts keys and emits no insignificant whitespace";
      run =
        (fun () ->
          let value =
            Json.Object
              [
                ("z", Json.Int 1);
                ("a", Json.Array [ Json.Bool true; Json.String "line\n" ]);
              ]
          in
          expect_equal_string ~expected:"{\"a\":[true,\"line\\n\"],\"z\":1}"
            (Json.to_string value));
    };
    {
      name = "canonical JSON parser rejects duplicate keys";
      run =
        (fun () ->
          match Json.parse "{\"a\":1,\"a\":2}" with
          | Error _ -> ()
          | Ok _ -> fail "duplicate JSON keys must be rejected");
    };
    {
      name = "JSON Unicode escapes retain nonzero decimal digits";
      run =
        (fun () ->
          match Json.parse "\"\\u1234\"" with
          | Ok (Json.String value) ->
              expect_equal_string ~expected:"\xe1\x88\xb4" value
          | Ok _ -> fail "Unicode escape did not produce a JSON string"
          | Error error -> fail "Unicode escape failed: %s" error.message);
    };
    {
      name = "JSON form-feed escapes retain their character";
      run =
        (fun () ->
          match Json.parse "\"before\\fafter\"" with
          | Ok (Json.String value) ->
              expect_equal_string ~expected:"before\012after" value
          | Ok _ -> fail "form-feed escape did not produce a JSON string"
          | Error error -> fail "form-feed escape failed: %s" error.message);
    };
    {
      name = "pretty JSON preserves empty and multi-element arrays";
      run =
        (fun () ->
          expect_equal_string ~expected:"[]\n"
            (Json.to_pretty_string (Json.Array []));
          expect_equal_string ~expected:"{}\n"
            (Json.to_pretty_string (Json.Object []));
          expect_equal_string ~expected:"[\n  1,\n  2\n]\n"
            (Json.to_pretty_string (Json.Array [ Json.Int 1; Json.Int 2 ]));
          expect_equal_string ~expected:"[\n  [\n    1\n  ]\n]\n"
            (Json.to_pretty_string
               (Json.Array [ Json.Array [ Json.Int 1 ] ]));
          expect_equal_string
            ~expected:"{\n  \"a\": 1,\n  \"z\": [\n    2\n  ]\n}\n"
            (Json.to_pretty_string
               (Json.Object
                  [ ("z", Json.Array [ Json.Int 2 ]); ("a", Json.Int 1) ])));
    };
    {
      name = "JSON parser preserves escape and UTF-8 boundary values";
      run =
        (fun () ->
          let expect_string source expected =
            match Json.parse source with
            | Ok (Json.String value) -> expect_equal_string ~expected value
            | Ok _ -> fail "escape did not produce a JSON string: %s" source
            | Error error -> fail "escape failed for %s: %s" source error.message
          in
          expect_string "\"\\\\\"" "\\";
          expect_string "\"\\b\"" "\008";
          expect_string "\"\\t\"" "\t";
          expect_string "\"\\uABCD\"" "\xea\xaf\x8d";
          expect_string "\"\\u00af\"" "\xc2\xaf";
          expect_string "\"\\u007f\"" "\127";
          expect_string "\"\\u07ff\"" "\xdf\xbf";
          (match Json.parse "\"\\u12G4\"" with
          | Error _ -> ()
          | Ok _ -> fail "invalid hexadecimal Unicode digit must be rejected");
          List.iter
            (fun boundary ->
              match Json.parse (string_of_int boundary) with
              | Ok (Json.Int value) -> expect_equal_int ~expected:boundary value
              | Ok _ ->
                  fail "%d must retain the JSON Int representation" boundary
              | Error error ->
                  fail "%d failed to parse: %s" boundary error.message)
            [ min_int; max_int ];
          let outside_native_range =
            [
              Int64.pred (Int64.of_int min_int);
              Int64.succ (Int64.of_int max_int);
            ]
          in
          List.iter
            (fun boundary ->
              match Json.parse (Int64.to_string boundary) with
              | Ok (Json.Int64 value) when Int64.equal value boundary -> ()
              | Ok _ ->
                  fail "%Ld must retain the JSON Int64 representation" boundary
              | Error error ->
                  fail "%Ld failed to parse: %s" boundary error.message)
            outside_native_range);
    };
    {
      name = "JSON decimal syntax retains its integer-only root cause";
      run =
        (fun () ->
          List.iter
            (fun source ->
              match Json.parse source with
              | Error error ->
                  expect_equal_string
                    ~expected:"runner JSON permits integers only"
                    error.message
              | Ok _ -> fail "%s must be rejected as non-integer JSON" source)
            [ "1.0"; "1e3"; "1E3" ]);
    };
    {
      name = "pure OCaml SHA-256 matches the FIPS abc vector";
      run =
        (fun () ->
          expect_equal_string
            ~expected:
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            (Sha256.digest_string "abc"));
    };
  ]

let yaml_source =
  "# workflow comment\r\n" ^ "defaults: &shared\r\n"
  ^ "  shell: bash # inline comment\r\n" ^ "jobs:\r\n" ^ "  build:\r\n"
  ^ "    steps:\r\n" ^ "      - name: 'compile'\r\n" ^ "        run: |\r\n"
  ^ "          echo ok\r\n" ^ "duplicate: one\r\n" ^ "duplicate: two\r\n"
  ^ "merged: *shared\r\n"

let yaml_tests =
  [
    {
      name = "a UTF-8 BOM alone is an empty YAML stream";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "\xef\xbb\xbf" in
          expect_true "BOM metadata must be retained" tree.bom;
          expect_true "BOM bytes cannot become a scalar document"
            (Yaml_cst.root tree = None));
    };
    {
      name = "YAML non-breaking-space escapes retain their Unicode value";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"escape.yml" "value: \"\\_\"\n" in
          let root = require_some "root" (Yaml_cst.root tree) in
          let mapping = require_some "mapping" (Yaml_cst.as_mapping root) in
          let value =
            require_some "value" (Yaml_cst.mapping_find "value" mapping)
            |> Yaml_cst.scalar_value |> require_some "escaped scalar"
          in
          expect_equal_string ~expected:"\xc2\xa0" value);
    };
    {
      name = "YAML next-line escape retains its Unicode value";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"escape.yml" "value: \"\\N\"\n" in
          let value =
            Yaml_cst.root tree |> fun node -> Option.bind node Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "value")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "escaped next-line scalar"
          in
          expect_equal_string ~expected:"\xc2\x85" value);
    };
    {
      name = "CRLF-terminated block scalar validation makes forward progress";
      run =
        (fun () ->
          let source = "literal: |\r\n  value\r\n" in
          let tree = Yaml_cst.parse ~file:"block.yml" source in
          expect_equal_string ~expected:source (Yaml_cst.print tree);
          let adjacent =
            Yaml_cst.parse ~file:"comments.yml"
              "first: ok\r\nkey: \"\"#adjacent\r\n"
          in
          match
            List.find_opt
              (fun problem ->
                problem.Yaml_cst.message
                = "comment requires separation after a quoted scalar")
              adjacent.problems
          with
          | Some problem ->
              expect_equal_int ~expected:2 problem.span.start.line
          | None -> fail "adjacent empty-scalar comment was not rejected");
    };
    {
      name = "lossless YAML print preserves comments styles and CRLF bytes";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"workflow.yml" yaml_source in
          expect_equal_string ~expected:yaml_source (Yaml_cst.print tree);
          expect_true "CRLF style must be retained" (tree.newline = `CrLf));
    };
    {
      name = "lossless YAML records anchors aliases comments and duplicate keys";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"workflow.yml" yaml_source in
          expect_true "anchor shared must be indexed"
            (Option.is_some (Yaml_cst.resolve_alias tree "shared"));
          expect_true "comments must be retained"
            (List.exists
               (fun trivia -> trivia.Yaml_cst.kind = Yaml_cst.Comment)
               tree.trivia);
          expect_true "duplicate key must be diagnosed"
            (List.exists
               (fun problem -> problem.Yaml_cst.code = "YAML-DUPLICATE-KEY")
               tree.problems);
          let flow = Yaml_cst.parse "{key: one, key: two}\n" in
          let flow_entries =
            Option.bind (Yaml_cst.root flow) Yaml_cst.as_mapping
            |> require_some "flow mapping"
          in
          expect_true "duplicate flow keys must retain their duplicate marker"
            ((List.nth flow_entries 1).duplicate));
    };
    {
      name = "mapping entry lookup preserves the selected key and value";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "wanted: exact\nother: value\n" in
          let entries =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> require_some "root mapping"
          in
          let entry =
            Yaml_cst.mapping_find_entry "wanted" entries
            |> require_some "wanted mapping entry"
          in
          expect_equal_string ~expected:"wanted" entry.key.value;
          expect_equal_string ~expected:"exact"
            (entry.value |> Yaml_cst.scalar_value
            |> require_some "wanted mapping value");
          let other =
            Yaml_cst.mapping_find_entry "other" entries
            |> require_some "other mapping entry"
          in
          expect_equal_string ~expected:"other" other.key.value;
          let decorated = Yaml_cst.parse "key: &anchor value\n" in
          let decorated_value =
            Option.bind (Yaml_cst.root decorated) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "key")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "decorated scalar value"
          in
          expect_equal_string ~expected:"value" decorated_value);
    };
    {
      name = "YAML structural equality compares sequence elements";
      run =
        (fun () ->
          let left = Yaml_cst.parse "- one\n- two\n"
          and same = Yaml_cst.parse "- one\n- two\n"
          and changed = Yaml_cst.parse "- one\n- changed\n" in
          expect_true "identical sequences must be structurally equal"
            (Yaml_cst.structural_equal left same);
          expect_true "same-length sequences with changed values are unequal"
            (not (Yaml_cst.structural_equal left changed));
          expect_true "a missing document root is not equal to a scalar root"
            (not
               (Yaml_cst.structural_equal (Yaml_cst.parse "")
                  (Yaml_cst.parse "value\n")));
          expect_true "flow sequence elements participate in structural equality"
            (not
               (Yaml_cst.structural_equal (Yaml_cst.parse "[one, two]\n")
                  (Yaml_cst.parse "[one, changed]\n")));
          expect_true "aliases with different targets are structurally unequal"
            (not
               (Yaml_cst.structural_equal (Yaml_cst.parse "*left\n")
                  (Yaml_cst.parse "*right\n")));
          let rooted = Yaml_cst.parse "value\n" in
          let rootless =
            {
              rooted with
              documents =
                List.map
                  (fun (document : Yaml_cst.document) ->
                    { document with root = None })
                  rooted.documents;
            }
          in
          expect_true "a present root cannot equal an absent root"
            (not (Yaml_cst.structural_equal rooted rootless));
          expect_true "two absent roots remain structurally equal"
            (Yaml_cst.structural_equal rootless rootless));
    };
    {
      name = "lossless YAML spans select the exact scalar bytes";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"workflow.yml" yaml_source in
          let root = require_some "document root" (Yaml_cst.root tree) in
          let mapping =
            require_some "root mapping" (Yaml_cst.as_mapping root)
          in
          let jobs =
            require_some "jobs" (Yaml_cst.mapping_find "jobs" mapping)
          in
          let jobs_map =
            require_some "jobs mapping" (Yaml_cst.as_mapping jobs)
          in
          let build =
            require_some "build" (Yaml_cst.mapping_find "build" jobs_map)
          in
          let build_map =
            require_some "build mapping" (Yaml_cst.as_mapping build)
          in
          let steps =
            require_some "steps" (Yaml_cst.mapping_find "steps" build_map)
          in
          let items =
            require_some "steps sequence" (Yaml_cst.as_sequence steps)
          in
          expect_equal_int ~expected:1 (List.length items);
          let item = List.hd items in
          let item_map =
            require_some "step mapping" (Yaml_cst.as_mapping item.value)
          in
          let name =
            require_some "step name" (Yaml_cst.mapping_find "name" item_map)
          in
          expect_equal_string ~expected:"compile"
            (require_some "name scalar" (Yaml_cst.scalar_value name)));
    };
    {
      name = "block sequence dash spans use absolute source offsets";
      run =
        (fun () ->
          let source = "prefix: ok\nitems:\n  - one\n  - two\n" in
          let tree = Yaml_cst.parse ~file:"workflow.yml" source in
          let root = require_some "document root" (Yaml_cst.root tree) in
          let mapping = require_some "root mapping" (Yaml_cst.as_mapping root) in
          let items =
            Yaml_cst.mapping_find "items" mapping
            |> fun node -> Option.bind node Yaml_cst.as_sequence
            |> require_some "items sequence"
          in
          let second = List.nth items 1 in
          let first_dash = String.index source '-' in
          let second_dash = String.index_from source (first_dash + 1) '-' in
          expect_equal_int ~expected:second_dash second.dash_span.start.byte;
          expect_equal_int ~expected:(second_dash + 1) second.dash_span.stop.byte);
    };
    {
      name = "block scalar spans run from the header through final content";
      run =
        (fun () ->
          let source = "key: |\n  one\n    two\n" in
          let tree = Yaml_cst.parse ~file:"workflow.yml" source in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "key")
            |> require_some "block scalar"
          in
          let span = Yaml_cst.node_span value in
          expect_equal_int ~expected:5 span.start.byte;
          expect_equal_int ~expected:1 span.start.line;
          expect_equal_int ~expected:6 span.start.column;
          expect_equal_int ~expected:20 span.stop.byte;
          expect_equal_int ~expected:3 span.stop.line;
          expect_equal_int ~expected:8 span.stop.column);
    };
    {
      name = "comment-preserving edits reject overlap and touch only the span";
      run =
        (fun () ->
          let tree = Yaml_cst.parse ~file:"workflow.yml" "key: old # keep\n" in
          let root = require_some "root" (Yaml_cst.root tree) in
          let mapping = require_some "mapping" (Yaml_cst.as_mapping root) in
          let value =
            require_some "key" (Yaml_cst.mapping_find "key" mapping)
          in
          let span = Yaml_cst.node_span value in
          let edited =
            match
              Yaml_cst.apply_edits tree
                [
                  {
                    Yaml_cst.start_byte = span.start.byte;
                    stop_byte = span.stop.byte;
                    replacement = "new";
                  };
                ]
            with
            | Ok value -> value
            | Error message -> fail "%s" message
          in
          expect_equal_string ~expected:"key: new # keep\n" edited;
          let compact = Yaml_cst.parse "abc" in
          let composed =
            Yaml_cst.apply_edits compact
              [
                { start_byte = 1; stop_byte = 1; replacement = "X" };
                { start_byte = 1; stop_byte = 2; replacement = "Y" };
              ]
          in
          (match composed with
          | Ok value -> expect_equal_string ~expected:"aXYc" value
          | Error message -> fail "same-boundary edits must compose: %s" message);
          let expect_outside_source label edit =
            match Yaml_cst.apply_edits compact [ edit ] with
            | Error "edit span is outside the source" -> ()
            | Error message -> fail "%s returned the wrong error: %s" label message
            | Ok value -> fail "%s was unexpectedly applied as %S" label value
          in
          expect_outside_source "an edit past the source boundary"
            { start_byte = 1; stop_byte = 4; replacement = "bad" };
          expect_outside_source "an edit with a reversed span"
            { start_byte = 2; stop_byte = 1; replacement = "bad" });
    };
    {
      name = "invalid CST nodes retain structured JSON evidence";
      run =
        (fun () ->
          let node =
            Yaml_cst.Invalid
              { raw = "["; reason = "unterminated"; span = Span.none }
          in
          let encoded = Yaml_cst.node_to_json node |> Json.to_string in
          List.iter
            (fun needle ->
              expect_true ("invalid node JSON omits " ^ needle)
                (Util.contains ~needle encoded))
            [
              "\"kind\":\"invalid\"";
              "\"raw\":\"[\"";
              "\"reason\":\"unterminated\"";
              "\"span\"";
            ]);
    };
    {
      name = "YAML event projection preserves document and collection style";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "---\nflow: [one, 'two']\n...\n" in
          expect_equal_string
            ~expected:
              "+STR\n\
               +DOC ---\n\
               +MAP\n\
               =VAL :flow\n\
               +SEQ []\n\
               =VAL :one\n\
               =VAL 'two\n\
               -SEQ\n\
               -MAP\n\
               -DOC ...\n\
               -STR\n"
             (Yaml_event.of_cst tree |> Yaml_event.to_string));
    };
    {
      name = "YAML tag percent decoding retains an incomplete trailing escape";
      run =
        (fun () ->
          let events =
            Yaml_cst.parse "--- !<tag:example,%A> value\n"
            |> Yaml_event.of_cst |> Yaml_event.to_string
          in
          expect_true "incomplete percent escape must remain literal"
            (Util.contains ~needle:"<tag:example,%A>" events));
    };
    {
      name = "YAML event tags require both verbatim delimiters";
      run =
        (fun () ->
          let events =
            Yaml_cst.parse "value: !plain> data\n"
            |> Yaml_event.of_cst |> Yaml_event.to_string
          in
          expect_true "a suffix angle bracket alone is not a verbatim tag"
            (Util.contains ~needle:"<!plain>>" events));
    };
    {
      name = "document properties decorate an explicit-key mapping";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "--- !!map\n? a\n: b\n" in
          expect_equal_string
            ~expected:
              "+STR\n\
               +DOC ---\n\
               +MAP <tag:yaml.org,2002:map>\n\
               =VAL :a\n\
               =VAL :b\n\
               -MAP\n\
               -DOC\n\
               -STR\n"
            (Yaml_event.of_cst tree |> Yaml_event.to_string));
    };
    {
      name = "explicit flow-mapping keys retain their collection style";
      run =
        (fun () ->
          let events =
            Yaml_cst.parse "? {a: b}\n: value\n" |> Yaml_event.of_cst
            |> Yaml_event.to_string
          in
          expect_true "the explicit key must remain a flow mapping"
            (Util.contains ~needle:"+MAP {}\n" events));
    };
    {
      name = "a property-only line decorates the following collection";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "&sequence\n- a\n" in
          expect_equal_string
            ~expected:"+STR\n+DOC\n+SEQ &sequence\n=VAL :a\n-SEQ\n-DOC\n-STR\n"
            (Yaml_event.of_cst tree |> Yaml_event.to_string));
    };
    {
      name = "compact nested sequences retain their collection boundary";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "- - inner\n  - sibling\n- outer\n" in
          expect_equal_string
            ~expected:
              "+STR\n\
               +DOC\n\
               +SEQ\n\
               +SEQ\n\
               =VAL :inner\n\
               =VAL :sibling\n\
               -SEQ\n\
               =VAL :outer\n\
               -SEQ\n\
               -DOC\n\
               -STR\n"
            (Yaml_event.of_cst tree |> Yaml_event.to_string));
    };
    {
      name = "plain multiline values apply YAML folding";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "plain: a\n b\n\n c\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping ->
            Option.bind mapping (Yaml_cst.mapping_find "plain") |> fun node ->
            Option.bind node Yaml_cst.scalar_value
            |> require_some "folded plain scalar"
          in
          expect_equal_string ~expected:"a b\nc" value);
    };
    {
      name = "plain multiline folding preserves a trailing backslash";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "plain: first\\\n second\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "plain")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "backslash plain scalar"
          in
          expect_equal_string ~expected:"first\\ second" value);
    };
    {
      name = "plain scalars do not absorb trailing document blank lines";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "plain: value\n\n\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "plain")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "trailing blank plain scalar"
          in
          expect_equal_string ~expected:"value" value);
    };
    {
      name = "single-quoted multiline folding preserves a trailing backslash";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: 'first\\\n  second'\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "value")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "single-quoted multiline scalar"
          in
          expect_equal_string ~expected:"first\\ second" value);
    };
    {
      name = "quoted multiline folding preserves trailing blank paragraphs";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: 'text\n\n\n  '\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "value")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "quoted multiline trailing blanks"
          in
          expect_equal_string ~expected:"text\n\n" value);
    };
    {
      name = "GitHub expressions remain block-context plain scalars";
      run =
        (fun () ->
          let source =
            "inputs:\n  repository:\n    default: ${{ github.repository }}\n"
          in
          let tree = Yaml_cst.parse ~file:"action.yml" source in
          expect_true "expression braces must not start a flow collection"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "content follows a completed flow collection")
                  tree.problems));
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping ->
            Option.bind mapping (Yaml_cst.mapping_find "inputs") |> fun node ->
            Option.bind node Yaml_cst.as_mapping |> fun mapping ->
            Option.bind mapping (Yaml_cst.mapping_find "repository")
            |> fun node ->
            Option.bind node Yaml_cst.as_mapping |> fun mapping ->
            Option.bind mapping (Yaml_cst.mapping_find "default") |> fun node ->
            Option.bind node Yaml_cst.scalar_value
            |> require_some "GitHub expression scalar"
          in
          expect_equal_string ~expected:"${{ github.repository }}" value);
    };
    {
      name = "balanced flow with an empty quoted scalar ends on its own line";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: [\"\"]\nnext: ok\n" in
          expect_true "balanced flow must not consume the following mapping"
            (tree.problems = []);
          let next =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "next")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "next scalar"
          in
          expect_equal_string ~expected:"ok" next);
    };
    {
      name = "doubled single quotes keep hashes inside the scalar";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: 'it''s # data'\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "value")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "single-quoted scalar"
          in
          expect_equal_string ~expected:"it's # data" value);
    };
    {
      name = "flow validation ignores folded block scalar payloads";
      run =
        (fun () ->
          let source =
            "description: >\n  [Learn more](https://example.invalid/docs)\n"
          in
          let tree = Yaml_cst.parse ~file:"action.yml" source in
          expect_true "block scalar text must not be parsed as flow YAML"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "content follows a completed flow collection")
                  tree.problems)));
    };
    {
      name = "block header validation ignores shell pipes in folded payloads";
      run =
        (fun () ->
          let source =
            "command: >\n  xcodebuild test\n  -scheme Example\n  | xcpretty\n"
          in
          let tree = Yaml_cst.parse ~file:".circleci/config.yml" source in
          expect_true "block scalar shell pipe must remain payload text"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message = "invalid block scalar header")
                  tree.problems)));
    };
    {
      name = "all validators ignore nested block scalar payload syntax";
      run =
        (fun () ->
          let source =
            {|steps:
  - bash: |
      BIN_DIR=bin
      [ -d "$BIN_DIR" ] && rm -rf "$BIN_DIR"
      const suffix = condition ? "ok" : "";
|}
          in
          let tree = Yaml_cst.parse ~file:"azure-pipelines.yml" source in
          expect_true "payload text must not be validated as YAML structure"
            (not
               (List.exists
                   (fun problem -> problem.Yaml_cst.code = "YAML-SYNTAX")
                   tree.problems)));
    };
    {
      name = "validation resumes after a block scalar dedent";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "literal: |\n  body\nbroken: [\n" in
          expect_true "dedented malformed YAML must not be hidden as payload"
            (List.exists
               (fun problem -> problem.Yaml_cst.code = "YAML-SYNTAX")
               tree.problems));
    };
    {
      name = "dedented mapping values leave block scalar validation state";
      run =
        (fun () ->
          let tree =
            Yaml_cst.parse "literal: |\n  body\nnext: \"bad\\q\"\n"
          in
          let problem =
            List.find_opt
              (fun problem ->
                problem.Yaml_cst.message
                = "invalid escape in a double-quoted scalar")
              tree.problems
            |> require_some "dedented invalid escape diagnostic"
          in
          expect_equal_int ~expected:3 problem.span.start.line);
    };
    {
      name = "escape validation resumes at the first byte after block payload";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "literal: |\n  body\n\"bad\\q\"\n" in
          expect_true "dedented quote state must begin at its opening byte"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "invalid escape in a double-quoted scalar")
               tree.problems));
    };
    {
      name = "an unindented blank line remains block scalar payload";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "literal: |\n\n  body\n" in
          let value =
            Option.bind (Yaml_cst.root tree) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "literal")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "literal scalar"
          in
          expect_equal_string ~expected:"\nbody\n" value);
    };
    {
      name = "block scalar at end of input stays within source bounds";
      run =
        (fun () ->
          let source = "literal: |\n  body" in
          let tree = Yaml_cst.parse source in
          expect_equal_string ~expected:source (Yaml_cst.print tree));
    };
    {
      name = "directives accept comments only after separated content";
      run =
        (fun () ->
          let valid = Yaml_cst.parse "%YAML 1.2 # supported\n---\nvalue: ok\n" in
          expect_true "a separated directive comment must be ignored"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message = "invalid YAML directive")
                  valid.problems));
          let misplaced =
            Yaml_cst.parse "---\nplain\n# comment\n%YAML 1.2\n---\nnext\n"
          in
          expect_true "a leading comment cannot disguise an in-document directive"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message = "directive appears before document end")
               misplaced.problems);
          let trailing =
            Yaml_cst.parse "---\nplain #\n%YAML 1.2\n---\nnext\n"
          in
          expect_true "a trailing separated comment must end the plain scalar"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message = "directive appears before document end")
               trailing.problems);
          let unfinished = Yaml_cst.parse "%YAML 1.2\n# waiting\n\n" in
          let problem =
            List.find_opt
              (fun problem ->
                problem.Yaml_cst.message
                = "directive is not followed by a document")
              unfinished.problems
            |> require_some "unfinished directive diagnostic"
          in
          expect_equal_int ~expected:1 problem.span.start.line);
    };
    {
      name = "YAML directive versions require decimal major and minor digits";
      run =
        (fun () ->
          let zero_minor = Yaml_cst.parse "%YAML 1.0\n---\nvalue: ok\n" in
          expect_true "zero is a valid minor-version digit"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message = "invalid YAML directive")
                  zero_minor.problems));
          let upper_major = Yaml_cst.parse "%YAML 9.2\n---\nvalue: ok\n" in
          expect_true "nine is a valid major-version digit"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message = "invalid YAML directive")
                  upper_major.problems));
          let tree = Yaml_cst.parse "%YAML :.2\n---\nvalue: ok\n" in
          expect_true "a non-decimal major version must be rejected"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message = "invalid YAML directive")
               tree.problems);
          let high_minor = Yaml_cst.parse "%YAML 1.:\n---\nvalue: ok\n" in
          expect_true "a minor version above nine must be rejected"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message = "invalid YAML directive")
               high_minor.problems);
          let malformed_tag = Yaml_cst.parse "%TAG !only!\n---\nvalue: ok\n" in
          expect_true "a malformed TAG directive must be rejected"
            (List.exists
               (fun problem -> problem.Yaml_cst.message = "invalid directive")
               malformed_tag.problems));
    };
    {
      name = "escaped quotes do not close a flow scalar";
      run =
        (fun () ->
          let tree =
            Yaml_cst.parse
              {|value: ["a\"b"]
|}
          in
          expect_true "escaped flow quote must remain inside the scalar"
            (not
               (List.exists
                  (fun problem -> problem.Yaml_cst.code = "YAML-SYNTAX")
                  tree.problems)));
    };
    {
      name = "flow structure resumes after an escaped quoted character";
      run =
        (fun () ->
          let tree = Yaml_cst.parse {|value: ["a\"b"] trailing
|} in
          expect_true "content after the completed flow must be diagnosed"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "content follows a completed flow collection")
               tree.problems));
    };
    {
      name = "truncated hexadecimal escapes fail within source bounds";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: \"\\u" in
          expect_true "an escape truncated at EOF must be diagnosed"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "invalid escape in a double-quoted scalar")
               tree.problems));
    };
    {
      name = "quoted scalar comments require and accept separation";
      run =
        (fun () ->
          let valid = Yaml_cst.parse "key: \"value\" # comment: ignored\n"
          and invalid = Yaml_cst.parse "key: \"value\"#comment\n" in
          let has_problem tree =
            List.exists
              (fun problem ->
                problem.Yaml_cst.message
                = "comment requires separation after a quoted scalar")
              tree.Yaml_cst.problems
          in
          expect_true "separated comment must be accepted"
            (not (has_problem valid) && valid.problems = []);
          expect_true "adjacent comment must be rejected" (has_problem invalid);
          let empty = Yaml_cst.parse "key: \"\" # trailing\n" in
          let empty_value =
            Option.bind (Yaml_cst.root empty) Yaml_cst.as_mapping
            |> fun mapping -> Option.bind mapping (Yaml_cst.mapping_find "key")
            |> fun node -> Option.bind node Yaml_cst.scalar_value
            |> require_some "empty quoted scalar before comment"
          in
          expect_equal_string ~expected:"" empty_value;
          let embedded =
            Yaml_cst.parse "key: \"before # inside\"\nnext: value\n"
          in
          expect_true "a hash inside a quote cannot open a continuation"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "quoted mapping value continuation is not indented")
                  embedded.problems));
          let second_colon = Yaml_cst.parse "key: \"value\": extra\n" in
          expect_true "a colon after a closed quoted value is structural"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "multiple mapping separators in a plain scalar")
               second_colon.problems);
          let after_escaped_double =
            Yaml_cst.parse "key: \"value \\\" # inside\" : extra\n"
          and after_single =
            Yaml_cst.parse "key: 'value # inside' : extra\n"
          in
          List.iter
            (fun (label, tree) ->
              expect_true label
                (List.exists
                   (fun problem ->
                     problem.Yaml_cst.message
                     = "multiple mapping separators in a plain scalar")
                   tree.Yaml_cst.problems))
            [
              ( "an escaped double quote cannot expose an inner hash comment",
                after_escaped_double );
              ( "a single-quoted hash cannot hide following structure",
                after_single );
            ]);
    };
    {
      name = "node-property tokens and quote boundaries preserve mapping colons";
      run =
        (fun () ->
          let property = Yaml_cst.parse "key: !tag: scalar\n" in
          expect_true "a colon inside a node property is not a second mapping"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "multiple mapping separators in a plain scalar")
                  property.problems));
          let tagged_quote =
            Yaml_cst.parse "key: !tag \"value: inside\"\n"
          in
          expect_true "a quoted scalar following a property hides inner colons"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "multiple mapping separators in a plain scalar")
                  tagged_quote.problems));
          let plain = Yaml_cst.parse "key: foo-\"bar: baz\"\n" in
          expect_true "an adjacent shell quote does not hide a mapping colon"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "multiple mapping separators in a plain scalar")
               plain.problems));
    };
    {
      name = "flow-depth accounting opens and closes quote context exactly";
      run =
        (fun () ->
          let inside = Yaml_cst.parse "flow: [key:\"value: inside\"]\n" in
          expect_true "a quote after a flow colon must hide its inner colon"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "multiple mapping separators in a plain scalar")
                  inside.problems));
          let after = Yaml_cst.parse "key: [value]:\"hidden: colon\"\n" in
          expect_true "a closed flow cannot leak quote context into block YAML"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "multiple mapping separators in a plain scalar")
               after.problems);
          let delimiter_inside_quote =
            Yaml_cst.parse {|flow: [key:"literal ]: inside"]
|}
          in
          expect_true "a flow delimiter inside a quoted value remains data"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "multiple mapping separators in a plain scalar")
                  delimiter_inside_quote.problems)));
    };
    {
      name = "invalid tag tokens reject either unmatched flow brace";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "!bad{ value\n" in
          expect_true "a tag containing an opening brace must be rejected"
            (List.exists
               (fun problem -> problem.Yaml_cst.message = "invalid tag token")
               tree.problems);
          let handles =
            Yaml_cst.parse
              "%TAG !ok! tag:example,\n---\n[!ok!one,!missing!two]\n"
          in
          expect_true "flow delimiters must expose each tag handle"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message = "undefined tag handle")
               handles.problems);
          let block_comma = Yaml_cst.parse "- !!str, value\n"
          and valid_tag = Yaml_cst.parse "- !!str value\n" in
          expect_true "a block-context tag cannot end in comma"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "tag cannot contain a block-context comma")
               block_comma.problems);
          expect_true "a tag without a block-context comma remains valid"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "tag cannot contain a block-context comma")
                  valid_tag.problems)));
    };
    {
      name = "decorated scalar events retain their underlying value";
      run =
        (fun () ->
          let events =
            Yaml_cst.parse "&anchor scalar\n" |> Yaml_event.of_cst
            |> Yaml_event.to_string
          in
          expect_true "decorated scalar must emit a value event"
            (Util.contains ~needle:"=VAL &anchor :scalar" events));
    };
    {
      name = "decorated aliases retain their underlying event";
      run =
        (fun () ->
          let decorated_alias =
            Yaml_cst.Decorated
              {
                value =
                  Yaml_cst.Alias
                    { name = "base"; raw = "*base"; span = Span.none };
                anchor = Some "extra";
                tag = None;
                span = Span.none;
              }
          in
          let tree : Yaml_cst.t =
            {
              file = "decorated-alias.yml";
              source = "&extra *base\n";
              bom = false;
              newline = `Lf;
              documents =
                [ { root = Some decorated_alias; directives = []; span = Span.none } ];
              trivia = [];
              anchors = [];
              problems = [];
            }
          in
          let events = Yaml_event.of_cst tree |> Yaml_event.to_string in
          expect_true "lossless invalid alias properties must retain the alias"
            (Util.contains ~needle:"=ALI *base" events));
    };
    {
      name = "same-indent comments do not define block content indentation";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "value: |\n    \n# outside\nnext: ok\n" in
          expect_true "same-indent comment must remain outside block indentation"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "leading block-scalar whitespace exceeds content indentation")
                  tree.problems)));
    };
    {
      name = "first indented block comment fixes the reference indentation";
      run =
        (fun () ->
          let tree =
            Yaml_cst.parse "value: |\n   \n  # first\n    # second\nnext: ok\n"
          in
          expect_true "later comments cannot replace the first indentation"
            (List.exists
               (fun problem ->
                 problem.Yaml_cst.message
                 = "leading block-scalar whitespace exceeds content indentation")
               tree.problems));
    };
    {
      name = "inline comments do not add plain-scalar mapping separators";
      run =
        (fun () ->
          let source =
            {|permissions:
  id-token: write # IMPORTANT: required
# tee: /dev/stderr: unavailable
steps:
  - run: # Step 1: install
      command: true
|}
          in
          let tree = Yaml_cst.parse ~file:"workflow.yml" source in
          expect_true "comments must be outside the node grammar"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "multiple mapping separators in a plain scalar")
                  tree.problems)));
    };
    {
      name = "plain script scalars retain shell quotes hashes and backslashes";
      run =
        (fun () ->
          let source =
            {|script:
  - sed -i "s#<IMAGE>#${IMAGE}#g" deployment.yaml
only:
  - /^v[0-9]+(\.[0-9]+){0,2}(-rc\.[0-9]+)?$/
|}
          in
          let tree = Yaml_cst.parse ~file:".gitlab-ci.yml" source in
          expect_true "plain scalars must not open YAML quoted or flow nodes"
            (not
               (List.exists
                  (fun problem -> problem.Yaml_cst.code = "YAML-SYNTAX")
                  tree.problems)));
    };
    {
      name = "shell quotes ending after colons do not open YAML scalars";
      run =
        (fun () ->
          let source =
            {|script:
  - echo "Push image:"
only:
  - /^v[0-9]+(\.[0-9]+)$/
|}
          in
          let tree = Yaml_cst.parse ~file:".gitlab-ci.yml" source in
          expect_true "plain regex escapes must remain outside YAML quotes"
            (not
               (List.exists
                  (fun problem ->
                    problem.Yaml_cst.message
                    = "invalid escape in a double-quoted scalar")
                  tree.problems)));
    };
    {
      name = "anchor names ending in colon remain scalar properties";
      run =
        (fun () ->
          let tree = Yaml_cst.parse "&a: key: &a value\nfoo:\n  *a:\n" in
          expect_equal_string
            ~expected:
              "+STR\n\
               +DOC\n\
               +MAP\n\
               =VAL &a: :key\n\
               =VAL &a :value\n\
               =VAL :foo\n\
               =ALI *a:\n\
               -MAP\n\
               -DOC\n\
               -STR\n"
            (Yaml_event.of_cst tree |> Yaml_event.to_string));
    };
  ]

let tests = foundation_tests @ yaml_tests

let () =
  Printexc.record_backtrace true;
  let failed = ref 0 in
  List.iter
    (fun test ->
      try
        test.run ();
        Printf.printf "ok - %s\n%!" test.name
      with
      | Assertion_failed message ->
          incr failed;
          Printf.eprintf "not ok - %s: %s\n%!" test.name message
      | exception_ ->
          incr failed;
          Printf.eprintf "not ok - %s: unexpected %s\n%s%!" test.name
            (Printexc.to_string exception_)
            (Printexc.get_backtrace ()))
    tests;
  if !failed <> 0 then (
    Printf.eprintf "%d/%d tests failed\n%!" !failed (List.length tests);
    exit 1)
  else Printf.printf "%d tests passed\n%!" (List.length tests)
