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
               tree.problems));
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
          expect_equal_string ~expected:"key: new # keep\n" edited);
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
