use workflow_verifier::internal::conformance::foundation::Budget;
use workflow_verifier::internal::conformance::syntax::{
    Edit, ScalarStyle, TriviaKind, YamlDocument, YamlNodeKind,
};

#[test]
fn yaml_is_lossless_and_retains_comments_anchors_and_aliases() {
    let source = "# lead\ndefaults: &base\n  image: rust:1.98 # pinned\njob:\n  <<: *base\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert_eq!(document.print(), source);
    assert!(document.problems().is_empty());
    assert!(
        document
            .trivia()
            .iter()
            .any(|item| item.kind == TriviaKind::Comment)
    );
    assert!(document.anchors().iter().any(|item| item.name == "base"));
    assert!(document.aliases().iter().any(|item| item.name == "base"));
    let root = document.root().expect("mapping root");
    assert!(matches!(root.kind(), YamlNodeKind::Mapping));
    assert!(root.field("job").is_some());
}

#[test]
fn anchor_and_alias_scanning_ignores_quoted_or_empty_markers() {
    let source =
        "real: &actual value\nalias: *actual\nsingle: '&fake'\ndouble: \"*fake\"\nempty: &\n";
    let document = YamlDocument::parse("anchors.yml", source, Budget::default());
    assert_eq!(
        document
            .anchors()
            .iter()
            .map(|anchor| anchor.name.as_str())
            .collect::<Vec<_>>(),
        vec!["actual"]
    );
    assert_eq!(
        document
            .aliases()
            .iter()
            .map(|alias| alias.name.as_str())
            .collect::<Vec<_>>(),
        vec!["actual"]
    );
}

#[test]
fn crlf_is_lossless_but_not_part_of_yaml_scalar_content() {
    let source = "on:\r\n  push:\r\n    branches:\r\n      - main\r\njobs:\r\n  build:\r\n    steps:\r\n      - run: echo ok\r\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);
    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("on")
            .and_then(|on| on.field("push"))
            .and_then(|push| push.field("branches"))
            .and_then(|branches| branches.sequence())
            .and_then(|items| items.first())
            .and_then(|branch| branch.scalar()),
        Some("main")
    );
    assert_eq!(
        root.field("jobs")
            .and_then(|jobs| jobs.field("build"))
            .and_then(|build| build.field("steps"))
            .and_then(|steps| steps.sequence())
            .and_then(|items| items.first())
            .and_then(|step| step.field("run"))
            .and_then(|run| run.scalar()),
        Some("echo ok")
    );
}

#[test]
fn duplicate_keys_and_malformed_regions_are_explicit() {
    let duplicate = YamlDocument::parse("ci.yml", "job: one\njob: two\n", Budget::default());
    assert!(
        duplicate
            .problems()
            .iter()
            .any(|problem| problem.code == "YAML-DUPLICATE-KEY")
    );

    let malformed = YamlDocument::parse("ci.yml", "jobs: [\n", Budget::default());
    assert!(
        malformed
            .problems()
            .iter()
            .any(|problem| problem.code == "YAML-SYNTAX")
    );
    assert!(
        malformed
            .invalid_regions()
            .iter()
            .any(|region| region.raw.contains('['))
    );
    assert_eq!(malformed.print(), "jobs: [\n");
}

#[test]
fn scalars_and_block_scalars_have_semantic_values() {
    let source = "plain: value\nquoted: 'it''s # data'\ncommand: |-\n  echo one\n  echo two\nlist: [one, \"two\"]\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("plain").and_then(|node| node.scalar()),
        Some("value")
    );
    assert_eq!(
        root.field("quoted").and_then(|node| node.scalar()),
        Some("it's # data")
    );
    assert_eq!(
        root.field("command").and_then(|node| node.scalar()),
        Some("echo one\necho two")
    );
    let list = root
        .field("list")
        .and_then(|node| node.sequence())
        .expect("flow sequence");
    assert_eq!(list.len(), 2);
    assert_eq!(list[1].scalar(), Some("two"));
}

#[test]
fn scalar_style_and_raw_accessors_preserve_lexical_form_only_for_owned_text() {
    let document = YamlDocument::parse(
        "ci.yml",
        "plain: value\nsingle: 'quoted'\ndouble: \"quoted\"\nliteral: |\n  line\nsequence: [one]\n",
        Budget::default(),
    );
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let root = document.root().expect("mapping root");
    let cases = [
        ("plain", ScalarStyle::Plain, "value"),
        ("single", ScalarStyle::SingleQuoted, "'quoted'"),
        ("double", ScalarStyle::DoubleQuoted, "\"quoted\""),
    ];
    for (field, style, raw) in cases {
        let node = root.field(field).expect("scalar field");
        assert_eq!(node.scalar_style(), Some(style), "{field:?}");
        assert_eq!(node.raw(), Some(raw), "{field:?}");
    }
    assert_eq!(
        root.field("literal")
            .and_then(workflow_verifier::internal::conformance::syntax::YamlNode::scalar_style),
        Some(ScalarStyle::Literal)
    );
    assert_eq!(root.scalar_style(), None);
    assert_eq!(root.raw(), None);
    let sequence = root.field("sequence").expect("sequence field");
    assert_eq!(sequence.scalar_style(), None);
    assert_eq!(sequence.raw(), None);

    let malformed = YamlDocument::parse("ci.yml", "value: [\n", Budget::default());
    let invalid = malformed
        .root()
        .and_then(|node| node.field("value"))
        .expect("invalid value node");
    assert!(matches!(invalid.kind(), YamlNodeKind::Invalid));
    assert_eq!(invalid.raw(), Some("["));
    assert_eq!(invalid.scalar_style(), None);
}

#[test]
fn exact_edits_compose_at_boundaries_and_reject_overlap() {
    let document = YamlDocument::parse("ci.yml", "key: old # keep\n", Budget::default());
    assert_eq!(document.file(), "ci.yml");
    let old = document
        .root()
        .and_then(|root| root.field("key"))
        .expect("old scalar");
    let edited = document
        .apply_edits(&[Edit::replace(
            old.span().start.byte,
            old.span().stop.byte,
            "new",
        )])
        .expect("valid edit");
    assert_eq!(edited, "key: new # keep\n");

    let compact = YamlDocument::parse("ci.yml", "abc", Budget::default());
    assert_eq!(
        compact.apply_edits(&[Edit::replace(1, 1, "X"), Edit::replace(1, 2, "Y")]),
        Ok("aXYc".to_owned())
    );
    assert!(
        compact
            .apply_edits(&[Edit::replace(0, 2, "x"), Edit::replace(1, 3, "y")])
            .is_err()
    );
    assert_eq!(
        compact.apply_edits(&[Edit::replace(0, 1, "A"), Edit::replace(1, 2, "B")]),
        Ok("ABc".to_owned())
    );
    assert!(
        compact
            .apply_edits(&[Edit::replace(2, 1, "reversed")])
            .is_err()
    );

    let utf8 = YamlDocument::parse("utf8.yml", "éx", Budget::default());
    let beyond_end = utf8.print().len().saturating_add(1);
    for edit in [
        Edit::replace(0, beyond_end, "past-end"),
        Edit::replace(1, 2, "split-start"),
        Edit::replace(0, 1, "split-stop"),
    ] {
        assert!(utf8.apply_edits(&[edit]).is_err());
    }
}

#[test]
fn input_budget_fails_closed_without_panicking() {
    let source = "0123456789";
    let document = YamlDocument::parse(
        "ci.yml",
        source,
        Budget {
            max_input_bytes: 4,
            ..Budget::default()
        },
    );
    assert!(document.root().is_none());
    assert!(
        document
            .problems()
            .iter()
            .any(|problem| problem.message.starts_with("Incomplete.Resource_limit:"))
    );
    let problem = document.problems().first().expect("resource problem");
    assert_eq!(
        problem.span.source,
        workflow_verifier::internal::conformance::foundation::SourceId(0)
    );
    assert_eq!(problem.span.start.byte, 0);
    assert_eq!(problem.span.stop.byte, source.len());
    assert_eq!(
        problem.span.stop.column,
        u32::try_from(source.chars().count().saturating_add(1)).expect("fixture column fits u32")
    );
}

#[test]
fn directives_and_document_boundaries_are_distinct_lossless_trivia() {
    let source = "%YAML 1.2\n---\nkey: value\n...\n";
    let document = YamlDocument::parse("markers.yml", source, Budget::default());
    assert_eq!(document.print(), source);
    assert_eq!(
        document
            .trivia()
            .iter()
            .map(|item| (item.kind, item.raw.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (TriviaKind::Directive, "%YAML 1.2"),
            (TriviaKind::DocumentStart, "---"),
            (TriviaKind::DocumentEnd, "..."),
        ]
    );
}

#[test]
fn compact_sequence_mapping_spans_exclude_the_dash_prefix() {
    let source = "steps:\n  - uses: x\n  - run: y\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    let items = document
        .root()
        .and_then(|root| root.field("steps"))
        .and_then(|steps| steps.sequence())
        .expect("steps sequence");
    assert_eq!(
        (items[0].span().start.byte, items[0].span().stop.byte),
        (11, 18)
    );
    assert_eq!(
        (items[1].span().start.byte, items[1].span().stop.byte),
        (23, 29)
    );
}

#[test]
fn empty_flow_collections_are_valid_and_lossless() {
    let source = "permissions: {}\nbranches: []\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);
    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("permissions")
            .and_then(|node| node.mapping())
            .map(<[_]>::len),
        Some(0)
    );
    assert_eq!(
        root.field("branches")
            .and_then(|node| node.sequence())
            .map(<[_]>::len),
        Some(0)
    );
}

#[test]
fn compact_mapping_with_nested_sequence_does_not_consume_the_document_tail() {
    let source = "first:\n  parallel:\n    matrix:\n      - TARGETS:\n          - alpine\n          - ubuntu\nsecond:\n  script: echo ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);

    let root = document.root().expect("mapping root");
    let matrix_item = root
        .field("first")
        .and_then(|first| first.field("parallel"))
        .and_then(|parallel| parallel.field("matrix"))
        .and_then(|matrix| matrix.sequence())
        .and_then(|items| items.first())
        .expect("matrix item");
    assert_eq!(
        matrix_item
            .field("TARGETS")
            .and_then(|targets| targets.sequence())
            .map(<[_]>::len),
        Some(2)
    );
    assert_eq!(
        root.field("second")
            .and_then(|second| second.field("script"))
            .and_then(|script| script.scalar()),
        Some("echo ok")
    );
}

#[test]
fn sequence_block_scalar_does_not_consume_the_document_tail() {
    let source =
        "first:\n  script:\n    - |-\n      echo one\n      echo two\nsecond:\n  script: echo ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);

    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("first")
            .and_then(|first| first.field("script"))
            .and_then(|script| script.sequence())
            .and_then(|items| items.first())
            .and_then(|command| command.scalar()),
        Some("echo one\necho two")
    );
    assert_eq!(
        root.field("second")
            .and_then(|second| second.field("script"))
            .and_then(|script| script.scalar()),
        Some("echo ok")
    );
}

#[test]
fn anchored_block_scalar_does_not_consume_the_document_tail() {
    let source = "script: &shared |-\n  echo one\n  echo two\njob:\n  script: *shared\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);

    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("script").and_then(|script| script.scalar()),
        Some("echo one\necho two")
    );
    assert_eq!(
        root.field("job")
            .and_then(|job| job.field("script"))
            .and_then(|script| script.alias()),
        Some("shared")
    );
    assert!(
        root.field("job")
            .and_then(|job| job.field("script"))
            .and_then(|script| script.scalar())
            .is_none(),
        "an unresolved alias is not a scalar value"
    );
}

#[test]
fn anchored_collection_span_includes_the_anchor_property() {
    let source = "patterns: &shared\n  - one\n  - two\njob:\n  value: ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let patterns = document
        .root()
        .and_then(|root| root.field("patterns"))
        .expect("anchored sequence");
    assert_eq!(
        (patterns.span().start.byte, patterns.span().stop.byte),
        (
            source.find("&shared").expect("anchor"),
            source.find("\njob:").expect("next field")
        )
    );
    assert_eq!(patterns.sequence().map(<[_]>::len), Some(2));
    assert!(
        document
            .root()
            .is_some_and(|root| root.field("job").is_some())
    );
}

#[test]
fn collection_span_excludes_a_trailing_inline_comment() {
    let source = "patterns:\n  - one\n  - two # explanation\nnext: ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    let patterns = document
        .root()
        .and_then(|root| root.field("patterns"))
        .expect("sequence");
    assert_eq!(
        patterns.span().stop.byte,
        source.find(" # explanation").expect("comment start")
    );
    assert!(
        document
            .trivia()
            .iter()
            .any(|item| { item.kind == TriviaKind::Comment && item.raw == "# explanation" })
    );
}

#[test]
fn nested_mapping_and_entry_spans_exclude_a_scalar_inline_comment() {
    let source = "job:\n  variables:\n    FLAG: \"false\" # explanation\nnext: ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let variables = document
        .root()
        .and_then(|root| root.field("job"))
        .and_then(|job| job.field("variables"))
        .expect("variables mapping");
    let flag = variables
        .mapping()
        .and_then(|entries| entries.first())
        .expect("FLAG entry");
    let expected_stop = source.find(" # explanation").expect("comment start");
    assert_eq!(flag.value.span().stop.byte, expected_stop);
    assert_eq!(flag.span.stop.byte, expected_stop);
    assert_eq!(variables.span().stop.byte, expected_stop);
}

#[test]
fn tagged_inline_collection_keeps_its_node_kind_and_decorated_span() {
    let source = "steps:\n  - !reference [.base, before_script]\n  - echo ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let items = document
        .root()
        .and_then(|root| root.field("steps"))
        .and_then(|steps| steps.sequence())
        .expect("steps");
    assert_eq!(items[0].kind(), YamlNodeKind::Sequence);
    assert!(items[0].scalar().is_none());
    assert_eq!(items[0].sequence().map(<[_]>::len), Some(2));
    assert_eq!(
        (items[0].span().start.byte, items[0].span().stop.byte),
        (
            source.find("!reference").expect("tag"),
            source.find(']').expect("flow collection") + 1
        )
    );
    assert_eq!(items[1].scalar(), Some("echo ok"));
}

#[test]
fn multiline_plain_sequence_scalar_does_not_consume_the_document_tail() {
    let source = "first:\n  script:\n    - New-ItemProperty -Path value `\n      -Name enabled -Value 1\nsecond:\n  script: echo ok\n";
    let document = YamlDocument::parse("ci.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    assert_eq!(document.print(), source);

    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("first")
            .and_then(|first| first.field("script"))
            .and_then(|script| script.sequence())
            .and_then(|items| items.first())
            .and_then(|command| command.scalar()),
        Some("New-ItemProperty -Path value ` -Name enabled -Value 1")
    );
    assert_eq!(
        root.field("second")
            .and_then(|second| second.field("script"))
            .and_then(|script| script.scalar()),
        Some("echo ok")
    );
}

#[test]
fn indentationless_sequence_is_a_mapping_value_without_hiding_following_keys() {
    let source = "on:\n  push:\n    branches:\n    - main\njobs:\n  build:\n    steps:\n    - run: echo ok\n";
    let document = YamlDocument::parse("workflow.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("on")
            .and_then(|on| on.field("push"))
            .and_then(|push| push.field("branches"))
            .and_then(|branches| branches.sequence())
            .and_then(|items| items.first())
            .and_then(|item| item.scalar()),
        Some("main")
    );
    assert_eq!(
        root.field("jobs")
            .and_then(|jobs| jobs.field("build"))
            .and_then(|build| build.field("steps"))
            .and_then(|steps| steps.sequence())
            .map(<[_]>::len),
        Some(1)
    );
}

#[test]
fn flow_collection_members_and_mapping_entries_own_exact_source_spans() {
    let source = "values: [one, \"two\", [three], {four: five}] # trailing\nnext: done\n";
    let document = YamlDocument::parse("flow.yml", source, Budget::default());
    assert!(document.problems().is_empty(), "{:?}", document.problems());
    let values = document
        .root()
        .and_then(|root| root.field("values"))
        .and_then(|values| values.sequence())
        .expect("flow sequence");
    let expected = ["one", "\"two\"", "[three]", "{four: five}"];
    assert_eq!(values.len(), expected.len());
    for (node, raw) in values.iter().zip(expected) {
        assert_eq!(
            source.get(node.span().start.byte..node.span().stop.byte),
            Some(raw)
        );
    }
    let nested = values[2].sequence().expect("nested flow sequence");
    assert_eq!(nested.len(), 1);
    assert_eq!(
        source.get(nested[0].span().start.byte..nested[0].span().stop.byte),
        Some("three")
    );
    let mapping = values[3].mapping().expect("nested flow mapping");
    assert_eq!(mapping.len(), 1);
    assert_eq!(mapping[0].key, "four");
    assert_eq!(
        source.get(mapping[0].key_span.start.byte..mapping[0].key_span.stop.byte),
        Some("four")
    );
    assert_eq!(mapping[0].value.scalar(), Some("five"));
    assert_eq!(
        source.get(mapping[0].value.span().start.byte..mapping[0].value.span().stop.byte),
        Some("five")
    );
    assert_eq!(
        source.get(
            document
                .root()
                .and_then(|root| root.field("values"))
                .expect("values node")
                .span()
                .start
                .byte
                ..document
                    .root()
                    .and_then(|root| root.field("values"))
                    .expect("values node")
                    .span()
                    .stop
                    .byte
        ),
        Some("[one, \"two\", [three], {four: five}]")
    );
}

#[test]
fn block_scalar_styles_chomping_indentation_and_invalid_headers_are_exact() {
    let scalar = |header: &str, payload: &str| {
        let source = format!("value: {header}\n{payload}");
        let document = YamlDocument::parse("block.yml", &source, Budget::default());
        let node = document
            .root()
            .and_then(|root| root.field("value"))
            .expect("block scalar")
            .clone();
        (source, document, node)
    };

    let cases = [
        ("|", "  one\n  two\n", ScalarStyle::Literal, "one\ntwo\n"),
        ("|-", "  one\n  two\n", ScalarStyle::Literal, "one\ntwo"),
        ("|+", "  one\n\n", ScalarStyle::Literal, "one\n\n"),
        (
            ">",
            "  one\n  two\n\n  three\n",
            ScalarStyle::Folded,
            "one two\n\nthree\n",
        ),
        ("|2", "    deep\n", ScalarStyle::Literal, "  deep\n"),
    ];
    for (header, payload, style, expected) in cases {
        let (source, document, node) = scalar(header, payload);
        assert!(
            document.problems().is_empty(),
            "{header}: {:?}",
            document.problems()
        );
        assert_eq!(node.scalar_style(), Some(style), "{header}");
        assert_eq!(node.scalar(), Some(expected), "{header}");
        let expected_raw = format!("{header}\n{payload}");
        let expected_raw = expected_raw.strip_suffix('\n').unwrap_or(&expected_raw);
        assert_eq!(
            source.get(node.span().start.byte..node.span().stop.byte),
            Some(expected_raw),
            "{header}"
        );
    }

    for header in ["|0", "|+-", ">-+"] {
        let (_, document, _) = scalar(header, "  value\n");
        assert!(
            document
                .problems()
                .iter()
                .any(|problem| problem.message == "invalid block scalar header"),
            "invalid header {header:?}"
        );
    }
}

#[test]
fn parser_trivia_does_not_terminate_an_open_mapping() {
    let source = "first: one\n\n# comment\n%YAML 1.2\n---\n...\nsecond: two\n";
    let document = YamlDocument::parse("trivia.yml", source, Budget::default());
    let root = document.root().expect("mapping root");
    assert_eq!(
        root.field("first").and_then(|node| node.scalar()),
        Some("one")
    );
    assert_eq!(
        root.field("second").and_then(|node| node.scalar()),
        Some("two")
    );
}

#[test]
fn empty_mapping_and_sequence_values_respect_equal_and_lower_indentation() {
    let sibling = YamlDocument::parse("sibling.yml", "first:\nsecond: value\n", Budget::default());
    let root = sibling.root().expect("mapping root");
    assert_eq!(root.field("first").and_then(|node| node.scalar()), Some(""));
    assert_eq!(
        root.field("second").and_then(|node| node.scalar()),
        Some("value")
    );

    let anchored = YamlDocument::parse(
        "anchor.yml",
        "first: &anchor\nsecond: value\n",
        Budget::default(),
    );
    let root = anchored.root().expect("anchored mapping root");
    assert_eq!(
        root.field("first").and_then(|node| node.scalar()),
        Some("&anchor")
    );
    assert!(root.field("second").is_some());

    let anchored_equal = YamlDocument::parse(
        "anchored-equal.yml",
        "first: &anchor\n- item\nsecond: value\n",
        Budget::default(),
    );
    let root = anchored_equal.root().expect("anchored sequence root");
    assert_eq!(
        root.field("first")
            .and_then(|node| node.sequence())
            .and_then(|items| items.first())
            .and_then(|node| node.scalar()),
        Some("item")
    );
    assert!(root.field("second").is_some());

    let equal = YamlDocument::parse(
        "equal.yml",
        "first:\n- item\nsecond: value\n",
        Budget::default(),
    );
    let root = equal.root().expect("indentationless sequence root");
    assert_eq!(
        root.field("first")
            .and_then(|node| node.sequence())
            .and_then(|items| items.first())
            .and_then(|node| node.scalar()),
        Some("item")
    );
    assert!(root.field("second").is_some());

    let sequence = YamlDocument::parse(
        "sequence.yml",
        "nested:\n  items:\n    -\n    - next\ntail: done\n",
        Budget::default(),
    );
    let root = sequence.root().expect("nested mapping root");
    let items = root
        .field("nested")
        .and_then(|node| node.field("items"))
        .and_then(|node| node.sequence())
        .expect("sequence items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].scalar(), Some(""));
    assert_eq!(items[1].scalar(), Some("next"));
    assert_eq!(
        root.field("tail").and_then(|node| node.scalar()),
        Some("done")
    );

    let lower = YamlDocument::parse(
        "lower.yml",
        "nested:\n  items:\n    -\ntail: done\n",
        Budget::default(),
    );
    let root = lower.root().expect("lower-indent mapping root");
    assert_eq!(
        root.field("nested")
            .and_then(|node| node.field("items"))
            .and_then(|node| node.sequence())
            .and_then(|items| items.first())
            .and_then(|node| node.scalar()),
        Some("")
    );
    assert_eq!(
        root.field("tail").and_then(|node| node.scalar()),
        Some("done")
    );
}

#[test]
fn nested_flow_and_empty_block_offsets_are_byte_exact() {
    let source = "prefix:\n  mapping:\n    key: value\n  sequence:\n    - plain\nflow: {first: one,second: two,first: duplicate,malformed}\nempty: |\nnext: done\nkeep: |+\nend: done\ninvalid: |+- #\n";
    let document = YamlDocument::parse("offsets.yml", source, Budget::default());
    let root = document.root().expect("mapping root");

    let mapping = root
        .field("prefix")
        .and_then(|node| node.field("mapping"))
        .expect("nested mapping");
    assert_eq!(
        source.get(mapping.span().start.byte..mapping.span().stop.byte),
        Some("key: value")
    );
    let key = mapping
        .mapping()
        .and_then(|entries| entries.first())
        .expect("nested entry");
    assert_eq!(
        source.get(key.key_span.start.byte..key.key_span.stop.byte),
        Some("key")
    );
    let sequence = root
        .field("prefix")
        .and_then(|node| node.field("sequence"))
        .expect("nested sequence");
    assert_eq!(
        source.get(sequence.span().start.byte..sequence.span().stop.byte),
        Some("- plain")
    );

    let flow = root
        .field("flow")
        .and_then(|node| node.mapping())
        .expect("flow mapping");
    assert_eq!(flow.len(), 3);
    for entry in flow {
        assert_eq!(
            source.get(entry.key_span.start.byte..entry.key_span.stop.byte),
            Some(entry.key.as_str())
        );
        assert_eq!(
            source.get(entry.value.span().start.byte..entry.value.span().stop.byte),
            entry.value.scalar()
        );
    }
    let malformed = document
        .problems()
        .iter()
        .find(|problem| problem.message == "flow mapping entry has no ':'")
        .expect("malformed flow entry");
    assert_eq!(malformed.span.start.byte, source.find("malformed").unwrap());
    let duplicate = document
        .problems()
        .iter()
        .find(|problem| problem.code == "YAML-DUPLICATE-KEY")
        .expect("duplicate flow key");
    assert_eq!(
        source.get(duplicate.span.start.byte..duplicate.span.stop.byte),
        Some("first")
    );

    for name in ["empty", "keep"] {
        let node = root.field(name).expect("empty block scalar");
        assert_eq!(node.scalar(), Some(""), "{name}");
    }
    assert_eq!(
        source.get(
            root.field("empty").unwrap().span().start.byte
                ..root.field("empty").unwrap().span().stop.byte
        ),
        Some("|")
    );
    assert_eq!(
        source.get(
            root.field("keep").unwrap().span().start.byte
                ..root.field("keep").unwrap().span().stop.byte
        ),
        Some("|+")
    );
    let invalid = document
        .problems()
        .iter()
        .find(|problem| problem.message == "invalid block scalar header")
        .expect("invalid header");
    assert_eq!(
        source.get(invalid.span.start.byte..invalid.span.stop.byte),
        Some("|+- #")
    );
}
