use workflow_verifier_foundation::Budget;
use workflow_verifier_syntax::{Edit, TriviaKind, YamlDocument, YamlNodeKind};

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
fn exact_edits_compose_at_boundaries_and_reject_overlap() {
    let document = YamlDocument::parse("ci.yml", "key: old # keep\n", Budget::default());
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
}

#[test]
fn input_budget_fails_closed_without_panicking() {
    let document = YamlDocument::parse(
        "ci.yml",
        "0123456789",
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
