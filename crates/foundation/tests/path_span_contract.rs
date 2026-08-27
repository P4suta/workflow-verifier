use workflow_verifier_foundation::{
    PathError, Position, PublicPath, Span, Utf16Position, byte_to_utf16, utf16_to_byte,
};

fn position(byte: usize, line: u32, column: u32) -> Position {
    Position { byte, line, column }
}

#[test]
fn public_path_accessors_keys_and_display_preserve_the_validated_value() {
    let raw = "café/straße.yml";
    let path = PublicPath::new(raw).expect("portable path");
    assert_eq!(path.as_str(), raw);
    assert_eq!(path.to_string(), raw);
    assert_eq!(path.portable_key(), "café/strasse.yml");
    assert_eq!(
        PathError::ParentSegment.to_string(),
        "invalid public path: ParentSegment"
    );
}

#[test]
fn span_contains_closed_boundaries_and_merge_respects_file_identity() {
    let prefix_bytes = "prefix".len();
    let body_bytes = "body".len();
    let stop_byte = prefix_bytes + body_bytes;
    let span = Span::new(
        "workflow.yml",
        position(prefix_bytes, 1, 1),
        position(stop_byte, 1, 1),
    );
    assert!(span.contains(prefix_bytes));
    assert!(span.contains(stop_byte));
    assert!(span.contains(prefix_bytes + body_bytes / 2));
    assert!(
        !span.contains(
            prefix_bytes
                .checked_sub(1)
                .expect("fixture prefix is nonempty")
        )
    );
    assert!(!span.contains(stop_byte + 1));

    let earlier = Span::new(
        "workflow.yml",
        position(0, 1, 1),
        position(prefix_bytes, 1, 1),
    );
    let merged = span.merge(&earlier);
    assert_eq!(merged.file, "workflow.yml");
    assert_eq!(merged.start, earlier.start);
    assert_eq!(merged.stop, span.stop);

    let other_file = Span::new("other.yml", Position::default(), Position::default());
    assert_eq!(span.merge(&other_file), span);
    assert_eq!(span.to_string(), "workflow.yml:1:1");
}

struct UtfFixture {
    source: String,
    second_line_start: usize,
    astral_end: usize,
    second_line_end: usize,
    third_line_start: usize,
    astral_utf16_width: u32,
    second_line_utf16_width: u32,
    last_line_utf16_width: u32,
}

fn utf_fixture() -> UtfFixture {
    let first_line = "first\n";
    let astral = "😀";
    let second_line_tail = "x\n";
    let last_line = "last";
    let source = format!("{first_line}{astral}{second_line_tail}{last_line}");
    let second_line_start = first_line.len();
    let astral_end = second_line_start + astral.len();
    let second_line_end = astral_end + "x".len();
    let third_line_start = second_line_end + "\n".len();
    let astral_utf16_width = u32::try_from(astral.encode_utf16().count())
        .expect("one Unicode scalar fits an LSP coordinate");
    let second_line_utf16_width = astral_utf16_width + 1;
    let last_line_utf16_width =
        u32::try_from(last_line.encode_utf16().count()).expect("fixture column fits the protocol");
    UtfFixture {
        source,
        second_line_start,
        astral_end,
        second_line_end,
        third_line_start,
        astral_utf16_width,
        second_line_utf16_width,
        last_line_utf16_width,
    }
}

#[test]
fn utf16_to_byte_covers_lines_astral_boundaries_and_line_ends() {
    let fixture = utf_fixture();

    assert_eq!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: 1,
                character: 0,
            }
        ),
        Ok(fixture.second_line_start)
    );
    assert_eq!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: 1,
                character: fixture.astral_utf16_width,
            }
        ),
        Ok(fixture.astral_end)
    );
    assert_eq!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: 1,
                character: fixture.second_line_utf16_width,
            }
        ),
        Ok(fixture.second_line_end)
    );
    assert_eq!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: 2,
                character: 0,
            }
        ),
        Ok(fixture.third_line_start)
    );
    assert!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: 1,
                character: fixture
                    .astral_utf16_width
                    .checked_sub(1)
                    .expect("astral scalars occupy multiple UTF-16 code units"),
            }
        )
        .is_err()
    );
    assert!(
        utf16_to_byte(
            &fixture.source,
            Utf16Position {
                line: u32::try_from(fixture.source.lines().count())
                    .expect("fixture line count fits the protocol"),
                character: 0,
            }
        )
        .is_err()
    );
}

#[test]
fn byte_to_utf16_covers_astral_boundaries_lines_and_end_of_input() {
    let fixture = utf_fixture();
    assert_eq!(
        byte_to_utf16(&fixture.source, fixture.astral_end),
        Ok(Utf16Position {
            line: 1,
            character: fixture.astral_utf16_width,
        })
    );
    assert_eq!(
        byte_to_utf16(&fixture.source, fixture.third_line_start),
        Ok(Utf16Position {
            line: 2,
            character: 0,
        })
    );
    assert_eq!(
        byte_to_utf16(&fixture.source, fixture.source.len()),
        Ok(Utf16Position {
            line: 2,
            character: fixture.last_line_utf16_width,
        })
    );
    assert!(byte_to_utf16(&fixture.source, fixture.second_line_start + 1).is_err());
    assert!(
        byte_to_utf16(
            &fixture.source,
            fixture
                .source
                .len()
                .checked_add(1)
                .expect("fixture length can advance one byte")
        )
        .is_err()
    );
}
