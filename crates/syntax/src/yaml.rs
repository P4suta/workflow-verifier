use std::collections::BTreeSet;
use workflow_verifier_foundation::{Budget, BudgetTracker, Position, Span};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriviaKind {
    Comment,
    Blank,
    Directive,
    DocumentStart,
    DocumentEnd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trivia {
    pub kind: TriviaKind,
    pub raw: String,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    pub name: String,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidRegion {
    pub raw: String,
    pub reason: String,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamlProblem {
    pub code: String,
    pub message: String,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YamlNodeKind {
    Scalar,
    Mapping,
    Sequence,
    Alias,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scalar {
    value: String,
    raw: String,
    style: ScalarStyle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NodeData {
    Scalar(Scalar),
    Mapping(Vec<MappingEntry>),
    Sequence(Vec<YamlNode>),
    Alias(String),
    Invalid { raw: String, reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YamlNode {
    data: NodeData,
    span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingEntry {
    pub key: String,
    pub key_span: Span,
    pub value: YamlNode,
    pub span: Span,
}

impl YamlNode {
    #[must_use]
    pub fn kind(&self) -> YamlNodeKind {
        match self.data {
            NodeData::Scalar(_) => YamlNodeKind::Scalar,
            NodeData::Mapping(_) => YamlNodeKind::Mapping,
            NodeData::Sequence(_) => YamlNodeKind::Sequence,
            NodeData::Alias(_) => YamlNodeKind::Alias,
            NodeData::Invalid { .. } => YamlNodeKind::Invalid,
        }
    }

    #[must_use]
    pub fn span(&self) -> &Span {
        &self.span
    }

    #[must_use]
    pub fn scalar(&self) -> Option<&str> {
        match &self.data {
            NodeData::Scalar(value) => Some(&value.value),
            _ => None,
        }
    }

    #[must_use]
    pub fn alias(&self) -> Option<&str> {
        match &self.data {
            NodeData::Alias(name) => Some(name),
            _ => None,
        }
    }

    #[must_use]
    pub fn scalar_style(&self) -> Option<ScalarStyle> {
        match &self.data {
            NodeData::Scalar(value) => Some(value.style),
            _ => None,
        }
    }

    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        match &self.data {
            NodeData::Scalar(value) => Some(&value.raw),
            NodeData::Invalid { raw, .. } => Some(raw),
            _ => None,
        }
    }

    #[must_use]
    pub fn mapping(&self) -> Option<&[MappingEntry]> {
        match &self.data {
            NodeData::Mapping(entries) => Some(entries),
            _ => None,
        }
    }

    #[must_use]
    pub fn sequence(&self) -> Option<&[YamlNode]> {
        match &self.data {
            NodeData::Sequence(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Self> {
        self.mapping()?
            .iter()
            .find(|entry| entry.key == name)
            .map(|entry| &entry.value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edit {
    pub start_byte: usize,
    pub stop_byte: usize,
    pub replacement: String,
}

impl Edit {
    #[must_use]
    pub fn replace(start_byte: usize, stop_byte: usize, replacement: impl Into<String>) -> Self {
        Self {
            start_byte,
            stop_byte,
            replacement: replacement.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct YamlDocument {
    file: String,
    source: String,
    root: Option<YamlNode>,
    trivia: Vec<Trivia>,
    anchors: Vec<Anchor>,
    aliases: Vec<Anchor>,
    problems: Vec<YamlProblem>,
    invalid_regions: Vec<InvalidRegion>,
}

impl YamlDocument {
    #[must_use]
    pub fn parse(file: impl Into<String>, source: &str, budget: Budget) -> Self {
        let file = file.into();
        let tracker = BudgetTracker::new(budget);
        if let Err(error) = tracker.input(source.len()) {
            return Self {
                file: file.clone(),
                source: source.to_owned(),
                root: None,
                trivia: Vec::new(),
                anchors: Vec::new(),
                aliases: Vec::new(),
                problems: vec![YamlProblem {
                    code: "YAML-RESOURCE-LIMIT".to_owned(),
                    message: error.to_string(),
                    span: slow_span_for(&file, source, 0, source.len()),
                }],
                invalid_regions: Vec::new(),
            };
        }
        let lines = lines(source);
        let positions = PositionIndex::new(source);
        let (trivia, anchors, aliases) = scan_metadata(&file, source, &lines, &positions);
        let mut parser = Parser {
            file: &file,
            source,
            lines: &lines,
            positions: &positions,
            problems: Vec::new(),
            invalid_regions: Vec::new(),
        };
        let first = parser.next_content(0);
        let root = first.and_then(|index| parser.parse_block(index).map(|(node, _)| node));
        let problems = std::mem::take(&mut parser.problems);
        let invalid_regions = std::mem::take(&mut parser.invalid_regions);
        drop(parser);
        Self {
            file,
            source: source.to_owned(),
            root,
            trivia,
            anchors,
            aliases,
            problems,
            invalid_regions,
        }
    }

    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }

    #[must_use]
    pub fn print(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn root(&self) -> Option<&YamlNode> {
        self.root.as_ref()
    }

    #[must_use]
    pub fn trivia(&self) -> &[Trivia] {
        &self.trivia
    }

    #[must_use]
    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    #[must_use]
    pub fn aliases(&self) -> &[Anchor] {
        &self.aliases
    }

    #[must_use]
    pub fn problems(&self) -> &[YamlProblem] {
        &self.problems
    }

    #[must_use]
    pub fn invalid_regions(&self) -> &[InvalidRegion] {
        &self.invalid_regions
    }

    /// Apply a deterministic transaction to the original bytes.
    ///
    /// # Errors
    /// Rejects out-of-range, non-UTF-8-boundary, or overlapping edit spans.
    pub fn apply_edits(&self, edits: &[Edit]) -> Result<String, String> {
        let mut ordered = edits.to_vec();
        for edit in &ordered {
            if edit.start_byte > edit.stop_byte
                || edit.stop_byte > self.source.len()
                || !self.source.is_char_boundary(edit.start_byte)
                || !self.source.is_char_boundary(edit.stop_byte)
            {
                return Err("edit span is outside the source".to_owned());
            }
        }
        ordered.sort_by(|left, right| {
            left.start_byte
                .cmp(&right.start_byte)
                .then(left.stop_byte.cmp(&right.stop_byte))
        });
        for pair in ordered.windows(2) {
            let Some(left) = pair.first() else { continue };
            let Some(right) = pair.get(1) else { continue };
            let overlaps = left.stop_byte > right.start_byte
                && left.start_byte != left.stop_byte
                && right.start_byte != right.stop_byte;
            if overlaps {
                return Err("edit spans overlap".to_owned());
            }
        }
        ordered.sort_by(|left, right| {
            right
                .start_byte
                .cmp(&left.start_byte)
                .then(right.stop_byte.cmp(&left.stop_byte))
        });
        let mut output = self.source.clone();
        for edit in ordered {
            output.replace_range(edit.start_byte..edit.stop_byte, &edit.replacement);
        }
        Ok(output)
    }
}

#[derive(Clone, Copy)]
struct Line<'a> {
    start: usize,
    end: usize,
    indent: usize,
    content: &'a str,
}

fn lines(source: &str) -> Vec<Line<'_>> {
    let mut output = Vec::new();
    let mut start = 0usize;
    for segment in source.split_inclusive('\n') {
        let without_newline = segment.strip_suffix('\n').unwrap_or(segment);
        let raw = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        let end = start.saturating_add(raw.len());
        let indent = raw.bytes().take_while(|byte| *byte == b' ').count();
        let content = raw.get(indent..).unwrap_or_default();
        output.push(Line {
            start,
            end,
            indent,
            content,
        });
        start = start.saturating_add(segment.len());
    }
    if source.is_empty() {
        output.push(Line {
            start: 0,
            end: 0,
            indent: 0,
            content: "",
        });
    }
    output
}

fn slow_position_at(source: &str, byte: usize) -> Position {
    let bounded = byte.min(source.len());
    let boundary = (0..=bounded)
        .rev()
        .find(|offset| source.is_char_boundary(*offset))
        .unwrap_or(0);
    let prefix = &source[..boundary];
    let line_count = prefix
        .bytes()
        .filter(|candidate| *candidate == b'\n')
        .count();
    let line = u32::try_from(line_count.saturating_add(1)).unwrap_or(u32::MAX);
    let line_start = prefix.rfind('\n').map_or(0, |offset| offset + 1);
    let columns = prefix[line_start..].chars().count();
    let column = u32::try_from(columns.saturating_add(1)).unwrap_or(u32::MAX);
    Position {
        byte: boundary,
        line,
        column,
    }
}

fn slow_span_for(file: &str, source: &str, start: usize, stop: usize) -> Span {
    Span::new(
        file,
        slow_position_at(source, start),
        slow_position_at(source, stop),
    )
}

struct PositionIndex {
    line_starts: Vec<usize>,
}

impl PositionIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = Vec::new();
        line_starts.push(0);
        line_starts.extend(
            source
                .as_bytes()
                .iter()
                .enumerate()
                .filter_map(|(index, byte)| (*byte == b'\n').then_some(index.saturating_add(1))),
        );
        Self { line_starts }
    }

    fn position(&self, source: &str, byte: usize) -> Position {
        let bounded = byte.min(source.len());
        let boundary = (0..=bounded)
            .rev()
            .find(|offset| source.is_char_boundary(*offset))
            .unwrap_or(0);
        let line_index = self
            .line_starts
            .partition_point(|start| *start <= boundary)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        let columns = source[line_start..boundary].chars().count();
        Position {
            byte: boundary,
            line: u32::try_from(line_index.saturating_add(1)).unwrap_or(u32::MAX),
            column: u32::try_from(columns.saturating_add(1)).unwrap_or(u32::MAX),
        }
    }

    fn span(&self, file: &str, source: &str, start: usize, stop: usize) -> Span {
        Span::new(
            file,
            self.position(source, start),
            self.position(source, stop),
        )
    }
}

fn scan_metadata(
    file: &str,
    source: &str,
    lines: &[Line<'_>],
    positions: &PositionIndex,
) -> (Vec<Trivia>, Vec<Anchor>, Vec<Anchor>) {
    let mut trivia = Vec::new();
    for line in lines {
        let trimmed = line.content.trim();
        let kind = if trimmed.is_empty() {
            Some(TriviaKind::Blank)
        } else if trimmed.starts_with('#') {
            Some(TriviaKind::Comment)
        } else if trimmed.starts_with('%') {
            Some(TriviaKind::Directive)
        } else if trimmed == "---" {
            Some(TriviaKind::DocumentStart)
        } else if trimmed == "..." {
            Some(TriviaKind::DocumentEnd)
        } else {
            None
        };
        if let Some(kind) = kind {
            trivia.push(Trivia {
                kind,
                raw: source[line.start..line.end].to_owned(),
                span: positions.span(file, source, line.start, line.end),
            });
        }
        if let Some(comment) = comment_offset(line.content) {
            let start = line
                .start
                .saturating_add(line.indent)
                .saturating_add(comment);
            trivia.push(Trivia {
                kind: TriviaKind::Comment,
                raw: source[start..line.end].to_owned(),
                span: positions.span(file, source, start, line.end),
            });
        }
    }
    let anchors = scan_properties(file, source, positions, '&');
    let aliases = scan_properties(file, source, positions, '*');
    (trivia, anchors, aliases)
}

fn scan_properties(
    file: &str,
    source: &str,
    positions: &PositionIndex,
    marker: char,
) -> Vec<Anchor> {
    let mut output = Vec::new();
    let bytes = source.as_bytes();
    let marker = marker as u8;
    let mut single = false;
    let mut double = false;
    let mut characters = bytes.iter().copied().enumerate().peekable();
    while let Some((index, byte)) = characters.next() {
        match byte {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            byte if byte == marker && !single && !double => {
                let start = index;
                let Some((name_start, _)) = characters.peek().copied() else {
                    continue;
                };
                let mut end = name_start;
                while characters.peek().is_some_and(|(_, byte)| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                }) {
                    let _ = characters.next();
                    end = characters
                        .peek()
                        .map_or(source.len(), |(next_index, _)| *next_index);
                }
                if end > name_start {
                    output.push(Anchor {
                        name: source[name_start..end].to_owned(),
                        span: positions.span(file, source, start, end),
                    });
                }
            }
            _ => {}
        }
    }
    output
}

fn comment_offset(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if double && escaped {
            escaped = false;
            continue;
        }
        if double && byte == b'\\' {
            escaped = true;
        } else if byte == b'\'' && !double {
            single = !single;
        } else if byte == b'"' && !single {
            double = !double;
        } else if byte == b'#'
            && !single
            && !double
            && (index == 0 || bytes.get(index.wrapping_sub(1)) == Some(&b' '))
        {
            return Some(index);
        }
    }
    None
}

struct Parser<'a> {
    file: &'a str,
    source: &'a str,
    lines: &'a [Line<'a>],
    positions: &'a PositionIndex,
    problems: Vec<YamlProblem>,
    invalid_regions: Vec<InvalidRegion>,
}

impl Parser<'_> {
    fn is_trivia(&self, index: usize) -> bool {
        self.lines.get(index).is_none_or(|line| {
            let value = line.content.trim();
            value.is_empty()
                || value.starts_with('#')
                || value.starts_with('%')
                || value == "---"
                || value == "..."
        })
    }

    fn next_content(&self, index: usize) -> Option<usize> {
        self.lines
            .iter()
            .enumerate()
            .skip(index)
            .find_map(|(candidate, _)| (!self.is_trivia(candidate)).then_some(candidate))
    }

    fn problem(&mut self, code: &str, message: impl Into<String>, start: usize, stop: usize) {
        self.problems.push(YamlProblem {
            code: code.to_owned(),
            message: message.into(),
            span: self.positions.span(self.file, self.source, start, stop),
        });
    }

    fn invalid(&mut self, reason: impl Into<String>, start: usize, stop: usize) -> YamlNode {
        let reason = reason.into();
        let raw = self.source.get(start..stop).unwrap_or_default().to_owned();
        let span = self.positions.span(self.file, self.source, start, stop);
        self.invalid_regions.push(InvalidRegion {
            raw: raw.clone(),
            reason: reason.clone(),
            span: span.clone(),
        });
        YamlNode {
            data: NodeData::Invalid { raw, reason },
            span,
        }
    }

    fn parse_block(&mut self, index: usize) -> Option<(YamlNode, usize)> {
        let line = *self.lines.get(index)?;
        let indent = line.indent;
        if sequence_head(line.content).is_some() {
            Some(self.parse_sequence(index, indent))
        } else if split_mapping(line.content).is_some() {
            Some(self.parse_mapping(index, indent))
        } else {
            let node = self.parse_inline(
                line.content,
                line.start.saturating_add(line.indent),
                line.end,
            );
            Some((node, index.saturating_add(1)))
        }
    }

    fn parse_mapping(&mut self, mut index: usize, indent: usize) -> (YamlNode, usize) {
        let start = self
            .lines
            .get(index)
            .map_or(0, |line| line.start.saturating_add(indent));
        let mut stop = start;
        let mut entries = Vec::new();
        let mut keys = BTreeSet::new();
        while self.lines.get(index).is_some() {
            if self.is_trivia(index) {
                index = index.saturating_add(1);
                continue;
            }
            let Some(line) = self.lines.get(index).copied() else {
                break;
            };
            if line.indent != indent || sequence_head(line.content).is_some() {
                break;
            }
            let Some((raw_key, value_offset)) = split_mapping(line.content) else {
                break;
            };
            let key = decode_plain_or_quoted(raw_key.trim())
                .unwrap_or_else(|_| raw_key.trim().to_owned());
            let key_start = line.start.saturating_add(line.indent);
            let key_stop = key_start.saturating_add(raw_key.trim_end().len());
            if !keys.insert(key.clone()) {
                self.problem(
                    "YAML-DUPLICATE-KEY",
                    format!("duplicate mapping key: {key}"),
                    key_start,
                    key_stop,
                );
            }
            let raw_value = line.content.get(value_offset..).unwrap_or_default();
            let leading = raw_value.bytes().take_while(|byte| *byte == b' ').count();
            let raw_value = raw_value.get(leading..).unwrap_or_default();
            let value_start = line
                .start
                .saturating_add(line.indent)
                .saturating_add(value_offset)
                .saturating_add(leading);
            let (value, next) =
                self.parse_mapping_value(index, indent, raw_value, value_start, line.end);
            stop = stop.max(value.span.stop.byte);
            let entry_span = self.positions.span(self.file, self.source, key_start, stop);
            entries.push(MappingEntry {
                key,
                key_span: self
                    .positions
                    .span(self.file, self.source, key_start, key_stop),
                value,
                span: entry_span,
            });
            index = next;
        }
        (
            YamlNode {
                data: NodeData::Mapping(entries),
                span: self.positions.span(self.file, self.source, start, stop),
            },
            index,
        )
    }

    fn parse_sequence(&mut self, mut index: usize, indent: usize) -> (YamlNode, usize) {
        let start = self
            .lines
            .get(index)
            .map_or(0, |line| line.start.saturating_add(indent));
        let mut stop = start;
        let mut items = Vec::new();
        while self.lines.get(index).is_some() {
            if self.is_trivia(index) {
                index = index.saturating_add(1);
                continue;
            }
            let Some(line) = self.lines.get(index).copied() else {
                break;
            };
            if line.indent != indent {
                break;
            }
            let Some(head) = sequence_head(line.content) else {
                break;
            };
            let value_start = line.start.saturating_add(line.indent).saturating_add(head);
            let value_text = line.content.get(head..).unwrap_or_default();
            let (value, next) = if value_text.trim().is_empty() {
                if let Some(child) = self.next_content(index.saturating_add(1)) {
                    let child_line = self.lines[child];
                    if child_line.indent > indent {
                        self.parse_block(child).unwrap_or_else(|| {
                            (self.empty_scalar(line.end), index.saturating_add(1))
                        })
                    } else {
                        (self.empty_scalar(line.end), index.saturating_add(1))
                    }
                } else {
                    (self.empty_scalar(line.end), index.saturating_add(1))
                }
            } else if let Some(mapping_head) = split_mapping(value_text) {
                self.parse_compact_mapping(index, indent, head, line, value_text, mapping_head)
            } else if let Some((header_offset, header)) = block_scalar_header(value_text) {
                self.parse_block_scalar_with_properties(
                    index,
                    indent,
                    value_text,
                    value_start,
                    header_offset,
                    header,
                )
            } else {
                self.parse_inline_with_continuation(
                    index,
                    indent,
                    value_text,
                    value_start,
                    line.end,
                )
            };
            stop = stop.max(value.span.stop.byte);
            items.push(value);
            index = next;
        }
        (
            YamlNode {
                data: NodeData::Sequence(items),
                span: self.positions.span(self.file, self.source, start, stop),
            },
            index,
        )
    }

    fn parse_compact_mapping(
        &mut self,
        index: usize,
        sequence_indent: usize,
        head: usize,
        line: Line<'_>,
        content: &str,
        mapping_head: (&str, usize),
    ) -> (YamlNode, usize) {
        let (raw_key, value_offset) = mapping_head;
        let key =
            decode_plain_or_quoted(raw_key.trim()).unwrap_or_else(|_| raw_key.trim().to_owned());
        let key_start = line.start.saturating_add(line.indent).saturating_add(head);
        let raw_value = content.get(value_offset..).unwrap_or_default();
        let leading = raw_value.bytes().take_while(|byte| *byte == b' ').count();
        let raw_value = raw_value.get(leading..).unwrap_or_default();
        let value_start = key_start
            .saturating_add(value_offset)
            .saturating_add(leading);
        let mapping_indent = sequence_indent.saturating_add(head);
        let (first_value, mut next) =
            self.parse_mapping_value(index, mapping_indent, raw_value, value_start, line.end);
        let mut entries = vec![MappingEntry {
            key,
            key_span: self.positions.span(
                self.file,
                self.source,
                key_start,
                key_start.saturating_add(raw_key.trim_end().len()),
            ),
            span: self.positions.span(
                self.file,
                self.source,
                key_start,
                first_value.span.stop.byte,
            ),
            value: first_value,
        }];
        if let Some(child) = self.next_content(next) {
            let child_line = self.lines[child];
            if child_line.indent == mapping_indent
                && let Some((mapping, after)) = self.parse_block(child)
                && let NodeData::Mapping(mut more) = mapping.data
            {
                entries.append(&mut more);
                next = after;
            }
        }
        let stop = entries
            .iter()
            .map(|entry| entry.span.stop.byte)
            .max()
            .unwrap_or(line.end);
        (
            YamlNode {
                data: NodeData::Mapping(entries),
                span: self.positions.span(self.file, self.source, key_start, stop),
            },
            next,
        )
    }

    fn parse_mapping_value(
        &mut self,
        index: usize,
        parent_indent: usize,
        raw_value: &str,
        value_start: usize,
        line_end: usize,
    ) -> (YamlNode, usize) {
        if raw_value.is_empty() || raw_value.starts_with('#') {
            if let Some(child) = self.next_content(index.saturating_add(1))
                && (self.lines[child].indent > parent_indent
                    || (self.lines[child].indent == parent_indent
                        && sequence_head(self.lines[child].content).is_some()))
            {
                return self
                    .parse_block(child)
                    .unwrap_or_else(|| (self.empty_scalar(line_end), index.saturating_add(1)));
            }
            return (self.empty_scalar(line_end), index.saturating_add(1));
        }
        if let Some((header_offset, header)) = block_scalar_header(raw_value) {
            return self.parse_block_scalar_with_properties(
                index,
                parent_indent,
                raw_value,
                value_start,
                header_offset,
                header,
            );
        }
        if matches!(raw_value.as_bytes().first(), Some(b'&' | b'!')) {
            if let Some(child) = self.next_content(index.saturating_add(1))
                && (self.lines[child].indent > parent_indent
                    || (self.lines[child].indent == parent_indent
                        && sequence_head(self.lines[child].content).is_some()))
            {
                let (mut node, next) = self
                    .parse_block(child)
                    .unwrap_or_else(|| (self.empty_scalar(line_end), index.saturating_add(1)));
                let stop = node.span.stop.byte;
                node.span = self
                    .positions
                    .span(self.file, self.source, value_start, stop);
                if let NodeData::Scalar(value) = &mut node.data {
                    self.source
                        .get(value_start..stop)
                        .unwrap_or(raw_value)
                        .clone_into(&mut value.raw);
                }
                return (node, next);
            }
            return (
                self.parse_inline(raw_value, value_start, line_end),
                index.saturating_add(1),
            );
        }
        self.parse_inline_with_continuation(index, parent_indent, raw_value, value_start, line_end)
    }

    fn parse_block_scalar(
        &mut self,
        index: usize,
        parent_indent: usize,
        header: &str,
        header_start: usize,
    ) -> (YamlNode, usize) {
        let style = if header.starts_with('|') {
            ScalarStyle::Literal
        } else {
            ScalarStyle::Folded
        };
        let chomping = header.chars().find(|value| matches!(value, '+' | '-'));
        let explicit = header
            .chars()
            .find_map(|value| value.to_digit(10))
            .and_then(|value| usize::try_from(value).ok());
        if header
            .chars()
            .filter(|value| matches!(value, '+' | '-'))
            .count()
            > 1
            || explicit == Some(0)
        {
            self.problem(
                "YAML-SYNTAX",
                "invalid block scalar header",
                header_start,
                header_start.saturating_add(header.len()),
            );
        }
        let mut next = index.saturating_add(1);
        let mut payload = Vec::new();
        let mut content_indent = explicit.map(|value| parent_indent.saturating_add(value));
        while let Some(line) = self.lines.get(next).copied() {
            if line.content.trim().is_empty() {
                payload.push(String::new());
                next = next.saturating_add(1);
                continue;
            }
            if line.indent <= parent_indent {
                break;
            }
            let chosen = *content_indent.get_or_insert(line.indent);
            if line.indent < chosen {
                break;
            }
            let raw = self
                .source
                .get(line.start.saturating_add(chosen)..line.end)
                .unwrap_or_default();
            payload.push(raw.to_owned());
            next = next.saturating_add(1);
        }
        let mut value = if style == ScalarStyle::Literal {
            payload.join("\n")
        } else {
            fold_lines(&payload)
        };
        match chomping {
            Some('-') => {
                while value.ends_with('\n') {
                    value.pop();
                }
            }
            Some('+') => {
                if next != index.saturating_add(1) {
                    value.push('\n');
                }
            }
            _ => {
                while value.ends_with('\n') {
                    value.pop();
                }
                if next != index.saturating_add(1) {
                    value.push('\n');
                }
            }
        }
        let stop = self
            .lines
            .get(next.saturating_sub(1))
            .map_or(header_start.saturating_add(header.len()), |line| line.end);
        (
            YamlNode {
                data: NodeData::Scalar(Scalar {
                    value,
                    raw: self.source[header_start..stop].to_owned(),
                    style,
                }),
                span: self
                    .positions
                    .span(self.file, self.source, header_start, stop),
            },
            next,
        )
    }

    fn parse_block_scalar_with_properties(
        &mut self,
        index: usize,
        parent_indent: usize,
        raw_value: &str,
        value_start: usize,
        header_offset: usize,
        header: &str,
    ) -> (YamlNode, usize) {
        let (mut node, next) = self.parse_block_scalar(
            index,
            parent_indent,
            header,
            value_start.saturating_add(header_offset),
        );
        let stop = node.span.stop.byte;
        node.span = self
            .positions
            .span(self.file, self.source, value_start, stop);
        if let NodeData::Scalar(value) = &mut node.data {
            self.source
                .get(value_start..stop)
                .unwrap_or(raw_value)
                .clone_into(&mut value.raw);
        }
        (node, next)
    }

    fn parse_inline(&mut self, raw: &str, start: usize, line_end: usize) -> YamlNode {
        let comment = comment_offset(raw).unwrap_or(raw.len());
        let value = raw.get(..comment).unwrap_or_default().trim_end();
        let stop = start.saturating_add(value.len()).min(line_end);
        if let Some(offset) = inline_property_value_offset(value) {
            let mut node = self.parse_inline(
                value.get(offset..).unwrap_or_default(),
                start.saturating_add(offset),
                line_end,
            );
            let decorated_stop = node.span.stop.byte;
            node.span = self
                .positions
                .span(self.file, self.source, start, decorated_stop);
            if let NodeData::Scalar(scalar) = &mut node.data {
                self.source
                    .get(start..decorated_stop)
                    .unwrap_or(value)
                    .clone_into(&mut scalar.raw);
            }
            return node;
        }
        if value.starts_with('[') {
            if !balanced_flow(value, '[', ']') {
                self.problem("YAML-SYNTAX", "unterminated flow sequence", start, line_end);
                return self.invalid("unterminated flow sequence", start, line_end);
            }
            return self.parse_flow_sequence(value, start, stop);
        }
        if value.starts_with('{') {
            if !balanced_flow(value, '{', '}') {
                self.problem("YAML-SYNTAX", "unterminated flow mapping", start, line_end);
                return self.invalid("unterminated flow mapping", start, line_end);
            }
            return self.parse_flow_mapping(value, start, stop);
        }
        if let Some(name) = value.strip_prefix('*') {
            return YamlNode {
                data: NodeData::Alias(name.trim().to_owned()),
                span: self.positions.span(self.file, self.source, start, stop),
            };
        }
        let (decoded, style) = match decode_scalar(value) {
            Ok(value) => value,
            Err(message) => {
                self.problem("YAML-SYNTAX", &message, start, stop);
                return self.invalid(message, start, stop);
            }
        };
        YamlNode {
            data: NodeData::Scalar(Scalar {
                value: decoded,
                raw: value.to_owned(),
                style,
            }),
            span: self.positions.span(self.file, self.source, start, stop),
        }
    }

    fn parse_inline_with_continuation(
        &mut self,
        index: usize,
        parent_indent: usize,
        raw: &str,
        start: usize,
        line_end: usize,
    ) -> (YamlNode, usize) {
        let mut node = self.parse_inline(raw, start, line_end);
        let NodeData::Scalar(scalar) = &node.data else {
            return (node, index.saturating_add(1));
        };
        if scalar.style != ScalarStyle::Plain {
            return (node, index.saturating_add(1));
        }

        let mut lines = vec![scalar.value.clone()];
        let mut next = index.saturating_add(1);
        let mut stop = node.span.stop.byte;
        let mut has_continuation = false;
        while let Some(line) = self.lines.get(next).copied() {
            let trimmed = line.content.trim();
            if trimmed.is_empty() {
                lines.push(String::new());
                next = next.saturating_add(1);
                continue;
            }
            if trimmed.starts_with('#') {
                next = next.saturating_add(1);
                continue;
            }
            if line.indent <= parent_indent {
                break;
            }
            let comment = comment_offset(line.content).unwrap_or(line.content.len());
            lines.push(
                line.content
                    .get(..comment)
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
            );
            stop = line.end;
            has_continuation = true;
            next = next.saturating_add(1);
        }
        if !has_continuation {
            return (node, index.saturating_add(1));
        }

        if let NodeData::Scalar(scalar) = &mut node.data {
            scalar.value = fold_lines(&lines);
            self.source
                .get(start..stop)
                .unwrap_or(raw)
                .clone_into(&mut scalar.raw);
        }
        node.span = self.positions.span(self.file, self.source, start, stop);
        (node, next)
    }

    fn parse_flow_sequence(&mut self, value: &str, start: usize, stop: usize) -> YamlNode {
        let inner = value
            .get(1..value.len().saturating_sub(1))
            .unwrap_or_default();
        let items = split_flow(inner)
            .into_iter()
            .filter(|(_, item)| !item.trim().is_empty())
            .map(|(offset, item)| {
                let leading = item.len().saturating_sub(item.trim_start().len());
                self.parse_inline(
                    item.trim(),
                    start
                        .saturating_add(1)
                        .saturating_add(offset)
                        .saturating_add(leading),
                    start
                        .saturating_add(1)
                        .saturating_add(offset)
                        .saturating_add(item.len()),
                )
            })
            .collect();
        YamlNode {
            data: NodeData::Sequence(items),
            span: self.positions.span(self.file, self.source, start, stop),
        }
    }

    fn parse_flow_mapping(&mut self, value: &str, start: usize, stop: usize) -> YamlNode {
        let inner = value
            .get(1..value.len().saturating_sub(1))
            .unwrap_or_default();
        let mut entries = Vec::new();
        if inner.trim().is_empty() {
            return YamlNode {
                data: NodeData::Mapping(entries),
                span: self.positions.span(self.file, self.source, start, stop),
            };
        }
        let mut keys = BTreeSet::new();
        for (offset, item) in split_flow(inner) {
            let Some((raw_key, value_offset)) = split_mapping(item) else {
                self.problem(
                    "YAML-SYNTAX",
                    "flow mapping entry has no ':'",
                    start.saturating_add(1).saturating_add(offset),
                    stop,
                );
                continue;
            };
            let key = decode_plain_or_quoted(raw_key.trim())
                .unwrap_or_else(|_| raw_key.trim().to_owned());
            let key_start = start.saturating_add(1).saturating_add(offset);
            if !keys.insert(key.clone()) {
                self.problem(
                    "YAML-DUPLICATE-KEY",
                    format!("duplicate mapping key: {key}"),
                    key_start,
                    key_start.saturating_add(raw_key.len()),
                );
            }
            let raw_value = item.get(value_offset..).unwrap_or_default().trim();
            let value_start = key_start.saturating_add(value_offset).saturating_add(
                item[value_offset..]
                    .len()
                    .saturating_sub(item[value_offset..].trim_start().len()),
            );
            let child =
                self.parse_inline(raw_value, value_start, key_start.saturating_add(item.len()));
            entries.push(MappingEntry {
                key,
                key_span: self.positions.span(
                    self.file,
                    self.source,
                    key_start,
                    key_start.saturating_add(raw_key.len()),
                ),
                span: self
                    .positions
                    .span(self.file, self.source, key_start, child.span.stop.byte),
                value: child,
            });
        }
        YamlNode {
            data: NodeData::Mapping(entries),
            span: self.positions.span(self.file, self.source, start, stop),
        }
    }

    fn empty_scalar(&self, at: usize) -> YamlNode {
        YamlNode {
            data: NodeData::Scalar(Scalar {
                value: String::new(),
                raw: String::new(),
                style: ScalarStyle::Plain,
            }),
            span: self.positions.span(self.file, self.source, at, at),
        }
    }
}

fn sequence_head(value: &str) -> Option<usize> {
    if value == "-" {
        Some(1)
    } else if value.starts_with("- ") {
        Some(2)
    } else {
        None
    }
}

fn split_mapping(value: &str) -> Option<(&str, usize)> {
    let bytes = value.as_bytes();
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut square = 0u32;
    let mut curly = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if double && escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if double => escaped = true,
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b'[' if !single && !double => square = square.saturating_add(1),
            b']' if !single && !double => square = square.saturating_sub(1),
            b'{' if !single && !double => curly = curly.saturating_add(1),
            b'}' if !single && !double => curly = curly.saturating_sub(1),
            b':' if !single
                && !double
                && square == 0
                && curly == 0
                && bytes
                    .get(index.saturating_add(1))
                    .is_none_or(u8::is_ascii_whitespace) =>
            {
                return Some((&value[..index], index.saturating_add(1)));
            }
            _ => {}
        }
    }
    None
}

fn balanced_flow(value: &str, open: char, close: char) -> bool {
    let mut depth = 0u32;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for character in value.chars() {
        if double && escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && double {
            escaped = true;
        } else if character == '\'' && !double {
            single = !single;
        } else if character == '"' && !single {
            double = !double;
        } else if !single && !double && character == open {
            depth = depth.saturating_add(1);
        } else if !single && !double && character == close {
            let Some(next) = depth.checked_sub(1) else {
                return false;
            };
            depth = next;
        }
    }
    depth == 0 && !single && !double
}

fn split_flow(value: &str) -> Vec<(usize, &str)> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut start = 0usize;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut square = 0u32;
    let mut curly = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if double && escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if double => escaped = true,
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b'[' if !single && !double => square = square.saturating_add(1),
            b']' if !single && !double => square = square.saturating_sub(1),
            b'{' if !single && !double => curly = curly.saturating_add(1),
            b'}' if !single && !double => curly = curly.saturating_sub(1),
            b',' if !single && !double && square == 0 && curly == 0 => {
                output.push((start, &value[start..index]));
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    output.push((start, &value[start..]));
    output
}

fn decode_plain_or_quoted(value: &str) -> Result<String, String> {
    decode_scalar(value).map(|(decoded, _)| decoded)
}

fn decode_scalar(value: &str) -> Result<(String, ScalarStyle), String> {
    if value.starts_with('\'') {
        if !value.ends_with('\'') || value.len() < 2 {
            return Err("unterminated single-quoted scalar".to_owned());
        }
        let inner = value.get(1..value.len() - 1).unwrap_or_default();
        Ok((inner.replace("''", "'"), ScalarStyle::SingleQuoted))
    } else if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return Err("unterminated double-quoted scalar".to_owned());
        }
        decode_double(value.get(1..value.len() - 1).unwrap_or_default())
            .map(|decoded| (decoded, ScalarStyle::DoubleQuoted))
    } else {
        Ok((value.to_owned(), ScalarStyle::Plain))
    }
}

fn decode_double(value: &str) -> Result<String, String> {
    const YAML_HEXADECIMAL_RADIX: u32 = 16;
    const YAML_BYTE_ESCAPE_DIGITS: usize = 2;
    const YAML_SHORT_UNICODE_ESCAPE_DIGITS: usize = 4;
    const YAML_LONG_UNICODE_ESCAPE_DIGITS: usize = 8;

    let mut output = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            return Err("unterminated escape in a double-quoted scalar".to_owned());
        };
        match escaped {
            '0' => output.push('\0'),
            'a' => output.push('\u{7}'),
            'b' => output.push('\u{8}'),
            't' | '\t' => output.push('\t'),
            'n' => output.push('\n'),
            'v' => output.push('\u{b}'),
            'f' => output.push('\u{c}'),
            'r' => output.push('\r'),
            'e' => output.push('\u{1b}'),
            ' ' => output.push(' '),
            '"' => output.push('"'),
            '/' => output.push('/'),
            '\\' => output.push('\\'),
            'N' => output.push('\u{85}'),
            '_' => output.push('\u{a0}'),
            'L' => output.push('\u{2028}'),
            'P' => output.push('\u{2029}'),
            'x' | 'u' | 'U' => {
                let digits = match escaped {
                    'x' => YAML_BYTE_ESCAPE_DIGITS,
                    'u' => YAML_SHORT_UNICODE_ESCAPE_DIGITS,
                    _ => YAML_LONG_UNICODE_ESCAPE_DIGITS,
                };
                let mut raw = String::new();
                for _ in 0..digits {
                    let Some(digit) = characters.next() else {
                        return Err("incomplete hexadecimal escape".to_owned());
                    };
                    raw.push(digit);
                }
                let scalar = u32::from_str_radix(&raw, YAML_HEXADECIMAL_RADIX)
                    .map_err(|_| "invalid hexadecimal escape".to_owned())?;
                let character = char::from_u32(scalar)
                    .ok_or_else(|| "invalid Unicode scalar escape".to_owned())?;
                output.push(character);
            }
            _ => return Err("invalid escape in a double-quoted scalar".to_owned()),
        }
    }
    Ok(output)
}

fn is_block_header(value: &str) -> bool {
    value.starts_with('|') || value.starts_with('>')
}

fn block_scalar_header(value: &str) -> Option<(usize, &str)> {
    let mut offset = 0usize;
    loop {
        let rest = value.get(offset..)?;
        if is_block_header(rest) {
            return Some((offset, rest));
        }
        if !matches!(rest.as_bytes().first(), Some(b'&' | b'!')) {
            return None;
        }
        let property_length = rest
            .bytes()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if property_length == rest.len() {
            return None;
        }
        let whitespace = rest[property_length..]
            .bytes()
            .take_while(u8::is_ascii_whitespace)
            .count();
        offset = offset
            .saturating_add(property_length)
            .saturating_add(whitespace);
    }
}

fn inline_property_value_offset(value: &str) -> Option<usize> {
    let mut offset = 0usize;
    let mut found = false;
    loop {
        let rest = value.get(offset..)?;
        if !matches!(rest.as_bytes().first(), Some(b'&' | b'!')) {
            return found.then_some(offset);
        }
        let property_length = rest
            .bytes()
            .position(|byte| byte.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if property_length == rest.len() {
            return None;
        }
        let whitespace = rest[property_length..]
            .bytes()
            .take_while(u8::is_ascii_whitespace)
            .count();
        offset = offset
            .saturating_add(property_length)
            .saturating_add(whitespace);
        found = true;
    }
}

fn fold_lines(lines: &[String]) -> String {
    let mut output = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index != 0 {
            let previous_blank = lines.get(index - 1).is_some_and(String::is_empty);
            if previous_blank || line.is_empty() || line.starts_with(' ') {
                output.push('\n');
            } else {
                output.push(' ');
            }
        }
        output.push_str(line);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_positions_match_the_reference_scan_at_every_byte() {
        for source in ["", "alpha", "alpha\n", "alpha\n😀 beta\r\n終\n"] {
            let index = PositionIndex::new(source);
            for byte in 0..=source.len().saturating_add(1) {
                assert_eq!(
                    index.position(source, byte),
                    slow_position_at(source, byte),
                    "source={source:?}, byte={byte}"
                );
            }
        }
    }

    #[test]
    fn physical_lines_comments_and_properties_have_exact_byte_boundaries() {
        let source = "a\r\n  b\nlast";
        let parsed = lines(source);
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            (
                parsed[0].start,
                parsed[0].end,
                parsed[0].indent,
                parsed[0].content
            ),
            (0, "a".len(), 0, "a")
        );
        assert_eq!(
            (
                parsed[1].start,
                parsed[1].end,
                parsed[1].indent,
                parsed[1].content
            ),
            ("a\r\n".len(), "a\r\n  b".len(), "  ".len(), "b",)
        );
        assert_eq!(
            (
                parsed[2].start,
                parsed[2].end,
                parsed[2].indent,
                parsed[2].content
            ),
            ("a\r\n  b\n".len(), source.len(), 0, "last")
        );
        let span = slow_span_for("fixture.yml", source, "a\r\n".len(), source.len());
        assert_eq!(span.file, "fixture.yml");
        assert_eq!(span.start.byte, "a\r\n".len());
        assert_eq!(span.stop.byte, source.len());

        let comment_cases = [
            ("# comment", Some(0)),
            ("value # comment", Some("value ".len())),
            ("value#data", None),
            ("'# data' # comment", Some("'# data' ".len())),
            ("\"# data\" # comment", Some("\"# data\" ".len())),
            (
                "\"escaped \\\"# data\" # comment",
                Some("\"escaped \\\"# data\" ".len()),
            ),
            ("\"it's # data\" # comment", Some("\"it's # data\" ".len())),
            ("'\"# data\"' # comment", Some("'\"# data\"' ".len())),
        ];
        for (value, expected) in comment_cases {
            assert_eq!(comment_offset(value), expected, "comment in {value:?}");
        }

        let properties = "real: &anchor value\nalias: *anchor\nsingle: '&fake'\ndouble: \"*fake\"\ndouble_apostrophe: \"it's &fake\"\nsingle_double: '\"*fake\"'\n";
        let positions = PositionIndex::new(properties);
        let anchors = scan_properties("fixture.yml", properties, &positions, '&');
        let aliases = scan_properties("fixture.yml", properties, &positions, '*');
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].name, "anchor");
        assert_eq!(
            anchors[0].span.start.byte,
            properties.find("&anchor").expect("anchor start")
        );
        assert_eq!(
            anchors[0].span.stop.byte,
            properties.find(" value").expect("anchor stop")
        );
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].name, "anchor");
        assert_eq!(
            aliases[0].span.start.byte,
            properties.find("*anchor").expect("alias start")
        );

        let odd_opposite_quote = "single: '\"'\nreal: &after_single\n";
        let positions = PositionIndex::new(odd_opposite_quote);
        let anchors = scan_properties("fixture.yml", odd_opposite_quote, &positions, '&');
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].name, "after_single");
        assert_eq!(
            anchors[0].span.start.byte,
            odd_opposite_quote.find("&after_single").unwrap()
        );
    }

    #[test]
    // Quote-state and nesting cases form one scanner transition matrix.
    #[allow(clippy::too_many_lines)]
    fn mapping_and_flow_splitters_respect_quotes_escapes_and_nesting() {
        let mapping_cases = [
            ("key: value", Some(("key", "key:".len()))),
            ("key:", Some(("key", "key:".len()))),
            ("url:https://example.test", None),
            (
                "'quoted: key': value",
                Some(("'quoted: key'", "'quoted: key':".len())),
            ),
            (
                "\"quoted: key\": value",
                Some(("\"quoted: key\"", "\"quoted: key\":".len())),
            ),
            (
                "[nested: value]: result",
                Some(("[nested: value]", "[nested: value]:".len())),
            ),
            (
                "{nested: value}: result",
                Some(("{nested: value}", "{nested: value}:".len())),
            ),
            (
                "\"escaped \\\" : data\": value",
                Some(("\"escaped \\\" : data\"", "\"escaped \\\" : data\":".len())),
            ),
            ("'[': value", Some(("'['", "'[':".len()))),
            ("\"{\": value", Some(("\"{\"", "\"{\":".len()))),
            ("[']': value]", None),
            ("{'}': value}", None),
            (
                "\"it's: data\": value",
                Some(("\"it's: data\"", "\"it's: data\":".len())),
            ),
            (
                "'say \"key: value\"': result",
                Some(("'say \"key: value\"'", "'say \"key: value\"':".len())),
            ),
            (
                "'odd \" quote: data': result",
                Some(("'odd \" quote: data'", "'odd \" quote: data':".len())),
            ),
            (
                "prefix\\\"\": value",
                Some(("prefix\\\"\"", "prefix\\\"\":".len())),
            ),
        ];
        for (value, expected) in mapping_cases {
            assert_eq!(split_mapping(value), expected, "mapping {value:?}");
        }

        for (value, expected) in [
            ("[]", true),
            ("[one, [two]]", true),
            ("['[not structural]']", true),
            ("[\"escaped \\\" ]\"]", true),
            ("[one", false),
            ("one]", false),
            ("['unterminated]", false),
            ("[\"unterminated]", false),
        ] {
            assert_eq!(balanced_flow(value, '[', ']'), expected, "flow {value:?}");
        }

        let flow = "one,'two,three',[four,five],{six: seven},\"eight,\\\"nine\"";
        let parts = split_flow(flow);
        let expected = [
            "one",
            "'two,three'",
            "[four,five]",
            "{six: seven}",
            "\"eight,\\\"nine\"",
        ];
        assert_eq!(
            parts.iter().map(|(_, part)| *part).collect::<Vec<_>>(),
            expected
        );
        for (offset, part) in parts {
            assert_eq!(
                flow.get(offset..offset.saturating_add(part.len())),
                Some(part)
            );
        }

        for (value, expected) in [
            ("\"it's,one\",two", vec!["\"it's,one\"", "two"]),
            (
                "'say \"one,two\"',three",
                vec!["'say \"one,two\"'", "three"],
            ),
            (
                "'odd \" quote, still',three",
                vec!["'odd \" quote, still'", "three"],
            ),
            ("prefix\\\"\",next", vec!["prefix\\\"\"", "next"]),
        ] {
            assert_eq!(
                split_flow(value)
                    .into_iter()
                    .map(|(_, part)| part)
                    .collect::<Vec<_>>(),
                expected,
                "flow quote state in {value:?}"
            );
        }
        for (value, expected) in [
            ("one,'[',two", vec!["one", "'['", "two"]),
            ("one,\"{\",two", vec!["one", "\"{\"", "two"]),
            ("[one,']',two],tail", vec!["[one,']',two]", "tail"]),
            ("{one:'}',two},tail", vec!["{one:'}',two}", "tail"]),
            (
                "one,\"it's, data\",tail",
                vec!["one", "\"it's, data\"", "tail"],
            ),
            (
                "one,'\"quoted, data\"',tail",
                vec!["one", "'\"quoted, data\"'", "tail"],
            ),
            (
                "one,\"escaped \\\" comma, data\",tail",
                vec!["one", "\"escaped \\\" comma, data\"", "tail"],
            ),
        ] {
            assert_eq!(
                split_flow(value)
                    .into_iter()
                    .map(|(_, part)| part)
                    .collect::<Vec<_>>(),
                expected,
                "flow split {value:?}"
            );
        }
    }

    #[test]
    fn scalar_decoder_implements_every_yaml_double_quote_escape() {
        assert_eq!(
            decode_scalar("''"),
            Ok((String::new(), ScalarStyle::SingleQuoted))
        );
        assert_eq!(
            decode_scalar("\"\""),
            Ok((String::new(), ScalarStyle::DoubleQuoted))
        );
        let escape_cases = [
            (r"\0", "\0"),
            (r"\a", "\u{7}"),
            (r"\b", "\u{8}"),
            (r"\t", "\t"),
            ("\\\t", "\t"),
            (r"\n", "\n"),
            (r"\v", "\u{b}"),
            (r"\f", "\u{c}"),
            (r"\r", "\r"),
            (r"\e", "\u{1b}"),
            (r"\ ", " "),
            (r#"\""#, "\""),
            (r"\/", "/"),
            (r"\\", "\\"),
            (r"\N", "\u{85}"),
            (r"\_", "\u{a0}"),
            (r"\L", "\u{2028}"),
            (r"\P", "\u{2029}"),
            (r"\x41", "A"),
            (r"\u03A9", "Ω"),
            (r"\U0001F600", "😀"),
        ];
        for (encoded, expected) in escape_cases {
            assert_eq!(
                decode_double(encoded),
                Ok(expected.to_owned()),
                "escape {encoded:?}"
            );
        }
        for invalid in [r"\", r"\q", r"\x4", r"\xGG", r"\uD800", r"\UFFFFFFFF"] {
            assert!(
                decode_double(invalid).is_err(),
                "invalid escape {invalid:?}"
            );
        }

        assert_eq!(
            decode_scalar("plain"),
            Ok(("plain".to_owned(), ScalarStyle::Plain))
        );
        assert_eq!(
            decode_scalar("''"),
            Ok((String::new(), ScalarStyle::SingleQuoted))
        );
        assert_eq!(
            decode_scalar("'it''s'"),
            Ok(("it's".to_owned(), ScalarStyle::SingleQuoted))
        );
        assert_eq!(
            decode_scalar(r#""line\n""#),
            Ok(("line\n".to_owned(), ScalarStyle::DoubleQuoted))
        );
        for invalid in ["'", "'unterminated", "\"", "\"unterminated"] {
            assert!(
                decode_scalar(invalid).is_err(),
                "invalid scalar {invalid:?}"
            );
        }
    }

    #[test]
    fn folded_lines_preserve_blank_and_more_indented_boundaries() {
        let strings = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(fold_lines(&strings(&[])), "");
        assert_eq!(fold_lines(&strings(&["one"])), "one");
        assert_eq!(fold_lines(&strings(&["one", "two"])), "one two");
        assert_eq!(fold_lines(&strings(&["one", "", "two"])), "one\n\ntwo");
        assert_eq!(
            fold_lines(&strings(&["one", "  indented"])),
            "one\n  indented"
        );
    }
}
