use crate::json::JsonValue;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Position {
    pub byte: usize,
    pub line: u32,
    pub column: u32,
}

impl Default for Position {
    fn default() -> Self {
        Self {
            byte: 0,
            line: 1,
            column: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Utf16Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Span {
    pub file: String,
    pub start: Position,
    pub stop: Position,
}

impl Default for Span {
    fn default() -> Self {
        let origin = Position::default();
        Self {
            file: "<unknown>".to_owned(),
            start: origin,
            stop: origin,
        }
    }
}

impl Span {
    #[must_use]
    pub fn new(file: impl Into<String>, start: Position, stop: Position) -> Self {
        Self {
            file: file.into(),
            start,
            stop,
        }
    }

    #[must_use]
    pub fn contains(&self, byte: usize) -> bool {
        self.start.byte <= byte && byte <= self.stop.byte
    }

    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        if self.file != other.file {
            return self.clone();
        }
        Self {
            file: self.file.clone(),
            start: self.start.min(other.start),
            stop: self.stop.max(other.stop),
        }
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        fn position(value: Position) -> JsonValue {
            JsonValue::Object(BTreeMap::from([
                (
                    "byte".to_owned(),
                    JsonValue::Integer(i64::try_from(value.byte).unwrap_or(i64::MAX)),
                ),
                (
                    "column".to_owned(),
                    JsonValue::Integer(i64::from(value.column)),
                ),
                ("line".to_owned(), JsonValue::Integer(i64::from(value.line))),
            ]))
        }
        JsonValue::Object(BTreeMap::from([
            (
                "file".to_owned(),
                JsonValue::String(self.file.replace('\\', "/")),
            ),
            ("start".to_owned(), position(self.start)),
            ("stop".to_owned(), position(self.stop)),
        ]))
    }
}

impl fmt::Display for Span {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.file, self.start.line, self.start.column
        )
    }
}

/// Translate an LSP UTF-16 position into a UTF-8 byte offset. Positions inside
/// a surrogate pair and positions beyond a line are rejected.
///
/// # Errors
/// Returns an error for an absent line, a position beyond the line, or a
/// position that splits an astral character's surrogate pair.
pub fn utf16_to_byte(source: &str, position: Utf16Position) -> Result<usize, String> {
    let target_line = usize::try_from(position.line).map_err(|_| "line is out of range")?;
    let mut line_start = 0usize;
    let mut line = 0usize;
    for (offset, byte) in source.bytes().enumerate() {
        if line == target_line {
            break;
        }
        if byte == b'\n' {
            line += 1;
            line_start = offset + 1;
        }
    }
    if line != target_line {
        return Err("line is out of range".to_owned());
    }
    let line_end = source[line_start..]
        .find('\n')
        .map_or(source.len(), |relative| line_start + relative);
    let wanted = position.character;
    let mut utf16 = 0u32;
    for (relative, character) in source[line_start..line_end].char_indices() {
        if utf16 == wanted {
            return Ok(line_start + relative);
        }
        let width = u32::try_from(character.len_utf16()).unwrap_or(2);
        if utf16.saturating_add(width) > wanted {
            return Err("UTF-16 position splits a surrogate pair".to_owned());
        }
        utf16 = utf16.saturating_add(width);
    }
    if utf16 == wanted {
        Ok(line_end)
    } else {
        Err("character is out of range".to_owned())
    }
}

/// Translate a UTF-8 byte boundary into an LSP UTF-16 position.
///
/// # Errors
/// Returns an error when `byte` is out of range, splits UTF-8, or the public
/// position cannot fit in the protocol's 32-bit coordinates.
pub fn byte_to_utf16(source: &str, byte: usize) -> Result<Utf16Position, String> {
    if byte > source.len() || !source.is_char_boundary(byte) {
        return Err("byte is not a UTF-8 boundary".to_owned());
    }
    let prefix = &source[..byte];
    let line = u32::try_from(
        prefix
            .bytes()
            .filter(|candidate| *candidate == b'\n')
            .count(),
    )
    .map_err(|_| "line is out of range")?;
    let line_start = prefix.rfind('\n').map_or(0, |offset| offset + 1);
    let character = prefix[line_start..]
        .chars()
        .try_fold(0u32, |total, value| {
            let width = u32::try_from(value.len_utf16()).map_err(|_| ())?;
            total.checked_add(width).ok_or(())
        })
        .map_err(|()| "UTF-16 column is out of range")?;
    Ok(Utf16Position { line, character })
}

#[cfg(test)]
mod tests {
    use super::{Utf16Position, byte_to_utf16, utf16_to_byte};

    #[test]
    fn utf16_round_trip_handles_astral_characters() {
        let source = "a😀b\n次";
        assert_eq!(
            utf16_to_byte(
                source,
                Utf16Position {
                    line: 0,
                    character: 3
                }
            ),
            Ok(5)
        );
        assert_eq!(
            byte_to_utf16(source, 5),
            Ok(Utf16Position {
                line: 0,
                character: 3
            })
        );
        assert!(
            utf16_to_byte(
                source,
                Utf16Position {
                    line: 0,
                    character: 2
                }
            )
            .is_err()
        );
    }
}
