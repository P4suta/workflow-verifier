use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    Null,
    Boolean(bool),
    Integer(i64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonLimits {
    pub max_bytes: usize,
    pub max_depth: u32,
    pub max_values: usize,
}

impl Default for JsonLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            max_depth: 128,
            max_values: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "JSON byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for JsonError {}

impl JsonValue {
    /// Parse language-independent product JSON.
    ///
    /// # Errors
    /// Rejects malformed syntax, duplicate keys, non-integer numbers, and
    /// values outside the default deterministic resource envelope.
    pub fn parse(source: &str) -> Result<Self, JsonError> {
        Self::parse_with_limits(source, JsonLimits::default())
    }

    /// Parse product JSON from an explicitly validated UTF-8 byte boundary.
    ///
    /// # Errors
    /// Returns the first UTF-8 or strict JSON contract violation.
    pub fn parse_bytes(source: &[u8]) -> Result<Self, JsonError> {
        let text = std::str::from_utf8(source).map_err(|error| JsonError {
            offset: error.valid_up_to(),
            message: "JSON input is not valid UTF-8".to_owned(),
        })?;
        Self::parse(text)
    }

    /// Parse product JSON under a caller-supplied non-widening envelope.
    ///
    /// # Errors
    /// Returns the first syntax, type, duplicate-key, integer, or resource
    /// violation with its byte offset.
    pub fn parse_with_limits(source: &str, limits: JsonLimits) -> Result<Self, JsonError> {
        if source.len() > limits.max_bytes {
            return Err(JsonError {
                offset: 0,
                message: "Incomplete.Resource_limit: JSON byte budget exceeded".to_owned(),
            });
        }
        let mut parser = Parser {
            source: source.as_bytes(),
            offset: 0,
            limits,
            values: 0,
        };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.offset != source.len() {
            return Err(parser.error("trailing JSON input"));
        }
        Ok(value)
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        let mut output = String::new();
        self.write_canonical(&mut output);
        output
    }

    #[must_use]
    pub fn canonical_line(&self) -> String {
        let mut output = self.canonical();
        output.push('\n');
        output
    }

    fn write_canonical(&self, output: &mut String) {
        match self {
            Self::Null => output.push_str("null"),
            Self::Boolean(true) => output.push_str("true"),
            Self::Boolean(false) => output.push_str("false"),
            Self::Integer(value) => output.push_str(&value.to_string()),
            Self::String(value) => write_string(output, value),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write_canonical(output);
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_string(output, name);
                    output.push(':');
                    value.write_canonical(output);
                }
                output.push('}');
            }
        }
    }

    /// Check that a value is an object containing no unknown field.
    ///
    /// # Errors
    /// Returns a contextual error for a non-object or the first unknown field.
    pub fn exact_object<'a>(
        &'a self,
        context: &str,
        allowed: &[&str],
    ) -> Result<&'a BTreeMap<String, Self>, String> {
        let Self::Object(fields) = self else {
            return Err(format!("{context} must be an object"));
        };
        let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
        if let Some(name) = fields.keys().find(|name| !allowed.contains(name.as_str())) {
            return Err(format!("{context} has unknown field {name}"));
        }
        Ok(fields)
    }

    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(name),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }
}

fn write_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    source: &'a [u8],
    offset: usize,
    limits: JsonLimits,
    values: usize,
}

impl Parser<'_> {
    fn error(&self, message: impl Into<String>) -> JsonError {
        JsonError {
            offset: self.offset,
            message: message.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.offset).copied()
    }

    fn take(&mut self) -> Result<u8, JsonError> {
        let Some(value) = self.peek() else {
            return Err(self.error("unexpected end of JSON"));
        };
        self.offset += 1;
        Ok(value)
    }

    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.offset += 1;
        }
    }

    fn value(&mut self, depth: u32) -> Result<JsonValue, JsonError> {
        if depth > self.limits.max_depth {
            return Err(self.error("Incomplete.Resource_limit: JSON nesting budget exceeded"));
        }
        self.values = self.values.saturating_add(1);
        if self.values > self.limits.max_values {
            return Err(self.error("Incomplete.Resource_limit: JSON value budget exceeded"));
        }
        self.whitespace();
        match self.peek() {
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(b't') => self.literal(b"true", JsonValue::Boolean(true)),
            Some(b'f') => self.literal(b"false", JsonValue::Boolean(false)),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'[') => self.array(depth + 1),
            Some(b'{') => self.object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) | None => Err(self.error("expected a JSON value")),
        }
    }

    fn literal(&mut self, literal: &[u8], value: JsonValue) -> Result<JsonValue, JsonError> {
        for expected in literal {
            if self.take()? != *expected {
                return Err(self.error(format!("expected {}", String::from_utf8_lossy(literal))));
            }
        }
        Ok(value)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        if self.take()? != b'"' {
            return Err(self.error("expected string"));
        }
        let mut output = Vec::new();
        loop {
            match self.take()? {
                b'"' => {
                    return String::from_utf8(output)
                        .map_err(|_| self.error("decoded JSON string is not valid UTF-8"));
                }
                b'\\' => match self.take()? {
                    b'"' => output.push(b'"'),
                    b'\\' => output.push(b'\\'),
                    b'/' => output.push(b'/'),
                    b'b' => output.push(0x08),
                    b'f' => output.push(0x0c),
                    b'n' => output.push(b'\n'),
                    b'r' => output.push(b'\r'),
                    b't' => output.push(b'\t'),
                    b'u' => {
                        let first = self.unicode_escape()?;
                        let scalar = if (0xd800..=0xdbff).contains(&first) {
                            if self.take()? != b'\\' || self.take()? != b'u' {
                                return Err(self
                                    .error("high surrogate must be followed by a low surrogate"));
                            }
                            let second = self.unicode_escape()?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err(self
                                    .error("high surrogate must be followed by a low surrogate"));
                            }
                            0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                        } else if (0xdc00..=0xdfff).contains(&first) {
                            return Err(self.error("lone low surrogate is invalid"));
                        } else {
                            first
                        };
                        let Some(character) = char::from_u32(scalar) else {
                            return Err(self.error("invalid Unicode scalar"));
                        };
                        let mut encoded = [0u8; 4];
                        output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                    }
                    _ => return Err(self.error("invalid string escape")),
                },
                control if control < 0x20 => {
                    return Err(self.error("unescaped control character"));
                }
                byte => output.push(byte),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = match self.take()? {
                byte @ b'0'..=b'9' => u32::from(byte - b'0'),
                byte @ b'a'..=b'f' => u32::from(byte - b'a' + 10),
                byte @ b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return Err(self.error("invalid Unicode escape")),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(self.error("leading zero in JSON number"));
                }
            }
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        if self
            .peek()
            .is_some_and(|byte| matches!(byte, b'.' | b'e' | b'E'))
        {
            return Err(self.error("canonical product JSON permits integers only"));
        }
        let raw = std::str::from_utf8(&self.source[start..self.offset])
            .map_err(|_| self.error("invalid integer"))?;
        let number = raw
            .parse::<i64>()
            .map_err(|_| self.error("integer is out of range"))?;
        Ok(JsonValue::Integer(number))
    }

    fn array(&mut self, depth: u32) -> Result<JsonValue, JsonError> {
        let _ = self.take()?;
        self.whitespace();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(JsonValue::Array(Vec::new()));
        }
        let mut values = Vec::new();
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            match self.take()? {
                b']' => return Ok(JsonValue::Array(values)),
                b',' => {}
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: u32) -> Result<JsonValue, JsonError> {
        let _ = self.take()?;
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(JsonValue::Object(BTreeMap::new()));
        }
        let mut fields = BTreeMap::new();
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("JSON object key must be a string"));
            }
            let name = self.string()?;
            if fields.contains_key(&name) {
                return Err(self.error(format!("duplicate JSON object key: {name}")));
            }
            self.whitespace();
            if self.take()? != b':' {
                return Err(self.error("expected ':'"));
            }
            let value = self.value(depth)?;
            fields.insert(name, value);
            self.whitespace();
            match self.take()? {
                b'}' => return Ok(JsonValue::Object(fields)),
                b',' => {}
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

#[cfg(test)]
mod tests {
    use super::JsonValue;

    #[test]
    fn canonical_contract() {
        let value =
            JsonValue::parse(" { \"z\" : [true, null], \"a\":\"é\\n\" } ").expect("valid fixture");
        assert_eq!(value.canonical(), "{\"a\":\"é\\n\",\"z\":[true,null]}");
    }

    #[test]
    fn strict_input_contract() {
        for invalid in [
            "{\"a\":1,\"a\":2}",
            "01",
            "1.0",
            "9223372036854775808",
            "\"\\ud800\"",
            "[1,]",
        ] {
            assert!(JsonValue::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn surrogate_pair_decodes() {
        assert_eq!(
            JsonValue::parse("\"\\ud83d\\ude00\"").expect("valid fixture"),
            JsonValue::String("😀".to_owned())
        );
    }
}
