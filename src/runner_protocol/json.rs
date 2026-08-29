use std::collections::BTreeMap;

// JSON Unicode escape widths and UTF-16 surrogate bounds are fixed by RFC
// 8259 and the Unicode scalar-value definition.
const JSON_UNICODE_ESCAPE_DIGITS: usize = 4;
const BITS_PER_HEX_DIGIT: u32 = 4;
const HEX_ALPHA_DIGIT_OFFSET: u32 = 10;
const UTF16_HIGH_SURROGATE_START: u32 = 0xd800;
const UTF16_HIGH_SURROGATE_END: u32 = 0xdbff;
const UTF16_LOW_SURROGATE_START: u32 = 0xdc00;
const UTF16_LOW_SURROGATE_END: u32 = 0xdfff;
const UTF16_SUPPLEMENTARY_PLANE_START: u32 = 0x1_0000;
const UTF16_SURROGATE_PAYLOAD_BITS: u32 = 10;
const JSON_CONTROL_BYTE_LIMIT: u8 = 0x20;
const JSON_CONTROL_CHARACTER_LIMIT: char = '\u{20}';

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Value {
    pub(crate) fn object(&self) -> Option<&BTreeMap<String, Self>> {
        if let Self::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn array(&self) -> Option<&[Self]> {
        if let Self::Array(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn bool(&self) -> Option<bool> {
        if let Self::Bool(value) = self {
            Some(*value)
        } else {
            None
        }
    }
    pub(crate) fn integer(&self) -> Option<i64> {
        if let Self::Integer(value) = self {
            Some(*value)
        } else {
            None
        }
    }
}

pub(crate) fn parse(source: &str) -> Result<Value, String> {
    let mut parser = Parser {
        source: source.as_bytes(),
        offset: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    if parser.offset == parser.source.len() {
        Ok(value)
    } else {
        Err(parser.error("trailing JSON input"))
    }
}

struct Parser<'a> {
    source: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        format!("JSON byte {}: {message}", self.offset)
    }

    fn whitespace(&mut self) {
        let whitespace_bytes = self
            .source
            .get(self.offset..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .count();
        self.offset = self.offset.saturating_add(whitespace_bytes);
    }

    fn take(&mut self) -> Result<u8, String> {
        let byte = self
            .source
            .get(self.offset)
            .copied()
            .ok_or_else(|| self.error("unexpected end of input"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn literal(&mut self, suffix: &[u8], value: Value) -> Result<Value, String> {
        for expected in suffix {
            if self.take()? != *expected {
                return Err(self.error("invalid literal"));
            }
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<Value, String> {
        self.whitespace();
        match self.take()? {
            b'n' => self.literal(b"ull", Value::Null),
            b't' => self.literal(b"rue", Value::Bool(true)),
            b'f' => self.literal(b"alse", Value::Bool(false)),
            b'"' => self.string_after_quote().map(Value::String),
            b'[' => self.array(),
            b'{' => self.object(),
            first @ (b'-' | b'0'..=b'9') => self.integer(first),
            _ => Err(self.error("expected a JSON value")),
        }
    }

    fn string_after_quote(&mut self) -> Result<String, String> {
        let mut output = String::new();
        loop {
            match self.take()? {
                b'"' => return Ok(output),
                b'\\' => match self.take()? {
                    b'"' => output.push('"'),
                    b'\\' => output.push('\\'),
                    b'/' => output.push('/'),
                    b'b' => output.push('\u{0008}'),
                    b'f' => output.push('\u{000c}'),
                    b'n' => output.push('\n'),
                    b'r' => output.push('\r'),
                    b't' => output.push('\t'),
                    b'u' => {
                        let value = self.unicode_scalar()?;
                        output.push(
                            char::from_u32(value).ok_or_else(|| self.error("invalid codepoint"))?,
                        );
                    }
                    _ => return Err(self.error("invalid string escape")),
                },
                byte if byte < JSON_CONTROL_BYTE_LIMIT => {
                    return Err(self.error("control byte in string"));
                }
                _ => {
                    let start = self.offset.saturating_sub(1);
                    let remaining = std::str::from_utf8(&self.source[start..])
                        .map_err(|_| self.error("invalid UTF-8"))?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or_else(|| self.error("truncated UTF-8"))?;
                    output.push(character);
                    self.offset = start.saturating_add(character.len_utf8());
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..JSON_UNICODE_ESCAPE_DIGITS {
            let digit = match self.take()? {
                byte @ b'0'..=b'9' => u32::from(byte - b'0'),
                byte @ b'a'..=b'f' => u32::from(byte - b'a') + HEX_ALPHA_DIGIT_OFFSET,
                byte @ b'A'..=b'F' => u32::from(byte - b'A') + HEX_ALPHA_DIGIT_OFFSET,
                _ => return Err(self.error("invalid Unicode escape")),
            };
            // The shifted accumulator and one-hex-digit payload occupy
            // disjoint bits, so addition is the clearest composition.
            value = (value << BITS_PER_HEX_DIGIT) + digit;
        }
        Ok(value)
    }

    fn unicode_scalar(&mut self) -> Result<u32, String> {
        let first = self.unicode_escape()?;
        if (UTF16_HIGH_SURROGATE_START..=UTF16_HIGH_SURROGATE_END).contains(&first) {
            if self.take()? != b'\\' || self.take()? != b'u' {
                return Err(self.error("high surrogate must be followed by a low surrogate"));
            }
            let second = self.unicode_escape()?;
            if !(UTF16_LOW_SURROGATE_START..=UTF16_LOW_SURROGATE_END).contains(&second) {
                return Err(self.error("high surrogate must be followed by a low surrogate"));
            }
            Ok(UTF16_SUPPLEMENTARY_PLANE_START
                + ((first - UTF16_HIGH_SURROGATE_START) << UTF16_SURROGATE_PAYLOAD_BITS)
                + (second - UTF16_LOW_SURROGATE_START))
        } else if (UTF16_LOW_SURROGATE_START..=UTF16_LOW_SURROGATE_END).contains(&first) {
            Err(self.error("lone low surrogate is invalid"))
        } else {
            Ok(first)
        }
    }

    fn integer(&mut self, first: u8) -> Result<Value, String> {
        let start = self.offset.saturating_sub(1);
        if first == b'-' && !self.source.get(self.offset).is_some_and(u8::is_ascii_digit) {
            return Err(self.error("invalid integer"));
        }
        let first_digit = if first == b'-' {
            self.source.get(self.offset).copied()
        } else {
            Some(first)
        };
        let following_digit = if first == b'-' {
            self.source.get(self.offset.saturating_add(1))
        } else {
            self.source.get(self.offset)
        };
        if first_digit == Some(b'0') && following_digit.is_some_and(u8::is_ascii_digit) {
            return Err(self.error("integer has a leading zero"));
        }
        let digits = self.source[self.offset..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        self.offset = self.offset.saturating_add(digits);
        if self
            .source
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b'.' | b'e' | b'E'))
        {
            return Err(self.error("runner JSON permits integers only"));
        }
        let raw = std::str::from_utf8(&self.source[start..self.offset])
            .map_err(|_| self.error("invalid integer"))?;
        raw.parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| self.error("integer out of range"))
    }

    fn array(&mut self) -> Result<Value, String> {
        let mut values = Vec::new();
        self.whitespace();
        if self.source.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            match self.take()? {
                b']' => return Ok(Value::Array(values)),
                b',' => {}
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        let mut fields = BTreeMap::new();
        self.whitespace();
        if self.source.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.whitespace();
            if self.take()? != b'"' {
                return Err(self.error("object key must be a string"));
            }
            let key = self.string_after_quote()?;
            if fields.contains_key(&key) {
                return Err(self.error("duplicate object key"));
            }
            self.whitespace();
            if self.take()? != b':' {
                return Err(self.error("expected ':'"));
            }
            fields.insert(key, self.value()?);
            self.whitespace();
            match self.take()? {
                b'}' => return Ok(Value::Object(fields)),
                b',' => {}
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }
}

pub(crate) fn canonical(value: &Value) -> String {
    let mut output = String::new();
    write_value(&mut output, value);
    output
}

fn write_value(output: &mut String, value: &Value) {
    use std::fmt::Write as _;
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Integer(value) => write!(output, "{value}").expect("String write"),
        Value::String(value) => {
            output.push('"');
            for character in value.chars() {
                match character {
                    '"' => output.push_str("\\\""),
                    '\\' => output.push_str("\\\\"),
                    '\u{0008}' => output.push_str("\\b"),
                    '\u{000c}' => output.push_str("\\f"),
                    '\n' => output.push_str("\\n"),
                    '\r' => output.push_str("\\r"),
                    '\t' => output.push_str("\\t"),
                    value if value < JSON_CONTROL_CHARACTER_LIMIT => {
                        write!(output, "\\u{:04x}", u32::from(value)).expect("String write");
                    }
                    value => output.push(value),
                }
            }
            output.push('"');
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(output, value);
            }
            output.push(']');
        }
        Value::Object(fields) => {
            output.push('{');
            for (index, (key, value)) in fields.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(output, &Value::String(key.clone()));
                output.push(':');
                write_value(output, value);
            }
            output.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Value, canonical, parse};

    #[test]
    fn every_json_escape_unicode_width_and_surrogate_pair_is_exact() {
        assert_eq!(
            parse(r#""\\\"\/\b\f\n\r\t""#),
            Ok(Value::String("\\\"/\u{8}\u{c}\n\r\t".to_owned()))
        );
        assert_eq!(
            parse(r#""\u0041\u00e9\u20AC\ud83d\ude00""#),
            Ok(Value::String("Aé€😀".to_owned()))
        );
        assert_eq!(parse("\"é€😀\""), Ok(Value::String("é€😀".to_owned())));
        for invalid in [r#""\q""#, r#""\u12xz""#, r#""\ud800""#, "\"\u{1f}\""] {
            assert!(parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn integer_grammar_and_error_offsets_are_strict() {
        assert_eq!(parse("-1"), Ok(Value::Integer(-1)));
        for invalid in ["-", "01", "-01", "1.0", "1e2", "9223372036854775808"] {
            let error = parse(invalid).expect_err("invalid integer");
            assert!(error.starts_with("JSON byte "), "{error:?}");
            assert!(error.len() > "JSON byte ".len());
        }
    }

    #[test]
    fn canonical_strings_escape_every_json_control_boundary() {
        assert_eq!(
            canonical(&Value::String("\"\\\u{8}\u{c}\n\r\t\u{1f} ".to_owned())),
            r#""\"\\\b\f\n\r\t\u001f ""#
        );
    }
}
