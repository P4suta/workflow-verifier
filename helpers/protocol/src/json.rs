use std::collections::BTreeMap;

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
        while self
            .source
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.offset += 1;
        }
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
                        let mut value = 0u32;
                        for _ in 0..4 {
                            value = (value << 4)
                                | match self.take()? {
                                    byte @ b'0'..=b'9' => u32::from(byte - b'0'),
                                    byte @ b'a'..=b'f' => u32::from(byte - b'a' + 10),
                                    byte @ b'A'..=b'F' => u32::from(byte - b'A' + 10),
                                    _ => return Err(self.error("invalid Unicode escape")),
                                };
                        }
                        output.push(
                            char::from_u32(value).ok_or_else(|| self.error("invalid codepoint"))?,
                        );
                    }
                    _ => return Err(self.error("invalid string escape")),
                },
                byte if byte < 0x20 => return Err(self.error("control byte in string")),
                byte if byte.is_ascii() => output.push(char::from(byte)),
                first => {
                    let width = if first & 0xe0 == 0xc0 {
                        2
                    } else if first & 0xf0 == 0xe0 {
                        3
                    } else if first & 0xf8 == 0xf0 {
                        4
                    } else {
                        return Err(self.error("invalid UTF-8"));
                    };
                    let start = self.offset - 1;
                    let stop = start + width;
                    let bytes = self
                        .source
                        .get(start..stop)
                        .ok_or_else(|| self.error("truncated UTF-8"))?;
                    output.push_str(
                        std::str::from_utf8(bytes).map_err(|_| self.error("invalid UTF-8"))?,
                    );
                    self.offset = stop;
                }
            }
        }
    }

    fn integer(&mut self, first: u8) -> Result<Value, String> {
        let start = self.offset - 1;
        if first == b'-' && !self.source.get(self.offset).is_some_and(u8::is_ascii_digit) {
            return Err(self.error("invalid integer"));
        }
        while self.source.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
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
                    value if value < '\u{0020}' => {
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
