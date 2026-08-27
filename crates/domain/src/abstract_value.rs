use crate::UnknownReason;
use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_foundation::{JsonValue, Span};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueType {
    Never,
    Null,
    Bool,
    Number,
    String,
    List,
    Object,
    Dynamic,
}

impl ValueType {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Number => "number",
            Self::String => "string",
            Self::List => "list",
            Self::Object => "object",
            Self::Dynamic => "dynamic",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AbstractTruth {
    False,
    True,
    Maybe,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StringValue {
    Bottom,
    Constants(Vec<String>),
    Affix {
        prefix: Option<String>,
        suffix: Option<String>,
    },
    Pattern(String),
    Top,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Bottom,
    Null,
    Boolean(AbstractTruth),
    Number {
        minimum: Option<i64>,
        maximum: Option<i64>,
    },
    String(StringValue),
    List(Option<Vec<AbstractValue>>),
    Object(Option<BTreeMap<String, AbstractValue>>),
    Unknown(Vec<UnknownReason>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Trust {
    Trusted,
    Mixed,
    Untrusted,
    Unknown(Vec<UnknownReason>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Secrecy {
    Public,
    Sensitive,
    Secret,
    Unknown(Vec<UnknownReason>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Provenance {
    pub origin: String,
    pub span: Span,
    pub operation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbstractValue {
    pub value_type: ValueType,
    pub value: Value,
    pub trust: Trust,
    pub secrecy: Secrecy,
    pub provenance: Vec<Provenance>,
}

impl Default for AbstractValue {
    fn default() -> Self {
        Self {
            value_type: ValueType::Never,
            value: Value::Bottom,
            trust: Trust::Trusted,
            secrecy: Secrecy::Public,
            provenance: Vec::new(),
        }
    }
}

fn deduplicate_reasons(values: impl IntoIterator<Item = UnknownReason>) -> Vec<UnknownReason> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl AbstractValue {
    #[must_use]
    pub fn string_constant(
        value: impl Into<String>,
        trust: Trust,
        secrecy: Secrecy,
        provenance: Vec<Provenance>,
    ) -> Self {
        Self {
            value_type: ValueType::String,
            value: Value::String(StringValue::Constants(vec![value.into()])),
            trust,
            secrecy,
            provenance,
        }
    }

    #[must_use]
    pub fn unknown(reason: UnknownReason) -> Self {
        Self {
            value_type: ValueType::Dynamic,
            value: Value::Unknown(vec![reason.clone()]),
            trust: Trust::Unknown(vec![reason.clone()]),
            secrecy: Secrecy::Unknown(vec![reason]),
            provenance: Vec::new(),
        }
    }

    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self.value == Value::Bottom {
            return other.clone();
        }
        if other.value == Value::Bottom {
            return self.clone();
        }
        let value_type = if self.value_type == ValueType::Never {
            other.value_type
        } else if other.value_type == ValueType::Never || self.value_type == other.value_type {
            self.value_type
        } else {
            ValueType::Dynamic
        };
        let mut provenance: BTreeSet<Provenance> = self.provenance.iter().cloned().collect();
        provenance.extend(other.provenance.iter().cloned());
        Self {
            value_type,
            value: join_value(&self.value, &other.value),
            trust: join_trust(&self.trust, &other.trust),
            secrecy: join_secrecy(&self.secrecy, &other.secrecy),
            provenance: provenance.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn constants(&self) -> Option<&[String]> {
        match &self.value {
            Value::String(StringValue::Constants(values)) => Some(values),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        self.trust == Trust::Untrusted
    }

    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.secrecy == Secrecy::Secret
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "provenance".to_owned(),
                JsonValue::Array(
                    self.provenance
                        .iter()
                        .map(|item| {
                            JsonValue::Object(BTreeMap::from([
                                (
                                    "operation".to_owned(),
                                    JsonValue::String(item.operation.clone()),
                                ),
                                ("origin".to_owned(), JsonValue::String(item.origin.clone())),
                                ("span".to_owned(), item.span.to_json()),
                            ]))
                        })
                        .collect(),
                ),
            ),
            ("secrecy".to_owned(), secrecy_json(&self.secrecy)),
            ("trust".to_owned(), trust_json(&self.trust)),
            (
                "type".to_owned(),
                JsonValue::String(self.value_type.name().to_owned()),
            ),
            ("value".to_owned(), value_json(&self.value)),
        ]))
    }
}

fn common_prefix(left: &str, right: &str) -> Option<String> {
    let bytes = left
        .bytes()
        .zip(right.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    if bytes == 0 {
        None
    } else {
        let boundary = (0..=bytes)
            .rev()
            .find(|offset| left.is_char_boundary(*offset))?;
        Some(left[..boundary].to_owned())
    }
}

fn common_suffix(left: &str, right: &str) -> Option<String> {
    let mut left_chars = left.chars().rev();
    let mut right_chars = right.chars().rev();
    let mut suffix = Vec::new();
    loop {
        match (left_chars.next(), right_chars.next()) {
            (Some(a), Some(b)) if a == b => suffix.push(a),
            _ => break,
        }
    }
    if suffix.is_empty() {
        None
    } else {
        suffix.reverse();
        Some(suffix.into_iter().collect())
    }
}

fn join_strings(left: &StringValue, right: &StringValue) -> StringValue {
    match (left, right) {
        (StringValue::Bottom, value) | (value, StringValue::Bottom) => value.clone(),
        (StringValue::Constants(left), StringValue::Constants(right)) => {
            let values: Vec<_> = left
                .iter()
                .chain(right)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if values.len() <= 8 {
                StringValue::Constants(values)
            } else {
                StringValue::Top
            }
        }
        (StringValue::Constants(values), StringValue::Affix { prefix, suffix })
        | (StringValue::Affix { prefix, suffix }, StringValue::Constants(values))
            if values.len() == 1 =>
        {
            let value = values.first().map(String::as_str).unwrap_or_default();
            let prefix = prefix
                .as_deref()
                .and_then(|part| common_prefix(value, part));
            let suffix = suffix
                .as_deref()
                .and_then(|part| common_suffix(value, part));
            if prefix.is_none() && suffix.is_none() {
                StringValue::Top
            } else {
                StringValue::Affix { prefix, suffix }
            }
        }
        (
            StringValue::Affix {
                prefix: left_prefix,
                suffix: left_suffix,
            },
            StringValue::Affix {
                prefix: right_prefix,
                suffix: right_suffix,
            },
        ) => {
            let prefix = left_prefix
                .as_deref()
                .zip(right_prefix.as_deref())
                .and_then(|(left, right)| common_prefix(left, right));
            let suffix = left_suffix
                .as_deref()
                .zip(right_suffix.as_deref())
                .and_then(|(left, right)| common_suffix(left, right));
            if prefix.is_none() && suffix.is_none() {
                StringValue::Top
            } else {
                StringValue::Affix { prefix, suffix }
            }
        }
        (StringValue::Pattern(left), StringValue::Pattern(right)) if left == right => {
            StringValue::Pattern(left.clone())
        }
        _ => StringValue::Top,
    }
}

fn join_value(left: &Value, right: &Value) -> Value {
    match (left, right) {
        (Value::Null, Value::Null) => Value::Null,
        (Value::Boolean(left), Value::Boolean(right)) => Value::Boolean(if left == right {
            *left
        } else {
            AbstractTruth::Maybe
        }),
        (
            Value::Number {
                minimum: left_minimum,
                maximum: left_maximum,
            },
            Value::Number {
                minimum: right_minimum,
                maximum: right_maximum,
            },
        ) => Value::Number {
            minimum: left_minimum.zip(*right_minimum).map(|(a, b)| a.min(b)),
            maximum: left_maximum.zip(*right_maximum).map(|(a, b)| a.max(b)),
        },
        (Value::String(left), Value::String(right)) => Value::String(join_strings(left, right)),
        (Value::List(Some(left)), Value::List(Some(right))) if left.len() == right.len() => {
            Value::List(Some(
                left.iter().zip(right).map(|(a, b)| a.join(b)).collect(),
            ))
        }
        (Value::List(_), Value::List(_)) => Value::List(None),
        (Value::Object(Some(left)), Value::Object(Some(right))) => {
            let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
            let bottom = AbstractValue::default();
            Value::Object(Some(
                keys.into_iter()
                    .map(|key| {
                        let left = left.get(key).unwrap_or(&bottom);
                        let right = right.get(key).unwrap_or(&bottom);
                        (key.clone(), left.join(right))
                    })
                    .collect(),
            ))
        }
        (Value::Object(_), Value::Object(_)) => Value::Object(None),
        (Value::Unknown(left), Value::Unknown(right)) => {
            Value::Unknown(deduplicate_reasons(left.iter().chain(right).cloned()))
        }
        (Value::Unknown(values), _) | (_, Value::Unknown(values)) => {
            Value::Unknown(deduplicate_reasons(values.iter().cloned().chain([
                UnknownReason::UnsupportedSyntax("incompatible value join".to_owned()),
            ])))
        }
        _ => Value::Unknown(vec![UnknownReason::UnsupportedSyntax(
            "incompatible value join".to_owned(),
        )]),
    }
}

fn join_trust(left: &Trust, right: &Trust) -> Trust {
    match (left, right) {
        (Trust::Untrusted, _) | (_, Trust::Untrusted) => Trust::Untrusted,
        (Trust::Unknown(left), Trust::Unknown(right)) => {
            Trust::Unknown(deduplicate_reasons(left.iter().chain(right).cloned()))
        }
        (Trust::Unknown(values), _) | (_, Trust::Unknown(values)) => Trust::Unknown(values.clone()),
        (Trust::Mixed, _) | (_, Trust::Mixed) => Trust::Mixed,
        (Trust::Trusted, Trust::Trusted) => Trust::Trusted,
    }
}

fn join_secrecy(left: &Secrecy, right: &Secrecy) -> Secrecy {
    match (left, right) {
        (Secrecy::Secret, _) | (_, Secrecy::Secret) => Secrecy::Secret,
        (Secrecy::Unknown(left), Secrecy::Unknown(right)) => {
            Secrecy::Unknown(deduplicate_reasons(left.iter().chain(right).cloned()))
        }
        (Secrecy::Unknown(values), _) | (_, Secrecy::Unknown(values)) => {
            Secrecy::Unknown(values.clone())
        }
        (Secrecy::Sensitive, _) | (_, Secrecy::Sensitive) => Secrecy::Sensitive,
        (Secrecy::Public, Secrecy::Public) => Secrecy::Public,
    }
}

fn reasons_json(values: &[UnknownReason]) -> JsonValue {
    JsonValue::Array(values.iter().map(UnknownReason::to_json).collect())
}

fn trust_json(value: &Trust) -> JsonValue {
    match value {
        Trust::Trusted => JsonValue::String("trusted".to_owned()),
        Trust::Mixed => JsonValue::String("mixed".to_owned()),
        Trust::Untrusted => JsonValue::String("untrusted".to_owned()),
        Trust::Unknown(values) => JsonValue::Object(BTreeMap::from([
            ("reasons".to_owned(), reasons_json(values)),
            ("state".to_owned(), JsonValue::String("unknown".to_owned())),
        ])),
    }
}

fn secrecy_json(value: &Secrecy) -> JsonValue {
    match value {
        Secrecy::Public => JsonValue::String("public".to_owned()),
        Secrecy::Sensitive => JsonValue::String("sensitive".to_owned()),
        Secrecy::Secret => JsonValue::String("secret".to_owned()),
        Secrecy::Unknown(values) => JsonValue::Object(BTreeMap::from([
            ("reasons".to_owned(), reasons_json(values)),
            ("state".to_owned(), JsonValue::String("unknown".to_owned())),
        ])),
    }
}

fn value_json(value: &Value) -> JsonValue {
    match value {
        Value::Bottom | Value::String(StringValue::Bottom) => {
            JsonValue::String("bottom".to_owned())
        }
        Value::Null => JsonValue::Null,
        Value::Boolean(AbstractTruth::False) => JsonValue::Boolean(false),
        Value::Boolean(AbstractTruth::True) => JsonValue::Boolean(true),
        Value::Boolean(AbstractTruth::Maybe) => JsonValue::String("maybe".to_owned()),
        Value::Number { minimum, maximum } => JsonValue::Object(BTreeMap::from([
            (
                "maximum".to_owned(),
                maximum.map_or(JsonValue::Null, JsonValue::Integer),
            ),
            (
                "minimum".to_owned(),
                minimum.map_or(JsonValue::Null, JsonValue::Integer),
            ),
        ])),
        Value::String(StringValue::Constants(values)) => JsonValue::Object(BTreeMap::from([(
            "constants".to_owned(),
            JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect()),
        )])),
        Value::String(StringValue::Affix { prefix, suffix }) => {
            JsonValue::Object(BTreeMap::from([
                (
                    "prefix".to_owned(),
                    prefix.clone().map_or(JsonValue::Null, JsonValue::String),
                ),
                (
                    "suffix".to_owned(),
                    suffix.clone().map_or(JsonValue::Null, JsonValue::String),
                ),
            ]))
        }
        Value::String(StringValue::Pattern(value)) => JsonValue::Object(BTreeMap::from([(
            "pattern".to_owned(),
            JsonValue::String(value.clone()),
        )])),
        Value::String(StringValue::Top) => JsonValue::String("top".to_owned()),
        Value::List(None) => JsonValue::String("list-top".to_owned()),
        Value::List(Some(values)) => {
            JsonValue::Array(values.iter().map(AbstractValue::to_json).collect())
        }
        Value::Object(None) => JsonValue::String("object-top".to_owned()),
        Value::Object(Some(values)) => JsonValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.to_json()))
                .collect(),
        ),
        Value::Unknown(values) => JsonValue::Object(BTreeMap::from([(
            "unknown".to_owned(),
            reasons_json(values),
        )])),
    }
}
