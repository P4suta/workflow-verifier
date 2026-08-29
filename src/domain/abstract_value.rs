use crate::domain::UnknownReason;
use crate::foundation::{JsonValue, SourceId, Span};
use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// Rebind every provenance span, including spans nested inside collection
    /// values, after source interning or program composition.
    pub fn remap_sources(&mut self, remap: &HashMap<SourceId, SourceId>) {
        for provenance in &mut self.provenance {
            provenance.span.source = remap
                .get(&provenance.span.source)
                .copied()
                .unwrap_or(provenance.span.source);
        }
        remap_value_sources(&mut self.value, remap);
    }

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
        let mut joined = self.clone();
        let _ = joined.join_assign(other);
        joined
    }

    /// Join `other` into this value without rebuilding unchanged state.
    ///
    /// Returns `true` exactly when the resulting abstract value differs from
    /// the value on entry. Provenance remains sorted and duplicate-free after
    /// every non-bottom join.
    pub fn join_assign(&mut self, other: &Self) -> bool {
        if self.value == Value::Bottom {
            if self == other {
                return false;
            }
            self.clone_from(other);
            return true;
        }
        if other.value == Value::Bottom {
            return false;
        }
        let value_type = if self.value_type == ValueType::Never {
            other.value_type
        } else if other.value_type == ValueType::Never || self.value_type == other.value_type {
            self.value_type
        } else {
            ValueType::Dynamic
        };
        let mut changed = false;
        if self.value_type != value_type {
            self.value_type = value_type;
            changed = true;
        }
        changed |= join_value_assign(&mut self.value, &other.value);
        changed |= join_trust_assign(&mut self.trust, &other.trust);
        changed |= join_secrecy_assign(&mut self.secrecy, &other.secrecy);
        changed |= join_provenance_assign(&mut self.provenance, &other.provenance);
        changed
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

fn remap_value_sources(value: &mut Value, remap: &HashMap<SourceId, SourceId>) {
    match value {
        Value::List(Some(values)) => {
            for value in values {
                value.remap_sources(remap);
            }
        }
        Value::Object(Some(values)) => {
            for value in values.values_mut() {
                value.remap_sources(remap);
            }
        }
        Value::Bottom
        | Value::Null
        | Value::Boolean(_)
        | Value::Number { .. }
        | Value::String(_)
        | Value::List(None)
        | Value::Object(None)
        | Value::Unknown(_) => {}
    }
}

fn assign_if_changed<T: Eq>(target: &mut T, value: T) -> bool {
    if *target == value {
        false
    } else {
        *target = value;
        true
    }
}

fn join_sorted_unique_assign<T: Clone + Ord>(left: &mut Vec<T>, right: &[T]) -> bool {
    let left_was_canonical = left.windows(2).all(|pair| pair[0] < pair[1]);
    if !left_was_canonical {
        left.sort_unstable();
        left.dedup();
    }
    let mut right = right.to_vec();
    right.sort_unstable();
    right.dedup();

    let original_len = left.len();
    let mut merged = Vec::with_capacity(left.len().saturating_add(right.len()));
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => {
                merged.push(left[left_index].clone());
                left_index += 1;
            }
            std::cmp::Ordering::Equal => {
                merged.push(left[left_index].clone());
                left_index += 1;
                right_index += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(right[right_index].clone());
                right_index += 1;
            }
        }
    }
    merged.extend_from_slice(&left[left_index..]);
    merged.extend_from_slice(&right[right_index..]);
    let changed = !left_was_canonical || merged.len() != original_len;
    *left = merged;
    changed
}

fn join_provenance_assign(left: &mut Vec<Provenance>, right: &[Provenance]) -> bool {
    join_sorted_unique_assign(left, right)
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

fn join_strings_assign(left: &mut StringValue, right: &StringValue) -> bool {
    if matches!(left, StringValue::Bottom) {
        if matches!(right, StringValue::Bottom) {
            return false;
        }
        left.clone_from(right);
        return true;
    }
    if matches!(right, StringValue::Bottom) {
        return false;
    }
    let constants_join = if let (StringValue::Constants(values), StringValue::Constants(right)) =
        (&mut *left, right)
    {
        let changed = join_sorted_unique_assign(values, right);
        Some((changed, values.len() > 8))
    } else {
        None
    };
    if let Some((changed, overflow)) = constants_join {
        if overflow {
            *left = StringValue::Top;
            return true;
        }
        return changed;
    }
    if let (StringValue::Pattern(left), StringValue::Pattern(right)) = (&*left, right)
        && left == right
    {
        return false;
    }
    if matches!(left, StringValue::Top) {
        return false;
    }
    if matches!(right, StringValue::Top) {
        *left = StringValue::Top;
        return true;
    }
    let joined = join_strings(left, right);
    assign_if_changed(left, joined)
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

fn join_value_assign(left: &mut Value, right: &Value) -> bool {
    match (&mut *left, right) {
        (Value::String(left), Value::String(right)) => join_strings_assign(left, right),
        (Value::List(Some(left)), Value::List(Some(right))) if left.len() == right.len() => left
            .iter_mut()
            .zip(right)
            .fold(false, |changed, (left, right)| {
                left.join_assign(right) || changed
            }),
        (Value::Object(Some(left)), Value::Object(Some(right))) => {
            let mut changed = false;
            for (key, right) in right {
                if let Some(left) = left.get_mut(key) {
                    changed |= left.join_assign(right);
                } else {
                    left.insert(key.clone(), right.clone());
                    changed = true;
                }
            }
            changed
        }
        (Value::Unknown(left), Value::Unknown(right)) => join_sorted_unique_assign(left, right),
        (Value::Unknown(left), _) => {
            let reason = UnknownReason::UnsupportedSyntax("incompatible value join".to_owned());
            join_sorted_unique_assign(left, std::slice::from_ref(&reason))
        }
        (_, Value::Unknown(right)) => {
            let mut reasons = right.clone();
            let reason = UnknownReason::UnsupportedSyntax("incompatible value join".to_owned());
            let _ = join_sorted_unique_assign(&mut reasons, std::slice::from_ref(&reason));
            *left = Value::Unknown(reasons);
            true
        }
        _ => {
            let joined = join_value(left, right);
            assign_if_changed(left, joined)
        }
    }
}

fn join_trust_assign(left: &mut Trust, right: &Trust) -> bool {
    match (&mut *left, right) {
        (Trust::Untrusted, _) | (Trust::Trusted, Trust::Trusted) => false,
        (slot, Trust::Untrusted) => {
            *slot = Trust::Untrusted;
            true
        }
        (Trust::Unknown(left), Trust::Unknown(right)) => join_sorted_unique_assign(left, right),
        (Trust::Unknown(_), _) => false,
        (slot, Trust::Unknown(reasons)) => {
            *slot = Trust::Unknown(reasons.clone());
            true
        }
        (Trust::Mixed, _) => false,
        (slot, Trust::Mixed) => {
            *slot = Trust::Mixed;
            true
        }
    }
}

fn join_secrecy_assign(left: &mut Secrecy, right: &Secrecy) -> bool {
    match (&mut *left, right) {
        (Secrecy::Secret, _) | (Secrecy::Public, Secrecy::Public) => false,
        (slot, Secrecy::Secret) => {
            *slot = Secrecy::Secret;
            true
        }
        (Secrecy::Unknown(left), Secrecy::Unknown(right)) => join_sorted_unique_assign(left, right),
        (Secrecy::Unknown(_), _) => false,
        (slot, Secrecy::Unknown(reasons)) => {
            *slot = Secrecy::Unknown(reasons.clone());
            true
        }
        (Secrecy::Sensitive, _) => false,
        (slot, Secrecy::Sensitive) => {
            *slot = Secrecy::Sensitive;
            true
        }
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
