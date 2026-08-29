use crate::domain::{
    AbstractTruth, AbstractValue, Condition, Secrecy, StringValue, Trust, UnknownReason, Value,
};
use crate::foundation::{Position, Span};
use crate::verifier::{Diagnostic, Fix, Property, PropertyState, TraceHop};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

#[derive(serde::Serialize)]
pub(crate) struct PositionView {
    byte: usize,
    column: u32,
    line: u32,
}

impl From<Position> for PositionView {
    fn from(value: Position) -> Self {
        Self {
            byte: value.byte,
            column: value.column,
            line: value.line,
        }
    }
}

#[derive(serde::Serialize)]
pub(crate) struct SpanView {
    source: u32,
    start: PositionView,
    stop: PositionView,
}

impl From<Span> for SpanView {
    fn from(value: Span) -> Self {
        Self {
            source: value.source.0,
            start: value.start.into(),
            stop: value.stop.into(),
        }
    }
}

pub(crate) struct UnknownView<'a>(pub &'a UnknownReason);

impl Serialize for UnknownView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (kind, detail) = self.0.kind_and_detail();
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("detail", detail)?;
        map.serialize_entry("kind", kind)?;
        map.end()
    }
}

struct UnknownsView<'a>(&'a [UnknownReason]);

impl Serialize for UnknownsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for reason in self.0 {
            sequence.serialize_element(&UnknownView(reason))?;
        }
        sequence.end()
    }
}

pub(crate) struct ConditionView<'a>(pub &'a Condition);

impl Serialize for ConditionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Condition::False => serializer.serialize_bool(false),
            Condition::True => serializer.serialize_bool(true),
            Condition::Branch {
                variable,
                low,
                high,
            } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("high", &ConditionView(high))?;
                map.serialize_entry("low", &ConditionView(low))?;
                map.serialize_entry("variable", variable)?;
                map.end()
            }
        }
    }
}

pub(crate) struct AbstractValueView<'a>(pub &'a AbstractValue);

impl Serialize for AbstractValueView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("provenance", &ProvenanceView(&value.provenance))?;
        map.serialize_entry("secrecy", &SecrecyView(&value.secrecy))?;
        map.serialize_entry("trust", &TrustView(&value.trust))?;
        map.serialize_entry("type", value.value_type.name())?;
        map.serialize_entry("value", &ValueView(&value.value))?;
        map.end()
    }
}

struct ProvenanceView<'a>(&'a [crate::domain::Provenance]);

impl Serialize for ProvenanceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            #[derive(serde::Serialize)]
            struct Item<'a> {
                operation: &'a str,
                origin: &'a str,
                span: SpanView,
            }
            sequence.serialize_element(&Item {
                operation: &item.operation,
                origin: &item.origin,
                span: item.span.into(),
            })?;
        }
        sequence.end()
    }
}

struct TrustView<'a>(&'a Trust);

impl Serialize for TrustView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Trust::Trusted => serializer.serialize_str("trusted"),
            Trust::Mixed => serializer.serialize_str("mixed"),
            Trust::Untrusted => serializer.serialize_str("untrusted"),
            Trust::Unknown(reasons) => unknown_state(reasons, serializer),
        }
    }
}

struct SecrecyView<'a>(&'a Secrecy);

impl Serialize for SecrecyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Secrecy::Public => serializer.serialize_str("public"),
            Secrecy::Sensitive => serializer.serialize_str("sensitive"),
            Secrecy::Secret => serializer.serialize_str("secret"),
            Secrecy::Unknown(reasons) => unknown_state(reasons, serializer),
        }
    }
}

fn unknown_state<S: Serializer>(
    reasons: &[UnknownReason],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry("reasons", &UnknownsView(reasons))?;
    map.serialize_entry("state", "unknown")?;
    map.end()
}

struct ValueView<'a>(&'a Value);

impl Serialize for ValueView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Bottom | Value::String(StringValue::Bottom) => {
                serializer.serialize_str("bottom")
            }
            Value::Null => serializer.serialize_none(),
            Value::Boolean(AbstractTruth::False) => serializer.serialize_bool(false),
            Value::Boolean(AbstractTruth::True) => serializer.serialize_bool(true),
            Value::Boolean(AbstractTruth::Maybe) => serializer.serialize_str("maybe"),
            Value::Number { minimum, maximum } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("maximum", maximum)?;
                map.serialize_entry("minimum", minimum)?;
                map.end()
            }
            Value::String(StringValue::Constants(values)) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("constants", values)?;
                map.end()
            }
            Value::String(StringValue::Affix { prefix, suffix }) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("prefix", prefix)?;
                map.serialize_entry("suffix", suffix)?;
                map.end()
            }
            Value::String(StringValue::Pattern(pattern)) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("pattern", pattern)?;
                map.end()
            }
            Value::String(StringValue::Top) => serializer.serialize_str("top"),
            Value::List(None) => serializer.serialize_str("list-top"),
            Value::List(Some(values)) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&AbstractValueView(value))?;
                }
                sequence.end()
            }
            Value::Object(None) => serializer.serialize_str("object-top"),
            Value::Object(Some(values)) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, &AbstractValueView(value))?;
                }
                map.end()
            }
            Value::Unknown(reasons) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("unknown", &UnknownsView(reasons))?;
                map.end()
            }
        }
    }
}

pub(crate) struct DiagnosticView<'a>(pub &'a Diagnostic);

impl Serialize for DiagnosticView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let fields = 6
            + usize::from(!value.capabilities.is_empty())
            + usize::from(!value.evidence.is_empty())
            + usize::from(value.fix.is_some())
            + usize::from(!value.trace.is_empty());
        let mut map = serializer.serialize_map(Some(fields))?;
        if !value.capabilities.is_empty() {
            map.serialize_entry(
                "capabilities",
                &value
                    .capabilities
                    .iter()
                    .map(|capability| capability.name())
                    .collect::<Vec<_>>(),
            )?;
        }
        map.serialize_entry("confidence", value.confidence.name())?;
        if !value.evidence.is_empty() {
            map.serialize_entry("evidence", &value.evidence)?;
        }
        if let Some(fix) = &value.fix {
            map.serialize_entry("fix", &FixView(fix))?;
        }
        map.serialize_entry("id", &value.id)?;
        map.serialize_entry("message", &value.message)?;
        map.serialize_entry("rule_id", &value.rule_id)?;
        map.serialize_entry("severity", value.severity.name())?;
        map.serialize_entry("span", &SpanView::from(value.span))?;
        if !value.trace.is_empty() {
            map.serialize_entry("trace", &TraceView(&value.trace))?;
        }
        map.end()
    }
}

struct TraceView<'a>(&'a [TraceHop]);

impl Serialize for TraceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for hop in self.0 {
            #[derive(serde::Serialize)]
            struct Hop<'a> {
                label: &'a str,
                node: u32,
                span: SpanView,
            }
            sequence.serialize_element(&Hop {
                label: &hop.label,
                node: hop.node_id.0,
                span: hop.span.into(),
            })?;
        }
        sequence.end()
    }
}

struct FixView<'a>(&'a Fix);

impl Serialize for FixView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("description", &value.description)?;
        map.serialize_entry("kind", &value.kind)?;
        if let Some(replacement) = &value.replacement {
            map.serialize_entry("replacement", replacement)?;
        }
        if let Some(span) = value.span {
            map.serialize_entry("span", &SpanView::from(span))?;
        }
        map.end()
    }
}

pub(crate) struct PropertyView<'a>(pub &'a Property);

impl Serialize for PropertyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("explanation", &value.explanation)?;
        map.serialize_entry("id", &value.id)?;
        if let PropertyState::Unknown(reasons) = &value.state {
            map.serialize_entry("reasons", &UnknownsView(reasons))?;
        }
        map.serialize_entry("state", value.state.name())?;
        if let Some(subject) = &value.subject {
            map.serialize_entry("subject", subject)?;
        }
        map.end()
    }
}
