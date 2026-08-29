use crate::foundation::JsonValue;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnknownReason {
    UnsupportedSyntax(String),
    ExternalState(String),
    UnresolvedDependency(String),
    RecursiveCall(String),
    DynamicString(String),
    PhaseUnavailable(String),
    MissingEvidence(String),
    ResourceLimit(String),
}

impl UnknownReason {
    #[must_use]
    pub fn kind_and_detail(&self) -> (&'static str, &str) {
        match self {
            Self::UnsupportedSyntax(detail) => ("unsupported_syntax", detail),
            Self::ExternalState(detail) => ("external_state", detail),
            Self::UnresolvedDependency(detail) => ("unresolved_dependency", detail),
            Self::RecursiveCall(detail) => ("recursive_call", detail),
            Self::DynamicString(detail) => ("dynamic_string", detail),
            Self::PhaseUnavailable(detail) => ("phase_unavailable", detail),
            Self::MissingEvidence(detail) => ("missing_evidence", detail),
            Self::ResourceLimit(detail) => ("resource_limit", detail),
        }
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        let (kind, detail) = self.kind_and_detail();
        JsonValue::Object(BTreeMap::from([
            ("detail".to_owned(), JsonValue::String(detail.to_owned())),
            ("kind".to_owned(), JsonValue::String(kind.to_owned())),
        ]))
    }
}

impl fmt::Display for UnknownReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, detail) = self.kind_and_detail();
        if detail.is_empty() {
            formatter.write_str(kind)
        } else {
            write!(formatter, "{kind}: {detail}")
        }
    }
}
