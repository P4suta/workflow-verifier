#![forbid(unsafe_code)]

//! Provider-neutral semantic domain. Values are total and explicitly preserve
//! uncertainty; no constructor performs I/O or consults ambient state.

pub mod abstract_value;
pub mod condition;
pub mod ir;
pub mod unknown;

pub use crate::foundation::SourceId;
pub use abstract_value::{
    AbstractTruth, AbstractValue, Provenance, Secrecy, StringValue, Trust, Value, ValueType,
};
pub use condition::{Condition, Truth};
pub use ir::{
    Capability, Edge, EdgeKind, Graph, IrIssue, Node, NodeId, NodeKind, ObservableEffect, Phase,
    Program, Provider, Source,
};
pub use unknown::UnknownReason;
