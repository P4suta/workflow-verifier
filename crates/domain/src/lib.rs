#![forbid(unsafe_code)]

//! Provider-neutral semantic domain. Values are total and explicitly preserve
//! uncertainty; no constructor performs I/O or consults ambient state.

pub mod abstract_value;
pub mod condition;
pub mod ir;
pub mod unknown;

pub use abstract_value::{AbstractValue, Provenance, Secrecy, Trust, Value, ValueType};
pub use condition::{Condition, Truth};
pub use ir::{
    Capability, Edge, EdgeKind, Graph, IrIssue, Node, NodeKind, ObservableEffect, Phase, Provider,
};
pub use unknown::UnknownReason;
