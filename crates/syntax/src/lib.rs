#![forbid(unsafe_code)]

//! Lossless YAML syntax layer.

mod yaml;

pub use yaml::{
    Anchor, Edit, InvalidRegion, MappingEntry, ScalarStyle, Trivia, TriviaKind, YamlDocument,
    YamlNode, YamlNodeKind, YamlProblem,
};
