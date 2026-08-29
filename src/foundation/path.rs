use caseless::Caseless;
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathError {
    Empty,
    Absolute,
    DrivePrefix,
    Backslash,
    EmptySegment,
    DotSegment,
    ParentSegment,
    Nul,
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid public path: {self:?}")
    }
}

impl std::error::Error for PathError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicPath(String);

impl PublicPath {
    /// Validate and own a path used by a portable public protocol.
    ///
    /// # Errors
    /// Rejects absolute, drive-prefixed, backslash, NUL, empty, dot, and
    /// parent segments.
    pub fn new(value: impl Into<String>) -> Result<Self, PathError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PathError::Empty);
        }
        if value.contains('\0') {
            return Err(PathError::Nul);
        }
        if value.starts_with('/') {
            return Err(PathError::Absolute);
        }
        if value.contains('\\') {
            return Err(PathError::Backslash);
        }
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return Err(PathError::DrivePrefix);
            }
        }
        for segment in value.split('/') {
            match segment {
                "" => return Err(PathError::EmptySegment),
                "." => return Err(PathError::DotSegment),
                ".." => return Err(PathError::ParentSegment),
                _ => {}
            }
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn portable_key(&self) -> String {
        portable_path_key(&self.0)
    }
}

impl fmt::Display for PublicPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[must_use]
pub fn normalize_slashes(value: &str) -> String {
    value.replace('\\', "/")
}

/// NFC plus Unicode lowercase is the conservative portable collision key.
/// It intentionally may report more collisions than one host filesystem.
#[must_use]
pub fn portable_path_key(value: &str) -> String {
    value.chars().nfd().default_case_fold().nfc().collect()
}

#[cfg(test)]
mod tests {
    use super::{PathError, PublicPath};

    #[test]
    fn public_path_is_relative_and_portable() {
        assert!(PublicPath::new(".github/workflows/ci.yml").is_ok());
        assert_eq!(PublicPath::new("../secret"), Err(PathError::ParentSegment));
        assert_eq!(PublicPath::new("C:/secret"), Err(PathError::DrivePrefix));
        let composed = PublicPath::new("caf\u{e9}.yml").expect("valid fixture");
        let decomposed = PublicPath::new("cafe\u{301}.yml").expect("valid fixture");
        assert_eq!(composed.portable_key(), decomposed.portable_key());
    }
}
