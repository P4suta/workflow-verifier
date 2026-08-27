/// Provider-independent mutability classification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyClass {
    Local,
    Immutable,
    Mutable,
    Unknown,
}

fn exact_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn exact_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[must_use]
pub fn valid_content_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| exact_lower_hex(hex, 64))
}

fn immutable_revision(value: &str) -> bool {
    exact_hex(value, 40) || exact_hex(value, 64) || valid_content_digest(value)
}

#[must_use]
pub fn classify_reference(reference: &str) -> DependencyClass {
    if reference.starts_with("./") || reference.starts_with("../") {
        return DependencyClass::Local;
    }
    if let Some((_, revision)) = reference.rsplit_once('@') {
        if immutable_revision(revision) {
            DependencyClass::Immutable
        } else {
            DependencyClass::Mutable
        }
    } else if reference.contains("://") {
        DependencyClass::Mutable
    } else {
        DependencyClass::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{DependencyClass, classify_reference, valid_content_digest};

    #[test]
    fn provider_independent_classification() {
        assert_eq!(classify_reference("./action"), DependencyClass::Local);
        assert_eq!(
            classify_reference("org/action@main"),
            DependencyClass::Mutable
        );
        assert_eq!(
            classify_reference("org/action@0123456789abcdef0123456789abcdef01234567"),
            DependencyClass::Immutable
        );
        assert_eq!(
            classify_reference("docker://alpine:latest"),
            DependencyClass::Mutable
        );
        assert_eq!(classify_reference("opaque"), DependencyClass::Unknown);
        assert!(valid_content_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_content_digest(&format!("sha256:{}", "g".repeat(64))));
    }
}
