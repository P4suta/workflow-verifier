use workflow_verifier::internal::conformance::foundation::content_digest;

pub fn digest(label: &str) -> String {
    content_digest(label.as_bytes())
}
