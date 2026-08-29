use crate::domain::Capability;
use crate::foundation::{Budget, JsonValue, normalize_slashes, sha256_hex};
use crate::syntax::{Edit, MappingEntry, ScalarStyle, YamlDocument, YamlNode};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixShell {
    Posix,
    Bash,
    PowerShell,
    Cmd,
    Python,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixProposal {
    pub id: String,
    pub description: String,
    pub edits: Vec<Edit>,
    pub safe: bool,
}

impl FixProposal {
    fn new(description: impl Into<String>, mut edits: Vec<Edit>, safe: bool) -> Self {
        use std::fmt::Write as _;
        let description = description.into();
        edits.sort_by(|left, right| {
            left.start_byte
                .cmp(&right.start_byte)
                .then(left.stop_byte.cmp(&right.stop_byte))
                .then(left.replacement.cmp(&right.replacement))
        });
        let mut material = description.clone();
        for edit in &edits {
            let _ = write!(
                material,
                "{}:{}:{}",
                edit.start_byte, edit.stop_byte, edit.replacement
            );
        }
        let digest = sha256_hex(material);
        Self {
            id: format!("fix_{}", digest.get(..20).unwrap_or(&digest)),
            description,
            edits,
            safe,
        }
    }

    #[must_use]
    pub fn replace_span(
        start_byte: usize,
        stop_byte: usize,
        replacement: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self::new(
            description,
            vec![Edit::replace(start_byte, stop_byte, replacement)],
            true,
        )
    }

    #[must_use]
    pub fn pin_dependency(
        document: &YamlDocument,
        reference: &str,
        revision: &str,
    ) -> Option<Self> {
        let node = find_scalar(document.root()?, reference)?;
        let prefix = reference.rfind('@').map_or_else(
            || format!("{reference}@"),
            |index| reference[..=index].to_owned(),
        );
        Some(Self::replace_span(
            node.span().start.byte,
            node.span().stop.byte,
            format!("{prefix}{revision}"),
            format!("pin {reference} to {revision}"),
        ))
    }

    #[must_use]
    pub fn reduce_write_all(
        document: &YamlDocument,
        unused_capabilities: &[Capability],
    ) -> Option<Self> {
        if ![Capability::RepositoryWrite, Capability::TokenWrite]
            .iter()
            .all(|capability| unused_capabilities.contains(capability))
        {
            return None;
        }
        let node = find_scalar(document.root()?, "write-all")?;
        Some(Self::replace_span(
            node.span().start.byte,
            node.span().stop.byte,
            "read-all",
            "reduce write-all after proving repository and token write grants unused",
        ))
    }

    #[must_use]
    pub fn bind_expression_to_environment(
        document: &YamlDocument,
        shell: FixShell,
        expression: &str,
        name: &str,
    ) -> Option<Self> {
        if !environment_name(name)
            || !(expression.starts_with("${{") || expression.starts_with("$[["))
        {
            return None;
        }
        let (entry, scalar) = find_run(document.root()?, expression)?;
        if scalar.scalar_style() != Some(ScalarStyle::Plain) {
            return None;
        }
        let command = scalar.scalar()?;
        let relative = exactly_once(command, expression)?;
        let variable = match shell {
            FixShell::Posix | FixShell::Bash => format!("\"${{{name}}}\""),
            FixShell::PowerShell => format!("\"$env:{name}\""),
            FixShell::Cmd => format!("\"%{name}%\""),
            FixShell::Python | FixShell::Unknown => return None,
        };
        let (insertion, has_newline) = line_insertion(document.print(), scalar.span().stop.byte);
        let newline = if document.print().contains("\r\n") {
            "\r\n"
        } else if document.print().contains('\r') {
            "\r"
        } else {
            "\n"
        };
        let indent = " ".repeat(entry.key_span.start.column.saturating_sub(1) as usize);
        let block = format!(
            "{}{indent}env:{newline}{indent}  {name}: {expression}{newline}",
            if has_newline { "" } else { newline }
        );
        Some(Self::new(
            format!("bind {expression} through environment variable {name}"),
            vec![
                Edit::replace(
                    scalar.span().start.byte + relative,
                    scalar.span().start.byte + relative + expression.len(),
                    variable,
                ),
                Edit::replace(insertion, insertion, block),
            ],
            true,
        ))
    }

    /// Combine safe, non-overlapping proposals into one atomic transaction.
    ///
    /// # Errors
    /// Rejects empty, unsafe, or overlapping proposal sets.
    pub fn combine(proposals: &[Self]) -> Result<Self, String> {
        if proposals.is_empty() {
            return Err("at least one fix proposal is required".to_owned());
        }
        if proposals.iter().any(|proposal| !proposal.safe) {
            return Err("unsafe proposals cannot be combined for automatic application".to_owned());
        }
        let mut edits: Vec<_> = proposals
            .iter()
            .flat_map(|proposal| proposal.edits.iter().cloned())
            .collect();
        edits.sort_by(|left, right| {
            left.start_byte
                .cmp(&right.start_byte)
                .then(left.stop_byte.cmp(&right.stop_byte))
        });
        if edits.windows(2).any(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            left.stop_byte > right.start_byte
                || (left.start_byte == left.stop_byte
                    && right.start_byte == right.stop_byte
                    && left.start_byte == right.start_byte)
        }) {
            return Err("fix proposals contain overlapping edits".to_owned());
        }
        let descriptions: BTreeSet<_> = proposals
            .iter()
            .map(|proposal| proposal.description.clone())
            .collect();
        Ok(Self::new(
            descriptions.into_iter().collect::<Vec<_>>().join("; "),
            edits,
            true,
        ))
    }

    /// Apply a safe transaction and require the result to parse cleanly.
    ///
    /// # Errors
    /// Rejects unsafe/out-of-range edits or a malformed resulting YAML document.
    pub fn apply(&self, document: &YamlDocument) -> Result<String, String> {
        if !self.safe {
            return Err("unsafe proposals cannot be applied automatically".to_owned());
        }
        let output = document.apply_edits(&self.edits)?;
        let reparsed = YamlDocument::parse(document.file(), &output, Budget::default());
        if reparsed.root().is_none() || !reparsed.invalid_regions().is_empty() {
            return Err("fixed document did not reparse cleanly".to_owned());
        }
        Ok(output)
    }

    /// Apply and ask a caller-owned analyzer to re-prove the semantic safety condition.
    ///
    /// # Errors
    /// Returns the edit or proof failure without mutating a file.
    pub fn apply_verified(
        &self,
        document: &YamlDocument,
        prove: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<String, String> {
        let output = self.apply(document)?;
        prove(&output)?;
        Ok(output)
    }

    #[must_use]
    pub fn unified_diff(&self, path: &str, before: &str, after: &str) -> String {
        if before == after {
            return String::new();
        }
        let before_lines = diff_lines(before);
        let after_lines = diff_lines(after);
        let path = normalize_slashes(path);
        let mut output = format!(
            "--- {path}\n+++ {path}\n@@ -1,{} +1,{} @@\n",
            before_lines.len(),
            after_lines.len()
        );
        for line in before_lines {
            output.push('-');
            output.push_str(line);
            output.push('\n');
        }
        for line in after_lines {
            output.push('+');
            output.push_str(line);
            output.push('\n');
        }
        output
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "description".to_owned(),
                JsonValue::String(self.description.clone()),
            ),
            (
                "edits".to_owned(),
                JsonValue::Array(
                    self.edits
                        .iter()
                        .map(|edit| {
                            JsonValue::Object(BTreeMap::from([
                                (
                                    "replacement".to_owned(),
                                    JsonValue::String(edit.replacement.clone()),
                                ),
                                (
                                    "start_byte".to_owned(),
                                    JsonValue::Integer(
                                        i64::try_from(edit.start_byte).unwrap_or(i64::MAX),
                                    ),
                                ),
                                (
                                    "stop_byte".to_owned(),
                                    JsonValue::Integer(
                                        i64::try_from(edit.stop_byte).unwrap_or(i64::MAX),
                                    ),
                                ),
                            ]))
                        })
                        .collect(),
                ),
            ),
            ("id".to_owned(), JsonValue::String(self.id.clone())),
            ("safe".to_owned(), JsonValue::Boolean(self.safe)),
        ]))
    }
}

fn find_scalar<'a>(node: &'a YamlNode, wanted: &str) -> Option<&'a YamlNode> {
    if node.scalar() == Some(wanted) {
        return Some(node);
    }
    node.mapping()
        .into_iter()
        .flatten()
        .find_map(|entry| find_scalar(&entry.value, wanted))
        .or_else(|| {
            node.sequence()
                .into_iter()
                .flatten()
                .find_map(|item| find_scalar(item, wanted))
        })
}

fn find_run<'a>(node: &'a YamlNode, expression: &str) -> Option<(&'a MappingEntry, &'a YamlNode)> {
    if let Some(entries) = node.mapping() {
        if entries.iter().all(|entry| entry.key != "env")
            && let Some(found) = entries.iter().find_map(|entry| {
                (entry.key == "run"
                    && entry
                        .value
                        .scalar()
                        .is_some_and(|value| value.contains(expression)))
                .then_some((entry, &entry.value))
            })
        {
            return Some(found);
        }
        if let Some(found) = entries
            .iter()
            .find_map(|entry| find_run(&entry.value, expression))
        {
            return Some(found);
        }
    }
    node.sequence()
        .into_iter()
        .flatten()
        .find_map(|item| find_run(item, expression))
}

fn exactly_once(haystack: &str, needle: &str) -> Option<usize> {
    let first = haystack.find(needle)?;
    (!haystack[first + needle.len()..].contains(needle)).then_some(first)
}

fn environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn line_insertion(source: &str, stop: usize) -> (usize, bool) {
    let suffix = &source[stop.min(source.len())..];
    for (relative, character) in suffix.char_indices() {
        match character {
            '\n' => return (stop + relative + 1, true),
            '\r' => {
                let width = usize::from(suffix.as_bytes().get(relative + 1) == Some(&b'\n')) + 1;
                return (stop + relative + width, true);
            }
            _ => {}
        }
    }
    (source.len(), false)
}

fn diff_lines(source: &str) -> Vec<&str> {
    let mut lines: Vec<_> = source.split('\n').collect();
    if lines.last() == Some(&"") {
        let _ = lines.pop();
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(source: &str) -> YamlDocument {
        YamlDocument::parse("fix.yml", source, Budget::default())
    }

    #[test]
    fn lexical_fix_helpers_observe_every_boundary() {
        assert_eq!(
            exactly_once("prefix TOKEN suffix", "TOKEN"),
            Some("prefix ".len())
        );
        assert_eq!(exactly_once("TOKEN TOKEN", "TOKEN"), None);
        assert_eq!(exactly_once("missing", "TOKEN"), None);

        for valid in ["A", "_A", "A0", "name_with_digits_42"] {
            assert!(environment_name(valid), "valid environment name {valid:?}");
        }
        for invalid in ["", "0A", "-A", "A-B", "A B", "Ä"] {
            assert!(
                !environment_name(invalid),
                "invalid environment name {invalid:?}"
            );
        }

        assert_eq!(
            line_insertion("run: x\nnext: y\n", "run: x".len()),
            ("run: x\n".len(), true)
        );
        assert_eq!(
            line_insertion("run: value suffix\nnext: y\n", "run: ".len()),
            ("run: value suffix\n".len(), true)
        );
        assert_eq!(
            line_insertion("run: x\r\nnext: y\r\n", "run: x".len()),
            ("run: x\r\n".len(), true)
        );
        assert_eq!(
            line_insertion("run: value suffix\r\nnext: y\r\n", "run: ".len()),
            ("run: value suffix\r\n".len(), true)
        );
        assert_eq!(
            line_insertion("run: x\rnext: y\r", "run: x".len()),
            ("run: x\r".len(), true)
        );
        assert_eq!(
            line_insertion("run: x", "run: x".len()),
            ("run: x".len(), false)
        );
        assert_eq!(
            line_insertion("run: x", usize::MAX),
            ("run: x".len(), false)
        );

        assert_eq!(diff_lines(""), Vec::<&str>::new());
        assert_eq!(diff_lines("one"), ["one"]);
        assert_eq!(diff_lines("one\n"), ["one"]);
        assert_eq!(diff_lines("one\ntwo"), ["one", "two"]);
        assert_eq!(diff_lines("one\n\n"), ["one", ""]);
    }

    #[test]
    fn run_lookup_requires_a_plain_unique_expression_outside_env() {
        let nested =
            document("jobs:\n  build:\n    steps:\n      - run: echo ${{ inputs.value }}\n");
        let (entry, scalar) = find_run(nested.root().expect("nested root"), "${{ inputs.value }}")
            .expect("nested run");
        assert_eq!(entry.key, "run");
        assert_eq!(scalar.scalar(), Some("echo ${{ inputs.value }}"));

        let environment = document("env:\n  TOKEN: ${{ inputs.value }}\nrun: echo safe\n");
        assert!(
            find_run(
                environment.root().expect("environment root"),
                "${{ inputs.value }}"
            )
            .is_none()
        );
        let absent = document("run: echo safe\n");
        assert!(find_run(absent.root().expect("absent root"), "${{ inputs.value }}").is_none());
    }

    #[test]
    fn binding_contract_covers_shells_rejections_and_line_endings() {
        let cases = [
            (FixShell::Posix, "\"${INPUT_VALUE}\""),
            (FixShell::Bash, "\"${INPUT_VALUE}\""),
            (FixShell::PowerShell, "\"$env:INPUT_VALUE\""),
            (FixShell::Cmd, "\"%INPUT_VALUE%\""),
        ];
        for (shell, replacement) in cases {
            let source = "steps:\n  - run: echo ${{ inputs.value }}\n";
            let proposal = FixProposal::bind_expression_to_environment(
                &document(source),
                shell,
                "${{ inputs.value }}",
                "INPUT_VALUE",
            )
            .expect("supported binding");
            let output = proposal.apply(&document(source)).expect("binding applies");
            assert!(output.contains(&format!("run: echo {replacement}")));
            assert!(output.contains("    env:\n      INPUT_VALUE: ${{ inputs.value }}\n"));
        }

        let crlf = "steps:\r\n  - run: echo $[[ inputs.value ]]\r\n";
        let proposal = FixProposal::bind_expression_to_environment(
            &document(crlf),
            FixShell::Bash,
            "$[[ inputs.value ]]",
            "INPUT_VALUE",
        )
        .expect("GitLab expression binding");
        assert!(
            proposal
                .apply(&document(crlf))
                .expect("CRLF binding")
                .contains("    env:\r\n      INPUT_VALUE: $[[ inputs.value ]]\r\n")
        );

        let plain = document("run: echo ${{ inputs.value }}\n");
        for shell in [FixShell::Python, FixShell::Unknown] {
            assert!(
                FixProposal::bind_expression_to_environment(
                    &plain,
                    shell,
                    "${{ inputs.value }}",
                    "INPUT_VALUE",
                )
                .is_none()
            );
        }
        for (expression, name) in [
            ("inputs.value", "INPUT_VALUE"),
            ("${{ inputs.value }}", "0INVALID"),
        ] {
            assert!(
                FixProposal::bind_expression_to_environment(
                    &plain,
                    FixShell::Bash,
                    expression,
                    name,
                )
                .is_none()
            );
        }
        for source in [
            "run: echo ${{ inputs.value }} ${{ inputs.value }}\n",
            "run: 'echo ${{ inputs.value }}'\n",
            "env:\n  INPUT_VALUE: existing\nrun: echo ${{ inputs.value }}\n",
        ] {
            assert!(
                FixProposal::bind_expression_to_environment(
                    &document(source),
                    FixShell::Bash,
                    "${{ inputs.value }}",
                    "INPUT_VALUE",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn transaction_contract_rejects_each_unsafe_shape_and_reproves_output() {
        let insertion = |at, replacement: &str| {
            FixProposal::new("insert", vec![Edit::replace(at, at, replacement)], true)
        };
        assert!(FixProposal::combine(&[]).is_err());
        let unsafe_proposal = FixProposal {
            id: "unsafe".to_owned(),
            description: "unsafe".to_owned(),
            edits: vec![Edit::replace(0, 0, "key: value\n")],
            safe: false,
        };
        assert!(FixProposal::combine(std::slice::from_ref(&unsafe_proposal)).is_err());
        assert!(unsafe_proposal.apply(&document("key: value\n")).is_err());

        let replacing = FixProposal::replace_span(0, "key".len(), "name", "replace key");
        assert!(FixProposal::combine(&[replacing.clone(), insertion("k".len(), "x")]).is_err());
        assert!(FixProposal::combine(&[insertion(0, "a"), insertion(0, "b")]).is_err());
        assert!(FixProposal::combine(&[insertion(0, "a"), insertion(1, "b")]).is_ok());
        assert!(
            FixProposal::combine(&[
                FixProposal::replace_span(0, "a".len(), "A", "replace first"),
                FixProposal::replace_span("a".len(), "ab".len(), "B", "replace second",),
            ])
            .is_ok()
        );

        let source = "key: value\n";
        let valid = FixProposal::replace_span(0, "key".len(), "name", "replace key");
        let mut proof_input = String::new();
        let output = valid
            .apply_verified(&document(source), |candidate| {
                proof_input = candidate.to_owned();
                Ok(())
            })
            .expect("reproved fix");
        assert_eq!(output, "name: value\n");
        assert_eq!(proof_input, output);
        assert!(
            valid
                .apply_verified(&document(source), |_| Err("proof rejected".to_owned()))
                .is_err()
        );

        let empty = FixProposal::replace_span(0, source.len(), "", "empty document");
        assert!(empty.apply(&document(source)).is_err());
        let malformed =
            FixProposal::replace_span(0, source.len(), "key: [\n", "malformed document");
        assert!(malformed.apply(&document(source)).is_err());
    }
}
