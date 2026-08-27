use std::collections::{BTreeMap, BTreeSet};
use workflow_verifier_domain::Capability;
use workflow_verifier_foundation::{Budget, JsonValue, normalize_slashes, sha256_hex};
use workflow_verifier_syntax::{Edit, MappingEntry, ScalarStyle, YamlDocument, YamlNode};

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
