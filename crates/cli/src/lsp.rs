//! Standard Language Server Protocol over stdio.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use workflow_verifier_domain::Capability;
use workflow_verifier_engine::{
    AnalysisEngine, AnalysisRequest, AnalysisResult, CancellationToken, ConfigSnapshot,
    LockSnapshot, SourceSnapshot,
};
use workflow_verifier_foundation::{
    Budget, JsonValue, Span, Utf16Position, byte_to_utf16, content_digest, utf16_to_byte,
};
use workflow_verifier_product::FixProposal;
use workflow_verifier_syntax::YamlDocument;
use workflow_verifier_verifier::{Diagnostic, Persona, Severity};

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 8192;
const MAX_COMPLETED_REQUEST_IDS: usize = 4096;

#[derive(Clone, Debug)]
struct Document {
    uri: String,
    workspace: String,
    logical_path: String,
    version: i64,
    text: String,
}

#[derive(Default)]
struct CancellationState {
    active: BTreeMap<String, CancellationToken>,
    pending: BTreeSet<String>,
    completed: BTreeSet<String>,
    completed_order: VecDeque<String>,
}

#[derive(Default)]
struct RequestCancellations(Mutex<CancellationState>);

impl RequestCancellations {
    fn start(&self, id: &Value) -> CancellationToken {
        let key = id_key(id);
        let token = CancellationToken::new();
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.completed.remove(&key) {
            state.completed_order.retain(|completed| completed != &key);
        }
        if state.pending.contains(&key) {
            token.cancel();
        }
        state.active.insert(key, token.clone());
        token
    }

    fn cancel(&self, id: &Value) {
        let key = id_key(id);
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(token) = state.active.get(&key) {
            token.cancel();
        } else if !state.completed.contains(&key) {
            state.pending.insert(key);
        }
    }

    fn finish(&self, id: &Value) {
        let key = id_key(id);
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(&key);
        state.pending.remove(&key);
        if state.completed.insert(key.clone()) {
            state.completed_order.push_back(key);
        }
        while state.completed_order.len() > MAX_COMPLETED_REQUEST_IDS {
            if let Some(expired) = state.completed_order.pop_front() {
                state.completed.remove(&expired);
            }
        }
    }
}

#[derive(Default)]
struct ObservedDocumentState {
    versions: BTreeMap<String, i64>,
    closed: BTreeSet<String>,
    active: BTreeMap<(String, i64), CancellationToken>,
}

#[derive(Default)]
struct ObservedDocuments(Mutex<ObservedDocumentState>);

impl ObservedDocuments {
    fn observe(&self, message: &Value) {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return;
        };
        let document = message
            .get("params")
            .and_then(|params| params.get("textDocument"));
        let Some(uri) = document
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return;
        };
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match method {
            "textDocument/didOpen" | "textDocument/didChange" => {
                if let Some(version) = document
                    .and_then(|value| value.get("version"))
                    .and_then(Value::as_i64)
                    && state
                        .versions
                        .get(uri)
                        .is_none_or(|current| version >= *current)
                {
                    state.versions.insert(uri.to_owned(), version);
                }
                state.closed.remove(uri);
                let current = state.versions.get(uri).copied();
                for ((active_uri, active_version), token) in &state.active {
                    if active_uri == uri && Some(*active_version) != current {
                        token.cancel();
                    }
                }
            }
            "textDocument/didClose" => {
                state.closed.insert(uri.to_owned());
                for ((active_uri, _), token) in &state.active {
                    if active_uri == uri {
                        token.cancel();
                    }
                }
            }
            _ => {}
        }
    }

    fn is_current(&self, uri: &str, version: i64) -> bool {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.closed.contains(uri) && state.versions.get(uri) == Some(&version)
    }

    fn is_closed(&self, uri: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
            .contains(uri)
    }

    fn start_analysis(&self, uri: &str, version: i64) -> Option<CancellationToken> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed.contains(uri) || state.versions.get(uri) != Some(&version) {
            return None;
        }
        let token = CancellationToken::new();
        state
            .active
            .insert((uri.to_owned(), version), token.clone());
        Some(token)
    }

    fn track_analysis(&self, uri: &str, version: i64, token: &CancellationToken) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .active
            .insert((uri.to_owned(), version), token.clone());
    }

    fn finish_analysis(&self, uri: &str, version: i64) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .remove(&(uri.to_owned(), version));
    }
}

struct Server {
    documents: BTreeMap<String, Document>,
    cancellations: Arc<RequestCancellations>,
    observed: Arc<ObservedDocuments>,
    engine: AnalysisEngine,
    semantic_cache: Mutex<BTreeMap<String, Vec<u32>>>,
    shutdown: bool,
}

impl Server {
    fn new(cancellations: Arc<RequestCancellations>, observed: Arc<ObservedDocuments>) -> Self {
        Self {
            documents: BTreeMap::new(),
            cancellations,
            observed,
            engine: AnalysisEngine::new(),
            semantic_cache: Mutex::new(BTreeMap::new()),
            shutdown: false,
        }
    }

    fn handle(&mut self, message: &Value) -> Vec<Value> {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return message
                .get("id")
                .map(|id| vec![error_response(id, -32600, "invalid JSON-RPC request")])
                .unwrap_or_default();
        };
        let id = message.get("id");
        let params = message.get("params").unwrap_or(&Value::Null);
        match method {
            "initialize" => id
                .map(|id| vec![success_response(id, &initialize_result())])
                .unwrap_or_default(),
            "initialized" | "exit" => Vec::new(),
            "shutdown" => {
                self.shutdown = true;
                id.map(|id| vec![success_response(id, &Value::Null)])
                    .unwrap_or_default()
            }
            "$/cancelRequest" => {
                if let Some(cancelled) = params.get("id") {
                    self.cancellations.cancel(cancelled);
                }
                Vec::new()
            }
            "textDocument/didOpen" => self.did_open(params),
            "textDocument/didChange" => self.did_change(params),
            "textDocument/didClose" => self.did_close(params),
            "workspace/didChangeWatchedFiles" | "workspace/didChangeConfiguration" => {
                self.engine = AnalysisEngine::new();
                Vec::new()
            }
            "textDocument/diagnostic" => self.request(id, |server, cancellation| {
                let uri = text_document_uri(params)?;
                let document = server.document(uri)?;
                Ok(json!({
                    "kind": "full",
                    "resultId": content_digest(document.text.as_bytes()),
                    "items": server.diagnostics(document, cancellation),
                }))
            }),
            "workspace/diagnostic" => self.request(id, |server, cancellation| {
                let items = server
                    .documents
                    .values()
                    .map(|document| {
                        json!({
                            "kind": "full",
                            "uri": document.uri,
                            "version": document.version,
                            "resultId": content_digest(document.text.as_bytes()),
                            "items": server.diagnostics(document, cancellation),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({"items": items}))
            }),
            "textDocument/completion" => self.request(id, |server, _| {
                let uri = text_document_uri(params)?;
                let document = server.document(uri)?;
                Ok(completions(document))
            }),
            "textDocument/hover" => self.request(id, |server, cancellation| {
                server.hover(params, cancellation)
            }),
            "textDocument/documentSymbol" => self.request(id, |server, cancellation| {
                server.document_symbols(params, cancellation)
            }),
            "workspace/symbol" => self.request(id, |server, cancellation| {
                Ok(server.workspace_symbols(cancellation))
            }),
            "textDocument/definition" => self.request(id, |server, _| server.definition(params)),
            "textDocument/references" => self.request(id, |server, _| server.references(params)),
            "textDocument/semanticTokens/full" => {
                self.request(id, |server, _| server.semantic_tokens(params))
            }
            "textDocument/semanticTokens/full/delta" => {
                self.request(id, |server, _| server.semantic_token_delta(params))
            }
            "textDocument/prepareRename" => {
                self.request(id, |server, _| server.prepare_rename(params))
            }
            "textDocument/rename" => self.request(id, |server, cancellation| {
                server.rename(params, cancellation)
            }),
            "textDocument/codeAction" => self.request(id, |server, cancellation| {
                server.code_actions(params, cancellation)
            }),
            _ => id
                .map(|id| vec![error_response(id, -32601, "method not found")])
                .unwrap_or_default(),
        }
    }

    fn request(
        &self,
        id: Option<&Value>,
        operation: impl FnOnce(&Self, &CancellationToken) -> Result<Value, String>,
    ) -> Vec<Value> {
        let Some(id) = id else {
            return Vec::new();
        };
        let cancellation = self.cancellations.start(id);
        let result = if cancellation.is_cancelled() {
            Err(error_response(id, -32800, "request cancelled"))
        } else {
            match operation(self, &cancellation) {
                Ok(_) | Err(_) if cancellation.is_cancelled() => {
                    Err(error_response(id, -32800, "request cancelled"))
                }
                Ok(result) => Ok(success_response(id, &result)),
                Err(message) => Err(error_response(id, -32602, &message)),
            }
        };
        self.cancellations.finish(id);
        vec![match result {
            Ok(response) | Err(response) => response,
        }]
    }

    fn document(&self, uri: &str) -> Result<&Document, String> {
        self.documents
            .get(uri)
            .ok_or_else(|| "document is not open".to_owned())
    }

    fn did_open(&mut self, params: &Value) -> Vec<Value> {
        let Some(item) = params.get("textDocument") else {
            return Vec::new();
        };
        let (Some(uri), Some(version), Some(text)) = (
            item.get("uri").and_then(Value::as_str),
            item.get("version").and_then(Value::as_i64),
            item.get("text").and_then(Value::as_str),
        ) else {
            return Vec::new();
        };
        let (workspace, logical_path) = logical_identity(uri);
        let document = Document {
            uri: uri.to_owned(),
            workspace,
            logical_path,
            version,
            text: text.to_owned(),
        };
        self.documents.insert(uri.to_owned(), document);
        self.publish_workspace(uri)
    }

    fn did_change(&mut self, params: &Value) -> Vec<Value> {
        let Some(item) = params.get("textDocument") else {
            return Vec::new();
        };
        let (Some(uri), Some(version)) = (
            item.get("uri").and_then(Value::as_str),
            item.get("version").and_then(Value::as_i64),
        ) else {
            return Vec::new();
        };
        let Some(document) = self.documents.get_mut(uri) else {
            return Vec::new();
        };
        if version <= document.version {
            return Vec::new();
        }
        let Some(changes) = params.get("contentChanges").and_then(Value::as_array) else {
            return Vec::new();
        };
        let mut text = document.text.clone();
        if apply_content_changes(&mut text, changes).is_err() {
            return Vec::new();
        }
        document.text = text;
        document.version = version;
        self.publish_workspace(uri)
    }

    fn did_close(&mut self, params: &Value) -> Vec<Value> {
        let Ok(uri) = text_document_uri(params) else {
            return Vec::new();
        };
        self.documents.remove(uri);
        if !self.observed.is_closed(uri) {
            return Vec::new();
        }
        vec![json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": []},
        })]
    }

    fn publish(&self, uri: &str) -> Option<Value> {
        let document = self.documents.get(uri)?;
        let cancellation = self
            .observed
            .start_analysis(&document.uri, document.version)?;
        let diagnostics = self.diagnostics(document, &cancellation);
        self.observed
            .finish_analysis(&document.uri, document.version);
        if !self.observed.is_current(&document.uri, document.version) {
            return None;
        }
        Some(json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": uri,
                "version": document.version,
                "diagnostics": diagnostics,
            },
        }))
    }

    fn publish_workspace(&self, uri: &str) -> Vec<Value> {
        let Some(workspace) = self.documents.get(uri).map(|document| &document.workspace) else {
            return Vec::new();
        };
        self.documents
            .values()
            .filter(|document| &document.workspace == workspace)
            .filter_map(|document| self.publish(&document.uri))
            .collect()
    }

    fn diagnostics(&self, document: &Document, cancellation: &CancellationToken) -> Vec<Value> {
        let syntax = YamlDocument::parse(
            document.logical_path.clone(),
            &document.text,
            Budget::default(),
        );
        if !syntax.problems().is_empty() {
            return syntax
                .problems()
                .iter()
                .map(|problem| {
                    json!({
                        "range": lsp_range(&problem.span, &document.text),
                        "severity": 1,
                        "code": problem.code,
                        "source": "workflow-verifier",
                        "message": problem.message,
                    })
                })
                .collect();
        }
        self.analysis(document, cancellation)
            .map(|result| {
                result
                    .report
                    .diagnostics()
                    .iter()
                    .filter(|diagnostic| diagnostic.span.file == document.logical_path)
                    .map(|diagnostic| lsp_diagnostic(diagnostic, &document.text))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn analysis(
        &self,
        document: &Document,
        cancellation: &CancellationToken,
    ) -> Result<workflow_verifier_engine::AnalysisResult, String> {
        self.analysis_with_text(document, None, cancellation)
    }

    fn analysis_with_text(
        &self,
        document: &Document,
        replacement: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<workflow_verifier_engine::AnalysisResult, String> {
        let replacements = replacement.map_or_else(BTreeMap::new, |source| {
            BTreeMap::from([(document.uri.clone(), source.to_owned())])
        });
        self.analysis_with_replacements(document, &replacements, cancellation)
    }

    fn analysis_with_replacements(
        &self,
        document: &Document,
        replacements: &BTreeMap<String, String>,
        cancellation: &CancellationToken,
    ) -> Result<workflow_verifier_engine::AnalysisResult, String> {
        self.observed
            .track_analysis(&document.uri, document.version, cancellation);
        let result = (|| {
            let mut sources = BTreeMap::new();
            for candidate in self
                .documents
                .values()
                .filter(|candidate| candidate.workspace == document.workspace)
            {
                let text = replacements
                    .get(&candidate.uri)
                    .map_or(candidate.text.as_str(), String::as_str);
                let syntax =
                    YamlDocument::parse(candidate.logical_path.clone(), text, Budget::default());
                if candidate.uri == document.uri
                    || (syntax.root().is_some() && syntax.invalid_regions().is_empty())
                {
                    sources.insert(candidate.logical_path.clone(), text.as_bytes().to_vec());
                }
            }
            let snapshot = SourceSnapshot::new(sources).map_err(|error| error.to_string())?;
            self.engine
                .analyze(&AnalysisRequest {
                    snapshot,
                    overlays: BTreeMap::new(),
                    roots: None,
                    config: ConfigSnapshot::default(),
                    lock: LockSnapshot::default(),
                    persona: Persona::Audit,
                    budget: Budget::default(),
                    cancellation: cancellation.clone(),
                    worker_count: 1,
                    strict: false,
                })
                .map_err(|error| error.to_string())
        })();
        self.observed
            .finish_analysis(&document.uri, document.version);
        result
    }

    fn hover(&self, params: &Value, cancellation: &CancellationToken) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let byte = request_byte(params, &document.text)?;
        if let Some(diagnostic) = self
            .analysis(document, cancellation)
            .ok()
            .into_iter()
            .flat_map(|result| result.report.diagnostics())
            .find(|diagnostic| {
                diagnostic.span.file == document.logical_path && diagnostic.span.contains(byte)
            })
        {
            let trace = diagnostic
                .trace
                .iter()
                .map(|hop| hop.label.as_str())
                .collect::<Vec<_>>()
                .join(" → ");
            return Ok(json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!(
                        "**{}** — {}\n\nConfidence: {}\n\nTrace: {}",
                        diagnostic.rule_id,
                        diagnostic.message,
                        diagnostic.confidence.name(),
                        trace
                    ),
                },
                "range": lsp_range(&diagnostic.span, &document.text),
            }));
        }
        Ok(Value::Null)
    }

    fn document_symbols(
        &self,
        params: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let result = self.analysis(document, cancellation)?;
        Ok(Value::Array(
            result
                .symbols
                .iter()
                .filter(|symbol| symbol.path == document.logical_path)
                .map(|symbol| {
                    json!({
                        "name": symbol.name,
                        "detail": symbol.kind,
                        "kind": symbol_kind(&symbol.kind),
                        "range": lsp_range(&symbol.span, &document.text),
                        "selectionRange": lsp_range(&symbol.span, &document.text),
                    })
                })
                .collect(),
        ))
    }

    fn workspace_symbols(&self, cancellation: &CancellationToken) -> Value {
        let mut symbols = Vec::new();
        for document in self.documents.values() {
            if cancellation.is_cancelled() {
                break;
            }
            if let Ok(result) = self.analysis(document, cancellation) {
                symbols.extend(result.symbols.iter().map(|symbol| {
                    json!({
                        "name": symbol.name,
                        "kind": symbol_kind(&symbol.kind),
                        "location": {
                            "uri": document.uri,
                            "range": lsp_range(&symbol.span, &document.text),
                        },
                    })
                }));
            }
        }
        Value::Array(symbols)
    }

    fn definition(&self, params: &Value) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let byte = request_byte(params, &document.text)?;
        let Some((word, _, _)) = word_at(&document.text, byte) else {
            return Ok(Value::Null);
        };
        if !(word.starts_with("./") || word.starts_with("../")) {
            return Ok(Value::Null);
        }
        let target = word
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_owned();
        let match_uri = self.documents.values().find(|candidate| {
            candidate.workspace == document.workspace
                && (candidate.logical_path == target
                    || candidate.logical_path == format!("{target}/action.yml")
                    || candidate.logical_path == format!("{target}/action.yaml"))
        });
        Ok(match_uri.map_or(
            Value::Null,
            |candidate| json!({"uri": candidate.uri, "range": zero_range()}),
        ))
    }

    fn references(&self, params: &Value) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let byte = request_byte(params, &document.text)?;
        let Some((word, _, _)) = word_at(&document.text, byte) else {
            return Ok(json!([]));
        };
        Ok(Value::Array(
            self.word_locations(&document.workspace, &word),
        ))
    }

    fn semantic_tokens(&self, params: &Value) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let result_id = token_result_id(document);
        let data = semantic_token_data(&document.text);
        self.semantic_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(result_id.clone(), data.clone());
        Ok(json!({"resultId": result_id, "data": data}))
    }

    fn semantic_token_delta(&self, params: &Value) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let current = token_result_id(document);
        if params.get("previousResultId").and_then(Value::as_str) == Some(&current) {
            Ok(json!({"resultId": current, "edits": []}))
        } else {
            let data = semantic_token_data(&document.text);
            let previous = params
                .get("previousResultId")
                .and_then(Value::as_str)
                .and_then(|id| {
                    self.semantic_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(id)
                        .cloned()
                });
            self.semantic_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(current.clone(), data.clone());
            Ok(previous.map_or_else(
                || json!({"resultId": current, "data": data}),
                |previous| {
                    json!({
                        "resultId": current,
                        "edits": [{"start": 0, "deleteCount": previous.len(), "data": data}],
                    })
                },
            ))
        }
    }

    fn prepare_rename(&self, params: &Value) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let byte = request_byte(params, &document.text)?;
        let (word, start, stop) = rename_word(&document.text, byte)?;
        if !self.rename_allowed(document, &word) {
            return Err(
                "rename requires a fully static local declaration and references".to_owned(),
            );
        }
        Ok(json!({
            "range": byte_range(&document.text, start, stop),
            "placeholder": word,
        }))
    }

    fn rename(&self, params: &Value, cancellation: &CancellationToken) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let byte = request_byte(params, &document.text)?;
        let (word, _, _) = rename_word(&document.text, byte)?;
        if !self.rename_allowed(document, &word) {
            return Err(
                "rename requires a fully static local declaration and references".to_owned(),
            );
        }
        let new_name = params
            .get("newName")
            .and_then(Value::as_str)
            .ok_or_else(|| "rename requires newName".to_owned())?;
        if !identifier(new_name) {
            return Err("newName is not a portable static identifier".to_owned());
        }
        let locations = self.word_edits(&document.workspace, &word);
        if locations.is_empty() {
            return Err("rename has no static local references".to_owned());
        }
        let before = self.analysis(document, cancellation)?;
        let mut replacements = BTreeMap::new();
        for (candidate, edits) in &locations {
            if cancellation.is_cancelled() {
                return Err("request cancelled".to_owned());
            }
            let mut staged = candidate.text.clone();
            for (start, stop) in edits.iter().rev() {
                staged.replace_range(*start..*stop, new_name);
            }
            let parsed =
                YamlDocument::parse(candidate.logical_path.clone(), &staged, Budget::default());
            let original = YamlDocument::parse(
                candidate.logical_path.clone(),
                &candidate.text,
                Budget::default(),
            );
            let problem_set = |document: &YamlDocument| {
                document
                    .problems()
                    .iter()
                    .map(|problem| (problem.code.clone(), problem.message.clone()))
                    .collect::<BTreeSet<_>>()
            };
            if parsed.root().is_none()
                || !parsed.invalid_regions().is_empty()
                || problem_set(&parsed) != problem_set(&original)
            {
                return Err("rename could not be re-proved after YAML parsing".to_owned());
            }
            replacements.insert(candidate.uri.clone(), staged);
        }
        let after = self.analysis_with_replacements(document, &replacements, cancellation)?;
        let before_projection = analysis_projection(&before, None);
        let after_projection = analysis_projection(&after, Some((new_name, &word)));
        if before_projection != after_projection {
            return Err("rename could not be re-proved without semantic changes".to_owned());
        }
        let document_changes = locations
            .into_iter()
            .map(|(candidate, edits)| {
                let edits = edits
                    .into_iter()
                    .map(|(start, stop)| {
                        json!({
                            "range": byte_range(&candidate.text, start, stop),
                            "newText": new_name,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "textDocument": {"uri": candidate.uri, "version": candidate.version},
                    "edits": edits,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({"documentChanges": document_changes}))
    }

    fn code_actions(
        &self,
        params: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, String> {
        let uri = text_document_uri(params)?;
        let document = self.document(uri)?;
        let before = self.analysis(document, cancellation)?;
        let unused = before
            .report
            .diagnostics()
            .iter()
            .filter(|diagnostic| {
                diagnostic.span.file == document.logical_path && diagnostic.rule_id == "WV-PERM-001"
            })
            .flat_map(|diagnostic| diagnostic.capabilities.iter().copied())
            .collect::<BTreeSet<_>>();
        if !unused.contains(&Capability::RepositoryWrite)
            || !unused.contains(&Capability::TokenWrite)
        {
            return Ok(json!([]));
        }
        let parsed = YamlDocument::parse(
            document.logical_path.clone(),
            &document.text,
            Budget::default(),
        );
        let Some(proposal) = FixProposal::reduce_write_all(
            &parsed,
            &[Capability::RepositoryWrite, Capability::TokenWrite],
        ) else {
            return Ok(json!([]));
        };
        let after = proposal
            .apply_verified(&parsed, |candidate| {
                let staged = self.analysis_with_text(document, Some(candidate), cancellation)?;
                let before_severe = severe_diagnostics(&before);
                if severe_diagnostics(&staged)
                    .difference(&before_severe)
                    .next()
                    .is_some()
                {
                    Err("quick fix introduced a critical/error diagnostic".to_owned())
                } else {
                    Ok(())
                }
            })
            .map_err(|error| format!("quick fix could not be re-proved: {error}"))?;
        let edits = proposal
            .edits
            .iter()
            .map(|edit| {
                json!({
                    "range": byte_range(&document.text, edit.start_byte, edit.stop_byte),
                    "newText": edit.replacement,
                })
            })
            .collect::<Vec<_>>();
        if after == document.text {
            return Ok(json!([]));
        }
        Ok(json!([{
            "title": proposal.description,
            "kind": "quickfix",
            "isPreferred": true,
            "edit": {
                "documentChanges": [{
                    "textDocument": {"uri": document.uri, "version": document.version},
                    "edits": edits,
                }]
            }
        }]))
    }

    fn word_locations(&self, workspace: &str, word: &str) -> Vec<Value> {
        self.documents
            .values()
            .filter(|document| document.workspace == workspace)
            .flat_map(|document| {
                word_spans(&document.text, word)
                    .into_iter()
                    .map(|(start, stop)| {
                        json!({
                            "uri": document.uri,
                            "range": byte_range(&document.text, start, stop),
                        })
                    })
            })
            .collect()
    }

    fn word_edits<'a>(
        &'a self,
        workspace: &str,
        word: &str,
    ) -> Vec<(&'a Document, Vec<(usize, usize)>)> {
        self.documents
            .values()
            .filter(|document| document.workspace == workspace)
            .filter_map(|document| {
                let spans = word_spans(&document.text, word);
                (!spans.is_empty()).then_some((document, spans))
            })
            .collect()
    }

    fn rename_allowed(&self, document: &Document, word: &str) -> bool {
        let mut declaration = false;
        let mut any = false;
        for candidate in self
            .documents
            .values()
            .filter(|candidate| candidate.workspace == document.workspace)
        {
            for (start, stop) in word_spans(&candidate.text, word) {
                any = true;
                let line_start = candidate.text[..start]
                    .rfind('\n')
                    .map_or(0, |offset| offset + 1);
                let line_end = candidate.text[stop..]
                    .find('\n')
                    .map_or(candidate.text.len(), |offset| stop + offset);
                let before = &candidate.text[line_start..start];
                let after = &candidate.text[stop..line_end];
                let indent = before.len().saturating_sub(before.trim_start().len());
                let job_declaration = candidate.logical_path.starts_with(".github/workflows/")
                    && indent == 2
                    && before.trim().is_empty()
                    && after.trim_start().starts_with(':');
                let id_declaration = before.trim_end().ends_with("id:");
                let reference = before.trim_end().ends_with("needs:")
                    || before.trim_end().ends_with("needs.")
                    || (before.contains("needs:") && (before.contains('[') || after.contains(']')));
                if job_declaration || id_declaration {
                    declaration = true;
                } else if !reference {
                    return false;
                }
            }
        }
        any && declaration
    }
}

/// Run the LSP server on process stdio.
#[must_use]
pub fn run_stdio() -> i32 {
    match serve(BufReader::new(io::stdin()), io::stdout()) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "workflow-verifier lsp: {error}");
            2
        }
    }
}

enum InputEvent {
    Message(Value),
    Error(String),
    End,
}

fn serve(mut input: impl BufRead + Send + 'static, mut output: impl Write) -> Result<(), String> {
    let cancellations = Arc::new(RequestCancellations::default());
    let reader_cancellations = Arc::clone(&cancellations);
    let observed = Arc::new(ObservedDocuments::default());
    let reader_observed = Arc::clone(&observed);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        loop {
            match read_message(&mut input) {
                Ok(Some(message)) => {
                    reader_observed.observe(&message);
                    if message.get("method").and_then(Value::as_str) == Some("$/cancelRequest")
                        && let Some(id) = message.get("params").and_then(|params| params.get("id"))
                    {
                        reader_cancellations.cancel(id);
                    }
                    if sender.send(InputEvent::Message(message)).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = sender.send(InputEvent::End);
                    break;
                }
                Err(error) => {
                    let _ = sender.send(InputEvent::Error(error));
                    break;
                }
            }
        }
    });
    let mut server = Server::new(cancellations, observed);
    loop {
        match receiver
            .recv()
            .map_err(|_| "LSP input reader disconnected".to_owned())?
        {
            InputEvent::Message(message) => {
                let exit = message.get("method").and_then(Value::as_str) == Some("exit");
                for response in server.handle(&message) {
                    write_message(&mut output, &response)?;
                }
                if exit {
                    return if server.shutdown {
                        Ok(())
                    } else {
                        Err("exit received before shutdown".to_owned())
                    };
                }
            }
            InputEvent::Error(error) => return Err(error),
            InputEvent::End => return Ok(()),
        }
    }
}

fn read_message(input: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut content_length = None;
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let count = input
            .read_line(&mut line)
            .map_err(|error| format!("LSP header read failed: {error}"))?;
        if count == 0 {
            return if header_bytes == 0 {
                Ok(None)
            } else {
                Err("LSP header ended unexpectedly".to_owned())
            };
        }
        header_bytes = header_bytes.saturating_add(count);
        if header_bytes > MAX_HEADER_BYTES {
            return Err("LSP header exceeded byte limit".to_owned());
        }
        if line == "\r\n" {
            break;
        }
        let line = line
            .strip_suffix("\r\n")
            .ok_or_else(|| "LSP headers require CRLF".to_owned())?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed LSP header".to_owned())?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err("duplicate LSP Content-Length".to_owned());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid LSP Content-Length".to_owned())?,
            );
        }
    }
    let length = content_length.ok_or_else(|| "LSP Content-Length is required".to_owned())?;
    if length > MAX_MESSAGE_BYTES {
        return Err("LSP message exceeded byte limit".to_owned());
    }
    let mut body = vec![0; length];
    input
        .read_exact(&mut body)
        .map_err(|error| format!("LSP body read failed: {error}"))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| format!("invalid LSP JSON: {error}"))
}

fn write_message(output: &mut impl Write, message: &Value) -> Result<(), String> {
    let body =
        serde_json::to_vec(message).map_err(|error| format!("LSP encode failed: {error}"))?;
    write!(output, "Content-Length: {}\r\n\r\n", body.len())
        .and_then(|()| output.write_all(&body))
        .and_then(|()| output.flush())
        .map_err(|error| format!("LSP write failed: {error}"))
}

fn initialize_result() -> Value {
    json!({
        "serverInfo": {"name": "workflow-verifier", "version": "0.1.0"},
        "capabilities": {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": true, "change": 2, "save": {"includeText": false}},
            "diagnosticProvider": {"identifier": "workflow-verifier", "interFileDependencies": true, "workspaceDiagnostics": true},
            "completionProvider": {"resolveProvider": false, "triggerCharacters": [":", "@", ".", "$", "{"]},
            "hoverProvider": true,
            "documentSymbolProvider": true,
            "workspaceSymbolProvider": true,
            "definitionProvider": true,
            "referencesProvider": true,
            "semanticTokensProvider": {
                "legend": {"tokenTypes": ["keyword", "string", "variable", "function", "property", "operator", "comment"], "tokenModifiers": ["declaration", "readonly"]},
                "full": {"delta": true}
            },
            "renameProvider": {"prepareProvider": true},
            "codeActionProvider": {"codeActionKinds": ["quickfix"], "resolveProvider": false},
            "workspace": {"workspaceFolders": {"supported": true, "changeNotifications": true}},
        }
    })
}

fn success_response(id: &Value, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_else(|_| "null".to_owned())
}

fn text_document_uri(params: &Value) -> Result<&str, String> {
    params
        .get("textDocument")
        .and_then(|value| value.get("uri"))
        .and_then(Value::as_str)
        .ok_or_else(|| "request requires textDocument.uri".to_owned())
}

fn logical_identity(uri: &str) -> (String, String) {
    for marker in ["/.github/", "/.circleci/"] {
        if let Some(index) = uri.find(marker) {
            return (uri[..index].to_owned(), uri[index + 1..].to_owned());
        }
    }
    for name in [
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
    ] {
        if uri.ends_with(name) {
            let workspace = uri
                .strip_suffix(name)
                .unwrap_or(uri)
                .trim_end_matches('/')
                .to_owned();
            return (workspace, name.to_owned());
        }
    }
    let (workspace, filename) = uri
        .rsplit_once('/')
        .map_or(("", "document.yml"), |(parent, name)| (parent, name));
    (workspace.to_owned(), filename.to_owned())
}

fn severe_diagnostics(
    result: &workflow_verifier_engine::AnalysisResult,
) -> BTreeSet<(String, String)> {
    result
        .report
        .diagnostics()
        .into_iter()
        .filter(|diagnostic| matches!(diagnostic.severity, Severity::Critical | Severity::Error))
        .map(|diagnostic| (diagnostic.rule_id, diagnostic.message))
        .collect()
}

fn request_byte(params: &Value, source: &str) -> Result<usize, String> {
    let position = params
        .get("position")
        .ok_or_else(|| "request requires position".to_owned())?;
    let line = position
        .get("line")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "position.line is invalid".to_owned())?;
    let character = position
        .get("character")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "position.character is invalid".to_owned())?;
    utf16_to_byte(source, Utf16Position { line, character })
}

fn byte_range(source: &str, start: usize, stop: usize) -> Value {
    let start = byte_to_utf16(source, start).unwrap_or(Utf16Position {
        line: 0,
        character: 0,
    });
    let stop = byte_to_utf16(source, stop).unwrap_or(start);
    json!({
        "start": {"line": start.line, "character": start.character},
        "end": {"line": stop.line, "character": stop.character},
    })
}

fn lsp_range(span: &Span, source: &str) -> Value {
    byte_range(
        source,
        span.start.byte.min(source.len()),
        span.stop.byte.min(source.len()),
    )
}

fn zero_range() -> Value {
    json!({"start":{"line":0,"character":0},"end":{"line":0,"character":0}})
}

fn lsp_diagnostic(diagnostic: &Diagnostic, source: &str) -> Value {
    json!({
        "range": lsp_range(&diagnostic.span, source),
        "severity": match diagnostic.severity {
            Severity::Critical | Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Note => 3,
        },
        "code": diagnostic.rule_id,
        "source": "workflow-verifier",
        "message": diagnostic.message,
        "data": {
            "id": diagnostic.id,
            "confidence": diagnostic.confidence.name(),
            "trace": diagnostic.trace.iter().map(|hop| &hop.label).collect::<Vec<_>>(),
        },
    })
}

fn completions(document: &Document) -> Value {
    let labels: &[&str] = if document.logical_path.contains(".gitlab-ci") {
        &["script", "stage", "needs", "rules", "include", "image"]
    } else if document.logical_path.contains("azure-pipelines") {
        &["steps", "jobs", "stages", "task", "template", "condition"]
    } else if document.logical_path.contains(".circleci") {
        &["jobs", "workflows", "steps", "run", "uses", "orbs"]
    } else {
        &["uses", "run", "permissions", "if", "needs", "env", "with"]
    };
    let items = labels
        .iter()
        .map(|label| json!({"label": label, "kind": 10, "insertText": format!("{label}: ")}))
        .collect::<Vec<_>>();
    json!({"isIncomplete": false, "items": items})
}

fn symbol_kind(kind: &str) -> i64 {
    match kind {
        "workflow" => 2,
        "job" | "stage" => 5,
        "step" | "command" | "call" => 12,
        _ => 13,
    }
}

fn token_result_id(document: &Document) -> String {
    content_digest(format!("{}\0{}", document.version, document.text))
}

fn semantic_token_data(source: &str) -> Vec<u32> {
    let mut tokens = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let Some(line_number) = u32::try_from(line_index).ok() else {
            break;
        };
        if let Some(comment) = line.find('#') {
            push_token(&mut tokens, line_number, line, comment, line.len(), 6);
        }
        if let Some(colon) = line.find(':') {
            let start = line.len().saturating_sub(line.trim_start().len());
            if start < colon {
                push_token(&mut tokens, line_number, line, start, colon, 4);
            }
        }
        let mut cursor = 0;
        while let Some(relative) = line[cursor..].find("${{") {
            let start = cursor + relative;
            let stop = line[start..]
                .find("}}")
                .map_or(line.len(), |value| start + value + 2);
            push_token(&mut tokens, line_number, line, start, stop, 2);
            cursor = stop;
        }
    }
    tokens.sort_by_key(|token| (token.0, token.1));
    let mut encoded = Vec::new();
    let mut previous_line = 0;
    let mut previous_start = 0;
    for (line, start, length, kind) in tokens {
        let delta_line = line.saturating_sub(previous_line);
        let delta_start = if delta_line == 0 {
            start.saturating_sub(previous_start)
        } else {
            start
        };
        encoded.extend([delta_line, delta_start, length, kind, 0]);
        previous_line = line;
        previous_start = start;
    }
    encoded
}

fn push_token(
    output: &mut Vec<(u32, u32, u32, u32)>,
    line_number: u32,
    line: &str,
    start: usize,
    stop: usize,
    kind: u32,
) {
    let prefix = &line[..start.min(line.len())];
    let value = &line[start.min(line.len())..stop.min(line.len())];
    let start = u32::try_from(prefix.encode_utf16().count()).unwrap_or(u32::MAX);
    let length = u32::try_from(value.encode_utf16().count()).unwrap_or(u32::MAX);
    if length > 0 {
        output.push((line_number, start, length, kind));
    }
}

fn word_at(source: &str, byte: usize) -> Option<(String, usize, usize)> {
    if byte > source.len() || !source.is_char_boundary(byte) {
        return None;
    }
    let allowed = |value: u8| {
        value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.' | b'/' | b'@')
    };
    let bytes = source.as_bytes();
    let mut start = byte;
    while start > 0 && allowed(bytes[start - 1]) {
        start -= 1;
    }
    let mut stop = byte;
    while stop < bytes.len() && allowed(bytes[stop]) {
        stop += 1;
    }
    (start < stop).then(|| (source[start..stop].to_owned(), start, stop))
}

fn rename_word(source: &str, byte: usize) -> Result<(String, usize, usize), String> {
    let (word, start, stop) = word_at(source, byte)
        .ok_or_else(|| "rename requires a static local identifier".to_owned())?;
    if !identifier(&word) || matches!(word.as_str(), "on" | "jobs" | "steps" | "uses" | "run") {
        return Err("rename is unsafe for dynamic, remote, or structural YAML names".to_owned());
    }
    Ok((word, start, stop))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn analysis_projection(result: &AnalysisResult, rename: Option<(&str, &str)>) -> Vec<String> {
    let mut graphs =
        result
            .report
            .graphs
            .iter()
            .map(|graph| {
                let mut node_values = BTreeMap::new();
                for node in &graph.nodes {
                    let mut value = node.to_json();
                    if let JsonValue::Object(fields) = &mut value {
                        fields.remove("id");
                        fields.remove("span");
                        if let Some(name) = fields.get_mut("name") {
                            normalize_identifier_value(name, rename);
                        }
                        if let Some(condition) = fields.get_mut("condition") {
                            normalize_identifier_value(condition, rename);
                        }
                    }
                    remove_analysis_spans(&mut value);
                    node_values.insert(node.id.as_str(), value);
                }

                let mut nodes = node_values.values().cloned().collect::<Vec<_>>();
                nodes.sort_by_cached_key(JsonValue::canonical);

                let mut edges =
                    graph
                        .edges
                        .iter()
                        .map(|edge| {
                            let mut condition = edge.condition.to_json();
                            normalize_identifier_value(&mut condition, rename);
                            let label = edge
                                .label
                                .clone()
                                .map_or(JsonValue::Null, JsonValue::String);
                            JsonValue::Object(BTreeMap::from([
                                ("condition".to_owned(), condition),
                                (
                                    "from".to_owned(),
                                    node_values.get(edge.from.as_str()).cloned().unwrap_or_else(
                                        || JsonValue::String(format!("missing:{}", edge.from)),
                                    ),
                                ),
                                (
                                    "kind".to_owned(),
                                    JsonValue::String(edge.kind.name().to_owned()),
                                ),
                                ("label".to_owned(), label),
                                (
                                    "to".to_owned(),
                                    node_values.get(edge.to.as_str()).cloned().unwrap_or_else(
                                        || JsonValue::String(format!("missing:{}", edge.to)),
                                    ),
                                ),
                            ]))
                        })
                        .collect::<Vec<_>>();
                edges.sort_by_cached_key(JsonValue::canonical);

                let mut entrypoints = graph
                    .entrypoints
                    .iter()
                    .map(|id| {
                        node_values
                            .get(id.as_str())
                            .cloned()
                            .unwrap_or_else(|| JsonValue::String(format!("missing:{id}")))
                    })
                    .collect::<Vec<_>>();
                entrypoints.sort_by_cached_key(JsonValue::canonical);

                JsonValue::Object(BTreeMap::from([
                    ("edges".to_owned(), JsonValue::Array(edges)),
                    ("entrypoints".to_owned(), JsonValue::Array(entrypoints)),
                    ("nodes".to_owned(), JsonValue::Array(nodes)),
                    (
                        "provider".to_owned(),
                        JsonValue::String(graph.provider.name().to_owned()),
                    ),
                    ("source".to_owned(), JsonValue::String(graph.source.clone())),
                ]))
                .canonical()
            })
            .collect::<Vec<_>>();
    graphs.sort();
    graphs
}

fn normalize_identifier_value(value: &mut JsonValue, rename: Option<(&str, &str)>) {
    match value {
        JsonValue::String(text) => {
            if let Some((new_name, old_name)) = rename {
                for (start, stop) in word_spans(text, new_name).into_iter().rev() {
                    text.replace_range(start..stop, old_name);
                }
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                normalize_identifier_value(value, rename);
            }
        }
        JsonValue::Object(fields) => {
            for value in fields.values_mut() {
                normalize_identifier_value(value, rename);
            }
        }
        JsonValue::Null | JsonValue::Boolean(_) | JsonValue::Integer(_) => {}
    }
}

fn remove_analysis_spans(value: &mut JsonValue) {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                remove_analysis_spans(value);
            }
        }
        JsonValue::Object(fields) => {
            fields.remove("span");
            for value in fields.values_mut() {
                remove_analysis_spans(value);
            }
        }
        JsonValue::Null | JsonValue::Boolean(_) | JsonValue::Integer(_) | JsonValue::String(_) => {}
    }
}

fn word_spans(source: &str, word: &str) -> Vec<(usize, usize)> {
    if word.is_empty() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find(word) {
        let start = cursor + relative;
        let stop = start + word.len();
        let boundary = |byte: Option<u8>| {
            byte.is_none_or(|value| {
                !(value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-'))
            })
        };
        if boundary(
            start
                .checked_sub(1)
                .and_then(|index| source.as_bytes().get(index).copied()),
        ) && boundary(source.as_bytes().get(stop).copied())
        {
            spans.push((start, stop));
        }
        cursor = stop;
    }
    spans
}

fn apply_content_changes(source: &mut String, changes: &[Value]) -> Result<(), String> {
    for change in changes {
        let text = change
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| "content change requires text".to_owned())?;
        let Some(range) = change.get("range") else {
            text.clone_into(source);
            continue;
        };
        let start = protocol_position(range.get("start"))?;
        let stop = protocol_position(range.get("end"))?;
        let start = utf16_to_byte(source, start)?;
        let stop = utf16_to_byte(source, stop)?;
        if start > stop {
            return Err("content change range is reversed".to_owned());
        }
        source.replace_range(start..stop, text);
    }
    Ok(())
}

fn protocol_position(value: Option<&Value>) -> Result<Utf16Position, String> {
    let value = value.ok_or_else(|| "range position is missing".to_owned())?;
    let line = value
        .get("line")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "range line is invalid".to_owned())?;
    let character = value
        .get("character")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "range character is invalid".to_owned())?;
    Ok(Utf16Position { line, character })
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn late_cancellation_does_not_poison_a_reused_request_id() {
        let cancellations = RequestCancellations::default();
        let id = json!(7);
        let first = cancellations.start(&id);
        assert!(!first.is_cancelled());
        cancellations.finish(&id);

        cancellations.cancel(&id);
        let reused = cancellations.start(&id);
        assert!(!reused.is_cancelled());
        cancellations.finish(&id);
    }

    #[test]
    fn cancellation_observed_before_request_start_is_retained() {
        let cancellations = RequestCancellations::default();
        let id = json!(8);
        cancellations.cancel(&id);
        let request = cancellations.start(&id);
        assert!(request.is_cancelled());
        cancellations.finish(&id);
    }

    #[test]
    fn completed_request_history_is_bounded() {
        let cancellations = RequestCancellations::default();
        for id in 0..MAX_COMPLETED_REQUEST_IDS + 32 {
            let id = json!(id);
            let request = cancellations.start(&id);
            assert!(!request.is_cancelled());
            cancellations.finish(&id);
        }
        let state = cancellations
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.completed.len(), MAX_COMPLETED_REQUEST_IDS);
        assert_eq!(state.completed_order.len(), MAX_COMPLETED_REQUEST_IDS);
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod performance_tests {
    use super::*;
    use std::fmt::Write as _;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    fn large_workflow(marker: usize) -> String {
        let mut source = "on: push\njobs:\n".to_owned();
        for index in 0..900 {
            writeln!(
                source,
                "  job_{index}:\n    steps:\n      - run: echo {index}_{marker:02}"
            )
            .expect("writing to a String cannot fail");
        }
        source
    }

    fn large_workflow_with_local_action() -> String {
        let mut source = "on: push\njobs:\n".to_owned();
        for index in 0..900 {
            if index == 0 {
                writeln!(
                    source,
                    "  job_{index}:\n    steps:\n      - uses: ./.github/actions/demo"
                )
                .expect("writing to a String cannot fail");
            } else {
                writeln!(
                    source,
                    "  job_{index}:\n    steps:\n      - run: echo {index}"
                )
                .expect("writing to a String cannot fail");
            }
        }
        source
    }

    #[test]
    #[ignore = "pinned release-mode LSP performance gate"]
    fn edit_to_diagnostics_p95_is_at_most_150_milliseconds() {
        let uri = "file:///workspace/.github/workflows/large.yml";
        let cancellations = Arc::new(RequestCancellations::default());
        let observed = Arc::new(ObservedDocuments::default());
        let mut server = Server::new(cancellations, observed);
        server.documents.insert(
            uri.to_owned(),
            Document {
                uri: uri.to_owned(),
                workspace: "file:///workspace".to_owned(),
                logical_path: ".github/workflows/large.yml".to_owned(),
                version: 0,
                text: large_workflow(0),
            },
        );
        let document = server.documents.get(uri).expect("fixture document");
        black_box(server.diagnostics(document, &CancellationToken::new()));

        let mut samples = Vec::new();
        for marker in 1..=20 {
            let document = server
                .documents
                .get_mut(uri)
                .expect("fixture document remains open");
            document.version = i64::try_from(marker).expect("bounded marker");
            document.text = large_workflow(marker);
            let document = server.documents.get(uri).expect("fixture document");
            let started = Instant::now();
            black_box(server.diagnostics(document, &CancellationToken::new()));
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p95 = samples[18];
        eprintln!("900-node edit-to-diagnostics p95: {p95:?}");
        assert!(
            p95 <= Duration::from_millis(150),
            "900-node edit-to-diagnostics p95 was {p95:?}; samples={samples:?}"
        );
    }

    #[test]
    #[ignore = "pinned release-mode LSP performance gate"]
    fn cancellation_is_observed_within_50_milliseconds() {
        let uri = "file:///workspace/.github/workflows/cancel.yml";
        let cancellations = Arc::new(RequestCancellations::default());
        let observed = Arc::new(ObservedDocuments::default());
        let mut server = Server::new(cancellations, observed);
        server.documents.insert(
            uri.to_owned(),
            Document {
                uri: uri.to_owned(),
                workspace: "file:///workspace".to_owned(),
                logical_path: ".github/workflows/cancel.yml".to_owned(),
                version: 0,
                text: large_workflow(0),
            },
        );

        let mut samples = Vec::new();
        for marker in 1..=20 {
            let document = server
                .documents
                .get_mut(uri)
                .expect("fixture document remains open");
            document.version = i64::try_from(marker).expect("bounded marker");
            document.text = large_workflow(marker);
            let document = server.documents.get(uri).expect("fixture document");
            let cancellation = CancellationToken::new();
            let result = std::thread::scope(|scope| {
                let worker_token = cancellation.clone();
                let (sender, receiver) = std::sync::mpsc::channel();
                scope.spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let cancelled_at = Instant::now();
                    worker_token.cancel();
                    sender
                        .send(cancelled_at)
                        .expect("test receiver remains live");
                });
                let result = server.analysis(document, &cancellation);
                let cancelled_at = receiver.recv().expect("cancellation timestamp");
                (result, cancelled_at.elapsed())
            });
            assert!(
                result.0.is_err(),
                "analysis completed before the cancellation was observed"
            );
            samples.push(result.1);
        }
        samples.sort_unstable();
        let p95 = samples[18];
        eprintln!("900-node cancellation p95: {p95:?}");
        assert!(
            p95 <= Duration::from_millis(50),
            "cancellation p95 was {p95:?}; samples={samples:?}"
        );
    }

    #[test]
    #[ignore = "pinned release-mode LSP performance gate"]
    fn transitive_invalidation_p95_is_at_most_500_milliseconds() {
        let workflow_uri = "file:///workspace/.github/workflows/local.yml";
        let action_uri = "file:///workspace/.github/actions/demo/action.yml";
        let cancellations = Arc::new(RequestCancellations::default());
        let observed = Arc::new(ObservedDocuments::default());
        let mut server = Server::new(cancellations, observed);
        server.documents.insert(
            workflow_uri.to_owned(),
            Document {
                uri: workflow_uri.to_owned(),
                workspace: "file:///workspace".to_owned(),
                logical_path: ".github/workflows/local.yml".to_owned(),
                version: 1,
                text: large_workflow_with_local_action(),
            },
        );
        server.documents.insert(
            action_uri.to_owned(),
            Document {
                uri: action_uri.to_owned(),
                workspace: "file:///workspace".to_owned(),
                logical_path: ".github/actions/demo/action.yml".to_owned(),
                version: 0,
                text: "name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo 00\n"
                    .to_owned(),
            },
        );
        let workflow = server
            .documents
            .get(workflow_uri)
            .expect("fixture workflow");
        let initial = server
            .analysis(workflow, &CancellationToken::new())
            .expect("initial analysis");
        let mut previous_digest = initial.report.semantic_digest;
        let mut samples = Vec::new();
        for marker in 1..=20 {
            let action = server
                .documents
                .get_mut(action_uri)
                .expect("fixture action remains open");
            action.version = i64::try_from(marker).expect("bounded marker");
            action.text = format!(
                "name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo {marker:02}\n"
            );
            let workflow = server
                .documents
                .get(workflow_uri)
                .expect("fixture workflow remains open");
            let started = Instant::now();
            let result = server
                .analysis(workflow, &CancellationToken::new())
                .expect("transitive analysis");
            samples.push(started.elapsed());
            assert_ne!(result.report.semantic_digest, previous_digest);
            previous_digest = result.report.semantic_digest;
        }
        samples.sort_unstable();
        let p95 = samples[18];
        eprintln!("900-node transitive invalidation p95: {p95:?}");
        assert!(
            p95 <= Duration::from_millis(500),
            "transitive invalidation p95 was {p95:?}; samples={samples:?}"
        );
    }
}
