use serde_json::{Value, json};
use std::fmt::Write as _;
use std::io::Write;
use std::process::{Command, Stdio};
use workflow_verifier::internal::conformance::foundation::content_digest;

fn frame(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(&value).unwrap();
    let mut output = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    output.extend(body);
    output
}

fn transcript(messages: Vec<Value>) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_workflow-verifier"))
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in messages {
        stdin.write_all(&frame(&message)).unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    decode_frames(&output.stdout)
}

fn decode_frames(mut bytes: &[u8]) -> Vec<Value> {
    let mut output = Vec::new();
    while !bytes.is_empty() {
        let boundary = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let header = std::str::from_utf8(&bytes[..boundary]).unwrap();
        let length = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let start = boundary + 4;
        output.push(serde_json::from_slice(&bytes[start..start + length]).unwrap());
        bytes = &bytes[start + length..];
    }
    output
}

fn response(messages: &[Value], id: i64) -> &Value {
    messages
        .iter()
        .find(|message| message.get("id") == Some(&json!(id)))
        .unwrap()
}

#[test]
fn stdio_lsp_handles_unsaved_partial_utf16_diagnostics_tokens_and_safe_rename() {
    let uri = "file:///workspace/.github/workflows/ci.yml";
    let source = "name: 😀\non: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
    let messages = transcript(vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"workspaceFolders":[{"uri":"file:///workspace","name":"workspace"}]}}),
        json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"yaml","version":1,"text":source}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"textDocument/diagnostic","params":{"textDocument":{"uri":uri}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"textDocument/completion","params":{"textDocument":{"uri":uri},"position":{"line":5,"character":9}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"textDocument/semanticTokens/full","params":{"textDocument":{"uri":uri}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"textDocument/prepareRename","params":{"textDocument":{"uri":uri},"position":{"line":3,"character":4}}}),
        json!({"jsonrpc":"2.0","id":6,"method":"textDocument/rename","params":{"textDocument":{"uri":uri},"position":{"line":3,"character":4},"newName":"compile"}}),
        json!({"jsonrpc":"2.0","id":7,"method":"textDocument/prepareRename","params":{"textDocument":{"uri":uri},"position":{"line":1,"character":6}}}),
        json!({"jsonrpc":"2.0","id":8,"method":"shutdown","params":null}),
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    ]);

    let capabilities = &response(&messages, 1)["result"]["capabilities"];
    assert_eq!(capabilities["positionEncoding"], "utf-16");
    assert!(capabilities["diagnosticProvider"].is_object());
    assert!(capabilities["completionProvider"].is_object());
    assert!(capabilities["semanticTokensProvider"].is_object());
    assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);

    let published = messages
        .iter()
        .find(|message| message.get("method") == Some(&json!("textDocument/publishDiagnostics")))
        .unwrap();
    assert_eq!(published["params"]["version"], 1);
    assert!(
        published["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "WV-SUPPLY-001")
    );
    assert!(
        response(&messages, 2)["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "WV-SUPPLY-001")
    );
    assert!(
        !response(&messages, 3)["result"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !response(&messages, 4)["result"]["data"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(response(&messages, 5)["result"]["range"].is_object());
    let rename = response(&messages, 6);
    assert_eq!(
        rename["result"]["documentChanges"][0]["textDocument"]["version"], 1,
        "{rename:#}"
    );
    assert_eq!(response(&messages, 7)["error"]["code"], -32602);
    assert_eq!(response(&messages, 8)["result"], Value::Null);
}

#[test]
fn partial_yaml_completion_and_pre_cancelled_request_remain_responsive() {
    let uri = "file:///workspace/.github/workflows/partial.yml";
    let messages = transcript(vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"yaml","version":3,"text":"on: push\njobs:\n  build:\n    steps:\n      - us"}}}),
        json!({"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":9}}),
        json!({"jsonrpc":"2.0","id":9,"method":"textDocument/hover","params":{"textDocument":{"uri":uri},"position":{"line":4,"character":8}}}),
        json!({"jsonrpc":"2.0","id":10,"method":"textDocument/completion","params":{"textDocument":{"uri":uri},"position":{"line":4,"character":10}}}),
        json!({"jsonrpc":"2.0","id":12,"method":"workspace/diagnostic","params":{"previousResultIds":[]}}),
        json!({"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":12}}),
        json!({"jsonrpc":"2.0","id":11,"method":"shutdown","params":null}),
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    ]);
    assert_eq!(response(&messages, 9)["error"]["code"], -32800);
    assert!(
        response(&messages, 10)["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "uses")
    );
    assert_eq!(response(&messages, 12)["error"]["code"], -32800);
}

#[test]
fn local_navigation_incremental_sync_token_delta_and_verified_code_action_work() {
    let workflow_uri = "file:///workspace/.github/workflows/ci.yml";
    let action_uri = "file:///workspace/.github/actions/demo/action.yml";
    let source = "on: push\njobs:\n  build:\n    permissions: write-all\n    steps:\n      - uses: ./.github/actions/demo\n";
    let previous_tokens = content_digest(format!("1\0{source}"));
    let messages = transcript(vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":workflow_uri,"languageId":"yaml","version":1,"text":source}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":action_uri,"languageId":"yaml","version":1,"text":"name: demo\nruns:\n  using: composite\n  steps:\n    - run: echo local\n"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"textDocument/definition","params":{"textDocument":{"uri":workflow_uri},"position":{"line":5,"character":20}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"textDocument/references","params":{"textDocument":{"uri":workflow_uri},"position":{"line":2,"character":4},"context":{"includeDeclaration":true}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"textDocument/codeAction","params":{"textDocument":{"uri":workflow_uri},"range":{"start":{"line":3,"character":4},"end":{"line":3,"character":26}},"context":{"diagnostics":[]}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"textDocument/semanticTokens/full","params":{"textDocument":{"uri":workflow_uri}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":workflow_uri,"version":2},"contentChanges":[{"range":{"start":{"line":0,"character":4},"end":{"line":0,"character":8}},"text":"workflow_dispatch"}]}}),
        json!({"jsonrpc":"2.0","id":6,"method":"textDocument/semanticTokens/full/delta","params":{"textDocument":{"uri":workflow_uri},"previousResultId":previous_tokens}}),
        json!({"jsonrpc":"2.0","id":7,"method":"shutdown","params":null}),
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    ]);
    assert_eq!(response(&messages, 2)["result"]["uri"], action_uri);
    assert!(
        !response(&messages, 3)["result"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let actions = response(&messages, 4)["result"].as_array().unwrap();
    assert!(actions.iter().any(|action| {
        action["edit"]["documentChanges"][0]["edits"]
            .as_array()
            .is_some_and(|edits| edits.iter().any(|edit| edit["newText"] == "read-all"))
    }));
    assert!(response(&messages, 5)["result"]["resultId"].is_string());
    assert!(
        !response(&messages, 6)["result"]["edits"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let latest_publish = messages
        .iter()
        .rfind(|message| {
            message.get("method") == Some(&json!("textDocument/publishDiagnostics"))
                && message["params"]["uri"] == workflow_uri
        })
        .unwrap();
    assert_eq!(latest_publish["params"]["version"], 2);
}

#[test]
fn diagnostics_suppress_results_obsoleted_while_analysis_is_running() {
    let uri = "file:///workspace/.github/workflows/large.yml";
    let mut source = "on: push\njobs:\n".to_owned();
    for index in 0..900 {
        write!(
            source,
            "  job_{index}:\n    steps:\n      - run: echo {index}\n"
        )
        .unwrap();
    }
    let replacement = "on: push\njobs:\n  latest:\n    steps:\n      - run: echo latest\n";
    let messages = transcript(vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"yaml","version":1,"text":source}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":uri,"version":2},"contentChanges":[{"text":replacement}]}}),
        json!({"jsonrpc":"2.0","id":2,"method":"shutdown","params":null}),
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    ]);
    let published = messages
        .iter()
        .filter(|message| {
            message.get("method") == Some(&json!("textDocument/publishDiagnostics"))
                && message["params"]["uri"] == uri
        })
        .collect::<Vec<_>>();
    assert!(!published.is_empty());
    assert!(
        published
            .iter()
            .all(|message| message["params"]["version"] != 1)
    );
    assert_eq!(published.last().unwrap()["params"]["version"], 2);
}

#[test]
fn rename_is_blocked_when_the_new_name_changes_structure_or_semantics() {
    let uri = "file:///workspace/.github/workflows/collision.yml";
    let source = "on: push\njobs:\n  build:\n    steps:\n      - run: echo one\n  test:\n    needs: build\n    steps:\n      - run: echo two\n";
    let messages = transcript(vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"yaml","version":1,"text":source}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"textDocument/rename","params":{"textDocument":{"uri":uri},"position":{"line":2,"character":4},"newName":"test"}}),
        json!({"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}),
        json!({"jsonrpc":"2.0","method":"exit","params":null}),
    ]);

    assert_eq!(response(&messages, 2)["error"]["code"], -32602);
    let message = response(&messages, 2)["error"]["message"].as_str().unwrap();
    assert!(message.contains("re-proved"), "{message}");
}
