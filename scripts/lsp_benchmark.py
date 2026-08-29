#!/usr/bin/env python3
"""Run one deterministic initial, no-op, or edited LSP diagnostics exchange."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, BinaryIO


def _write(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def _read(stream: BinaryIO) -> dict[str, Any]:
    length: int | None = None
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("LSP server closed its output")
        if line == b"\r\n":
            break
        name, separator, value = line.partition(b":")
        if not separator:
            raise RuntimeError("malformed LSP response header")
        if name.lower() == b"content-length":
            length = int(value.strip())
    if length is None or length > 16 * 1024 * 1024:
        raise RuntimeError("invalid LSP response length")
    body = stream.read(length)
    if len(body) != length:
        raise RuntimeError("truncated LSP response")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError("LSP response is not an object")
    return value


def _expect(stream: BinaryIO, predicate: Any) -> dict[str, Any]:
    for _ in range(8):
        message = _read(stream)
        if predicate(message):
            return message
    raise RuntimeError("expected LSP response was not observed")


def run(analyzer: Path, fixture: Path, mode: str) -> None:
    source = fixture.read_text(encoding="utf-8")
    uri = fixture.resolve().as_uri()
    process = subprocess.Popen(
        [str(analyzer.resolve()), "lsp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("LSP pipes were not created")
    try:
        _write(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"rootUri": fixture.parent.resolve().as_uri(), "capabilities": {}},
            },
        )
        _expect(process.stdout, lambda value: value.get("id") == 1)
        _write(process.stdin, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
        _write(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "yaml",
                        "version": 1,
                        "text": source,
                    }
                },
            },
        )
        _expect(
            process.stdout,
            lambda value: value.get("method") == "textDocument/publishDiagnostics",
        )
        if mode != "initial":
            changed = source if mode == "noop" else source + "\n# performance edit\n"
            _write(
                process.stdin,
                {
                    "jsonrpc": "2.0",
                    "method": "textDocument/didChange",
                    "params": {
                        "textDocument": {"uri": uri, "version": 2},
                        "contentChanges": [{"text": changed}],
                    },
                },
            )
            _expect(
                process.stdout,
                lambda value: (
                    value.get("method") == "textDocument/publishDiagnostics"
                    and value.get("params", {}).get("version") == 2
                ),
            )
        _write(
            process.stdin,
            {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": None},
        )
        _expect(process.stdout, lambda value: value.get("id") == 2)
        _write(process.stdin, {"jsonrpc": "2.0", "method": "exit", "params": None})
        process.stdin.close()
        code = process.wait(timeout=5)
        if code != 0:
            error = process.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LSP server exited {code}: {error}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--mode", choices=("initial", "noop", "edit"), required=True)
    arguments = parser.parse_args()
    try:
        run(arguments.analyzer, arguments.fixture, arguments.mode)
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as error:
        print(f"LSP benchmark: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
