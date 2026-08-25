# 日本語クイックスタートと制約

workflow-verifier は既定でオフラインです。テレメトリはなく、network、
secret、ファイル更新、workflow 実行はそれぞれ別の明示許可が必要です。

```text
workflow-verifier check .
workflow-verifier check --format json --output report-v2.json .
workflow-verifier sandbox plan --job build .
workflow-verifier sandbox run --job build --backend oci:docker .
workflow-verifier doctor --format json
```

sandbox v0.1 が再生するのは、明示した provider、workflow、job、event、
inputs、matrix、runner の具体的な1シナリオです。完全な CI runner 互換では
ありません。未知の expression、service、cache、artifact、deployment 等は
推測せず `Incomplete` になり、strict mode の終了コードは 3 です。
必要な隔離を実装できない host は終了コード 5 で停止し、弱い sandbox や
無制限 network へ切り替えません。

repository 内の設定は未信頼で、既定では診断を厳しくする変更だけ可能です。
抑制や権限拡大には repository 外の trusted policy、または明示的な
`--trust-repository-config` が必要です。cache は対象 tree 内から読みません。

macOS 版は ad-hoc 署名と Sigstore を使用し、Developer ID 署名と
notarization はありません。そのため通常の Gatekeeper 信頼は得られません。
また、v0.1 の監査は sole maintainer による署名付き self-audit であり、
独立監査ではありません。この2点が v0.1 で認める例外です。
