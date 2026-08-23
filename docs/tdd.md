# Test-driven development ledger

The project is built in vertical contracts. A slice may enter production code
only after its externally observable behavior is expressed by a failing test.
The implementation is then minimized until green, followed by a dependency and
naming refactor while the same test remains green.

| Slice | Red contract | Green criterion | Refactor boundary |
|---|---|---|---|
| Foundation | Canonical JSON and FIPS SHA-256 vectors | Byte-exact vectors pass | No dependency outside Stdlib |
| YAML CST | Lossless CRLF/comments, anchor/alias, duplicate key, nested sequence, span edit | Parse/print and structural contracts pass | `syntax` depends only on `foundation` |
| CI compilers | Provider golden fixtures fail before lowering exists | Four fixtures lower to equal semantic shapes | Provider syntax cannot leak into domain types |
| Frontend discovery | Azure's `stages`/`script` shape is claimed by GitLab | Provider-specific path identity wins before shape fallback | Detection precedence is owned once by the common frontend registry |
| Verifier | Vulnerable/safe/unknown triples per rule | Trace and property-state goldens pass | Rules consume facts, not YAML |
| Product surface | CLI snapshot contracts | Canonical JSON/SARIF/lock/diff byte-match | Side effects isolated in adapters |
| Sandbox | Backend conformance attack fixtures | Required controls attest or fail closed | Helpers share protocol JSON only |
| Workspace linking | Local action/template starts unresolved | Transitive unit is content-addressed and call-linked | I/O stays in application; linker stays pure |
| Resolution | Provider alias/project fixture has no transport context | Typed locator resolves an immutable source | Display reference and transport identity remain separate |
| Remote summaries | Locked binary call incorrectly becomes known | Exact source refines effects; missing implementation remains `Unknown` | Full-content digest, semantic source, and call overlay stay separate |
| Abstract domains | Generated semilattice/Boolean laws find a counterexample | Thousands of seeded laws pass deterministically | Minimize the domain fix, retain the counterexample |
| Robustness | AFL seed smoke and malformed corpus | Nonempty executions, no crash or hang | Harness contains no production fallback |
| Mutation | Incomplete or vacuous report is accepted | Every configured core prefix was actually mutated | Reviewed equivalents are explicit evidence |
| Evaluation | Bad precision/recall/performance fixture passes | 95%/100% and 10% gates reject it | Inputs are immutable and machine-readable |
| Performance experiment | Sequential runner drift looks like a code regression | A-B-B-A-A-B batches retain 21 samples per revision | Measurement order is owned by the pair orchestrator; the comparison gate is unchanged |
| Publication evidence | Missing or self-asserted review permits a tag publish | Candidate-bound corpus, four platforms, and external Sigstore identity pass | Evidence composition is separate from build and publish authority |
| Live dogfood | A passing artifact omits one provider or trusts a forged runtime event | Four real provider roots, zero diagnostics, and a recomputed evidence/audit chain pass | CLI execution and evidence verification remain separate processes |
| Determinism | Platform artifacts differ by newline/path/order | Exact report, lock, and fix bytes match | Canonicalization stays at ownership boundary |
| Native temporary resources | Parallel AppContainer tests collide on a clock-derived path | Atomic reservations and parallel probes pass | Allocation lives in helper runtime, containment stays backend-owned |
| Block scalar isolation | Markdown link text in a folded action description is misread as a flow collection | The production-shaped metadata has only its genuine binary-implementation `Unknown` | One block-header classifier owns both validation and payload boundaries |
| Lock protocol fixtures | A `lock-v1` determinism fixture cannot reproduce the current producer's `lock-v2` bytes | Two independent v2 probes match while v1 still round-trips canonically | Current-producer determinism and backward-read compatibility use separate contracts |

Commits should use `test:`, `feat:`, and `refactor:` prefixes when preserving the
red/green/refactor trail. CI includes an ordering-permutation contract that
constructs equivalent reports from reversed input, graph, and verification
enumerations and requires byte-identical canonical output.

The local release sequence is `just check` (or the corresponding `mise check`
task). It runs OCaml contracts, tooling unit tests, the architecture graph gate,
the pure-OCaml audit, install-surface verification, Rust conformance tests,
`rustfmt --check`, and Clippy with every warning denied.

Property tests use fixed seeds and print the failing case, making every failure
replayable. Coverage-guided fuzzing is separately bounded by wall time, memory,
output, and an execution-count check. Mutation testing runs a three-pass
baseline before mutants and rejects empty catalogs, unexecuted mutants,
unsubstantiated timeouts, uncovered source prefixes, and undocumented
equivalent survivors.

No green test may be obtained by weakening an assertion from a semantic fact to
mere output presence. When a test exposes an architectural mismatch, the
refactor moves responsibility to the owning layer before the next slice begins.
