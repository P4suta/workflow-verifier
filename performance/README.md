# Performance evidence

Performance is measured from the shell-free
`performance/rust-suite-v2.json` document. Each scenario has one independent
command, setup phase, per-sample preparation phase, timeout, and working
directory. The runner fixes locale and timezone, bounds output, records positive
nanosecond samples, and writes `performance-v2` atomically.

The suite measures distinct product workloads:

- cold static check;
- graph JSON generation;
- LSP initial analysis, no-op analysis, and edited analysis;
- a mixed four-provider workspace;
- repository dogfood.

There is no result-cache mode and no fresh-process “warm” or “incremental”
label. LSP scenarios exercise the persistent `AnalysisSession`; single-shot
commands always use the stateless `Analyzer`.

CI measures baseline `A` and candidate `B` one sample at a time in paired
`A-B-B-A-B-A-A-B` and `B-A-A-B-A-B-B-A` cycles. Each side receives 24 samples
with equal time-position sums, predecessor counts, and first/last placement.
The two `performance-v2` documents enter `performance-comparison-v2`.

Release baselines are platform-specific reviewed artifacts, never fabricated
from synthetic timings. `scripts/performance_gate.py` requires identical
environment and scenario sets, computes exact rational medians, and rejects an
unexplained regression greater than 10 percent. A permitted regression needs a
substantive reason and an HTTPS review URL; stale explanations are rejected.

Use `just performance-measure-rust REVISION` for one revision or
`just performance-pair-rust BASE_WORKSPACE BASE_REVISION REVISION` for a
period-balanced comparison. Pass the resulting ledgers to
`just performance-gate BASELINE`; a missing baseline is never success.
