# Performance evidence

Performance is measured from a `performance-suite-v1` document. Each scenario
defines shell-free argv for setup, per-sample preparation, and the measured
command in cold, warm, and incremental modes. The measurement runner fixes
locale and timezone, bounds time and output, records positive nanosecond samples,
and writes `performance-v1` atomically.

CI measures the baseline (`A`) and candidate (`B`) one sample at a time in
paired `A-B-B-A-B-A-A-B` / `B-A-A-B-A-B-B-A` cycles. Each side receives 24
samples with equal time-position sums, predecessor counts, and first/last
placement. The two aggregated `performance-v1` documents then enter the
unchanged 10% comparison gate.

The suite also generates an `arcade-scale-analysis` fixture with 64 repository
resources, 778 variables, two protected-environment deployments, and paired
artifact/cache consumers. The many inert resources retain a roughly 900-node
graph while the grant/gate density tracks the large .NET Arcade lock workflow
that exposed repeated reachability and dominator scans. Azure-native `bash`
steps keep provider detection unambiguous for both sides of a historical
comparison. The generator is deterministic and changes one marker for
incremental samples.

The suite uses the current `--cache-mode` contract. When a historical
config-v1 baseline is measured, the shell-free driver lowers `off` to
`--no-cache` and `user` to forced fresh analysis plus an isolated cache write.
The fixture likewise emits config-v1 only for a revision without the published
config-v2 schema. Thus both revisions perform a fresh gate computation; a
historical cached report is never compared with a fresh v0.1 analysis.
For the one config-v1-to-v2 transition, the paired driver attaches the
reviewed PR #6 rationale to each measured mode. That rationale is not attached
when both revisions publish config-v2, so future regressions remain subject to
the normal unexplained-regression failure.

Release baselines are platform-specific reviewed artifacts. They are not copied
from synthetic timings. `scripts/performance_gate.py` requires an identical
environment and scenario set, computes exact rational medians, and rejects an
unexplained regression greater than 10%. A permitted regression needs both a
substantive reason and an HTTPS review URL; stale explanations are rejected.

Use `just performance-measure <revision>` with a reviewed suite, followed by
`just performance-gate <baseline>`. Publication automation must supply the
reviewed baseline rather than treating a missing baseline as success.
