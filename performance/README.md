# Performance evidence

Performance is measured from a `performance-suite-v1` document. Each scenario
defines shell-free argv for setup, per-sample preparation, and the measured
command in cold, warm, and incremental modes. The measurement runner fixes
locale and timezone, bounds time and output, records positive nanosecond samples,
and writes `performance-v1` atomically.

CI measures the baseline (`A`) and candidate (`B`) in counterbalanced
`A-B-B-A-A-B` batches. Each side still receives 21 samples, while equal early,
middle, and late exposure removes runner warm-up, contention, and thermal order
bias. The two aggregated `performance-v1` documents then enter the unchanged
10% comparison gate.

Release baselines are platform-specific reviewed artifacts. They are not copied
from synthetic timings. `scripts/performance_gate.py` requires an identical
environment and scenario set, computes exact rational medians, and rejects an
unexplained regression greater than 10%. A permitted regression needs both a
substantive reason and an HTTPS review URL; stale explanations are rejected.

Use `just performance-measure <revision>` with a reviewed suite, followed by
`just performance-gate <baseline>`. Publication automation must supply the
reviewed baseline rather than treating a missing baseline as success.
