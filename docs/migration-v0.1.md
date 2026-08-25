# Migration to v0.1 contracts

The pre-release v1 config and lock formats are not current product contracts.
Run `workflow-verifier migrate INPUT --output OUTPUT`. Legacy suppressions
require explicit `--suppression-owner` and `--suppression-expiry`; legacy
resolver URLs are converted only when they are safe HTTPS origins. The emitted
config-v2 or lock-v2 is parsed again before it is written.

There is no migration for report-v1, runner-v1, sandbox-run-v1, or evidence-v1.
Regenerate those objects from an immutable source snapshot and explicit
scenario. Treating old bytes as current evidence would change their meaning and
is rejected.
