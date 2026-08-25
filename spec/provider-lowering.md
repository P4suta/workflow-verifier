# Provider lowering and scenario semantics

GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI lower into the same
phase-aware DAG. Nodes identify trigger, parameter, workflow, stage, job, step,
call, command, gate, resource, effect, or opaque semantics. Edges identify
control, data, call, capability, authorization, and local-unit relationships.
Stable source spans and provider semantic-profile IDs are mandatory.

Static lowering covers every understood provider construct and retains unknown
constructs. Runtime planning starts from one scenario-v1: provider, workflow
entrypoint, selected job, event, inputs, matrix values, variables, runner
platform, and secret names. It expands only concrete needs, matrix,
conditions, local reusable workflows, and composite actions reachable from that
selection, then emits topological job instances.

An unresolved call, service, cache, artifact, deployment, expression, runner
tool, or provider status/output semantic makes the affected plan Incomplete.
The planner must not flatten every command in the repository into one execution
list. Shell, working directory, environment, status, and output behavior are
selected by provider and runner OS; a Linux shell path is never claimed
supported on Windows.
