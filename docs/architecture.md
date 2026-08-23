# Architecture

Architectural integrity is the project's first priority. Feature throughput,
provider convenience, and short-term compatibility do not justify crossing a
layer boundary or weakening an explicit uncertainty state. Every production
change follows the red/green/refactor contract in [tdd.md](tdd.md).

## Dependency direction

```text
foundation
├── syntax ─────────┐
└── domain ───────┐ │
                  ├─┴─ frontend
                  └─── verifier
                        │
          ┌─────────────┴─────────────┐
          │                           │
       product                     sandbox
          └─────────────┬─────────────┘
                     application
                          │
                         bin
```

All OCaml libraries are private. `foundation` has no library dependency;
`verifier` cannot see YAML or provider frontends; `sandbox` cannot see product
configuration; and only `application` composes product and sandbox ports. The
exact Dune graph, module ownership, and absence of cycles are enforced by
`scripts/verify_architecture.py` in CI.

Side effects are capability-injected ports. Core modules receive source text,
resolver callbacks, backend attestations, and evidence values; they do not
open a network connection or launch a process. The executable is the only
filesystem adapter. A transport or executor that is not injected remains
unavailable rather than being discovered implicitly.

## Semantic pipeline

Each provider implements `detect -> parse -> expand -> resolve -> lower`.
Parsing produces a lossless YAML CST with byte and Unicode-aware line/column
spans. Expansion creates explicit nodes for templates, reusable workflows,
components, commands, executors, matrices, and unresolved external units.
Lowering yields `Trigger`, `Parameter`, `Workflow`, `Stage`, `Job`, `Step`,
`Call`, `Command`, `Gate`, `Resource`, `Effect`, and `Opaque` nodes joined by
control, data, call, grant, persist, read, and write edges.

The verifier evaluates values in a product domain of type, abstract value,
trust, secrecy, and provenance. Work-list fixed points operate over the graph;
unsupported syntax, recursive expansion, and unavailable external state rise
to an explicit `Unknown` rather than disappearing. Diagnostics are projections
of property states and retain the trace that produced them.

Workspace linking is a product-layer operation over compiled units, never a
filesystem shortcut inside a frontend. Directory analysis selects provider
entrypoints first. A pure local linker resolves only referenced YAML/action
manifests from an injected source set, inherits the caller's provider, compiles
the transitive closure, detects path escape or ambiguity, and attaches the exact
source digest. Missing local units remain `Unknown` and are marked local so a
workspace path can never reach the network resolver.

Remote syntax and transport identity are separate values. A dependency keeps
the provider spelling used for diagnostics, fixes, and lock identity, plus a
typed locator such as `Repository_file { repository; revision; path;
repository_type }`. GitLab project includes and Azure repository aliases can
therefore resolve without encoding context into an ad-hoc reference string.
The resolver hashes the complete immutable archive or response, then separately
fetches the semantic entry source at that same revision. The product-layer
dependency summarizer recompiles composite actions, reusable units, templates,
components, and orbs through the ordinary frontends and stores capabilities,
effects, completeness, and missing-evidence reasons in `lock-v2`. JavaScript,
Docker, and Azure task metadata contributes only what it declares; unavailable
implementation source remains `Unknown`. A digest-only `lock-v1` entry is still
readable but can never discharge semantic uncertainty.

`Unknown` is part of the domain, not a logging convention. A frontend cannot
discard unsupported provider meaning, and runtime evidence cannot turn an
unobserved effect into a proof of absence. Deterministic serialization uses
domain-owned total orders, never filesystem enumeration order.

## Architectural enforcement

`scripts/verify_architecture.py` checks exact Dune dependency tuples,
private/unwrapped libraries, unique module ownership, and acyclicity.
`scripts/verify_pure_ocaml.py` audits declared dependencies and linked artifacts
so the analyzer cannot acquire a foreign stub or hidden linter subprocess. The
install-layout gate independently restricts the public package to one analyzer
executable and the config/report schemas. Property, mutation, fuzz, and
cross-platform byte-comparison gates cover invariants beyond example fixtures.

## Runner boundary

The runner boundary is intentionally narrow. The analyzer emits a
content-addressed execution plan. A backend returns hash-chained evidence. No
native helper is loaded into the analyzer process. Backend availability is an
attestation that every advertised control is established atomically; partial
containment is reported as unavailable and never triggers an implicit fallback.
