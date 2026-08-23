# Dependency rules

The architecture is a directed acyclic graph:

```text
foundation -> syntax ----> frontend --\
          \-> domain ----> verifier ---> product --\
                                \-------> sandbox ---> application ---> bin
```

- Foundation owns deterministic bytes, spans, hashes, and canonical JSON.
- Syntax owns lossless source representation; it has no provider concepts.
- Domain owns semantic facts and graphs; it has no YAML concepts.
- Frontends are compilers from syntax into domain values.
- Verifier is a pure query over domain values and cannot see provider syntax.
- Product composes frontends and verifier into policy, lock, diff, fix, and
  report operations; sandbox owns plans and evidence independently.
- Application coordinates those pure operations through capability records.
- The executable adapters are the only filesystem, network, process, or OS
  boundary.

Dune private libraries enforce the arrows. There is no catch-all `common`
module, provider-specific field in the IR, mutable global registry, or exception
crossing a layer boundary. Expected incompleteness is a typed value.

Remote resolution deliberately has two evidence channels: the digest covers the
complete immutable response, while an exact-revision semantic entry source is
compiled into a `lock-v2` summary. Product owns that composition. Transport does
not infer effects, and frontends do not perform network access.
