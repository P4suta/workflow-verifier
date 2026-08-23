# Policy language

`.workflow-verifier.toml` is declarative. It has no string evaluation or plugin
execution. Built-in selectors can match provider, node kind, path, trust,
effect, capability, dependency mutability, and authorization dominance.

```toml
version = 1
persona = "gate"

[[rules]]
id = "ORG-001"
kind = "forbid"
selector.effect = "network"
selector.trust = "untrusted"
message = "untrusted data must not select network destinations"

[[rules]]
id = "ORG-002"
kind = "limit"
selector.capability = "repository_write"
limit = 0
```

Rule kinds are `forbid`, `require`, `limit`, and `forbid_path`. Boolean
composition is limited to typed `all`, `any`, and `none` selector groups.
Suppressions require a rule ID and non-empty reason.
