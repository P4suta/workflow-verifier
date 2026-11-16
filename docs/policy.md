# Policy language

`.workflow-verifier.toml` is declarative.
It has no string evaluation or plugin execution.
Built-in selectors can match provider, node kind, path, trust, effect, capability, dependency mutability, and authorization dominance.

```toml
version = 2
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

[[suppressions]]
rule = "WV-SUPPLY-001"
path = ".github/workflows/release.yml"
reason = "the release action is pinned by the organization mirror"
owner = "release-team"
expiry = "2027-06-30"
```

Rule kinds are `forbid`, `require`, `limit`, and `forbid_path`.
Boolean composition uses typed `all`, `any`, and `none` selector groups.

Each suppression needs a non-empty `rule`, `path`, `reason`, `owner`, and `expiry`.
`owner` is a portable identifier, and `expiry` is an ISO 8601 calendar date.
After the expiry date, loading the configuration fails with exit code 2, so an expired suppression stops every run until someone renews or removes it.
