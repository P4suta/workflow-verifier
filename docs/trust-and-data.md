# Configuration, cache, network, and secret trust

Repository `.workflow-verifier.toml` is untrusted by default. It may make
analysis stricter, but cannot suppress findings or grant resolvers, cache trust,
network, secrets, or execution. Privilege expansion requires a trusted policy
outside the source tree or the explicit `--trust-repository-config` opt-in.
Every suppression includes rule, path, reason, owner, and expiry; expiry is a
policy failure. Reports bind configuration origin, trust class, and digest.

No cache is read from the analyzed tree. Interactive user cache lives in the OS
user-cache location and CI caching is off by default. A cache hit is advisory:
source, config, lock, tool, policy, schema, and report integrity digests are
checked, and a fresh analysis still determines pass/fail. Corruption causes
reparse, never success from cached values alone.

Source discovery excludes only `.git` and workflow-verifier's own internal
cache/output directories by default. A trusted policy may declare portable
relative prefixes with `source_exclusions = ["_build"]`; each exclusion and the
complete exclusion-policy digest are recorded in `source-manifest-v2`.
Repository configuration cannot set this field unless the caller explicitly
grants `--trust-repository-config`. Configuration and an in-tree lock are read
from, or byte-rechecked against, the same captured source snapshot.
The default `.workflow-verifier.toml` and `workflow-verifier.lock` paths cannot
be excluded because their content or explicit absence is part of provenance.

Resolver permission is a normalized HTTPS origin plus path-segment policy.
Userinfo, encoded delimiters, private addresses, unsafe redirects, non-2xx
responses, unexpected effective URLs, and oversized responses are rejected.
Credentials use stdin/private channels and are not placed in argv, dumps, logs,
or temporary files.

Plans contain secret names only. Runtime grants are per name. Redaction is
streaming and preserves matches across output chunks. A secret value must not
appear in a plan, environment dump, evidence object, argv, scratch file, or
artifact. Network, resolver access, source writes, fixes, secrets, and execution
each require a separate authorization.
